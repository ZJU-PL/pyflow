"""Project-aware Python import and module resolution.

This module is intentionally modeled after Jedi's project/import resolution
layer, but exposes a small side-effect-free API suitable for PyFlow analyses.
It handles the filesystem parts of Python import semantics: project sys.path
construction, relative import anchoring, package ``__init__`` files, implicit
namespace packages, in-memory source maps, and dotted-name/path conversion.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from dataclasses import dataclass
from importlib.machinery import all_suffixes
from itertools import chain
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Set

from .imports import iter_import_nodes_in_scope

_CONTAINS_POTENTIAL_PROJECT = (
    "setup.py",
    ".git",
    ".hg",
    "requirements.txt",
    "MANIFEST.in",
    "pyproject.toml",
)


@dataclass(frozen=True)
class ModuleResolution:
    """Resolved module location and package metadata."""

    module_name: str
    path: Optional[str]
    is_package: bool = False
    is_namespace: bool = False
    namespace_paths: tuple[str, ...] = ()
    is_in_memory: bool = False


def _remove_duplicates_from_path(paths: Iterable[str]) -> List[str]:
    used: Set[str] = set()
    out: List[str] = []
    for path in paths:
        if path in used:
            continue
        used.add(path)
        out.append(path)
    return out


def _is_potential_project(path: Path) -> bool:
    for name in _CONTAINS_POTENTIAL_PROJECT:
        try:
            if path.joinpath(name).exists():
                return True
        except OSError:
            continue
    return False


def infer_project_path(path: str | os.PathLike[str] | None = None) -> Path:
    """Infer a project root similarly to Jedi's default project discovery."""

    if path is None:
        check = Path.cwd().absolute()
    else:
        check = Path(path).absolute()

    probable_path: Optional[Path] = None
    first_no_init_file: Optional[Path] = None

    for directory in chain([check], check.parents):
        if first_no_init_file is None:
            try:
                if directory.joinpath("__init__.py").exists():
                    continue
                if not directory.is_file():
                    first_no_init_file = directory
            except OSError:
                pass

        if probable_path is None and _is_potential_project(directory):
            probable_path = directory

    if probable_path is not None:
        return probable_path
    if first_no_init_file is not None:
        return first_no_init_file
    return check if check.is_dir() else check.parent


def remove_python_path_suffix(path: Path) -> Path:
    """Remove importable Python/extension suffixes and ``.pyi`` from a path."""

    for suffix in all_suffixes() + [".pyi"]:
        if path.suffix == suffix:
            return path.with_name(path.stem)
    return path


def transform_path_to_dotted(
    sys_path: Sequence[str], module_path: str | os.PathLike[str]
) -> tuple[Optional[tuple[str, ...]], bool]:
    """Return the shortest dotted import path for a module path.

    Returns ``(None, False)`` when the path is not importable from ``sys_path``.
    The boolean indicates whether the path refers to a package ``__init__``.
    """

    path = remove_python_path_suffix(Path(module_path).absolute())
    if path.name.startswith("."):
        return None, False

    is_package = path.name == "__init__"
    if is_package:
        path = path.parent

    path_str = os.path.realpath(str(path))
    candidates: List[tuple[str, ...]] = []
    for root in sys_path:
        if not root:
            root = os.curdir
        root_str = os.path.realpath(str(Path(root).absolute()))
        try:
            common = os.path.commonpath([root_str, path_str])
        except ValueError:
            continue
        if common != root_str:
            continue
        rest = os.path.relpath(path_str, root_str)
        if rest in ("", "."):
            continue
        parts = rest.split(os.sep)
        if not all(parts):
            continue
        candidates.append(tuple(re.sub(r"-stubs$", "", part) for part in parts))

    if not candidates:
        return None, False
    return sorted(candidates, key=len)[0], is_package


def _abs_path(base_file: Optional[str], str_path: str) -> Optional[str]:
    path = Path(str_path)
    if path.is_absolute():
        return str(path)
    if base_file is None or base_file.startswith("<"):
        return None
    return str(Path(base_file).parent.joinpath(path).resolve(strict=False))


def _literal_string_values(node: ast.AST) -> Iterator[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for item in node.elts:
            yield from _literal_string_values(item)


def check_sys_path_modifications(source: str, file_path: Optional[str]) -> List[str]:
    """Detect simple module-level ``sys.path`` additions in source code.

    This follows Jedi's tolerant approach, but remains AST/literal based so it
    never executes analyzed code.
    """

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    paths: List[str] = []
    for node in getattr(tree, "body", ()):
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AugAssign):
            targets = [node.target]
            value = node.value
        else:
            targets = []
            value = None

        for target in targets:
            base = target.value if isinstance(target, ast.Subscript) else target
            if (
                isinstance(base, ast.Attribute)
                and base.attr == "path"
                and isinstance(base.value, ast.Name)
                and base.value.id == "sys"
                and value is not None
            ):
                for path in _literal_string_values(value):
                    abs_path = _abs_path(file_path, path)
                    if abs_path is not None:
                        paths.append(abs_path)

        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr in {"append", "insert"}
            and isinstance(node.value.func.value, ast.Attribute)
            and node.value.func.value.attr == "path"
            and isinstance(node.value.func.value.value, ast.Name)
            and node.value.func.value.value.id == "sys"
        ):
            args = list(node.value.args)
            if node.value.func.attr == "insert" and len(args) >= 2:
                args = args[1:]
            if args:
                for path in _literal_string_values(args[0]):
                    abs_path = _abs_path(file_path, path)
                    if abs_path is not None:
                        paths.append(abs_path)

    return _remove_duplicates_from_path(paths)


class ProjectContext:
    """Project and import-path context for side-effect-free analysis."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        sys_path: Optional[Sequence[str]] = None,
        added_sys_path: Sequence[str] = (),
        smart_sys_path: bool = True,
        source_files: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.path = Path(path).absolute() if path is not None else infer_project_path()
        self._sys_path = list(map(str, sys_path)) if sys_path is not None else None
        self.added_sys_path = [str(p) for p in added_sys_path]
        self.smart_sys_path = smart_sys_path
        self.source_files: Dict[str, str] = dict(source_files or {})

    def with_source_files(self, source_files: Mapping[str, str]) -> "ProjectContext":
        self.source_files.update(source_files)
        return self

    def get_base_sys_path(self) -> List[str]:
        paths = list(sys.path) if self._sys_path is None else list(self._sys_path)
        return [p for p in paths if p != ""]

    def get_sys_path(
        self,
        *,
        script_path: str | os.PathLike[str] | None = None,
        add_parent_paths: bool = True,
        add_init_paths: bool = False,
        source: Optional[str] = None,
    ) -> List[str]:
        """Build an analysis sys.path with Jedi-style project additions."""

        prefixed: List[str] = []
        suffixed: List[str] = list(self.added_sys_path)
        base = self.get_base_sys_path()

        if self.smart_sys_path:
            prefixed.append(str(self.path))

            if script_path is not None:
                script = Path(script_path).absolute()
                if add_parent_paths:
                    traversed: List[str] = []
                    for parent_path in script.parents:
                        if (
                            parent_path == self.path
                            or self.path not in parent_path.parents
                        ):
                            break
                        if (
                            not add_init_paths
                            and parent_path.joinpath("__init__.py").is_file()
                        ):
                            continue
                        traversed.append(str(parent_path))
                    suffixed += list(reversed(traversed))

                if source is None:
                    source = self.source_files.get(str(script_path))
                if source is not None:
                    suffixed += check_sys_path_modifications(source, str(script))

        return _remove_duplicates_from_path(prefixed + base + suffixed)

    def module_name_from_path(
        self, file_path: str | os.PathLike[str], *, allow_absolute_fallback: bool = True
    ) -> str:
        """Infer an import-qualified module name for a path."""

        file_str = str(file_path)
        if file_str == "<string>" or file_str.startswith("<"):
            return "__pyflow_module__"

        path = Path(file_str)
        if not path.is_absolute():
            path = Path(file_str)
            abs_path = path.absolute()
        else:
            abs_path = path

        project_roots = [str(self.path)] + list(self.added_sys_path)
        dotted, _ = transform_path_to_dotted(project_roots, abs_path)
        if dotted is None:
            dotted, _ = transform_path_to_dotted(self.get_base_sys_path(), abs_path)
        if dotted:
            parts = list(dotted)
            if parts and parts[-1] == "__init__":
                parts = parts[:-1]
            if parts:
                return ".".join(parts)

        if not allow_absolute_fallback:
            return "main"

        stem = path.stem if path.suffix == ".py" else path.name
        return stem or "__pyflow_module__"

    def resolve_import_name(
        self,
        current_module: str,
        imported_module: Optional[str],
        level: int,
        *,
        current_path: str | os.PathLike[str] | None = None,
    ) -> Optional[str]:
        """Resolve an ``ImportFrom`` module name using PEP 328-style ascents."""

        if level <= 0:
            return imported_module

        effective_module = current_module
        if effective_module == "main" and current_path is not None:
            effective_module = self.module_name_from_path(current_path)

        package_parts = [p for p in effective_module.split(".") if p]
        is_package_module = False
        if package_parts and package_parts[-1] == "__init__":
            package_parts = package_parts[:-1]
            is_package_module = True
        elif current_path is not None:
            is_package_module = os.path.basename(str(current_path)) == "__init__.py"
        elif "." not in effective_module and effective_module != "main":
            is_package_module = True

        if package_parts and not is_package_module:
            package_parts = package_parts[:-1]

        ascents = level - 1
        if ascents > len(package_parts):
            return imported_module

        prefix = ".".join(package_parts[: len(package_parts) - ascents])
        if imported_module:
            return f"{prefix}.{imported_module}" if prefix else imported_module
        return prefix or imported_module

    def _source_map(self) -> Dict[str, str]:
        mapping: Dict[str, str] = {}
        roots = [str(self.path)] + self.get_base_sys_path() + self.added_sys_path
        for filename in self.source_files:
            name = self.module_name_from_path(filename)
            mapping[name] = filename
            if name.endswith(".__init__"):
                mapping[name[: -len(".__init__")]] = filename
            dotted, is_package = transform_path_to_dotted(roots, filename)
            if dotted:
                candidate = ".".join(
                    dotted[:-1] if is_package and dotted[-1] == "__init__" else dotted
                )
                if candidate:
                    mapping[candidate] = filename
        return mapping

    def find_module(
        self,
        module_name: str,
        *,
        script_path: str | os.PathLike[str] | None = None,
        source: Optional[str] = None,
        extra_sys_path: Sequence[str] = (),
    ) -> Optional[ModuleResolution]:
        """Resolve a dotted module to a Python source file or namespace package."""

        if not module_name:
            return None

        source_map = self._source_map()
        if module_name in source_map:
            path = source_map[module_name]
            return ModuleResolution(
                module_name=module_name,
                path=path,
                is_package=os.path.basename(path) == "__init__.py",
                is_in_memory=True,
            )

        parts = module_name.split(".")
        search_path = self.get_sys_path(script_path=script_path, source=source)
        search_path = _remove_duplicates_from_path(list(extra_sys_path) + search_path)

        namespace_paths: List[str] = []
        for root in search_path:
            if not root:
                root = os.curdir
            base = os.path.join(root, *parts)
            py_file = f"{base}.py"
            if os.path.isfile(py_file):
                return ModuleResolution(module_name, os.path.abspath(py_file))

            init_file = os.path.join(base, "__init__.py")
            if os.path.isfile(init_file):
                return ModuleResolution(
                    module_name,
                    os.path.abspath(init_file),
                    is_package=True,
                    namespace_paths=(os.path.abspath(base),),
                )

            if os.path.isdir(base):
                namespace_paths.append(os.path.abspath(base))

        if namespace_paths:
            return ModuleResolution(
                module_name,
                None,
                is_package=True,
                is_namespace=True,
                namespace_paths=tuple(_remove_duplicates_from_path(namespace_paths)),
            )
        return None

    def iter_imported_modules(
        self,
        tree: ast.AST,
        *,
        current_module: str,
        current_path: str | os.PathLike[str] | None = None,
    ) -> Iterator[str]:
        """Yield import-reachable modules from module-scope imports."""

        yielded: Set[str] = set()

        def emit(name: Optional[str]) -> Iterator[str]:
            if name and name not in yielded:
                yielded.add(name)
                yield name

        for node in iter_import_nodes_in_scope(getattr(tree, "body", ()) or ()):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    yield from emit(alias.name)
            elif isinstance(node, ast.ImportFrom):
                resolved = self.resolve_import_name(
                    current_module,
                    node.module or "",
                    node.level,
                    current_path=current_path,
                )
                yield from emit(resolved)
                if resolved:
                    for alias in node.names:
                        if alias.name == "*":
                            continue
                        candidate = f"{resolved}.{alias.name}"
                        if self.find_module(candidate, script_path=current_path):
                            yield from emit(candidate)
