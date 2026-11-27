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


@dataclass(frozen=True)
class ModuleIdentityResolver:
    """Derive module names relative to the nearest configured workspace root."""

    workspace_roots: tuple[Path, ...]

    def __init__(self, workspace_roots: Iterable[str | os.PathLike[str]]):
        object.__setattr__(
            self,
            "workspace_roots",
            tuple(Path(root).absolute() for root in workspace_roots),
        )

    def module_name_from_path(self, file_path: str | os.PathLike[str]) -> Optional[str]:
        path = Path(file_path).absolute()
        containing_roots: list[Path] = []
        for root in self.workspace_roots:
            try:
                path.relative_to(root)
            except ValueError:
                continue
            containing_roots.append(root)
        if not containing_roots:
            return None
        root = max(containing_roots, key=lambda item: len(item.parts))
        relative = path.relative_to(root).with_suffix("")
        parts = list(relative.parts)
        if len(parts) > 1 and parts[0] == "src" and not (root / "src" / "__init__.py").is_file():
            parts.pop(0)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts) or path.stem


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


def _prepare_module_realpath(
    module_path: str | os.PathLike[str],
    realpath_fn=os.path.realpath,
) -> tuple[Optional[str], bool]:
    path = remove_python_path_suffix(Path(module_path).absolute())
    if path.name.startswith("."):
        return None, False

    is_package = path.name == "__init__"
    if is_package:
        path = path.parent

    return realpath_fn(str(path)), is_package


def _transform_realpath_to_dotted(
    resolved_roots: Sequence[str],
    path_str: Optional[str],
    is_package: bool,
) -> tuple[Optional[tuple[str, ...]], bool]:
    if not path_str:
        return None, False

    candidates: List[tuple[str, ...]] = []
    sep = os.sep
    for root_str in resolved_roots:
        if path_str == root_str:
            continue
        # Fast prefix test avoids os.path.commonpath / os.path.relpath overhead
        # on the vast majority of non-matching sys.path roots.
        if root_str.endswith(sep):
            prefix = root_str
        else:
            prefix = root_str + sep
        if not path_str.startswith(prefix):
            continue
        rest = path_str[len(prefix) :]
        if not rest or rest == ".":
            continue
        parts = rest.split(sep)
        if not all(parts):
            continue
        candidates.append(tuple(re.sub(r"-stubs$", "", part) for part in parts))

    if not candidates:
        return None, False
    return min(candidates, key=len), is_package


def transform_path_to_dotted(
    sys_path: Sequence[str], module_path: str | os.PathLike[str]
) -> tuple[Optional[tuple[str, ...]], bool]:
    """Return the shortest dotted import path for a module path.

    Returns ``(None, False)`` when the path is not importable from ``sys_path``.
    The boolean indicates whether the path refers to a package ``__init__``.
    """

    path_str, is_package = _prepare_module_realpath(module_path)
    if not path_str:
        return None, False
    resolved_roots = [
        os.path.realpath(str(Path(root or os.curdir).absolute())) for root in sys_path
    ]
    return _transform_realpath_to_dotted(resolved_roots, path_str, is_package)


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
    if "sys" not in source or "path" not in source:
        return []

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
        workspace_roots: Sequence[str | os.PathLike[str]] = (),
        module_name_overrides: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.path = Path(path).absolute() if path is not None else infer_project_path()
        self._sys_path = list(map(str, sys_path)) if sys_path is not None else None
        self.added_sys_path = [str(p) for p in added_sys_path]
        self.smart_sys_path = smart_sys_path
        self.source_files: Dict[str, str] = dict(source_files or {})
        self.module_identity = ModuleIdentityResolver(workspace_roots)
        self.module_name_overrides = {
            os.path.realpath(filename): name
            for filename, name in (module_name_overrides or {}).items()
        }
        self._source_map_cache: Optional[Dict[str, str]] = None
        self._source_map_cache_keys: Optional[frozenset[str]] = None
        self._find_module_cache: Dict[tuple[object, ...], Optional[ModuleResolution]] = {}
        self._find_module_cache_order: List[tuple[object, ...]] = []
        self._max_find_module_cache = 8192
        self._realpath_cache: Dict[str, str] = {}
        self._resolved_roots_cache: Dict[tuple[str, ...], tuple[str, ...]] = {}
        self._sys_path_mod_cache: Dict[tuple[str, str], tuple[str, ...]] = {}
        self._sys_path_cache: Dict[tuple[object, ...], tuple[str, ...]] = {}

    def _realpath(self, path_str: str) -> str:
        cached = self._realpath_cache.get(path_str)
        if cached is not None:
            return cached
        resolved = os.path.realpath(path_str)
        if len(self._realpath_cache) >= 16384:
            self._realpath_cache.clear()
        self._realpath_cache[path_str] = resolved
        return resolved

    def _resolve_roots(self, roots: Sequence[str]) -> tuple[str, ...]:
        key = tuple(roots)
        cached = self._resolved_roots_cache.get(key)
        if cached is not None:
            return cached
        resolved = tuple(self._realpath(str(Path(root or os.curdir).absolute())) for root in roots)
        if len(self._resolved_roots_cache) >= 64:
            self._resolved_roots_cache.clear()
        self._resolved_roots_cache[key] = resolved
        return resolved

    def with_source_files(self, source_files: Mapping[str, str]) -> "ProjectContext":
        self.source_files.update(source_files)
        self._sys_path_cache.clear()
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
        base = self.get_base_sys_path()
        script_key = str(script_path) if script_path is not None else None
        resolved_source = (
            source
            if source is not None
            else (self.source_files.get(script_key) if script_key is not None else None)
        )
        cache_key = (
            script_key,
            add_parent_paths,
            add_init_paths,
            resolved_source,
            self.smart_sys_path,
            tuple(base),
            tuple(self.added_sys_path),
        )
        cached = self._sys_path_cache.get(cache_key)
        if cached is not None:
            return list(cached)

        prefixed: List[str] = []
        suffixed: List[str] = list(self.added_sys_path)

        if self.smart_sys_path:
            prefixed.append(str(self.path))
            src_dir = self.path.joinpath("src")
            if src_dir.is_dir() and not src_dir.joinpath("__init__.py").is_file():
                prefixed.append(str(src_dir))

            if script_path is not None:
                script = Path(script_path).absolute()
                if add_parent_paths:
                    traversed: List[str] = []
                    for parent_path in script.parents:
                        if parent_path == self.path or self.path not in parent_path.parents:
                            break
                        if not add_init_paths and parent_path.joinpath("__init__.py").is_file():
                            continue
                        traversed.append(str(parent_path))
                    suffixed += list(reversed(traversed))

                if resolved_source is not None:
                    script_str = str(script)
                    mod_key = (script_str, resolved_source)
                    cached_mods = self._sys_path_mod_cache.get(mod_key)
                    if cached_mods is None:
                        cached_mods = tuple(
                            check_sys_path_modifications(resolved_source, script_str)
                        )
                        if len(self._sys_path_mod_cache) >= 512:
                            self._sys_path_mod_cache.clear()
                        self._sys_path_mod_cache[mod_key] = cached_mods
                    if cached_mods:
                        suffixed.extend(cached_mods)

        result = _remove_duplicates_from_path(prefixed + base + suffixed)
        if len(self._sys_path_cache) >= 512:
            self._sys_path_cache.clear()
        self._sys_path_cache[cache_key] = tuple(result)
        return result

    def module_name_from_path(
        self, file_path: str | os.PathLike[str], *, allow_absolute_fallback: bool = True
    ) -> str:
        """Infer an import-qualified module name for a path."""

        file_str = str(file_path)
        if file_str == "<string>" or file_str.startswith("<"):
            return "__pyflow_module__"

        if self.module_name_overrides:
            override = self.module_name_overrides.get(self._realpath(file_str))
            if override is not None:
                return override

        workspace_module = self.module_identity.module_name_from_path(file_str)
        if workspace_module is not None:
            return workspace_module

        path = Path(file_str)
        abs_path = path if path.is_absolute() else path.absolute()

        path_real, is_package = _prepare_module_realpath(abs_path, self._realpath)
        project_roots = self._resolve_roots([str(self.path)] + list(self.added_sys_path))
        dotted, _ = _transform_realpath_to_dotted(project_roots, path_real, is_package)
        if dotted is None:
            base_roots = self._resolve_roots(self.get_base_sys_path())
            dotted, _ = _transform_realpath_to_dotted(base_roots, path_real, is_package)
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
            is_package_module = Path(current_path).stem == "__init__"
        elif "." not in effective_module and effective_module != "main":
            is_package_module = True

        if package_parts and not is_package_module:
            package_parts = package_parts[:-1]

        ascents = level - 1
        if ascents >= len(package_parts):
            return None

        prefix = ".".join(package_parts[: len(package_parts) - ascents])
        if imported_module:
            return f"{prefix}.{imported_module}" if prefix else imported_module
        return prefix or imported_module

    def _source_map(self) -> Dict[str, str]:
        # The map depends only on the set of source file paths and the (stable)
        # search roots, so it is rebuilt only when new files are registered
        # instead of on every module lookup.  Cross-module base-class resolution
        # calls this once per unresolved base, which previously rebuilt the map
        # over the whole project each time.
        current_keys = frozenset(self.source_files.keys())
        if self._source_map_cache is not None and self._source_map_cache_keys == current_keys:
            return self._source_map_cache
        mapping: Dict[str, str] = {}
        aliases: Dict[str, str] = {}
        ambiguous_aliases: Set[str] = set()
        resolved_roots = self._resolve_roots(
            [str(self.path)] + self.get_base_sys_path() + self.added_sys_path
        )
        for filename in self.source_files:
            name = self.module_name_from_path(filename)
            mapping[name] = filename
            if name.endswith(".__init__"):
                mapping[name[: -len(".__init__")]] = filename
            path_real, is_package = _prepare_module_realpath(filename, self._realpath)
            dotted, is_package = _transform_realpath_to_dotted(
                resolved_roots, path_real, is_package
            )
            if dotted:
                candidate = ".".join(
                    dotted[:-1] if is_package and dotted[-1] == "__init__" else dotted
                )
                if candidate:
                    if candidate in aliases and aliases[candidate] != filename:
                        ambiguous_aliases.add(candidate)
                    else:
                        aliases[candidate] = filename
        for alias, filename in aliases.items():
            if alias not in ambiguous_aliases:
                mapping.setdefault(alias, filename)
        self._source_map_cache = mapping
        self._source_map_cache_keys = current_keys
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
                is_package=os.path.basename(path) in {"__init__.py", "__init__.pyi"},
                is_in_memory=True,
            )

        parts = module_name.split(".")
        search_path = self.get_sys_path(script_path=script_path, source=source)
        search_path = _remove_duplicates_from_path(list(extra_sys_path) + search_path)

        # Filesystem probing stats many candidate paths; cache both positive
        # and negative lookups keyed by the effective search path tuple so
        # sibling files share probes and missing imports are not re-statted.
        # The in-memory source map is always consulted first above.
        cache_key: tuple[object, ...] = (module_name, tuple(search_path))
        if cache_key in self._find_module_cache:
            return self._find_module_cache[cache_key]

        result: Optional[ModuleResolution] = None
        namespace_paths: List[str] = []
        for root in search_path:
            if not root:
                root = os.curdir
            parent = root
            blocked = False
            for part in parts[:-1]:
                package_dir = os.path.join(parent, part)
                has_package_init = any(
                    os.path.isfile(os.path.join(package_dir, filename))
                    for filename in ("__init__.py", "__init__.pyi")
                )
                has_module_file = any(
                    os.path.isfile(f"{package_dir}{suffix}") for suffix in (".py", ".pyi")
                )
                if has_package_init or (os.path.isdir(package_dir) and not has_module_file):
                    parent = package_dir
                    continue
                blocked = True
                break
            if blocked:
                continue

            base = os.path.join(parent, parts[-1])
            init_file = next(
                (
                    os.path.join(base, filename)
                    for filename in ("__init__.py", "__init__.pyi")
                    if os.path.isfile(os.path.join(base, filename))
                ),
                None,
            )
            if init_file is not None:
                result = ModuleResolution(
                    module_name,
                    os.path.abspath(init_file),
                    is_package=True,
                    namespace_paths=(os.path.abspath(base),),
                )
                break

            module_file = next(
                (
                    f"{base}{suffix}"
                    for suffix in (".py", ".pyi")
                    if os.path.isfile(f"{base}{suffix}")
                ),
                None,
            )
            if module_file is not None:
                result = ModuleResolution(module_name, os.path.abspath(module_file))
                break

            if os.path.isdir(base):
                namespace_paths.append(os.path.abspath(base))
        else:
            if namespace_paths:
                result = ModuleResolution(
                    module_name,
                    None,
                    is_package=True,
                    is_namespace=True,
                    namespace_paths=tuple(_remove_duplicates_from_path(namespace_paths)),
                )

        if result is not None:
            self._find_module_cache[cache_key] = result
            self._find_module_cache_order.append(cache_key)
            if len(self._find_module_cache_order) > self._max_find_module_cache:
                for stale_key in self._find_module_cache_order[: -self._max_find_module_cache]:
                    self._find_module_cache.pop(stale_key, None)
                self._find_module_cache_order = self._find_module_cache_order[
                    -self._max_find_module_cache :
                ]
        return result

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
                    resolved_mod = self.find_module(resolved, script_path=current_path)
                    if resolved_mod is None or resolved_mod.is_package:
                        for alias in node.names:
                            if alias.name == "*":
                                continue
                            candidate = f"{resolved}.{alias.name}"
                            if self.find_module(candidate, script_path=current_path):
                                yield from emit(candidate)
