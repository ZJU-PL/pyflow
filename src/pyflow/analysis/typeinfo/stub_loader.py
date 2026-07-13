"""Stub-file discovery and mapping for PEP 484 ``.pyi`` type stubs.

Scans directories for ``.pyi`` files (including typeshed-style layouts)
and builds import-name → file-path mappings.  Supports PEP 561 stub
packages and adjacent ``.pyi`` files.

The filesystem-scanning logic is adapted from Jedi's
``jedi.inference.gradual.typeshed``
(https://github.com/davidhalter/jedi).

SPDX-FileCopyrightText: 2025 David Halter and contributors
SPDX-FileCopyrightText: 2026 PyFlow Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections import namedtuple
from pathlib import Path

# ---------------------------------------------------------------------------
# Path information tuple
# ---------------------------------------------------------------------------

_StubPathInfo = namedtuple("_StubPathInfo", ["path", "is_third_party"])

# Default paths relative to a typeshed root.
_DEFAULT_STDLIB_DIR = "stdlib"
_DEFAULT_STUBS_DIR = "stubs"

# Directories to skip during recursive scanning.
_IGNORE_DIRS: frozenset[str] = frozenset(
    {".tox", ".venv", ".mypy_cache", "venv", "__pycache__", ".git"}
)


# ---------------------------------------------------------------------------
# Stub-map construction
# ---------------------------------------------------------------------------


def build_stub_map(
    directories: list[Path],
    *,
    python_version: tuple[int, int] | None = None,
    stdlib_subdir: str = _DEFAULT_STDLIB_DIR,
    stubs_subdir: str = _DEFAULT_STUBS_DIR,
) -> dict[str, str]:
    """Build an import-name → stub-file-path mapping from a set of directories.

    For typeshed-style directories, *stdlib_subdir* and *stubs_subdir* are
    scanned with version-aware subdirectory resolution (e.g. ``stdlib/3.10/``).

    Args:
        directories: Root directories to scan for ``.pyi`` files.
        python_version: If given, used to select a version-specific subdirectory
            inside *stdlib_subdir* and *stubs_subdir*.
        stdlib_subdir: Name of the stdlib stubs subdirectory.
        stubs_subdir: Name of the third-party stubs subdirectory.

    Returns:
        A dictionary mapping import names to absolute ``.pyi`` file paths.
    """
    map_: dict[str, str] = {}

    for directory in directories:
        path = Path(directory)
        if not path.is_dir():
            continue

        # Scan the directory directly for .pyi files
        _scan_directory(map_, path, is_third_party=False)

        # If this looks like a typeshed root, scan stdlib/ and stubs/
        stdlib_path = path / stdlib_subdir
        if python_version is not None and stdlib_path.is_dir():
            version_path = stdlib_path / f"{python_version[0]}.{python_version[1]}"
            if version_path.is_dir():
                _scan_directory(map_, version_path, is_third_party=False)
            else:
                _scan_directory(map_, stdlib_path, is_third_party=False)
        elif stdlib_path.is_dir():
            _scan_directory(map_, stdlib_path, is_third_party=False)

        stubs_path = path / stubs_subdir
        if stubs_path.is_dir():
            for entry in sorted(stubs_path.iterdir()):
                if entry.is_dir():
                    _scan_directory(
                        map_,
                        entry,
                        is_third_party=True,
                        prefix=entry.name,
                    )

    return map_


def _scan_directory(
    map_: dict[str, str],
    directory: Path,
    *,
    is_third_party: bool,
    prefix: str = "",
) -> None:
    """Scan a single directory for ``.pyi`` files.

    Walks the directory tree and adds mappings for packages (``__init__.pyi``)
    and modules (``*.pyi``).
    """
    try:
        entries = sorted(directory.iterdir())
    except (OSError, PermissionError):
        return

    if prefix:
        init_pyi = directory / "__init__.pyi"
        if init_pyi.is_file():
            map_[prefix] = str(init_pyi)

    for entry in entries:
        if entry.is_dir():
            if entry.name in _IGNORE_DIRS:
                continue
            init_pyi = entry / "__init__.pyi"
            module_name = f"{prefix}.{entry.name}" if prefix else entry.name
            if init_pyi.is_file():
                map_[module_name] = str(init_pyi)
            _scan_directory(
                map_,
                entry,
                is_third_party=is_third_party,
                prefix=module_name,
            )
        elif entry.is_file() and entry.suffix == ".pyi":
            name = entry.stem
            if name != "__init__":
                module_name = f"{prefix}.{name}" if prefix else name
                map_[module_name] = str(entry)


# ---------------------------------------------------------------------------
# Adjacent .pyi discovery
# ---------------------------------------------------------------------------


def find_adjacent_pyi(py_file: str | Path) -> str | None:
    """Find the ``.pyi`` stub file adjacent to a ``.py`` file.

    Simply appends ``"i"`` to the path (``foo.py`` → ``foo.pyi``).

    Args:
        py_file: Path to a ``.py`` file.

    Returns:
        The absolute path to the ``.pyi`` file if it exists, or ``None``.
    """
    path = Path(py_file)
    pyi_path = path.with_suffix(".pyi")
    if pyi_path.is_file():
        return str(pyi_path)
    return None


def find_package_pyi(package_dir: str | Path) -> str | None:
    """Find the ``__init__.pyi`` for a package directory.

    Args:
        package_dir: Path to a Python package directory.

    Returns:
        The absolute path to ``__init__.pyi`` if it exists, or ``None``.
    """
    init_pyi = Path(package_dir) / "__init__.pyi"
    if init_pyi.is_file():
        return str(init_pyi)
    return None


# ---------------------------------------------------------------------------
# Stub-package discovery (PEP 561)
# ---------------------------------------------------------------------------


def find_stub_packages(sys_path: list[str], import_name: str) -> list[str]:
    """Find PEP 561 stub packages for *import_name* on *sys_path*.

    A stub package is a directory named ``{import_name}-stubs/`` containing
    an ``__init__.pyi`` file.

    Args:
        sys_path: Python search path entries.
        import_name: The top-level import name to find stubs for.

    Returns:
        A list of ``__init__.pyi`` paths found in stub packages.
    """
    results: list[str] = []
    for path_entry in sys_path:
        stub_dir = Path(path_entry) / f"{import_name}-stubs"
        init_pyi = stub_dir / "__init__.pyi"
        if init_pyi.is_file():
            results.append(str(init_pyi))
    return results


# ---------------------------------------------------------------------------
# Cached stub-map access
# ---------------------------------------------------------------------------

_stub_map_cache: dict[tuple[object, ...], dict[str, str]] = {}


def get_cached_stub_map(
    directories: list[Path],
    *,
    python_version: tuple[int, int] | None = None,
) -> dict[str, str]:
    """Return a cached import-name → stub-file mapping.

    Results are cached by the tuple of directory paths and Python version.

    Args:
        directories: Root directories to scan.
        python_version: Optional Python version for version-specific resolution.

    Returns:
        A cached mapping dictionary.
    """
    key = (*(str(d) for d in directories), python_version or ())
    if key not in _stub_map_cache:
        _stub_map_cache[key] = build_stub_map(
            directories, python_version=python_version
        )
    return _stub_map_cache[key]


def clear_stub_map_cache() -> None:
    """Clear the cached stub-map, forcing re-scan on next access."""
    _stub_map_cache.clear()


# ---------------------------------------------------------------------------
# Stub-file parsing — extract type information from .pyi files
# ---------------------------------------------------------------------------


import ast
from dataclasses import dataclass, field

from pyflow.frontend.project_resolution import ProjectContext


@dataclass
class StubFunctionInfo:
    """Extracted type information for a function in a ``.pyi`` stub file.

    Attributes:
        name: The function name.
        params: List of ``(param_name, type_annotation_string)`` tuples.
        returns: The return-type annotation string, or ``None``.
        decorators: List of decorator name strings.
    """

    name: str
    params: list[tuple[str, str | None]] = field(default_factory=list)
    param_kinds: dict[str, str] = field(default_factory=dict)
    returns: str | None = None
    decorators: list[str] = field(default_factory=list)


@dataclass
class StubImportInfo:
    """Raw import information extracted from a ``.pyi`` stub file."""

    module: str | None
    names: list[tuple[str, str | None]] = field(default_factory=list)
    level: int = 0
    is_from: bool = False


@dataclass
class StubClassInfo:
    """Extracted type information for a class in a ``.pyi`` stub file.

    Attributes:
        name: The class name.
        bases: List of base-class name strings.
        methods: List of :class:`StubFunctionInfo` for class methods.
        class_vars: List of ``(name, annotation_string)`` tuples.
    """

    name: str
    bases: list[str] = field(default_factory=list)
    methods: list[StubFunctionInfo] = field(default_factory=list)
    class_vars: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class StubInfo:
    """Parsed type information from a ``.pyi`` stub file.

    Attributes:
        functions: Top-level function signatures.
        classes: Top-level class definitions.
        variables: Top-level ``(name, type_annotation_string)`` pairs.
    """

    functions: list[StubFunctionInfo] = field(default_factory=list)
    classes: list[StubClassInfo] = field(default_factory=list)
    variables: list[tuple[str, str]] = field(default_factory=list)
    imports: list[StubImportInfo] = field(default_factory=list)


@dataclass(frozen=True)
class StubDiagnostic:
    """Structured diagnostic emitted while resolving or parsing stubs."""

    code: str
    category: str
    module_name: str
    message: str
    path: str | None = None
    severity: str = "warning"


@dataclass(frozen=True)
class ResolvedStub:
    """A resolved stub file and its parsed metadata."""

    module_name: str
    path: str
    info: StubInfo
    source: str


class StubResolver:
    """Resolve project, PEP 561, and typeshed stubs for import names."""

    def __init__(
        self,
        project_context: ProjectContext | None = None,
        *,
        typeshed_roots: list[str | Path] | None = None,
        python_version: tuple[int, int] | None = None,
    ) -> None:
        self.project_context = project_context or ProjectContext(None)
        self.typeshed_roots = [Path(root) for root in (typeshed_roots or [])]
        self.python_version = python_version
        self._path_cache: dict[tuple[str, str | None], tuple[str, str] | None] = {}
        self._info_cache: dict[str, ResolvedStub | None] = {}
        self._diagnostics: list[StubDiagnostic] = []

    def clear_cache(self) -> None:
        """Clear resolver-local path and parse caches."""
        self._path_cache.clear()
        self._info_cache.clear()

    def get_diagnostics(self) -> list[StubDiagnostic]:
        """Return structured resolver diagnostics."""
        return list(self._diagnostics)

    def resolve_path(
        self,
        module_name: str,
        *,
        script_path: str | None = None,
    ) -> str | None:
        """Return the best `.pyi` path for *module_name*, if one exists."""
        resolved = self._resolve_path_with_source(
            module_name,
            script_path=script_path,
        )
        return resolved[0] if resolved is not None else None

    def resolve(
        self,
        module_name: str,
        *,
        script_path: str | None = None,
    ) -> ResolvedStub | None:
        """Resolve and parse a stub for *module_name*."""
        path_and_source = self._resolve_path_with_source(
            module_name,
            script_path=script_path,
        )
        if path_and_source is None:
            return None

        path, source = path_and_source
        cached = self._info_cache.get(path)
        if cached is not None:
            return cached
        if path in self._info_cache:
            return None

        try:
            if path in self.project_context.source_files:
                info = parse_stub_source(self.project_context.source_files[path])
            else:
                info = parse_stub_file(path)
        except (OSError, SyntaxError) as exc:
            self._diagnostics.append(
                StubDiagnostic(
                    code="stub_parse_failed",
                    category="parse",
                    module_name=module_name,
                    path=path,
                    message=f"{type(exc).__name__}: {exc}",
                )
            )
            self._info_cache[path] = None
            return None

        resolved = ResolvedStub(
            module_name=module_name,
            path=path,
            info=info,
            source=source,
        )
        self._info_cache[path] = resolved
        return resolved

    def _resolve_path_with_source(
        self,
        module_name: str,
        *,
        script_path: str | None = None,
    ) -> tuple[str, str] | None:
        cache_key = (module_name, script_path)
        if cache_key in self._path_cache:
            return self._path_cache[cache_key]

        resolved = self._resolve_source_map_stub(module_name)
        if resolved is None:
            resolved = self._resolve_project_stub(module_name, script_path)
        if resolved is None:
            resolved = self._resolve_stub_package(module_name)
        if resolved is None:
            resolved = self._resolve_typeshed_stub(module_name)

        self._path_cache[cache_key] = resolved
        return resolved

    def _resolve_source_map_stub(self, module_name: str) -> tuple[str, str] | None:
        source_map = self.project_context._source_map()
        path = source_map.get(module_name)
        if path and str(path).endswith(".pyi"):
            return str(path), "source-map"
        return None

    def _resolve_project_stub(
        self,
        module_name: str,
        script_path: str | None,
    ) -> tuple[str, str] | None:
        resolution = self.project_context.find_module(
            module_name,
            script_path=script_path,
        )
        if resolution is None:
            return None

        if resolution.path:
            path = Path(resolution.path)
            if path.suffix == ".pyi" and path.is_file():
                return str(path), "project"
            adjacent = find_adjacent_pyi(path)
            if adjacent:
                return adjacent, "adjacent"

        for namespace_path in resolution.namespace_paths:
            package_stub = find_package_pyi(namespace_path)
            if package_stub:
                return package_stub, "namespace-package"
        return None

    def _resolve_stub_package(self, module_name: str) -> tuple[str, str] | None:
        parts = [part for part in module_name.split(".") if part]
        if not parts:
            return None
        top, rest = parts[0], parts[1:]
        for path_entry in self.project_context.get_sys_path():
            stub_root = Path(path_entry) / f"{top}-stubs"
            if not stub_root.is_dir():
                continue
            if not rest:
                init_path = stub_root / "__init__.pyi"
                if init_path.is_file():
                    return str(init_path), "stub-package"
                continue

            nested = stub_root.joinpath(*rest)
            module_file = nested.with_suffix(".pyi")
            if module_file.is_file():
                return str(module_file), "stub-package"
            package_file = nested / "__init__.pyi"
            if package_file.is_file():
                return str(package_file), "stub-package"
        return None

    def _resolve_typeshed_stub(self, module_name: str) -> tuple[str, str] | None:
        if not self.typeshed_roots:
            return None
        stub_map = get_cached_stub_map(
            self.typeshed_roots,
            python_version=self.python_version,
        )
        path = stub_map.get(module_name)
        if path:
            return path, "typeshed"
        return None


def parse_stub_file(path: str | Path) -> StubInfo:
    """Parse a ``.pyi`` stub file and extract type information.

    Uses Python's built-in :mod:`ast` module to parse the stub file.
    Extracts function signatures (parameter types, return types),
    class definitions (base classes, methods, class variables), and
    top-level variable annotations.

    Args:
        path: Path to the ``.pyi`` file.

    Returns:
        A :class:`StubInfo` containing the extracted type information.

    Raises:
        SyntaxError: If the file contains invalid Python syntax.
        OSError: If the file cannot be read.
    """
    return parse_stub_source(Path(path).read_text(encoding="utf-8"))


def parse_stub_source(source: str) -> StubInfo:
    """Parse ``.pyi`` source text and extract type information."""
    tree = ast.parse(source)

    info = StubInfo()
    _StubVisitor(info).visit(tree)
    return info


class _StubVisitor(ast.NodeVisitor):
    """AST visitor that extracts type information from a .pyi file."""

    def __init__(self, info: StubInfo) -> None:
        self._info = info

    # -- Top-level ----------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._info.functions.append(self._extract_function(node))

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._info.functions.append(self._extract_function(node))

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        self._info.imports.append(
            StubImportInfo(
                module=None,
                names=[(alias.name, alias.asname) for alias in node.names],
                is_from=False,
            )
        )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        self._info.imports.append(
            StubImportInfo(
                module=node.module or "",
                names=[(alias.name, alias.asname) for alias in node.names],
                level=node.level,
                is_from=True,
            )
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        cls = StubClassInfo(name=node.name)
        cls.bases = [_expr_to_str(b) for b in node.bases]
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cls.methods.append(self._extract_function(stmt))
            elif isinstance(stmt, ast.AnnAssign) and isinstance(
                stmt.target, ast.Name
            ):
                cls.class_vars.append(
                    (stmt.target.id, _expr_to_str(stmt.annotation))
                )
        self._info.classes.append(cls)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        if isinstance(node.target, ast.Name):
            self._info.variables.append(
                (node.target.id, _expr_to_str(node.annotation))
            )

    # -- Helpers ------------------------------------------------------------

    def _extract_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> StubFunctionInfo:
        func = StubFunctionInfo(name=node.name)
        func.decorators = [_expr_to_str(d) for d in node.decorator_list]

        for arg in node.args.posonlyargs + node.args.args:
            annotation = (
                _expr_to_str(arg.annotation) if arg.annotation else None
            )
            func.params.append((arg.arg, annotation))
            func.param_kinds[arg.arg] = (
                "posonly"
                if arg in node.args.posonlyargs
                else "pos_or_kw"
            )

        # *args
        if node.args.vararg:
            annotation = (
                _expr_to_str(node.args.vararg.annotation)
                if node.args.vararg.annotation
                else None
            )
            func.params.append((f"*{node.args.vararg.arg}", annotation))
            func.param_kinds[f"*{node.args.vararg.arg}"] = "vararg"

        for arg in node.args.kwonlyargs:
            annotation = (
                _expr_to_str(arg.annotation) if arg.annotation else None
            )
            func.params.append((arg.arg, annotation))
            func.param_kinds[arg.arg] = "kwonly"

        # **kwargs
        if node.args.kwarg:
            annotation = (
                _expr_to_str(node.args.kwarg.annotation)
                if node.args.kwarg.annotation
                else None
            )
            func.params.append((f"**{node.args.kwarg.arg}", annotation))
            func.param_kinds[f"**{node.args.kwarg.arg}"] = "kwarg"

        if node.returns:
            func.returns = _expr_to_str(node.returns)

        return func


def _expr_to_str(node: ast.expr | None) -> str:
    """Convert an AST expression node to its source-code string.

    Uses :func:`ast.unparse` on Python 3.9+, falling back to a simple
    name-extraction for older versions.
    """
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except AttributeError:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{_expr_to_str(node.value)}.{node.attr}"
        if isinstance(node, ast.Subscript):
            return f"{_expr_to_str(node.value)}[{_expr_to_str(node.slice)}]"
        return str(node)
