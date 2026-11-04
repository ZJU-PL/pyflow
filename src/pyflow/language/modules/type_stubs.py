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

import ast
import operator
import sys
from collections import namedtuple
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .project_resolution import ProjectContext

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


def default_typeshed_roots() -> list[Path]:
    """Return the vendored typeshed root shipped with PyFlow.

    The directory contains a snapshot of mypy's bundled typeshed.  It is
    used by default for stdlib and bundled third-party stubs; callers can
    pass an explicit ``typeshed_roots`` list to replace it.
    """
    root = Path(__file__).resolve().parents[2] / "stubs" / "typeshed"
    return [root] if (root / "stdlib").is_dir() else []


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

        # Scan directly for a flat stub directory.  A real typeshed root is
        # laid out as stdlib/ and stubs/; scanning it recursively would also
        # create bogus ``stubs.<distribution>`` import names.
        looks_like_typeshed = (path / stdlib_subdir).is_dir() or (path / stubs_subdir).is_dir()
        if not looks_like_typeshed:
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
                if not entry.is_dir():
                    continue
                init_pyi = entry / "__init__.pyi"
                if init_pyi.is_file():
                    # Flat stub layout: stubs/<distribution>/__init__.pyi
                    map_[entry.name] = str(init_pyi)
                # Standard typeshed layout:
                # stubs/<distribution>/<package>/...
                # The distribution directory is not an import component.
                _scan_directory(map_, entry, is_third_party=True)

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
        _stub_map_cache[key] = build_stub_map(directories, python_version=python_version)
    return _stub_map_cache[key]


def clear_stub_map_cache() -> None:
    """Clear the cached stub-map, forcing re-scan on next access."""
    _stub_map_cache.clear()


# ---------------------------------------------------------------------------
# Stub-file parsing — extract type information from .pyi files
# ---------------------------------------------------------------------------


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
class StubTypeVarInfo:
    """A ``TypeVar``/``ParamSpec``/``TypeVarTuple`` declaration in a stub."""

    name: str
    kind: str = "typevar"
    constraints: list[str] = field(default_factory=list)
    bound: str | None = None
    default: str | None = None
    covariant: bool = False
    contravariant: bool = False


@dataclass
class StubAliasInfo:
    """A module-level alias declared in a stub.

    ``value`` is the source text of the right-hand side.  It may be a type
    expression (``int | str``) or a value expression such as
    ``_inst.random`` used by the stdlib ``random`` module.
    """

    name: str
    value: str
    annotation: str | None = None


@dataclass
class StubInfo:
    """Parsed type information from a ``.pyi`` stub file.

    Attributes:
        functions: Top-level function signatures.
        classes: Top-level class definitions.
        variables: Top-level ``(name, type_annotation_string)`` pairs.
        imports: Raw import declarations.
        type_vars: Type variable declarations.
        aliases: Module-level assignment aliases.
        exports: Literal ``__all__`` contents, if declared.
    """

    functions: list[StubFunctionInfo] = field(default_factory=list)
    classes: list[StubClassInfo] = field(default_factory=list)
    variables: list[tuple[str, str]] = field(default_factory=list)
    imports: list[StubImportInfo] = field(default_factory=list)
    type_vars: list[StubTypeVarInfo] = field(default_factory=list)
    aliases: list[StubAliasInfo] = field(default_factory=list)
    exports: frozenset[str] | None = None


@dataclass(frozen=True)
class StubDiagnostic:
    """Structured diagnostic emitted while resolving or parsing stubs."""

    code: str
    category: str
    module_name: str
    message: str
    path: str | None = None
    severity: str = "warning"
    lineno: int | None = None
    col_offset: int | None = None


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
        roots = default_typeshed_roots() if typeshed_roots is None else typeshed_roots
        self.typeshed_roots = [Path(root) for root in roots]
        self.python_version = python_version or (sys.version_info.major, sys.version_info.minor)
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
            source_text = self.project_context.source_files.get(path)
            if source_text is not None:
                info = parse_stub_source(
                    source_text,
                    python_version=self.python_version,
                )
            else:
                info = parse_stub_file(
                    path,
                    python_version=self.python_version,
                )
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

    def _project_source_path(self, module_name: str) -> Path | None:
        """Return a project-owned source path that shadows typeshed."""
        resolution = self.project_context.find_module(module_name)
        if resolution is None or resolution.path is None:
            return None
        path = Path(resolution.path).resolve()
        roots = [
            Path(self.project_context.path).resolve(),
            *(
                Path(root).resolve()
                for root in self.project_context.module_identity.workspace_roots
            ),
        ]
        for root in roots:
            try:
                relative = path.relative_to(root)
            except ValueError:
                continue
            if {"site-packages", "dist-packages"}.intersection(relative.parts):
                continue
            return path
        return None

    def _resolve_typeshed_stub(self, module_name: str) -> tuple[str, str] | None:
        if not self.typeshed_roots:
            return None
        if self._project_source_path(module_name) is not None:
            # A project module named ``typing``/``json``/... shadows the
            # stdlib module and must not be replaced by a typeshed stub.
            return None
        stub_map = get_cached_stub_map(
            self.typeshed_roots,
            python_version=self.python_version,
        )
        path = stub_map.get(module_name)
        if path:
            return path, "typeshed"
        return None


def parse_stub_file(
    path: str | Path,
    *,
    python_version: tuple[int, int] | None = None,
) -> StubInfo:
    """Parse a ``.pyi`` stub file and extract type information."""
    return parse_stub_source(
        Path(path).read_text(encoding="utf-8"),
        python_version=python_version,
    )


def parse_stub_source(
    source: str,
    *,
    python_version: tuple[int, int] | None = None,
) -> StubInfo:
    """Parse ``.pyi`` source text and extract type information.

    ``python_version`` selects the branch of ``if sys.version_info``
    declarations.  It defaults to the interpreter running PyFlow.
    """
    tree = ast.parse(source)
    info = StubInfo()
    version = python_version or (sys.version_info.major, sys.version_info.minor)
    visitor = _StubVisitor(info, version)
    visitor.visit(tree)
    return info


class _StubVisitor(ast.NodeVisitor):
    """AST visitor that extracts type information from a .pyi file."""

    def __init__(self, info: StubInfo, python_version: tuple[int, int]) -> None:
        self._info = info
        self._version = python_version
        self._exports: list[str] = []
        self._saw_all = False

    # -- Module -------------------------------------------------------------

    def visit_Module(self, node: ast.Module) -> None:  # noqa: N802
        for statement in node.body:
            self.visit(statement)
        if self._saw_all:
            self._info.exports = frozenset(self._exports)

    # -- Imports ------------------------------------------------------------

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

    # -- Conditionals -------------------------------------------------------

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        truth = _version_condition_truth(node.test, self._version)
        if truth is True:
            statements = node.body
        elif truth is False:
            statements = node.orelse
        else:
            # Unknown platform/TYPE_CHECKING conditions: retain both branches
            # rather than silently losing declarations.
            statements = [*node.body, *node.orelse]
        for statement in statements:
            self.visit(statement)

    # -- Functions ----------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._info.functions.append(self._extract_function(node))

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._info.functions.append(self._extract_function(node))

    # -- Classes ------------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        cls = StubClassInfo(name=node.name)
        cls.bases = [_expr_to_str(b) for b in node.bases]
        for stmt in _flatten_stub_statements(node.body, self._version):
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cls.methods.append(self._extract_function(stmt))
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                annotation = _unwrap_class_var_annotation(_expr_to_str(stmt.annotation))
                if not any(name == stmt.target.id for name, _ in cls.class_vars):
                    cls.class_vars.append((stmt.target.id, annotation))
            elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if isinstance(target, ast.Name) and target.id != "__match_args__":
                    inferred = _constant_type_annotation(stmt.value)
                    if inferred is not None:
                        cls.class_vars.append((target.id, inferred))
        self._info.classes.append(cls)

    # -- Assignments --------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        targets = [target for target in node.targets if isinstance(target, ast.Name)]
        value = node.value

        for target in targets:
            if target.id == "__all__":
                names = _literal_string_list(value)
                if names is not None:
                    self._saw_all = True
                    self._exports = list(dict.fromkeys(names))

        if isinstance(value, ast.Call):
            callee = _call_name(value.func)
            if callee in {"TypeVar", "ParamSpec", "TypeVarTuple"}:
                declaration = _type_var_from_call(callee, value)
                if declaration is not None:
                    self._info.type_vars.append(declaration)
                return
            if callee in {"NewType", "TypeAliasType"} and len(value.args) >= 2:
                name = _constant_string(value.args[0])
                if name is not None:
                    self._info.aliases.append(StubAliasInfo(name, _expr_to_str(value.args[1])))
                return

        for target in targets:
            if target.id == "__all__":
                continue
            self._info.aliases.append(StubAliasInfo(target.id, _expr_to_str(value)))

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        if not isinstance(node.target, ast.Name):
            return
        name = node.target.id
        annotation = _expr_to_str(node.annotation)
        if name == "__all__":
            if node.value is not None:
                names = _literal_string_list(node.value)
                if names is not None:
                    self._saw_all = True
                    self._exports = list(dict.fromkeys(names))
            return
        if _is_type_alias_annotation(annotation):
            if node.value is not None:
                self._info.aliases.append(StubAliasInfo(name, _expr_to_str(node.value), annotation))
            return
        unwrapped = _unwrap_final_or_classvar(annotation)
        if unwrapped is not None:
            if node.value is not None and unwrapped in {"", "Any"}:
                unwrapped = _constant_type_annotation(node.value) or "Any"
            self._info.variables.append((name, unwrapped))
            return
        self._info.variables.append((name, annotation))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        if (
            isinstance(node.target, ast.Name)
            and node.target.id == "__all__"
            and isinstance(node.op, ast.Add)
        ):
            names = _literal_string_list(node.value)
            if names is not None:
                self._saw_all = True
                self._exports = list(dict.fromkeys([*self._exports, *names]))
            return
        self.generic_visit(node)

    # -- Helpers ------------------------------------------------------------

    def _extract_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> StubFunctionInfo:
        func = StubFunctionInfo(name=node.name)
        func.decorators = [_expr_to_str(d) for d in node.decorator_list]

        for arg in node.args.posonlyargs + node.args.args:
            annotation = _expr_to_str(arg.annotation) if arg.annotation else None
            func.params.append((arg.arg, annotation))
            func.param_kinds[arg.arg] = "posonly" if arg in node.args.posonlyargs else "pos_or_kw"

        if node.args.vararg:
            annotation = (
                _expr_to_str(node.args.vararg.annotation) if node.args.vararg.annotation else None
            )
            func.params.append((f"*{node.args.vararg.arg}", annotation))
            func.param_kinds[f"*{node.args.vararg.arg}"] = "vararg"

        for arg in node.args.kwonlyargs:
            annotation = _expr_to_str(arg.annotation) if arg.annotation else None
            func.params.append((arg.arg, annotation))
            func.param_kinds[arg.arg] = "kwonly"

        if node.args.kwarg:
            annotation = (
                _expr_to_str(node.args.kwarg.annotation) if node.args.kwarg.annotation else None
            )
            func.params.append((f"**{node.args.kwarg.arg}", annotation))
            func.param_kinds[f"**{node.args.kwarg.arg}"] = "kwarg"

        if node.returns:
            func.returns = _expr_to_str(node.returns)

        return func


def _flatten_stub_statements(
    statements: list[ast.stmt],
    version: tuple[int, int],
) -> Iterator[ast.stmt]:
    """Flatten version checks and try blocks inside a stub class body."""
    for statement in statements:
        if isinstance(statement, ast.If):
            truth = _version_condition_truth(statement.test, version)
            if truth is True:
                yield from _flatten_stub_statements(statement.body, version)
            elif truth is False:
                yield from _flatten_stub_statements(statement.orelse, version)
            else:
                yield from _flatten_stub_statements(statement.body, version)
                yield from _flatten_stub_statements(statement.orelse, version)
        elif isinstance(statement, ast.Try):
            yield from _flatten_stub_statements(statement.body, version)
            for handler in statement.handlers:
                yield from _flatten_stub_statements(handler.body, version)
            yield from _flatten_stub_statements(statement.orelse, version)
            yield from _flatten_stub_statements(statement.finalbody, version)
        else:
            yield statement


_VERSION_COMPARATORS = {
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
}


def _version_condition_truth(node: ast.expr, version: tuple[int, int]) -> bool | None:
    """Evaluate a simple ``sys.version_info`` condition, if possible."""
    if isinstance(node, ast.BoolOp):
        values = [_version_condition_truth(value, version) for value in node.values]
        if isinstance(node.op, ast.And):
            if any(value is False for value in values):
                return False
            return True if all(value is True for value in values) else None
        if any(value is True for value in values):
            return True
        return False if all(value is False for value in values) else None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        truth = _version_condition_truth(node.operand, version)
        return None if truth is None else not truth
    if isinstance(node, ast.Name) and node.id == "TYPE_CHECKING":
        return True
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "TYPE_CHECKING"
        and isinstance(node.value, ast.Name)
    ):
        return True
    if not isinstance(node, ast.Compare):
        return None

    left = _version_operand(node.left, version)
    if left is None:
        return None
    results: list[bool] = []
    current = left
    for op, comparator in zip(node.ops, node.comparators):
        right = _version_operand(comparator, version)
        compare = _VERSION_COMPARATORS.get(type(op))
        if right is None or compare is None:
            return None
        if isinstance(current, tuple) != isinstance(right, tuple):
            return None
        results.append(compare(current, right))
        current = right
    if not results:
        return None
    if all(results):
        return True
    return False


def _version_operand(node: ast.expr, version: tuple[int, int]):
    """Return the value of a ``sys.version_info`` expression, if static."""
    if isinstance(node, ast.Attribute) and node.attr == "version_info":
        if isinstance(node.value, ast.Name) and node.value.id == "sys":
            return (version[0], version[1])
        return None
    if isinstance(node, ast.Subscript):
        base = _version_operand(node.value, version)
        if base is None:
            return None
        if isinstance(node.slice, ast.Slice):
            if node.slice.lower is not None and _constant_string(node.slice.lower) is not None:
                return None
            if isinstance(node.slice.upper, ast.Constant) and node.slice.upper.value == 2:
                return (version[0], version[1])
            return None
        index = _version_operand(node.slice, version)
        if isinstance(index, int) and 0 <= index < len(version):
            return version[index]
        return None
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Tuple):
        values = [_version_operand(item, version) for item in node.elts]
        if any(value is None for value in values):
            return None
        return tuple(values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _version_operand(node.operand, version)
        if isinstance(inner, int):
            return -inner
    return None


def _type_var_from_call(callee: str, call: ast.Call) -> StubTypeVarInfo | None:
    if not call.args:
        return None
    name = _constant_string(call.args[0])
    if name is None:
        return None
    kind = {
        "TypeVar": "typevar",
        "ParamSpec": "paramspec",
        "TypeVarTuple": "typevartuple",
    }.get(callee, "typevar")
    constraints = [_expr_to_str(argument) for argument in call.args[1:]]
    keywords: dict[str, ast.expr] = {
        keyword.arg: keyword.value for keyword in call.keywords if keyword.arg is not None
    }
    return StubTypeVarInfo(
        name=name,
        kind=kind,
        constraints=constraints,
        bound=_expr_to_str(keywords["bound"]) if "bound" in keywords else None,
        default=_expr_to_str(keywords["default"]) if "default" in keywords else None,
        covariant=_is_true_constant(keywords.get("covariant")),
        contravariant=_is_true_constant(keywords.get("contravariant")),
    )


def _is_true_constant(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _call_name(node: ast.expr) -> str:
    return _expr_to_str(node).rsplit(".", 1)[-1]


def _constant_string(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _literal_string_list(node: ast.expr | None) -> list[str] | None:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    values: list[str] = []
    for element in node.elts:
        value = _constant_string(element)
        if value is None:
            return None
        values.append(value)
    return values


def _is_type_alias_annotation(annotation: str) -> bool:
    return annotation.rsplit(".", 1)[-1] in {"TypeAlias", "TypeAliasType"}


def _unwrap_final_or_classvar(annotation: str) -> str | None:
    """Return the inner annotation of ``Final[T]``/``ClassVar[T]``.

    A bare ``Final``/``ClassVar`` yields ``"Any"``; ``None`` means the
    annotation is not a Final/ClassVar declaration.
    """
    head, _, rest = annotation.partition("[")
    if head.rsplit(".", 1)[-1] not in {"Final", "ClassVar"}:
        return None
    if not rest:
        return "Any"
    return rest[:-1].strip() or "Any"


def _unwrap_class_var_annotation(annotation: str) -> str:
    unwrapped = _unwrap_final_or_classvar(annotation)
    return unwrapped if unwrapped is not None else annotation


def _constant_type_annotation(node: ast.expr | None) -> str | None:
    """Best-effort type annotation for a stub constant assignment."""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        value = node.value
        if value is None:
            return "None"
        if isinstance(value, bool):
            return "bool"
        if isinstance(value, int):
            return "int"
        if isinstance(value, float):
            return "float"
        if isinstance(value, complex):
            return "complex"
        if isinstance(value, str):
            return "str"
        if isinstance(value, bytes):
            return "bytes"
        return None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        return _constant_type_annotation(node.operand)
    if isinstance(node, ast.Attribute):
        return {
            "maxsize": "int",
            "platform": "str",
            "version": "str",
        }.get(node.attr)
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        if name in {"frozenset", "set"}:
            return "frozenset[Any]" if name == "frozenset" else "set[Any]"
        if name in {"list", "tuple", "dict"}:
            return f"{name}[Any]"
    return None


def _expr_to_str(node: ast.expr | None) -> str:
    """Convert an AST expression node to its source-code string."""
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
