"""
Dependency Resolver for handling import dependencies in static analysis.

This module provides configurable strategies for resolving import dependencies
when analyzing Python code, following established static analysis patterns.

Usage Examples:
    # Auto strategy (recommended default)
    resolver = DependencyResolver(strategy="auto")

    # Use stubs for missing dependencies
    resolver = DependencyResolver(strategy="stubs")

    # AST-only analysis (no runtime execution)
    resolver = DependencyResolver(strategy="ast_only")

    # Strict mode (fail on missing dependencies)
    resolver = DependencyResolver(strategy="strict")

Available Strategies:
    - AUTO: Use AST parsing only (side-effect free)
    - STUBS: Create stub modules for missing dependencies, attempt runtime execution
    - NOOP: Pre-create no-op stubs for all potential missing imports
    - STRICT: Fail immediately if any dependencies can't be resolved
    - AST_ONLY: Only use AST parsing, never attempt runtime execution (extracts function signatures and structure only)

This approach follows established patterns in static analysis literature for
handling the "missing dependencies" problem in a principled manner.
"""

import ast as python_ast
import builtins
import inspect
import json
import os
import subprocess
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Any, Optional, Iterable, Tuple, Set, cast
from enum import Enum

from pyflow.analysis.typeinfo.resolution.stubs import (
    ResolvedStub,
    StubClassInfo,
    StubFunctionInfo,
    StubResolver,
)
from pyflow.frontend.project_resolution import ProjectContext


@dataclass(frozen=True)
class _FakeCode:
    co_filename: str
    co_firstlineno: int


class _ASTFunctionProxy:
    """An enhanced callable proxy that looks like a Python function to the frontend.

    This lets the rest of the pipeline (InterfaceDeclaration -> Extractor ->
    FunctionExtractor) operate without executing the analyzed module.

    Enhanced to preserve more semantic information from AST:
    - Docstrings
    - Type annotations
    - Decorators
    - Class membership
    """

    def __init__(
        self,
        *,
        name: str,
        qualname: str,
        module: str,
        filename: str,
        firstlineno: int,
        signature: Optional[inspect.Signature],
        docstring: Optional[str] = None,
        decorators: Optional[List[str]] = None,
        is_async: bool = False,
        is_class_method: bool = False,
        type_hints: Optional[Dict[str, Any]] = None,
    ):
        self.__name__ = name
        self.__qualname__ = qualname
        self.__module__ = module
        self.__code__ = _FakeCode(filename, firstlineno)
        if signature is not None:
            self.__signature__ = signature
        self.__doc__ = docstring
        self._decorators = decorators or []
        self._is_async = is_async
        self._is_class_method = is_class_method
        self._type_hints = type_hints or {}

    def __call__(self, *args, **kwargs):
        # Never execute user code; this proxy is only for metadata.
        return None


def _infer_analysis_root(paths: Iterable[str]) -> Optional[str]:
    resolved_roots: List[str] = []

    for path in paths:
        if not path or path.startswith("<"):
            continue

        abs_path = os.path.realpath(path)
        current = abs_path if os.path.isdir(abs_path) else os.path.dirname(abs_path)
        if not current:
            continue

        while os.path.isfile(os.path.join(current, "__init__.py")):
            parent = os.path.dirname(current)
            if not parent or parent == current:
                break
            current = parent

        resolved_roots.append(current)

    if not resolved_roots:
        return None

    try:
        return os.path.commonpath(resolved_roots)
    except ValueError:
        return None


def _iter_toplevel_function_nodes(tree: python_ast.AST) -> Iterable[python_ast.AST]:
    """Iterate over top-level function and class definitions."""
    for node in getattr(tree, "body", []) or []:
        if isinstance(node, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)):
            yield node


def _iter_toplevel_class_nodes(tree: python_ast.AST) -> Iterable[python_ast.AST]:
    """Iterate over top-level class definitions."""
    for node in getattr(tree, "body", []) or []:
        if isinstance(node, python_ast.ClassDef):
            yield node


def _extract_docstring(node: python_ast.AST) -> Optional[str]:
    """Extract docstring from a function or class node."""
    if not hasattr(node, "body") or not node.body:
        return None

    first_stmt = node.body[0]
    if isinstance(first_stmt, python_ast.Expr) and isinstance(
        first_stmt.value, python_ast.Constant
    ):
        if isinstance(first_stmt.value.value, str):
            return first_stmt.value.value
    elif isinstance(first_stmt, python_ast.Expr) and hasattr(first_stmt.value, "s"):
        # Python < 3.8 compatibility
        return first_stmt.value.s

    return None


def _extract_decorator_names(node: python_ast.AST) -> List[str]:
    """Extract decorator names from a function or class node."""
    decorators = []
    if hasattr(node, "decorator_list"):
        for decorator in node.decorator_list:
            if isinstance(decorator, python_ast.Name):
                decorators.append(decorator.id)
            elif isinstance(decorator, python_ast.Attribute):
                # Handle qualified names like @module.decorator
                parts = []
                current = decorator
                while isinstance(current, python_ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, python_ast.Name):
                    parts.append(current.id)
                decorators.append(".".join(reversed(parts)))
            elif isinstance(decorator, python_ast.Call):
                # Handle @decorator(args)
                if isinstance(decorator.func, python_ast.Name):
                    decorators.append(decorator.func.id)
                elif isinstance(decorator.func, python_ast.Attribute):
                    parts = []
                    current = decorator.func
                    while isinstance(current, python_ast.Attribute):
                        parts.append(current.attr)
                        current = current.value
                    if isinstance(current, python_ast.Name):
                        parts.append(current.id)
                    decorators.append(".".join(reversed(parts)))
    return decorators


def _extract_literal_string_list(node: python_ast.AST) -> Optional[List[str]]:
    """Extract a static list/tuple/set of string values."""
    if isinstance(node, (python_ast.List, python_ast.Tuple, python_ast.Set)):
        out: List[str] = []
        for elt in node.elts:
            if isinstance(elt, python_ast.Constant) and isinstance(elt.value, str):
                out.append(elt.value)
            else:
                return None
        return out
    return None


def _is_property_decorator(name: str) -> bool:
    tail = name.rsplit(".", 1)[-1].lower()
    return tail in {"property", "cached_property", "abstractproperty"}


def _base_name_from_expr(node: python_ast.AST) -> Optional[str]:
    if isinstance(node, python_ast.Subscript):
        return _base_name_from_expr(node.value)
    if isinstance(node, python_ast.Name):
        return node.id
    if isinstance(node, python_ast.Attribute):
        parts = []
        current = node
        while isinstance(current, python_ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, python_ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    return None


def _iter_import_nodes_in_scope(nodes: Iterable[python_ast.AST]):
    """Yield import statements that execute in the current scope."""

    for node in nodes:
        if isinstance(node, (python_ast.Import, python_ast.ImportFrom)):
            yield node
            continue

        if isinstance(
            node,
            (python_ast.FunctionDef, python_ast.AsyncFunctionDef, python_ast.ClassDef),
        ):
            continue

        if isinstance(
            node,
            (
                python_ast.If,
                python_ast.For,
                python_ast.AsyncFor,
                python_ast.While,
                python_ast.With,
                python_ast.AsyncWith,
            ),
        ):
            yield from _iter_import_nodes_in_scope(getattr(node, "body", ()) or ())
            yield from _iter_import_nodes_in_scope(getattr(node, "orelse", ()) or ())
            continue

        if isinstance(node, python_ast.Try):
            yield from _iter_import_nodes_in_scope(getattr(node, "body", ()) or ())
            for handler in getattr(node, "handlers", ()) or ():
                yield from _iter_import_nodes_in_scope(
                    getattr(handler, "body", ()) or ()
                )
            yield from _iter_import_nodes_in_scope(getattr(node, "orelse", ()) or ())
            yield from _iter_import_nodes_in_scope(getattr(node, "finalbody", ()) or ())
            continue

        if hasattr(python_ast, "TryStar") and isinstance(node, python_ast.TryStar):
            yield from _iter_import_nodes_in_scope(getattr(node, "body", ()) or ())
            for handler in getattr(node, "handlers", ()) or ():
                yield from _iter_import_nodes_in_scope(
                    getattr(handler, "body", ()) or ()
                )
            yield from _iter_import_nodes_in_scope(getattr(node, "orelse", ()) or ())
            yield from _iter_import_nodes_in_scope(getattr(node, "finalbody", ()) or ())
            continue

        if hasattr(python_ast, "Match") and isinstance(node, python_ast.Match):
            for case in getattr(node, "cases", ()) or ():
                yield from _iter_import_nodes_in_scope(getattr(case, "body", ()) or ())


def _signature_from_ast(args: python_ast.arguments) -> inspect.Signature:
    params: List[inspect.Parameter] = []

    def add_param(
        name: str, kind: inspect._ParameterKind, default: Any = inspect._empty
    ):
        params.append(inspect.Parameter(name, kind, default=default))

    posonly = list(getattr(args, "posonlyargs", []) or [])
    regular = list(getattr(args, "args", []) or [])
    kwonly = list(getattr(args, "kwonlyargs", []) or [])

    # Defaults for posonly+regular apply to last N.
    positional = [*posonly, *regular]
    defaults = list(getattr(args, "defaults", []) or [])
    default_start = len(positional) - len(defaults)

    for i, a in enumerate(posonly):
        default = inspect._empty
        if defaults and i >= default_start:
            try:
                default = python_ast.literal_eval(defaults[i - default_start])
            except Exception:
                default = None
        add_param(a.arg, inspect.Parameter.POSITIONAL_ONLY, default)

    for i, a in enumerate(regular):
        default = inspect._empty
        pos_index = len(posonly) + i
        if defaults and pos_index >= default_start:
            try:
                default = python_ast.literal_eval(defaults[pos_index - default_start])
            except Exception:
                default = None
        add_param(a.arg, inspect.Parameter.POSITIONAL_OR_KEYWORD, default)

    if args.vararg is not None:
        add_param(args.vararg.arg, inspect.Parameter.VAR_POSITIONAL)

    kw_defaults = list(getattr(args, "kw_defaults", []) or [])
    for i, a in enumerate(kwonly):
        default = inspect._empty
        if i < len(kw_defaults) and kw_defaults[i] is not None:
            try:
                default = python_ast.literal_eval(kw_defaults[i])
            except Exception:
                default = None
        add_param(a.arg, inspect.Parameter.KEYWORD_ONLY, default)

    if args.kwarg is not None:
        add_param(args.kwarg.arg, inspect.Parameter.VAR_KEYWORD)

    return inspect.Signature(params)


class DependencyStrategy(Enum):
    """Available strategies for handling import dependencies."""

    AUTO = "auto"  # Side-effect free AST extraction (default)
    STUBS = "stubs"  # Create stub modules for missing dependencies
    NOOP = "noop"  # Treat missing functions as no-ops
    STRICT = "strict"  # Fail if dependencies can't be resolved
    AST_ONLY = "ast_only"  # Only use AST parsing, no runtime execution
    # Future advanced strategies:
    # DEPENDENCY_RESOLUTION = "deps"  # Resolve and analyze dependencies together


class DependencyResolver:
    """
    Configurable dependency resolver for static analysis.

    Provides multiple strategies for handling import dependencies:
    - Runtime execution with safe globals
    - Stub creation for missing modules
    - AST-based fallback analysis
    - Conservative no-op implementations
    """

    def __init__(
        self,
        strategy: str = "auto",
        verbose: bool = False,
        safe_modules: Optional[List[str]] = None,
        search_paths: Optional[List[str]] = None,
        class_hierarchy: Optional[Any] = None,
        include_private: bool = False,
        source_files: Optional[Dict[str, str]] = None,
        analysis_root: Optional[str] = None,
        allow_runtime_execution: bool = False,
        fail_on_diagnostics: bool = False,
        max_diagnostics: Optional[int] = None,
        max_runtime_fallback_ratio: Optional[float] = None,
        typeshed_roots: Optional[List[str | Path]] = None,
    ):
        """
        Initialize the dependency resolver.

        Args:
            strategy: Resolution strategy to use
            verbose: Whether to output detailed information
            safe_modules: List of modules to include in safe execution environment
            search_paths: Additional paths to search for module source files
            class_hierarchy: Optional ClassHierarchy instance for cross-module class tracking
            include_private: Include top-level names that start with "_" during AST extraction
            source_files: Optional map of filename -> source used for in-memory resolution
            typeshed_roots: Optional typeshed-style roots for additional `.pyi`
                resolution beyond project, adjacent, and PEP 561 stubs
        """
        self.strategy = DependencyStrategy(strategy)
        self.verbose = verbose
        self.safe_modules = safe_modules or [
            "math",
            "os",
            "sys",
            "re",
            "json",
            "datetime",
            "collections",
        ]
        self.search_paths = search_paths or []
        self.class_hierarchy = class_hierarchy
        self.include_private = include_private
        self.source_files = dict(source_files or {})
        self.analysis_root = os.path.realpath(analysis_root) if analysis_root else None
        self.allow_runtime_execution = allow_runtime_execution
        self.fail_on_diagnostics = fail_on_diagnostics
        self.max_diagnostics = max_diagnostics
        self.max_runtime_fallback_ratio = max_runtime_fallback_ratio
        self._analysis_root_explicit = analysis_root is not None
        if self.analysis_root is None:
            self.analysis_root = _infer_analysis_root(self.source_files.keys())
        project_path = self.analysis_root if self._analysis_root_explicit else None
        self.project_context = ProjectContext(
            project_path,
            added_sys_path=self.search_paths,
            source_files=self.source_files,
        )
        self.stub_resolver = StubResolver(
            self.project_context,
            typeshed_roots=typeshed_roots,
        )

        # Cache for resolved modules to avoid repeated work
        self._module_cache: Dict[str, Dict[str, Any]] = {}
        self._class_proxy_registry: Dict[str, type] = {}
        # Track missing dependencies for better error reporting
        self._missing_dependencies: Dict[str, List[str]] = (
            {}
        )  # module -> [importing_files]
        # Import graph: module -> imported modules
        self._import_graph: Dict[str, set[str]] = {}
        self._diagnostics: List[str] = []
        # Telemetry for precision/performance troubleshooting
        self._telemetry: Dict[str, int] = {
            "files_processed": 0,
            "runtime_exec_attempts": 0,
            "runtime_exec_failures": 0,
            "runtime_fallbacks": 0,
            "ast_extract_failures": 0,
            "diagnostics": 0,
            "private_defs_filtered": 0,
            "missing_dependencies": 0,
            "import_edges": 0,
            "source_map_hits": 0,
        }

    def _record_diagnostic(self, stage: str, file_path: str, detail: str) -> None:
        self._diagnostics.append(f"{stage}:{file_path}: {detail}")
        self._telemetry["diagnostics"] = len(self._diagnostics)

    def get_diagnostics(self) -> List[str]:
        """Get recorded extraction diagnostics."""
        return list(self._diagnostics)

    def get_stub_diagnostics(self, *, as_dict: bool = False):
        """Get structured diagnostics from project-aware stub resolution."""
        diagnostics = self.stub_resolver.get_diagnostics()
        if as_dict:
            return [diagnostic.__dict__.copy() for diagnostic in diagnostics]
        return diagnostics

    def _refresh_analysis_root(self) -> None:
        if self._analysis_root_explicit:
            if self.analysis_root is not None:
                self.project_context.path = Path(os.path.realpath(self.analysis_root))
            return
        inferred = _infer_analysis_root(self.source_files.keys())
        if inferred is not None:
            self.analysis_root = inferred

    def extract_functions(self, source: str, file_path: str) -> Dict[str, Any]:
        """
        Extract functions from source code using the configured strategy.

        Args:
            source: Python source code
            file_path: Path to the source file

        Returns:
            Dictionary mapping function names to function objects
        """
        file_path = str(file_path)
        self._telemetry["files_processed"] += 1
        self.source_files[file_path] = source
        self.project_context.source_files[file_path] = source
        self._refresh_analysis_root()
        strategy_handlers = {
            DependencyStrategy.STRICT: self._extract_with_runtime,
            DependencyStrategy.STUBS: self._extract_with_stubs,
            DependencyStrategy.NOOP: self._extract_noop,
            DependencyStrategy.AST_ONLY: self._extract_ast_only,
            DependencyStrategy.AUTO: self._extract_auto,
        }
        result = strategy_handlers[self.strategy](source, file_path)
        self._enforce_quality_gates(file_path)
        return result

    def _enforce_quality_gates(self, file_path: str) -> None:
        if self.fail_on_diagnostics and self._diagnostics:
            raise RuntimeError(
                f"Dependency diagnostics present for {file_path}: {self._diagnostics[-1]}"
            )

        if (
            self.max_diagnostics is not None
            and len(self._diagnostics) > self.max_diagnostics
        ):
            raise RuntimeError(
                f"Diagnostic budget exceeded ({len(self._diagnostics)} > {self.max_diagnostics})"
            )

        if self.max_runtime_fallback_ratio is not None:
            processed = self._telemetry.get("files_processed", 0)
            if processed > 0:
                fallbacks = self._telemetry.get("runtime_fallbacks", 0)
                ratio = fallbacks / processed
                if ratio > self.max_runtime_fallback_ratio:
                    raise RuntimeError(
                        "Runtime fallback ratio exceeded "
                        f"({ratio:.2f} > {self.max_runtime_fallback_ratio:.2f})"
                    )

    def _runtime_disabled_fallback(
        self, source: str, file_path: str, mode: str
    ) -> Dict[str, Any]:
        self._telemetry["runtime_fallbacks"] += 1
        if self.verbose:
            print(
                f"DEBUG: {mode} runtime extraction disabled for {file_path}; using AST-only fallback"
            )
        return self._extract_ast_functions(source, file_path)

    def _prepare_exec_globals(
        self, source: str, file_path: str, *, preload_stubs: bool = False
    ) -> Dict[str, Any]:
        exec_globals = self._create_safe_exec_globals()
        exec_globals["__file__"] = file_path
        if preload_stubs:
            exec_globals = self._handle_import_errors(source, exec_globals, file_path)
        return exec_globals

    def _execute_runtime_extraction(
        self,
        source: str,
        file_path: str,
        exec_globals: Dict[str, Any],
        *,
        diagnostic_stage: Optional[str] = None,
        allow_stub_imports: bool = False,
    ) -> Dict[str, Any]:
        # Runtime probing is isolated in a subprocess so sys.modules mutations
        # and other global state changes cannot leak into the analyzer process.
        names = self._runtime_probe_function_names(
            source, file_path, allow_stub_imports=allow_stub_imports
        )
        ast_functions = self._extract_ast_functions(source, file_path)
        functions = {
            name: ast_functions[name] for name in names if name in ast_functions
        }
        if functions:
            return functions
        if diagnostic_stage:
            self._record_diagnostic(
                diagnostic_stage, file_path, "runtime execution produced no functions"
            )
        return {}

    def _extract_signature(
        self, args: python_ast.arguments
    ) -> Optional[inspect.Signature]:
        try:
            return _signature_from_ast(args)
        except Exception:
            return None

    def _extract_function_proxy(
        self,
        node: python_ast.AST,
        module_name: str,
        file_path: str,
    ) -> _ASTFunctionProxy:
        lineno = int(getattr(node, "lineno", 1) or 1)
        return _ASTFunctionProxy(
            name=node.name,
            qualname=node.name,
            module=module_name,
            filename=file_path,
            firstlineno=lineno,
            signature=self._extract_signature(node.args),
            docstring=_extract_docstring(node),
            decorators=_extract_decorator_names(node),
            is_async=isinstance(node, python_ast.AsyncFunctionDef),
        )

    def _should_include_toplevel_name(self, name: str) -> bool:
        if self.include_private:
            return True
        if not name.startswith("_"):
            return True
        self._telemetry["private_defs_filtered"] += 1
        return False

    def _extract_top_level_classes(
        self, tree: python_ast.AST, module_name: str, file_path: str
    ) -> Dict[str, Dict[str, Any]]:
        classes = {}
        for node in _iter_toplevel_class_nodes(tree):
            if not self._should_include_toplevel_name(node.name):
                continue
            classes[node.name] = self._extract_class_info(node, module_name, file_path)
        return classes

    def _extract_top_level_functions(
        self, tree: python_ast.AST, module_name: str, file_path: str
    ) -> Dict[str, Any]:
        functions = {}
        for node in _iter_toplevel_function_nodes(tree):
            if not self._should_include_toplevel_name(node.name):
                continue
            functions[node.name] = self._extract_function_proxy(
                node, module_name, file_path
            )
        return functions

    def _cache_module_extraction(
        self,
        file_path: str,
        module_name: str,
        functions: Dict[str, Any],
        classes: Dict[str, Dict[str, Any]],
        imports: Dict[str, str],
    ) -> None:
        class_proxies = self._build_class_proxies(
            file_path, module_name, classes, imports
        )
        self._module_cache[file_path] = {
            "functions": functions,
            "classes": classes,
            "class_proxies": class_proxies,
            "imports": imports,
            "module_name": module_name,
        }

    def _extract_with_runtime(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions using runtime execution only."""
        if not self.allow_runtime_execution:
            return self._runtime_disabled_fallback(source, file_path, "Runtime")
        self._telemetry["runtime_exec_attempts"] += 1
        exec_globals = self._prepare_exec_globals(source, file_path)

        try:
            return self._execute_runtime_extraction(
                source,
                file_path,
                exec_globals,
                diagnostic_stage="runtime_exec",
                allow_stub_imports=False,
            )
        except Exception as e:
            self._telemetry["runtime_exec_failures"] += 1
            self._record_diagnostic(
                "runtime_exec", file_path, f"{type(e).__name__}: {e}"
            )
            if self.verbose:
                print(f"ERROR: Runtime extraction failed for {file_path}: {e}")
            return {}

    def _extract_with_stubs(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions using runtime execution with enhanced stub modules."""
        if not self.allow_runtime_execution:
            return self._runtime_disabled_fallback(source, file_path, "Stub-assisted")
        self._telemetry["runtime_exec_attempts"] += 1
        exec_globals = self._prepare_exec_globals(source, file_path)

        # Try normal execution first
        try:
            functions = self._execute_runtime_extraction(
                source,
                file_path,
                exec_globals,
                allow_stub_imports=True,
            )
            if functions:
                return functions
        except ImportError as e:
            if self.verbose:
                print(f"DEBUG: Import error in {file_path}: {e}")

            # Create enhanced stubs for missing imports (may find source files)
            exec_globals_with_stubs = self._prepare_exec_globals(
                source, file_path, preload_stubs=True
            )
            try:
                functions = self._execute_runtime_extraction(
                    source,
                    file_path,
                    exec_globals_with_stubs,
                    diagnostic_stage="stub_runtime_exec",
                    allow_stub_imports=True,
                )
                if functions:
                    return functions
            except Exception as stub_e:
                self._telemetry["runtime_exec_failures"] += 1
                self._record_diagnostic(
                    "stub_runtime_exec", file_path, f"{type(stub_e).__name__}: {stub_e}"
                )
                if self.verbose:
                    print(f"DEBUG: Even with stubs, execution failed: {stub_e}")

        # If runtime execution failed, fall back to AST extraction for local functions
        if self.verbose:
            print(
                f"DEBUG: Runtime execution failed for {file_path}, falling back to AST extraction"
            )
        self._telemetry["runtime_fallbacks"] += 1
        return self._extract_ast_functions(source, file_path)

    def get_missing_dependencies(self) -> Dict[str, List[str]]:
        """Get a report of missing dependencies and where they were imported.

        Returns:
            Dict mapping module names to list of files that import them
        """
        return dict(self._missing_dependencies)

    def _extract_noop(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions but treat all external dependencies as no-ops."""
        if not self.allow_runtime_execution:
            return self._runtime_disabled_fallback(source, file_path, "No-op")
        self._telemetry["runtime_exec_attempts"] += 1
        exec_globals = self._prepare_exec_globals(source, file_path, preload_stubs=True)

        try:
            return self._execute_runtime_extraction(
                source,
                file_path,
                exec_globals,
                diagnostic_stage="noop_runtime_exec",
                allow_stub_imports=True,
            )
        except Exception as e:
            self._telemetry["runtime_exec_failures"] += 1
            self._record_diagnostic(
                "noop_runtime_exec", file_path, f"{type(e).__name__}: {e}"
            )
            if self.verbose:
                print(f"DEBUG: No-op extraction failed for {file_path}: {e}")
            self._telemetry["runtime_fallbacks"] += 1
            return self._extract_ast_functions(source, file_path)

    def _runtime_probe_function_names(
        self,
        source: str,
        file_path: str,
        *,
        allow_stub_imports: bool,
    ) -> List[str]:
        script = r"""
import builtins
import json
import os
import sys
import types

FILE_PATH = sys.argv[1]
ALLOW_STUBS = sys.argv[2] == "1"
SOURCE = sys.stdin.read()

def _noop(*args, **kwargs):
    return None

def _make_stub_module(module_name):
    module = types.ModuleType(module_name)
    module.__file__ = f"<stub:{module_name}>"
    module.__getattr__ = lambda name, _module_name=module_name: _noop
    return module

orig_import = builtins.__import__

def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    try:
        return orig_import(name, globals, locals, fromlist, level)
    except ImportError:
        if not ALLOW_STUBS:
            raise
        parts = [p for p in name.split(".") if p]
        if not parts:
            raise
        parent = None
        module = None
        for i in range(1, len(parts) + 1):
            fullname = ".".join(parts[:i])
            module = sys.modules.get(fullname)
            if module is None:
                module = _make_stub_module(fullname)
                sys.modules[fullname] = module
            if parent is not None:
                setattr(parent, parts[i - 1], module)
            parent = module
        return module

builtins.__import__ = _safe_import

namespace = {"__name__": "__pyflow_analysis__", "__file__": FILE_PATH, "input": lambda *a, **k: ""}

try:
    import os as _os
    _os.system = lambda *a, **k: 0
    _os.popen = lambda *a, **k: None
except Exception:
    pass

try:
    compiled = compile(SOURCE, FILE_PATH, "exec")
    exec(compiled, namespace)
except Exception as exc:
    print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
    sys.exit(1)
finally:
    builtins.__import__ = orig_import

functions = []
for name, obj in namespace.items():
    if name.startswith("_"):
        continue
    if not callable(obj):
        continue
    code = getattr(obj, "__code__", None)
    if code is None:
        continue
    if getattr(code, "co_filename", None) != FILE_PATH:
        continue
    functions.append(name)

print(json.dumps({"functions": sorted(functions)}))
"""

        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                file_path,
                "1" if allow_stub_imports else "0",
            ],
            input=source,
            text=True,
            capture_output=True,
            check=False,
        )

        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()

        if completed.returncode != 0:
            message = stderr or stdout or "runtime probe failed"
            raise RuntimeError(message)

        payload = json.loads(stdout or "{}")
        return list(payload.get("functions", []))

    def _extract_ast_only(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions using only AST parsing."""
        return self._extract_ast_functions(source, file_path)

    def _extract_ast_functions(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions and classes using AST parsing with enhanced information."""
        try:
            tree = python_ast.parse(source)
            module_name = self._get_module_name_from_path(file_path)
            self._record_import_edges(tree, module_name, file_path)
            imports = self._extract_import_map(tree, module_name)
            classes = self._extract_top_level_classes(tree, module_name, file_path)
            functions = self._extract_top_level_functions(tree, module_name, file_path)
            self._cache_module_extraction(
                file_path, module_name, functions, classes, imports
            )
            return functions
        except Exception as e:
            self._telemetry["ast_extract_failures"] += 1
            self._record_diagnostic(
                "ast_extract", file_path, f"{type(e).__name__}: {e}"
            )
            if self.verbose:
                print(f"DEBUG: AST extraction failed for {file_path}: {e}")
            return {}

    def _extract_class_info(
        self, node: python_ast.ClassDef, module_name: str, file_path: str
    ) -> Dict[str, Any]:
        """Extract information from a class definition."""
        base_names = []
        for base in node.bases:
            base_name = _base_name_from_expr(base)
            if base_name:
                base_names.append(base_name)

        methods = {}
        for item in node.body:
            if isinstance(item, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)):
                lineno = int(getattr(item, "lineno", 1) or 1)
                docstring = _extract_docstring(item)
                decorators = _extract_decorator_names(item)
                is_async = isinstance(item, python_ast.AsyncFunctionDef)
                is_classmethod = any("classmethod" in d.lower() for d in decorators)
                is_staticmethod = any("staticmethod" in d.lower() for d in decorators)
                is_property = any(_is_property_decorator(d) for d in decorators)

                methods[item.name] = {
                    "name": item.name,
                    "qualname": f"{node.name}.{item.name}",
                    "signature": self._extract_signature(item.args),
                    "docstring": docstring,
                    "decorators": decorators,
                    "is_async": is_async,
                    "is_classmethod": is_classmethod,
                    "is_staticmethod": is_staticmethod,
                    "is_property": is_property,
                    "lineno": lineno,
                }

        return {
            "name": node.name,
            "qualname": f"{module_name}.{node.name}",
            "bases": base_names,
            "methods": methods,
            "docstring": _extract_docstring(node),
            "decorators": _extract_decorator_names(node),
            "lineno": int(getattr(node, "lineno", 1) or 1),
        }

    def _signature_from_stub_function(
        self, func: StubFunctionInfo
    ) -> inspect.Signature:
        params: List[inspect.Parameter] = []
        for raw_name, _annotation in func.params:
            kind_name = func.param_kinds.get(raw_name)
            kind: inspect._ParameterKind
            if raw_name.startswith("**"):
                name = raw_name[2:]
                kind = inspect.Parameter.VAR_KEYWORD
            elif raw_name.startswith("*"):
                name = raw_name[1:]
                kind = inspect.Parameter.VAR_POSITIONAL
            elif kind_name == "posonly":
                name = raw_name
                kind = inspect.Parameter.POSITIONAL_ONLY
            elif kind_name == "kwonly":
                name = raw_name
                kind = inspect.Parameter.KEYWORD_ONLY
            else:
                name = raw_name
                kind = inspect.Parameter.POSITIONAL_OR_KEYWORD
            params.append(inspect.Parameter(name, kind))
        return inspect.Signature(params)

    def _stub_function_proxy(
        self,
        func: StubFunctionInfo,
        module_name: str,
        file_path: str,
        *,
        qualname: Optional[str] = None,
        is_class_method: bool = False,
    ) -> _ASTFunctionProxy:
        type_hints = {
            name.lstrip("*"): annotation
            for name, annotation in func.params
            if annotation is not None
        }
        if func.returns is not None:
            type_hints["return"] = func.returns
        return _ASTFunctionProxy(
            name=func.name,
            qualname=qualname or func.name,
            module=module_name,
            filename=file_path,
            firstlineno=1,
            signature=self._signature_from_stub_function(func),
            decorators=list(func.decorators),
            is_class_method=is_class_method,
            type_hints=type_hints,
        )

    def _stub_class_info(
        self,
        cls: StubClassInfo,
        module_name: str,
    ) -> Dict[str, Any]:
        methods: Dict[str, Dict[str, Any]] = {}
        for method in cls.methods:
            decorators = list(method.decorators)
            methods[method.name] = {
                "name": method.name,
                "qualname": f"{cls.name}.{method.name}",
                "signature": self._signature_from_stub_function(method),
                "docstring": None,
                "decorators": decorators,
                "is_async": False,
                "is_classmethod": any("classmethod" in d.lower() for d in decorators),
                "is_staticmethod": any("staticmethod" in d.lower() for d in decorators),
                "is_property": any(_is_property_decorator(d) for d in decorators),
                "lineno": 1,
                "type_hints": {
                    name.lstrip("*"): annotation
                    for name, annotation in method.params
                    if annotation is not None
                },
                "return": method.returns,
            }
        return {
            "name": cls.name,
            "qualname": f"{module_name}.{cls.name}",
            "bases": list(cls.bases),
            "methods": methods,
            "docstring": None,
            "decorators": [],
            "lineno": 1,
            "class_vars": list(cls.class_vars),
        }

    def _create_module_from_resolved_stub(
        self,
        module_name: str,
        resolved: ResolvedStub,
    ) -> types.ModuleType:
        functions = {
            func.name: self._stub_function_proxy(
                func,
                module_name,
                resolved.path,
            )
            for func in resolved.info.functions
            if self._should_include_toplevel_name(func.name)
        }
        classes = {
            cls.name: self._stub_class_info(cls, module_name)
            for cls in resolved.info.classes
            if self._should_include_toplevel_name(cls.name)
        }
        self._cache_module_extraction(
            resolved.path,
            module_name,
            functions,
            classes,
            {},
        )
        module = cast(
            types.ModuleType,
            self._create_enhanced_stub_module(module_name, functions, classes),
        )
        for variable_name, _annotation in resolved.info.variables:
            if self._should_include_toplevel_name(variable_name):
                setattr(
                    module,
                    variable_name,
                    self._create_noop_function(f"{module_name}.{variable_name}"),
                )
        return module

    def _extract_import_map(
        self, tree: python_ast.AST, module_name: str
    ) -> Dict[str, str]:
        imports: Dict[str, str] = {}

        for node in _iter_import_nodes_in_scope(getattr(tree, "body", ()) or ()):
            if isinstance(node, python_ast.Import):
                for alias in node.names:
                    imports[alias.asname or alias.name.split(".")[-1]] = alias.name
            elif isinstance(node, python_ast.ImportFrom):
                effective_module = self._resolve_imported_module(
                    module_name,
                    node.module or "",
                    int(getattr(node, "level", 0) or 0),
                )
                for alias in node.names:
                    if alias.name == "*":
                        for exported in self._expand_star_import_names(
                            effective_module
                        ):
                            imports.setdefault(
                                exported, f"{effective_module}.{exported}"
                            )
                        continue
                    local_name = alias.asname or alias.name
                    imports[local_name] = (
                        f"{effective_module}.{alias.name}"
                        if effective_module
                        else alias.name
                    )

        return imports

    def _expand_star_import_names(self, module_name: str) -> List[str]:
        """Expand ``from module import *`` names when source is available."""
        if not module_name:
            return []

        resolved_stub = self.stub_resolver.resolve(module_name)
        if resolved_stub is not None:
            stub_discovered: Set[str] = set()
            for func in resolved_stub.info.functions:
                if not func.name.startswith("_"):
                    stub_discovered.add(func.name)
            for cls in resolved_stub.info.classes:
                if not cls.name.startswith("_"):
                    stub_discovered.add(cls.name)
            stub_discovered.update(
                name
                for name, _annotation in resolved_stub.info.variables
                if not name.startswith("_")
            )
            return sorted(stub_discovered)

        source_file = self._find_module_source(module_name)
        if source_file is None:
            return []

        try:
            module_source = self._load_source(source_file)
            tree = python_ast.parse(module_source)
        except Exception:
            return []

        explicit_all: Optional[List[str]] = None
        discovered: Set[str] = set()

        for node in getattr(tree, "body", []) or []:
            if isinstance(
                node,
                (
                    python_ast.FunctionDef,
                    python_ast.AsyncFunctionDef,
                    python_ast.ClassDef,
                ),
            ):
                if not node.name.startswith("_"):
                    discovered.add(node.name)
                continue

            if isinstance(node, python_ast.Assign):
                for target in node.targets:
                    if not isinstance(target, python_ast.Name):
                        continue
                    if target.id == "__all__":
                        explicit_all = _extract_literal_string_list(node.value)
                    elif not target.id.startswith("_"):
                        discovered.add(target.id)
                continue

            if isinstance(node, python_ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[-1]
                    if not local.startswith("_"):
                        discovered.add(local)
                continue

            if isinstance(node, python_ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    if not local.startswith("_"):
                        discovered.add(local)

        if explicit_all is not None:
            return [name for name in explicit_all if isinstance(name, str)]
        return sorted(discovered)

    def _resolve_proxy_base_name(
        self,
        base_name: str,
        module_name: str,
        imports: Dict[str, str],
    ) -> Optional[str]:
        if base_name in imports:
            return imports[base_name]
        if "." in base_name:
            head, tail = base_name.split(".", 1)
            if head in imports:
                return f"{imports[head]}.{tail}"
            return base_name
        return f"{module_name}.{base_name}"

    def _create_class_proxy(
        self,
        cls_info: Dict[str, Any],
        module_name: str,
        file_path: str,
        bases: Optional[Tuple[type, ...]] = None,
    ) -> type:
        attrs: Dict[str, Any] = {
            "__module__": module_name,
            "__doc__": cls_info.get("docstring"),
            "__pyflow_class_info__": cls_info,
        }
        public_methods: Dict[str, Any] = {}

        for method_name, method_info in cls_info.get("methods", {}).items():
            proxy = _ASTFunctionProxy(
                name=method_info["name"],
                qualname=method_info["qualname"],
                module=module_name,
                filename=file_path,
                firstlineno=method_info.get("lineno", 1),
                signature=method_info.get("signature"),
                docstring=method_info.get("docstring"),
                decorators=method_info.get("decorators", []),
                is_async=method_info.get("is_async", False),
                is_class_method=method_info.get("is_classmethod", False),
            )
            public_methods[method_name] = proxy

            if method_info.get("is_classmethod"):
                attrs[method_name] = classmethod(proxy)
            elif method_info.get("is_staticmethod"):
                attrs[method_name] = staticmethod(proxy)
            else:
                attrs[method_name] = proxy

        attrs["__pyflow_public_methods__"] = public_methods
        proxy_cls = type(cls_info["name"], bases or (object,), attrs)
        proxy_cls.__qualname__ = cls_info.get("qualname", cls_info["name"])
        return proxy_cls

    def _build_class_proxies(
        self,
        file_path: str,
        module_name: str,
        classes: Dict[str, Dict[str, Any]],
        imports: Dict[str, str],
    ) -> Dict[str, type]:
        built: Dict[str, type] = {}
        building: set[str] = set()

        def build(class_name: str) -> type:
            if class_name in built:
                return built[class_name]

            cls_info = classes[class_name]
            qualified = cls_info["qualname"]
            existing = self._class_proxy_registry.get(qualified)
            if existing is not None:
                built[class_name] = existing
                return existing

            if qualified in building:
                return object
            building.add(qualified)

            bases: List[type] = []
            for base_name in cls_info.get("bases", []):
                resolved = self._resolve_proxy_base_name(
                    base_name, module_name, imports
                )
                base_proxy = self._get_or_load_class_proxy(
                    resolved,
                    local_classes=classes,
                    local_builder=build,
                )
                if (
                    base_proxy is not None
                    and base_proxy is not object
                    and base_proxy not in bases
                ):
                    bases.append(base_proxy)

            proxy = self._create_class_proxy(
                cls_info,
                module_name,
                file_path,
                tuple(bases) if bases else (object,),
            )
            self._class_proxy_registry[qualified] = proxy
            built[class_name] = proxy
            building.remove(qualified)
            return proxy

        for class_name in classes:
            build(class_name)

        return built

    def _get_or_load_class_proxy(
        self,
        qualified_name: Optional[str],
        *,
        local_classes: Optional[Dict[str, Dict[str, Any]]] = None,
        local_builder=None,
    ) -> Optional[type]:
        if not qualified_name:
            return None

        existing = self._class_proxy_registry.get(qualified_name)
        if existing is not None:
            return existing

        if local_classes and local_builder:
            local_name = qualified_name.rsplit(".", 1)[-1]
            if (
                local_name in local_classes
                and local_classes[local_name]["qualname"] == qualified_name
            ):
                return local_builder(local_name)

        if "." not in qualified_name:
            return None

        module_name, class_name = qualified_name.rsplit(".", 1)
        source_file = self._find_module_source(module_name)
        if source_file is None:
            return None

        cache = self._module_cache.get(source_file)
        if cache is None:
            module_source = self._load_source(source_file)
            self._extract_ast_functions(module_source, source_file)
            cache = self._module_cache.get(source_file)

        if not cache:
            return None

        return cache.get("class_proxies", {}).get(class_name)

    def get_module_classes(self, file_path: str) -> Dict[str, type]:
        cache = self._module_cache.get(file_path)
        if cache is None and file_path in self.source_files:
            self._extract_ast_functions(self.source_files[file_path], file_path)
            cache = self._module_cache.get(file_path)
        if not cache:
            return {}
        return dict(cache.get("class_proxies", {}))

    def get_public_class_methods(self, cls: type) -> Dict[str, Any]:
        methods: Dict[str, Any] = {}
        for base in reversed(getattr(cls, "__mro__", ())):
            methods.update(getattr(base, "__pyflow_public_methods__", {}))
        return methods

    def get_public_method_specs(self, cls: type) -> Dict[str, Dict[str, Any]]:
        specs: Dict[str, Dict[str, Any]] = {}
        for base in reversed(getattr(cls, "__mro__", ())):
            class_info = getattr(base, "__pyflow_class_info__", None)
            if not class_info:
                continue
            for name, info in class_info.get("methods", {}).items():
                specs[name] = dict(info)
        return specs

    def _get_module_name_from_path(self, file_path: str) -> str:
        """Extract a dotted module name from file path.

        The old implementation used basename-only names (e.g. "util"), which
        collapsed modules from different packages into the same namespace.
        """
        return self.project_context.module_name_from_path(file_path)

    def _resolve_imported_module(
        self, current_module: str, imported_module: str, level: int
    ) -> str:
        """Resolve an import module considering relative import level."""
        return (
            self.project_context.resolve_import_name(
                current_module,
                imported_module,
                level,
            )
            or ""
        )

    def _record_import_edges(
        self, tree: python_ast.AST, current_module: str, file_path: str
    ) -> None:
        edges = self._import_graph.setdefault(current_module, set())
        for node in _iter_import_nodes_in_scope(getattr(tree, "body", ()) or ()):
            if isinstance(node, python_ast.Import):
                for alias in node.names:
                    target = alias.name
                    if target:
                        edges.add(target)
            elif isinstance(node, python_ast.ImportFrom):
                target = (
                    self.project_context.resolve_import_name(
                        current_module,
                        node.module or "",
                        int(getattr(node, "level", 0) or 0),
                        current_path=file_path,
                    )
                    or ""
                )
                if target:
                    edges.add(target)
        self._telemetry["import_edges"] = sum(
            len(v) for v in self._import_graph.values()
        )

    def _extract_auto(self, source: str, file_path: str) -> Dict[str, Any]:
        """Auto strategy: prefer AST parsing to avoid executing user code.

        Historically this resolver executed modules to obtain real function objects.
        That is unsafe (side effects) and brittle (imports, environment, IO).
        AUTO now behaves like AST_ONLY unless the caller explicitly selects a
        runtime-based strategy (STRICT/STUBS/NOOP).
        """
        if self.verbose:
            print(f"DEBUG: AUTO strategy using AST parsing for {file_path}")
        return self._extract_ast_only(source, file_path)

    def _create_safe_exec_globals(self) -> Dict[str, Any]:
        """Create a safe globals dict for exec()."""
        safe_globals = dict(vars(builtins))
        runtime_modules: Dict[str, types.ModuleType] = {}

        # Ensure module metadata exists and avoid triggering `if __name__ == "__main__":`
        # blocks during execution-based extraction.
        safe_globals.setdefault("__name__", "__pyflow_analysis__")

        # Prevent interactive/blocking behavior during execution-based extraction.
        # Static analysis should never prompt for input.
        safe_globals["input"] = lambda *args, **kwargs: ""

        # Add safe modules
        for module_name in self.safe_modules:
            try:
                imported = __import__(module_name)
                cloned = self._clone_module_for_exec(imported)
                runtime_modules[module_name] = cloned
                safe_globals[module_name] = cloned
            except ImportError:
                pass  # Skip unavailable modules

        # Reduce side effects during exec()-based extraction by stubbing the most
        # common "dangerous" primitives used in security benchmarks.
        os_mod = runtime_modules.get("os")
        if os_mod is not None:
            try:
                os_mod.system = lambda *args, **kwargs: 0
                os_mod.popen = lambda *args, **kwargs: None
            except Exception:
                pass

        if runtime_modules:
            safe_globals["__pyflow_runtime_modules__"] = runtime_modules

        return safe_globals

    def _clone_module_for_exec(self, module: types.ModuleType) -> types.ModuleType:
        cloned = types.ModuleType(module.__name__)
        cloned.__dict__.update(vars(module))
        return cloned

    def _handle_import_errors(
        self, source: str, exec_globals: Dict[str, Any], file_path: str = "<unknown>"
    ) -> Dict[str, Any]:
        """Handle import errors by creating importable module stubs."""
        stub_modules = self._build_stub_modules(source, file_path)
        if stub_modules:
            exec_globals["__pyflow_stub_modules__"] = stub_modules
            for module_name, module in stub_modules.items():
                if "." not in module_name:
                    exec_globals[module_name] = module
        return exec_globals

    def _create_enhanced_stub_module(
        self, module_name: str, functions: Dict[str, Any], classes: Dict[str, Any]
    ) -> Any:
        """Create an enhanced importable stub module."""
        module = types.ModuleType(module_name)
        module.__file__ = f"<stub:{module_name}>"

        for func_name, func_obj in functions.items():
            setattr(module, func_name, func_obj)

        for cls_name, cls_info in classes.items():
            setattr(
                module,
                cls_name,
                self._create_class_proxy(cls_info, module_name, "<stub>"),
            )

        def _fallback(name: str, _module_name: str = module_name):
            return self._create_noop_function(f"{_module_name}.{name}")

        module.__getattr__ = _fallback
        return module

    def _create_noop_function(self, name: str) -> Any:
        class NoOpFunction:
            def __init__(self, qualname: str):
                self.__name__ = qualname.split(".")[-1]
                self.__qualname__ = qualname
                self.__module__ = (
                    qualname.rsplit(".", 1)[0] if "." in qualname else "__pyflow_stub__"
                )

            def __call__(self, *args, **kwargs):
                return None

        return NoOpFunction(name)

    def _register_module_chain(
        self,
        modules: Dict[str, types.ModuleType],
        module_name: str,
        module: types.ModuleType,
    ) -> None:
        parts = [part for part in module_name.split(".") if part]
        if not parts:
            return

        for i in range(1, len(parts) + 1):
            name = ".".join(parts[:i])
            if i == len(parts):
                current = module
            else:
                current = modules.get(name) or self._create_stub_module(name)
            modules[name] = current

            if i > 1:
                parent = modules[".".join(parts[: i - 1])]
                setattr(parent, parts[i - 1], current)

    def _note_missing_dependency(self, module_name: str, file_path: str) -> None:
        importing_files = self._missing_dependencies.setdefault(module_name, [])
        if file_path not in importing_files:
            importing_files.append(file_path)
        self._telemetry["missing_dependencies"] = sum(
            len(v) for v in self._missing_dependencies.values()
        )

    def _load_stub_module(
        self,
        module_name: str,
        file_path: str,
        modules: Dict[str, types.ModuleType],
    ) -> types.ModuleType:
        resolved_stub = self.stub_resolver.resolve(module_name)
        if resolved_stub is not None:
            if self.verbose:
                print(
                    f"DEBUG: Found stub file for '{module_name}': {resolved_stub.path}"
                )
            return self._create_module_from_resolved_stub(module_name, resolved_stub)

        source_file = self._find_module_source(module_name)
        if source_file:
            if self.verbose:
                print(f"DEBUG: Found source file for '{module_name}': {source_file}")
            try:
                module_source = self._load_source(source_file)
                module_functions = self._extract_ast_functions(
                    module_source, source_file
                )
                cache = self._module_cache.get(source_file, {})
                module_classes = cache.get("classes", {})
                module = self._create_enhanced_stub_module(
                    module_name, module_functions, module_classes
                )
                if self.class_hierarchy and module_classes:
                    for cls_name, cls_info in module_classes.items():
                        self.class_hierarchy.register_class(
                            name=cls_info["name"],
                            bases=cls_info["bases"],
                            module=module_name,
                            methods=set(cls_info["methods"].keys()),
                            ast_node=None,
                        )
                return module
            except Exception as exc:
                self._record_diagnostic(
                    "stub_source_extract", source_file, f"{type(exc).__name__}: {exc}"
                )
                if self.verbose:
                    print(f"DEBUG: Failed to extract from {source_file}: {exc}")

        if self.verbose:
            print(f"DEBUG: Creating stub for missing module '{module_name}'")
        self._note_missing_dependency(module_name, file_path)
        return self._create_stub_module(module_name)

    def _build_stub_modules(
        self, source: str, file_path: str
    ) -> Dict[str, types.ModuleType]:
        try:
            tree = python_ast.parse(source)
        except Exception:
            self._record_diagnostic(
                "import_scan", file_path, "failed to parse source for stub modules"
            )
            return {}

        current_module = self._get_module_name_from_path(file_path)
        modules: Dict[str, types.ModuleType] = {}

        for node in _iter_import_nodes_in_scope(getattr(tree, "body", ()) or ()):
            if isinstance(node, python_ast.Import):
                for alias in node.names:
                    module_name = alias.name
                    module = self._load_stub_module(module_name, file_path, modules)
                    self._register_module_chain(modules, module_name, module)

            elif isinstance(node, python_ast.ImportFrom):
                module_name = (
                    self.project_context.resolve_import_name(
                        current_module,
                        node.module or "",
                        int(getattr(node, "level", 0) or 0),
                        current_path=file_path,
                    )
                    or ""
                )
                if not module_name:
                    continue

                module = modules.get(module_name)
                if module is None:
                    module = self._load_stub_module(module_name, file_path, modules)
                    self._register_module_chain(modules, module_name, module)

                for alias in node.names:
                    if alias.name == "*":
                        continue

                    child_module_name = f"{module_name}.{alias.name}"
                    child_source = self._find_module_source(child_module_name)
                    if child_source:
                        child_module = self._load_stub_module(
                            child_module_name, file_path, modules
                        )
                        self._register_module_chain(
                            modules, child_module_name, child_module
                        )
                        setattr(module, alias.name, child_module)
                    elif not hasattr(module, alias.name):
                        setattr(
                            module,
                            alias.name,
                            self._create_noop_function(f"{module_name}.{alias.name}"),
                        )

        return modules

    def _exec_with_stub_modules(
        self, compiled: Any, exec_globals: Dict[str, Any]
    ) -> None:
        if not self.allow_runtime_execution:
            raise RuntimeError(
                "Runtime module execution is disabled; enable allow_runtime_execution to opt in."
            )
        stub_modules = exec_globals.pop("__pyflow_stub_modules__", None)
        runtime_modules = exec_globals.pop("__pyflow_runtime_modules__", None)
        if not stub_modules and not runtime_modules:
            exec(compiled, exec_globals)
            return

        sentinel = object()
        originals: Dict[str, Any] = {}
        temp_modules: Dict[str, types.ModuleType] = {}
        if runtime_modules:
            temp_modules.update(runtime_modules)
        if stub_modules:
            temp_modules.update(stub_modules)
        try:
            for module_name, module in temp_modules.items():
                originals[module_name] = sys.modules.get(module_name, sentinel)
                sys.modules[module_name] = module
            exec(compiled, exec_globals)
        finally:
            for module_name, original in originals.items():
                if original is sentinel:
                    sys.modules.pop(module_name, None)
                else:
                    sys.modules[module_name] = original
            if stub_modules is not None:
                exec_globals["__pyflow_stub_modules__"] = stub_modules
            if runtime_modules is not None:
                exec_globals["__pyflow_runtime_modules__"] = runtime_modules

    def _find_imports(self, source: str) -> set:
        """Find all import statements in source code.

        Returns:
            Set of module names that are imported
        """
        try:
            tree = python_ast.parse(source)
            imports = set()

            for node in _iter_import_nodes_in_scope(getattr(tree, "body", ()) or ()):
                if isinstance(node, python_ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split(".")[0])
                elif isinstance(node, python_ast.ImportFrom) and node.module:
                    imports.add(node.module.split(".")[0])

            return imports
        except Exception:
            return set()

    def _find_imports_detailed(
        self, source: str
    ) -> Dict[str, List[Tuple[str, Optional[str]]]]:
        """Find all import statements in source code with detailed information.

        Returns:
            Dict mapping module names to list of (imported_name, alias) tuples
        """
        try:
            tree = python_ast.parse(source)
            imports: Dict[str, List[Tuple[str, Optional[str]]]] = {}

            for node in _iter_import_nodes_in_scope(getattr(tree, "body", ()) or ()):
                if isinstance(node, python_ast.Import):
                    for alias in node.names:
                        module_name = alias.name.split(".")[0]
                        if module_name not in imports:
                            imports[module_name] = []
                        imports[module_name].append((alias.name, alias.asname))
                elif isinstance(node, python_ast.ImportFrom) and node.module:
                    module_name = node.module.split(".")[0]
                    if module_name not in imports:
                        imports[module_name] = []
                    for alias in node.names:
                        imported_name = alias.name
                        if imported_name == "*":
                            continue
                        imports[module_name].append(
                            (f"{node.module}.{imported_name}", alias.asname)
                        )

            return imports
        except Exception:
            return {}

    def _find_module_source(self, module_name: str) -> Optional[str]:
        """Try to find the source file for a module.

        Args:
            module_name: The module name to search for

        Returns:
            Path to source file if found, None otherwise
        """
        stub_path = self.stub_resolver.resolve_path(module_name)
        if stub_path is not None:
            return stub_path

        resolution = self.project_context.find_module(module_name)
        if resolution is None or resolution.path is None:
            return None
        if resolution.is_in_memory:
            self._telemetry["source_map_hits"] += 1
        return resolution.path

    def _build_module_source_map(self) -> Dict[str, str]:
        return self.project_context._source_map()

    def _load_source(self, file_path: str) -> str:
        if file_path in self.source_files:
            return self.source_files[file_path]
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()

    def get_import_graph(self) -> Dict[str, List[str]]:
        """Get a deterministic snapshot of the import graph."""
        return {k: sorted(v) for k, v in sorted(self._import_graph.items())}

    def get_telemetry(self) -> Dict[str, int]:
        """Get resolver telemetry counters."""
        return dict(self._telemetry)

    def _create_stub_module(self, module_name: str) -> Any:
        """Create a stub module that provides no-op functions."""
        module = types.ModuleType(module_name)
        module.__file__ = f"<stub:{module_name}>"

        def _fallback(name: str, _module_name: str = module_name):
            return self._create_noop_function(f"{_module_name}.{name}")

        module.__getattr__ = _fallback
        return module

    def _create_noop_module(self, module_name: str) -> Any:
        """Create a module that provides only no-op functions."""
        return self._create_stub_module(module_name)

    def _create_ast_stub(self, func_node: python_ast.AST) -> Any:
        """Create a stub callable from a FunctionDef/AsyncFunctionDef AST node."""
        name = getattr(func_node, "name", "unknown")
        lineno = int(getattr(func_node, "lineno", 1) or 1)
        sig = None
        try:
            sig = _signature_from_ast(func_node.args)  # type: ignore[attr-defined]
        except Exception:
            sig = None
        return _ASTFunctionProxy(
            name=name,
            qualname=name,
            module="__pyflow_module__",
            filename="<ast>",
            firstlineno=lineno,
            signature=sig,
        )

    def _filter_functions(
        self, module_globals: Dict[str, Any], file_path: str
    ) -> Dict[str, Any]:
        """Filter out built-in and external functions, keep only file-local ones."""
        builtin_names = set(dir(builtins))
        if isinstance(builtins, dict):
            builtin_names.update(builtins.keys())

        filtered = {}
        for name, obj in module_globals.items():
            if (
                callable(obj)
                and not name.startswith("_")
                and name not in builtin_names
                and hasattr(obj, "__module__")
                and obj.__module__ is not None
                and obj.__module__ not in ("builtins", "__builtin__")
            ):

                # Additional check: try to determine if this function was defined in this file
                if hasattr(obj, "__code__") and hasattr(obj.__code__, "co_filename"):
                    if obj.__code__.co_filename == file_path:
                        filtered[name] = obj

        return filtered
