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
import os
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Callable, Iterable, Tuple
from enum import Enum


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
    if isinstance(first_stmt, python_ast.Expr) and isinstance(first_stmt.value, python_ast.Constant):
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

        # Cache for resolved modules to avoid repeated work
        self._module_cache: Dict[str, Dict[str, Any]] = {}
        # Track missing dependencies for better error reporting
        self._missing_dependencies: Dict[str, List[str]] = {}  # module -> [importing_files]
        # Import graph: module -> imported modules
        self._import_graph: Dict[str, set[str]] = {}
        # Telemetry for precision/performance troubleshooting
        self._telemetry: Dict[str, int] = {
            "files_processed": 0,
            "runtime_exec_attempts": 0,
            "runtime_exec_failures": 0,
            "ast_extract_failures": 0,
            "private_defs_filtered": 0,
            "missing_dependencies": 0,
            "import_edges": 0,
            "source_map_hits": 0,
        }

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
        if self.strategy == DependencyStrategy.STRICT:
            return self._extract_with_runtime(source, file_path)
        elif self.strategy == DependencyStrategy.STUBS:
            return self._extract_with_stubs(source, file_path)
        elif self.strategy == DependencyStrategy.NOOP:
            return self._extract_noop(source, file_path)
        elif self.strategy == DependencyStrategy.AST_ONLY:
            return self._extract_ast_only(source, file_path)
        else:  # AUTO strategy
            return self._extract_auto(source, file_path)

    def _extract_with_runtime(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions using runtime execution only."""
        self._telemetry["runtime_exec_attempts"] += 1
        exec_globals = self._create_safe_exec_globals()
        exec_globals["__file__"] = file_path

        try:
            compiled = compile(source, file_path, "exec")
            exec(compiled, exec_globals)
            return self._filter_functions(exec_globals, file_path)
        except Exception as e:
            self._telemetry["runtime_exec_failures"] += 1
            if self.verbose:
                print(f"ERROR: Runtime extraction failed for {file_path}: {e}")
            return {}

    def _extract_with_stubs(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions using runtime execution with enhanced stub modules."""
        self._telemetry["runtime_exec_attempts"] += 1
        exec_globals = self._create_safe_exec_globals()
        exec_globals["__file__"] = file_path

        # Try normal execution first
        try:
            compiled = compile(source, file_path, "exec")
            exec(compiled, exec_globals)
            functions = self._filter_functions(exec_globals, file_path)
            if functions:
                return functions
        except ImportError as e:
            if self.verbose:
                print(f"DEBUG: Import error in {file_path}: {e}")

            # Create enhanced stubs for missing imports (may find source files)
            exec_globals_with_stubs = self._handle_import_errors(source, exec_globals, file_path)
            try:
                compiled = compile(source, file_path, "exec")
                exec(compiled, exec_globals_with_stubs)
                functions = self._filter_functions(exec_globals_with_stubs, file_path)
                if functions:
                    return functions
            except Exception as stub_e:
                self._telemetry["runtime_exec_failures"] += 1
                if self.verbose:
                    print(f"DEBUG: Even with stubs, execution failed: {stub_e}")

        # If runtime execution failed, fall back to AST extraction for local functions
        if self.verbose:
            print(
                f"DEBUG: Runtime execution failed for {file_path}, falling back to AST extraction"
            )
        return self._extract_ast_functions(source, file_path)
    
    def get_missing_dependencies(self) -> Dict[str, List[str]]:
        """Get a report of missing dependencies and where they were imported.
        
        Returns:
            Dict mapping module names to list of files that import them
        """
        return dict(self._missing_dependencies)

    def _extract_noop(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions but treat all external dependencies as no-ops."""
        self._telemetry["runtime_exec_attempts"] += 1
        exec_globals = self._create_safe_exec_globals()
        exec_globals["__file__"] = file_path

        # Pre-populate with no-op stubs for any potential missing imports
        missing_imports = self._find_imports(source)
        for module_name in missing_imports:
            # Try to find source first, fall back to no-op stub
            source_file = self._find_module_source(module_name)
            if source_file:
                try:
                    module_source = self._load_source(source_file)
                    module_functions = self._extract_ast_functions(module_source, source_file)
                    module_classes = self._module_cache.get(source_file, {}).get("classes", {})
                    exec_globals[module_name] = self._create_enhanced_stub_module(
                        module_name, module_functions, module_classes
                    )
                    continue
                except Exception:
                    pass
            
            exec_globals[module_name] = self._create_noop_module(module_name)

        try:
            compiled = compile(source, file_path, "exec")
            exec(compiled, exec_globals)
            return self._filter_functions(exec_globals, file_path)
        except Exception as e:
            self._telemetry["runtime_exec_failures"] += 1
            if self.verbose:
                print(f"DEBUG: No-op extraction failed for {file_path}: {e}")
            return {}

    def _extract_ast_only(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions using only AST parsing."""
        return self._extract_ast_functions(source, file_path)

    def _extract_ast_functions(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions and classes using AST parsing with enhanced information."""
        try:
            tree = python_ast.parse(source)
            functions = {}
            classes = {}

            module_name = self._get_module_name_from_path(file_path)
            self._record_import_edges(tree, module_name, file_path)

            # Extract classes first (they may contain methods).
            # By default single-underscore private classes are skipped at the top
            # level (consistent with the original behaviour for functions).
            for node in _iter_toplevel_class_nodes(tree):
                if (not self.include_private) and node.name.startswith("_"):
                    self._telemetry["private_defs_filtered"] += 1
                    continue

                classes[node.name] = self._extract_class_info(node, module_name, file_path)

            # Extract top-level functions; single-underscore private functions
            # are intentionally excluded (they are implementation details).
            for node in _iter_toplevel_function_nodes(tree):
                if (not self.include_private) and node.name.startswith("_"):
                    self._telemetry["private_defs_filtered"] += 1
                    continue

                lineno = int(getattr(node, "lineno", 1) or 1)
                sig = None
                try:
                    sig = _signature_from_ast(node.args)
                except Exception:
                    sig = None

                docstring = _extract_docstring(node)
                decorators = _extract_decorator_names(node)
                is_async = isinstance(node, python_ast.AsyncFunctionDef)

                functions[node.name] = _ASTFunctionProxy(
                    name=node.name,
                    qualname=node.name,
                    module=module_name,
                    filename=file_path,
                    firstlineno=lineno,
                    signature=sig,
                    docstring=docstring,
                    decorators=decorators,
                    is_async=is_async,
                )

            # Store classes for potential use by class hierarchy
            if classes:
                self._module_cache[file_path] = {
                    "functions": functions,
                    "classes": classes,
                }

            return functions
        except Exception as e:
            self._telemetry["ast_extract_failures"] += 1
            if self.verbose:
                print(f"DEBUG: AST extraction failed for {file_path}: {e}")
            return {}

    def _extract_class_info(
        self, node: python_ast.ClassDef, module_name: str, file_path: str
    ) -> Dict[str, Any]:
        """Extract information from a class definition."""
        base_names = []
        for base in node.bases:
            if isinstance(base, python_ast.Name):
                base_names.append(base.id)
            elif isinstance(base, python_ast.Attribute):
                parts = []
                current = base
                while isinstance(current, python_ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, python_ast.Name):
                    parts.append(current.id)
                base_names.append(".".join(reversed(parts)))

        methods = {}
        for item in node.body:
            if isinstance(item, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)):
                lineno = int(getattr(item, "lineno", 1) or 1)
                sig = None
                try:
                    sig = _signature_from_ast(item.args)
                except Exception:
                    sig = None

                docstring = _extract_docstring(item)
                decorators = _extract_decorator_names(item)
                is_async = isinstance(item, python_ast.AsyncFunctionDef)
                is_classmethod = any("classmethod" in d.lower() for d in decorators)
                is_staticmethod = any("staticmethod" in d.lower() for d in decorators)

                methods[item.name] = {
                    "name": item.name,
                    "qualname": f"{node.name}.{item.name}",
                    "signature": sig,
                    "docstring": docstring,
                    "decorators": decorators,
                    "is_async": is_async,
                    "is_classmethod": is_classmethod,
                    "is_staticmethod": is_staticmethod,
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

    def _get_module_name_from_path(self, file_path: str) -> str:
        """Extract a dotted module name from file path.

        The old implementation used basename-only names (e.g. "util"), which
        collapsed modules from different packages into the same namespace.
        """
        import os
        if file_path == "<string>" or file_path.startswith("<"):
            return "__pyflow_module__"
        try:
            abs_path = os.path.realpath(file_path)
            cwd = os.path.realpath(os.getcwd())
            rel = os.path.relpath(abs_path, cwd)
        except ValueError:
            rel = os.path.basename(file_path)

        if rel.endswith(".py"):
            rel = rel[:-3]

        parts = rel.replace(os.sep, ".").split(".")
        parts = [p for p in parts if p and p != ".."]
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]

        if not parts:
            stem = os.path.splitext(os.path.basename(file_path))[0]
            return stem or "__pyflow_module__"
        return ".".join(parts)

    def _resolve_imported_module(
        self, current_module: str, imported_module: str, level: int
    ) -> str:
        """Resolve an import module considering relative import level."""
        if level <= 0:
            return imported_module
        parts = [p for p in current_module.split(".") if p]
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        else:
            parts = parts[:-1]
        ups = max(level - 1, 0)
        if ups >= len(parts):
            base = []
        else:
            base = parts[: len(parts) - ups]
        if imported_module:
            base.extend([p for p in imported_module.split(".") if p])
        return ".".join(base)

    def _record_import_edges(
        self, tree: python_ast.AST, current_module: str, file_path: str
    ) -> None:
        edges = self._import_graph.setdefault(current_module, set())
        for node in python_ast.walk(tree):
            if isinstance(node, python_ast.Import):
                for alias in node.names:
                    target = alias.name
                    if target:
                        edges.add(target)
            elif isinstance(node, python_ast.ImportFrom):
                target = self._resolve_imported_module(
                    current_module,
                    node.module or "",
                    int(getattr(node, "level", 0) or 0),
                )
                if target:
                    edges.add(target)
        self._telemetry["import_edges"] = sum(len(v) for v in self._import_graph.values())

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

        # Ensure module metadata exists and avoid triggering `if __name__ == "__main__":`
        # blocks during execution-based extraction.
        safe_globals.setdefault("__name__", "__pyflow_analysis__")

        # Prevent interactive/blocking behavior during execution-based extraction.
        # Static analysis should never prompt for input.
        safe_globals["input"] = lambda *args, **kwargs: ""

        # Add safe modules
        for module_name in self.safe_modules:
            try:
                safe_globals[module_name] = __import__(module_name)
            except ImportError:
                pass  # Skip unavailable modules

        # Reduce side effects during exec()-based extraction by stubbing the most
        # common "dangerous" primitives used in security benchmarks.
        os_mod = safe_globals.get("os")
        if os_mod is not None:
            try:
                os_mod.system = lambda *args, **kwargs: 0
                os_mod.popen = lambda *args, **kwargs: None
            except Exception:
                pass

        return safe_globals

    def _handle_import_errors(
        self, source: str, exec_globals: Dict[str, Any], file_path: str = "<unknown>"
    ) -> Dict[str, Any]:
        """Handle import errors by creating enhanced stub modules or finding source files."""
        import_info = self._find_imports_detailed(source)
        missing_modules = set(import_info.keys())

        for module_name in missing_modules:
            if module_name not in exec_globals:
                # Try to find source file first
                source_file = self._find_module_source(module_name)
                
                if source_file:
                    if self.verbose:
                        print(f"DEBUG: Found source file for '{module_name}': {source_file}")
                    try:
                        # Try to extract from source file
                        module_source = self._load_source(source_file)
                        module_functions = self._extract_ast_functions(module_source, source_file)
                        module_classes = self._module_cache.get(source_file, {}).get("classes", {})
                        
                        # Create enhanced stub module with actual extracted info
                        exec_globals[module_name] = self._create_enhanced_stub_module(
                            module_name, module_functions, module_classes
                        )
                        
                        # Register classes in hierarchy if available
                        if self.class_hierarchy and module_classes:
                            for cls_name, cls_info in module_classes.items():
                                self.class_hierarchy.register_class(
                                    name=cls_info["name"],
                                    bases=cls_info["bases"],
                                    module=module_name,
                                    methods=set(cls_info["methods"].keys()),
                                    ast_node=None,
                                )
                        continue
                    except Exception as e:
                        if self.verbose:
                            print(f"DEBUG: Failed to extract from {source_file}: {e}")
                
                # Fall back to basic stub
                if self.verbose:
                    print(f"DEBUG: Creating stub for missing module '{module_name}'")
                
                # Track missing dependency
                if module_name not in self._missing_dependencies:
                    self._missing_dependencies[module_name] = []
                self._missing_dependencies[module_name].append(file_path)
                self._telemetry["missing_dependencies"] = sum(
                    len(v) for v in self._missing_dependencies.values()
                )
                
                exec_globals[module_name] = self._create_stub_module(module_name)

        return exec_globals

    def _create_enhanced_stub_module(
        self, module_name: str, functions: Dict[str, Any], classes: Dict[str, Any]
    ) -> Any:
        """Create an enhanced stub module with extracted function and class information."""
        
        class EnhancedStubModule:
            def __init__(self, name, funcs, classes):
                self.__name__ = name
                self.__file__ = f"<stub:{name}>"
                self._functions = funcs
                self._classes = classes
                
                # Make functions directly accessible
                for func_name, func_obj in funcs.items():
                    setattr(self, func_name, func_obj)
                
                # Create class stubs
                for cls_name, cls_info in classes.items():
                    setattr(self, cls_name, self._create_class_stub(cls_name, cls_info))
            
            def _create_class_stub(self, cls_name, cls_info):
                """Create a stub class with methods."""
                methods = cls_info.get("methods", {})
                
                class StubClass:
                    def __init__(self):
                        self.__name__ = cls_name
                        self.__qualname__ = cls_info.get("qualname", cls_name)
                        self.__module__ = self.__name__
                        
                        # Add methods as attributes
                        for method_name, method_info in methods.items():
                            proxy = _ASTFunctionProxy(
                                name=method_info["name"],
                                qualname=method_info["qualname"],
                                module=self.__name__,
                                filename="<stub>",
                                firstlineno=method_info.get("lineno", 1),
                                signature=method_info.get("signature"),
                                docstring=method_info.get("docstring"),
                                decorators=method_info.get("decorators", []),
                                is_async=method_info.get("is_async", False),
                                is_class_method=method_info.get("is_classmethod", False),
                            )
                            setattr(self, method_name, proxy)
                
                StubClass.__name__ = cls_name
                return StubClass
            
            def __getattr__(self, name):
                # Fallback for attributes not explicitly set
                if name in self._functions:
                    return self._functions[name]
                return self._create_noop_function(f"{self.__name__}.{name}")
            
            def _create_noop_function(self, name):
                class NoOpFunction:
                    def __init__(self, name):
                        self.__name__ = name

                    def __call__(self, *args, **kwargs):
                        return None

                return NoOpFunction(name)
        
        return EnhancedStubModule(module_name, functions, classes)

    def _find_imports(self, source: str) -> set:
        """Find all import statements in source code.
        
        Returns:
            Set of module names that are imported
        """
        try:
            tree = python_ast.parse(source)
            imports = set()

            for node in python_ast.walk(tree):
                if isinstance(node, python_ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split(".")[0])
                elif isinstance(node, python_ast.ImportFrom) and node.module:
                    imports.add(node.module.split(".")[0])

            return imports
        except Exception:
            return set()

    def _find_imports_detailed(self, source: str) -> Dict[str, List[Tuple[str, Optional[str]]]]:
        """Find all import statements in source code with detailed information.
        
        Returns:
            Dict mapping module names to list of (imported_name, alias) tuples
        """
        try:
            tree = python_ast.parse(source)
            imports: Dict[str, List[Tuple[str, Optional[str]]]] = {}

            for node in python_ast.walk(tree):
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
                        imports[module_name].append((f"{node.module}.{imported_name}", alias.asname))

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
        import sys

        # First prefer in-memory source map (deterministic and side-effect free).
        source_map = self._build_module_source_map()
        if module_name in source_map:
            self._telemetry["source_map_hits"] += 1
            return source_map[module_name]
        init_name = f"{module_name}.__init__"
        if init_name in source_map:
            self._telemetry["source_map_hits"] += 1
            return source_map[init_name]
        
        # Convert module name to file path components
        parts = module_name.split(".")
        
        # Search in Python path
        search_dirs = list(sys.path) + self.search_paths
        
        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue
            
            # Try as a package
            potential_path = os.path.join(search_dir, *parts)
            py_file = f"{potential_path}.py"
            if os.path.isfile(py_file):
                return py_file
            
            # Try as package with __init__.py
            init_file = os.path.join(potential_path, "__init__.py")
            if os.path.isfile(init_file):
                return init_file
            
            # Try partial match (for nested packages)
            partial_path = search_dir
            for part in parts:
                partial_path = os.path.join(partial_path, part)
                py_file = f"{partial_path}.py"
                if os.path.isfile(py_file):
                    return py_file
                init_file = os.path.join(partial_path, "__init__.py")
                if os.path.isfile(init_file):
                    return init_file
        
        return None

    def _build_module_source_map(self) -> Dict[str, str]:
        mapping: Dict[str, str] = {}
        for filename in self.source_files.keys():
            module = self._get_module_name_from_path(filename)
            mapping[module] = filename
            if module.endswith(".__init__"):
                mapping[module[: -len(".__init__")]] = filename
        return mapping

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

        class StubModule:
            def __init__(self, name):
                self.__name__ = name
                self.__file__ = f"<stub:{name}>"

            def __getattr__(self, name):
                return self._create_noop_function(f"{self.__name__}.{name}")

            def _create_noop_function(self, name):
                class NoOpFunction:
                    def __init__(self, name):
                        self.__name__ = name

                    def __call__(self, *args, **kwargs):
                        if self.__name__ in ("print", "warn", "error"):
                            # Special case for common I/O functions
                            return None
                        return None  # Conservative no-op

                return NoOpFunction(name)

        return StubModule(module_name)

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
