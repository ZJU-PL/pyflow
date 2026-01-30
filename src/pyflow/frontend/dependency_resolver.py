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
    - AUTO: Try runtime execution first, fallback to AST parsing if imports fail
    - STUBS: Create stub modules for missing dependencies, attempt runtime execution
    - NOOP: Pre-create no-op stubs for all potential missing imports
    - STRICT: Fail immediately if any dependencies can't be resolved
    - AST_ONLY: Only use AST parsing, never attempt runtime execution (extracts function signatures and structure only)

This approach follows established patterns in static analysis literature for
handling the "missing dependencies" problem in a principled manner.
"""

import ast as python_ast
import builtins
from typing import Dict, List, Any, Optional, Callable
from enum import Enum


class DependencyStrategy(Enum):
    """Available strategies for handling import dependencies."""

    AUTO = "auto"  # Try runtime execution, fallback to AST parsing
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
    ):
        """
        Initialize the dependency resolver.

        Args:
            strategy: Resolution strategy to use
            verbose: Whether to output detailed information
            safe_modules: List of modules to include in safe execution environment
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

        # Cache for resolved modules to avoid repeated work
        self._module_cache: Dict[str, Dict[str, Any]] = {}

    def extract_functions(self, source: str, file_path: str) -> Dict[str, Any]:
        """
        Extract functions from source code using the configured strategy.

        Args:
            source: Python source code
            file_path: Path to the source file

        Returns:
            Dictionary mapping function names to function objects
        """
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
        exec_globals = self._create_safe_exec_globals()

        try:
            exec(source, exec_globals)
            return self._filter_functions(exec_globals, file_path)
        except Exception as e:
            if self.verbose:
                print(f"ERROR: Runtime extraction failed for {file_path}: {e}")
            return {}

    def _extract_with_stubs(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions using runtime execution with stub modules."""
        exec_globals = self._create_safe_exec_globals()

        # Try normal execution first
        try:
            exec(source, exec_globals)
            functions = self._filter_functions(exec_globals, file_path)
            if functions:
                return functions
        except ImportError as e:
            if self.verbose:
                print(f"DEBUG: Import error in {file_path}: {e}")

            # Create stubs for missing imports
            exec_globals_with_stubs = self._handle_import_errors(source, exec_globals)
            try:
                exec(source, exec_globals_with_stubs)
                functions = self._filter_functions(exec_globals_with_stubs, file_path)
                if functions:
                    return functions
            except Exception as stub_e:
                if self.verbose:
                    print(f"DEBUG: Even with stubs, execution failed: {stub_e}")

        # If runtime execution failed, fall back to AST extraction for local functions
        if self.verbose:
            print(
                f"DEBUG: Runtime execution failed for {file_path}, falling back to AST extraction"
            )
        return self._extract_ast_functions(source, file_path)

    def _extract_noop(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions but treat all external dependencies as no-ops."""
        exec_globals = self._create_safe_exec_globals()

        # Pre-populate with no-op stubs for any potential missing imports
        missing_imports = self._find_imports(source)
        for module_name in missing_imports:
            exec_globals[module_name] = self._create_noop_module(module_name)

        try:
            exec(source, exec_globals)
            return self._filter_functions(exec_globals, file_path)
        except Exception as e:
            if self.verbose:
                print(f"DEBUG: No-op extraction failed for {file_path}: {e}")
            return {}

    def _extract_ast_only(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions using only AST parsing."""
        return self._extract_ast_functions(source, file_path)

    def _extract_ast_functions(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions using AST parsing."""
        try:
            tree = python_ast.parse(source)
            functions = {}

            for node in python_ast.walk(tree):
                if isinstance(
                    node, python_ast.FunctionDef
                ) and not node.name.startswith("_"):
                    stub_func = self._create_ast_stub(node)
                    functions[node.name] = stub_func

            return functions
        except Exception as e:
            if self.verbose:
                print(f"DEBUG: AST extraction failed for {file_path}: {e}")
            return {}

    def _extract_auto(self, source: str, file_path: str) -> Dict[str, Any]:
        """Auto strategy: try runtime first, fallback to AST."""
        # Try runtime extraction with stubs first
        result = self._extract_with_stubs(source, file_path)
        if result:
            return result

        # Fallback to AST parsing
        if self.verbose:
            print(f"DEBUG: Falling back to AST parsing for {file_path}")
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
        self, source: str, exec_globals: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle import errors by creating stub modules."""
        missing_imports = self._find_imports(source)

        for module_name in missing_imports:
            if module_name not in exec_globals:
                if self.verbose:
                    print(f"DEBUG: Creating stub for missing module '{module_name}'")
                exec_globals[module_name] = self._create_stub_module(module_name)

        return exec_globals

    def _find_imports(self, source: str) -> set:
        """Find all import statements in source code."""
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

    def _create_ast_stub(self, func_node: python_ast.FunctionDef) -> Any:
        """Create a stub function from AST node."""

        class ASTStubFunction:
            def __init__(self, name, args_info=None):
                self.__name__ = name
                self._args_info = args_info or []

            def __call__(self, *args, **kwargs):
                # Note: verbose logging not available in stub context
                return None

        # Extract argument information
        args_info = []
        if hasattr(func_node, "args") and hasattr(func_node.args, "args"):
            for arg in func_node.args.args:
                args_info.append(arg.arg)

        return ASTStubFunction(func_node.name, args_info)

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
