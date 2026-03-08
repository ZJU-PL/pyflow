"""Program extractor for static analysis.

This module provides functionality to extract program information
from Python source code for static analysis purposes.

The Extractor class processes Python source code and builds internal
representations suitable for static analysis, including function and
class extraction, AST processing, and object management.

NOTE: This extractor is intentionally source/AST-based (no bytecode decompilation).
    It is designed to be conservative and side-effect free.
"""

import ast
import inspect
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Set

from pyflow.application.program import Program
from pyflow.application.context import CompilerContext
from pyflow.language.python.program import Object
from pyflow.language.python.program import ImaginaryObject, AbstractObject

from .function_extractor import FunctionExtractor
from .object_manager import ObjectManager
from .stub_manager import StubManager
from .source_locator import best_source_for_callable
from .class_hierarchy import ClassHierarchy, ClassInfo, CrossModuleResolver


def _infer_analysis_root(paths: List[str]) -> Optional[str]:
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


def _base_name_from_expr(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Subscript):
        return _base_name_from_expr(node.value)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    return None


def _is_synthetic_entry_code(code: Any) -> bool:
    annotation = getattr(code, "annotation", None)
    origin = getattr(annotation, "origin", ()) or ()
    for item in origin:
        if isinstance(item, str) and item.startswith("synthetic_module("):
            return True
    return False


def _iter_import_nodes_in_scope(nodes: Iterable[ast.AST]):
    """Yield import statements visible in the current scope.

    Descend through module-scope control-flow statements, but do not cross into
    nested function or class scopes where imports should not leak into the
    module-level namespace.
    """

    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
            continue

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
            yield from _iter_import_nodes_in_scope(getattr(node, "body", ()) or ())
            yield from _iter_import_nodes_in_scope(getattr(node, "orelse", ()) or ())
            continue

        if isinstance(node, ast.Try):
            yield from _iter_import_nodes_in_scope(getattr(node, "body", ()) or ())
            for handler in getattr(node, "handlers", ()) or ():
                yield from _iter_import_nodes_in_scope(getattr(handler, "body", ()) or ())
            yield from _iter_import_nodes_in_scope(getattr(node, "orelse", ()) or ())
            yield from _iter_import_nodes_in_scope(getattr(node, "finalbody", ()) or ())
            continue

        if hasattr(ast, "TryStar") and isinstance(node, ast.TryStar):
            yield from _iter_import_nodes_in_scope(getattr(node, "body", ()) or ())
            for handler in getattr(node, "handlers", ()) or ():
                yield from _iter_import_nodes_in_scope(getattr(handler, "body", ()) or ())
            yield from _iter_import_nodes_in_scope(getattr(node, "orelse", ()) or ())
            yield from _iter_import_nodes_in_scope(getattr(node, "finalbody", ()) or ())
            continue

        if hasattr(ast, "Match") and isinstance(node, ast.Match):
            for case in getattr(node, "cases", ()) or ():
                yield from _iter_import_nodes_in_scope(getattr(case, "body", ()) or ())


def _default_entry_args(callable_obj, existing_wrapper, *, skip_first: bool = False):
    try:
        sig = inspect.signature(callable_obj)
    except (TypeError, ValueError):
        return (), ()

    params = list(sig.parameters.values())
    if skip_first and params:
        params = params[1:]

    args = []
    kwds = []
    for param in params:
        if param.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            args.append(existing_wrapper(None))
        elif param.kind == inspect.Parameter.KEYWORD_ONLY:
            kwds.append((param.name, existing_wrapper(None)))
    return tuple(args), tuple(kwds)


def _should_include_interface_function(func_name: str, args) -> bool:
    if func_name != "main":
        return True
    return getattr(args, "include_main_entry_points", False)


def _get_interface_search_paths(args) -> list[str]:
    search_paths = getattr(args, "search_paths", None)
    if search_paths is not None:
        return list(search_paths)

    import sys

    return list(sys.path)


def _read_interface_source(file_path) -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


class Extractor:
    """Extracts program information from Python code for static analysis.

    The Extractor class is responsible for processing Python source code and
    building internal representations suitable for static analysis. It handles
    function and class extraction, AST processing, and object management.

    Attributes:
        compiler: CompilerContext for compilation state.
        verbose: Whether to output verbose information during extraction.
        source_code: Source code to process (string or dict of filename->source).
        functions: List of extracted functions.
        builtin: Count of builtin functions encountered.
        errors: Count of errors during extraction.
        failures: Count of failures during extraction.
        _source_files: Dictionary tracking source files for error reporting.
        desc: ProgramDescription object for program metadata.
        stub_manager: Manager for handling stub files.
        function_extractor: Extractor for functions and classes.
        object_manager: Manager for object representations.
        stubs: Stub files for backward compatibility.
        class_hierarchy: ClassHierarchy for MRO and cross-module resolution.
        cross_module_resolver: CrossModuleResolver for resolving across modules.
        _module_imports: Cache of imports per module for base class resolution.
    """

    def __init__(
        self,
        compiler: CompilerContext,
        verbose: bool = True,
        source_code: str = None,
        analysis_root: Optional[str] = None,
    ):
        """Initialize the program extractor.

        Args:
            compiler: CompilerContext for compilation state.
            verbose: Whether to output verbose information during extraction.
            source_code: Source code to process. Can be a single string or
                        dict mapping filenames to source code.
        """
        self.compiler = compiler
        self.verbose = verbose
        self.source_code = (
            source_code  # Can be a single string or dict of {filename: source}
        )
        self.analysis_root = (
            os.path.realpath(analysis_root) if analysis_root else None
        )
        if self.analysis_root is None and isinstance(source_code, dict):
            self.analysis_root = _infer_analysis_root(list(source_code.keys()))
        self.functions = []
        self.builtin = 0
        self.errors = 0
        self.failures = 0
        self._source_files = {}  # Track source files for better error reporting
        self._module_imports: Dict[str, Dict[str, str]] = {}  # module -> {name -> qualified}
        self._current_file_path: Optional[str] = None  # Current file being processed

        # Initialize desc attribute (program description)
        from pyflow.language.python.program import ProgramDescription

        self.desc = ProgramDescription()

        # Initialize component managers
        self.stub_manager = StubManager(compiler)
        self.function_extractor = FunctionExtractor(verbose)
        self.object_manager = ObjectManager(
            verbose, self.function_extractor, self.stub_manager
        )

        # Initialize class hierarchy for cross-module analysis
        self.class_hierarchy = ClassHierarchy(verbose=verbose)
        self.cross_module_resolver = CrossModuleResolver(
            self.class_hierarchy, verbose=verbose
        )

        # Expose stubs for backward compatibility
        self.stubs = self.stub_manager.stubs

    def extract_from_source(
        self, source: str, filename: str = "<string>", *, reset_telemetry: bool = True
    ) -> Program:
        """Extract program information from Python source code.

        Args:
            source: Python source code as a string.
            filename: Name of the source file (for error reporting).

        Returns:
            Program: Program object containing extracted information.
        """
        try:
            if reset_telemetry:
                self.function_extractor.ast_converter.reset_telemetry()
            self._current_file_path = filename  # Store for relative import resolution
            tree = ast.parse(source, filename)
            return self._extract_from_ast(tree, filename)
        except SyntaxError as e:
            if self.verbose:
                print(f"Syntax error in {filename}: {e}")
            self.errors += 1
            return Program()

    def extract_from_file(self, filename: str) -> Program:
        """Extract program information from a Python file.

        Args:
            filename: Path to the Python file to process.

        Returns:
            Program: Program object containing extracted information.
        """
        try:
            with open(filename, "r", encoding="utf-8") as f:
                source = f.read()
            return self.extract_from_source(source, filename)
        except FileNotFoundError:
            if self.verbose:
                print(f"File not found: {filename}")
            self.errors += 1
            return Program()
        except Exception as e:
            if self.verbose:
                print(f"Error reading {filename}: {e}")
            self.errors += 1
            return Program()

    def extract_from_multiple_files(self, source_files: dict) -> Program:
        """Extract program information from multiple Python files."""
        combined_program = Program()
        self._source_files = source_files
        self.function_extractor.ast_converter.reset_telemetry()

        for filename, source in source_files.items():
            if self.verbose:
                print(f"Processing file: {filename}")

            try:
                file_program = self.extract_from_source(
                    source, filename, reset_telemetry=False
                )
                # Add extracted functions to combined program
                if hasattr(file_program, "liveCode") and file_program.liveCode:
                    if (
                        not hasattr(combined_program, "liveCode")
                        or combined_program.liveCode is None
                    ):
                        combined_program.liveCode = set()
                    combined_program.liveCode.update(file_program.liveCode)
            except Exception as e:
                if self.verbose:
                    print(f"Error processing {filename}: {e}")
                self.errors += 1

        combined_program.frontend_telemetry = (
            self.function_extractor.ast_converter.get_telemetry()
        )
        combined_program.class_hierarchy = self.class_hierarchy
        combined_program.cross_module_resolver = self.cross_module_resolver
        return combined_program

    def _extract_from_ast(self, tree: ast.AST, filename: str) -> Program:
        """Extract program information from an AST."""
        program = Program()

        if self.verbose:
            print(f"DEBUG: Extracting from AST for {filename}")

        module_name = self._get_module_name(filename)
        self._current_file_path = filename  # Store for relative import resolution
        
        self._extract_imports(tree, module_name)
        self.function_extractor.extract_module_body(
            getattr(tree, "body", []) or [],
            program,
            module_name=module_name,
            filename=filename,
        )

        class_definitions = []
        for node in getattr(tree, "body", []) or []:
            if isinstance(node, ast.ClassDef):
                class_definitions.append(node)

        # Register classes in hierarchy first (needed for base class resolution)
        for node in class_definitions:
            self._register_class_in_hierarchy(node, module_name)

        # Extract functions and classes
        for node in getattr(tree, "body", []) or []:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self.verbose:
                    print(f"DEBUG: Found function definition: {node.name}")
                self.function_extractor.extract_function(node, program, filename)
            elif isinstance(node, ast.ClassDef):
                if self.verbose:
                    print(f"DEBUG: Found class definition: {node.name}")
                self.function_extractor.extract_class(
                    node,
                    program,
                    filename,
                    module_name=module_name,
                    qualname=node.name,
                )

        # Register module with cross-module resolver
        if self.cross_module_resolver:
            self.cross_module_resolver.register_module(
                module_name=module_name,
                classes={
                    cls_info.name: cls_info
                    for cls_info in self.class_hierarchy.classes.values()
                    if cls_info.module == module_name
                },
                imports=self._module_imports.get(module_name, {}),
            )

        program.class_hierarchy = self.class_hierarchy
        program.cross_module_resolver = self.cross_module_resolver
        program.frontend_telemetry = self.function_extractor.ast_converter.get_telemetry()

        if self.verbose:
            print(
                f"DEBUG: Extraction complete, liveCode has {len(program.liveCode)} functions"
            )
            print(
                f"DEBUG: Class hierarchy has {len(self.class_hierarchy.classes)} classes"
            )

        return program

    def _get_module_name(self, filename: str) -> str:
        """Convert a filename to a qualified module name.

        Uses the path relative to the current working directory so that two
        files with the same basename in different packages produce distinct
        module names (e.g. ``pkg.utils`` vs ``other.utils`` instead of both
        being ``utils``). Package ``__init__.py`` files are canonicalized to
        their package name so imports like ``from pkg import Base`` resolve to
        the same namespace that class registration uses.
        """
        if filename in ("<string>", "") or filename.startswith("<"):
            return "__main__"
        if not os.path.isabs(filename):
            rel = filename
        else:
            try:
                abs_path = os.path.realpath(filename)
                root = self.analysis_root or _infer_analysis_root([filename])
                if root is None:
                    root = os.path.dirname(abs_path)
                rel = os.path.relpath(abs_path, root)
            except ValueError:
                # On Windows, relpath can fail across drives.
                rel = os.path.basename(filename)
        # Strip .py extension
        if rel.endswith(".py"):
            rel = rel[:-3]
        # Convert path separators to dots; drop leading ".." components that
        # can't be represented as a valid dotted name.
        parts = rel.replace(os.sep, ".").split(".")
        parts = [p for p in parts if p and p != ".."]
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts:
            # Absolute path fallback: just use the stem of the filename.
            stem = os.path.splitext(os.path.basename(filename))[0]
            return stem or "__main__"
        return ".".join(parts)

    def _extract_imports(self, tree: ast.AST, module_name: str) -> None:
        """Extract import statements and build import mapping for the module.

        Handles:
        - Regular absolute imports
        - ``from module import name`` (including aliases)
        - ``from module import *`` — recorded as a sentinel entry so that
          downstream analyses know the entire namespace of *module* is visible
          in this scope
        - Relative imports (``from . import ...``)
        """
        imports: Dict[str, str] = {}

        # Sentinel key used to record star imports in the imports dict.
        # Value is a list of the star-imported module names.
        STAR_KEY = "<star_imports>"

        for node in _iter_import_nodes_in_scope(getattr(tree, "body", ()) or ()):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name.split(".")[-1]
                    imports[local_name] = alias.name

            elif isinstance(node, ast.ImportFrom):
                source_module = node.module or ""
                level = node.level or 0

                # Resolve relative imports against the current module.
                effective_module = self._resolve_import_from_module(
                    module_name, source_module, int(level)
                )

                for alias in node.names:
                    if alias.name == "*":
                        # Record the star import so cross-module resolvers can
                        # widen this scope with all exported names from the module.
                        star_list = imports.setdefault(STAR_KEY, [])
                        star_list.append(effective_module)
                        for exported in self._expand_star_import_names(effective_module):
                            imports.setdefault(exported, f"{effective_module}.{exported}")
                        continue
                    local_name = alias.asname or alias.name
                    if effective_module:
                        qualified = f"{effective_module}.{alias.name}"
                    else:
                        qualified = alias.name
                    imports[local_name] = qualified

        self._module_imports[module_name] = imports

        # Register imports with cross-module resolver
        if self.cross_module_resolver:
            self.cross_module_resolver.imports[module_name] = imports

    def _resolve_import_from_module(
        self, current_module: str, source_module: str, level: int
    ) -> str:
        """Resolve ``from ... import ...`` source to a dotted module name."""
        if level <= 0:
            return source_module

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

        if source_module:
            base.extend([p for p in source_module.split(".") if p])
        return ".".join(base)

    def _expand_star_import_names(self, module_name: str) -> List[str]:
        """Expand ``from module import *`` names when source is available."""
        source_map = self._build_module_source_map()
        module_source = source_map.get(module_name)
        if module_source is None:
            init_name = f"{module_name}.__init__"
            module_source = source_map.get(init_name)
        if module_source is None:
            return []

        try:
            tree = ast.parse(module_source)
        except SyntaxError:
            return []

        explicit_all: Optional[List[str]] = None
        discovered: Set[str] = set()

        for node in getattr(tree, "body", []) or []:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not node.name.startswith("_"):
                    discovered.add(node.name)
                continue

            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if target.id == "__all__":
                            explicit_all = self._extract_literal_string_list(node.value)
                        elif not target.id.startswith("_"):
                            discovered.add(target.id)
                continue

            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[-1]
                    if not local.startswith("_"):
                        discovered.add(local)
                continue

            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    if not local.startswith("_"):
                        discovered.add(local)

        if explicit_all is not None:
            return [name for name in explicit_all if isinstance(name, str)]
        return sorted(discovered)

    def _extract_literal_string_list(self, node: ast.AST) -> Optional[List[str]]:
        """Extract a static list/tuple/set of string values."""
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            out: List[str] = []
            for elt in node.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    out.append(elt.value)
                else:
                    return None
            return out
        return None

    def _build_module_source_map(self) -> Dict[str, str]:
        """Build module-name -> source mapping from in-memory source_code dict."""
        if not isinstance(self.source_code, dict):
            return {}

        mapping: Dict[str, str] = {}
        for filename, source in self.source_code.items():
            module = self._get_module_name(filename)
            mapping[module] = source
            if module.endswith(".__init__"):
                mapping[module[: -len(".__init__")]] = source
        return mapping

    def _register_class_in_hierarchy(self, node: ast.ClassDef, module_name: str) -> None:
        """Register a class in the class hierarchy with enhanced MRO support."""
        class_name = node.name
        qualified_name = f"{module_name}.{class_name}"
        
        base_names = []
        for base in node.bases:
            base_name = _base_name_from_expr(base)
            if base_name:
                base_names.append(base_name)
        
        methods: Set[str] = set()
        attributes: Set[str] = set()
        
        # Extract more detailed information
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.add(item.name)
            elif isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        attributes.add(target.id)
                    elif isinstance(target, ast.Attribute):
                        # Handle class attributes like cls.attr
                        if isinstance(target.value, ast.Name) and target.value.id == class_name:
                            attributes.add(target.attr)
        
        imported_names = self._module_imports.get(module_name, {})
        
        # Enhanced base class resolution with better error reporting
        resolved_bases = []
        unresolved_bases = []
        for base_name in base_names:
            resolved = self.class_hierarchy.resolve_base_class(
                base_name, module_name, imported_names
            )
            if resolved:
                resolved_bases.append(resolved)
            else:
                unresolved_bases.append(base_name)
                if self.verbose:
                    print(
                        f"WARNING: Could not resolve base class '{base_name}' "
                        f"for class '{qualified_name}'"
                    )
        
        self.class_hierarchy.register_class(
            name=class_name,
            bases=base_names,
            module=module_name,
            methods=methods,
            attributes=attributes,
            ast_node=node,
        )
        
        cls_info = self.class_hierarchy.get_class_info(qualified_name)
        if cls_info:
            cls_info.resolved_bases = resolved_bases
            # Store unresolved bases for potential later resolution
            if unresolved_bases:
                cls_info.bases = base_names  # Keep original names for retry

    def getObject(self, obj: Any) -> Object:
        """Get or create an object representation for static analysis."""
        return self.object_manager.get_object(obj)

    def getObjectCall(self, func: Any) -> tuple:
        """Get object call information for a function."""
        # Provide source_code mapping so downstream conversion can resolve bodies
        return self.object_manager.get_object_call(func, self.source_code)

    def makeImaginary(
        self, name: str, t: AbstractObject, preexisting: bool
    ) -> ImaginaryObject:
        return self.object_manager.make_imaginary(name, t, preexisting)

    def ensureLoaded(self, obj: AbstractObject) -> None:
        """Ensure an abstract object is loaded. Initialize typeinfo for type objects."""
        return self.object_manager.ensure_loaded(obj)

    def getCall(self, obj):
        """Get call information for an object."""
        # Bug #20 fix: the original code had unconditional print() calls here
        # (not guarded by self.verbose) that would pollute stdout during every
        # analysis run.  The debug information is now only emitted when
        # self.verbose is True, consistent with the rest of the class.
        if self.verbose:
            print(
                f"DEBUG: getCall called for {obj}, source_code type: {type(self.source_code)}"
            )
            if isinstance(self.source_code, dict):
                print(f"DEBUG: source_code keys: {list(self.source_code.keys())}")
        return self.object_manager.get_call(obj, self.source_code)

    def getInstance(self, typeobj: type) -> Any:
        """Get an abstract instance object for a given type.

        Args:
            typeobj: A Python type object (e.g., int, str, MyClass)

        Returns:
            AbstractObject: The abstract instance representing instances of the type
        """
        return self.object_manager.get_instance(typeobj)

    def resolve_method(self, class_name: str, method_name: str) -> Optional[str]:
        """Resolve a method through the class hierarchy using MRO.

        Args:
            class_name: The qualified or simple class name
            method_name: The method name to resolve

        Returns:
            The qualified name of the class that defines the method, or None
        """
        qualified_name = self._resolve_class_name(class_name)
        if qualified_name:
            return self.class_hierarchy.resolve_method(qualified_name, method_name)
        return None

    def resolve_attribute(self, class_name: str, attr_name: str) -> Optional[str]:
        """Resolve an attribute through the class hierarchy using MRO.

        Args:
            class_name: The qualified or simple class name
            attr_name: The attribute name to resolve

        Returns:
            The qualified name of the class that defines the attribute, or None
        """
        qualified_name = self._resolve_class_name(class_name)
        if qualified_name:
            return self.class_hierarchy.resolve_attribute(qualified_name, attr_name)
        return None

    def get_mro(self, class_name: str) -> List[str]:
        """Get the Method Resolution Order for a class.

        Args:
            class_name: The qualified or simple class name

        Returns:
            List of qualified class names in MRO order
        """
        qualified_name = self._resolve_class_name(class_name)
        if qualified_name:
            return self.class_hierarchy.get_mro(qualified_name)
        return []

    def get_all_subclasses(self, class_name: str) -> Set[str]:
        """Get all subclasses of a class.

        Args:
            class_name: The qualified or simple class name

        Returns:
            Set of qualified names of all subclasses
        """
        qualified_name = self._resolve_class_name(class_name)
        if qualified_name:
            return self.class_hierarchy.get_all_subclasses(qualified_name)
        return set()

    def _resolve_class_name(self, class_name: str) -> Optional[str]:
        """Resolve a class name to its qualified name.

        When the same simple name is defined in multiple modules the old
        implementation returned whichever module happened to come first in
        the dict iteration order (non-deterministic in Python < 3.7, and
        still arbitrary in 3.7+ when multiple modules define the same name).

        The new implementation:
        1. Returns immediately if the name is already fully qualified.
        2. Collects *all* matches and returns the unique one if there is
           exactly one, or None (with a warning) if there are multiple
           candidates so that callers can handle the ambiguity explicitly.
        """
        if class_name in self.class_hierarchy.classes:
            return class_name

        matches = []
        for module_name, name_map in sorted(self.class_hierarchy.name_to_qualified.items()):
            if class_name in name_map:
                matches.append(name_map[class_name])

        if len(matches) == 1:
            return matches[0]
        elif len(matches) > 1:
            # Ambiguous: the same simple name exists in multiple modules.
            # Prefer the non-builtin match if there is exactly one such match.
            non_builtin = [m for m in matches if not m.startswith("builtins.")]
            if len(non_builtin) == 1:
                return non_builtin[0]
            # Truly ambiguous — return None so callers can handle it.
            return None

        return None

    def convertFunction(
        self,
        func: Any,
        trace: bool = False,
        ssa: bool = True,
        descriptive: bool = False,
    ) -> Any:
        """Convert a Python function to PyFlow AST for static analysis."""
        # Get source code from the extractor's source_code first
        source = None
        if hasattr(self, "source_code") and self.source_code:
            if isinstance(self.source_code, dict):
                source = best_source_for_callable(func, self.source_code)
                if source is None:
                    # Fallback: search for function name in source files.
                    # Use a more sophisticated approach to avoid false matches.
                    for filename, file_source in self.source_code.items():
                        pattern = rf"\bdef\s+{re.escape(func.__name__)}\s*\("
                        if re.search(pattern, file_source):
                            source = file_source
                            break
            else:
                # Single source file
                source = self.source_code

        return self.function_extractor.convert_function(
            func, source_code=source, trace=trace, ssa=ssa, descriptive=descriptive
        )


def extractProgram(compiler: CompilerContext, program: Program) -> None:
    """
    Extract program information for static analysis.

    This extractor focuses on static analysis from source/AST (no decompilation).
    """
    if not hasattr(compiler, "extractor") or compiler.extractor is None:
        compiler.extractor = Extractor(compiler)

    # If we have multiple source files, extract from all of them
    if hasattr(compiler.extractor, "source_code") and isinstance(
        compiler.extractor.source_code, dict
    ):
        if compiler.console:
            compiler.console.output(
                f"Extracting from {len(compiler.extractor.source_code)} source files"
            )

        # Extract from multiple files
        extracted_program = compiler.extractor.extract_from_multiple_files(
            compiler.extractor.source_code
        )
        program.class_hierarchy = extracted_program.class_hierarchy
        program.cross_module_resolver = extracted_program.cross_module_resolver
        program.frontend_telemetry = extracted_program.frontend_telemetry

        # Add extracted functions to program's liveCode
        if hasattr(extracted_program, "liveCode") and extracted_program.liveCode:
            if not hasattr(program, "liveCode") or program.liveCode is None:
                program.liveCode = set()
            program.liveCode.update(extracted_program.liveCode)
            # Bug #20 fix: these were unconditional print() calls (not guarded
            # by self.verbose / compiler.console) that polluted stdout on every
            # analysis run.  Route through the compiler console instead.
            if compiler.console:
                compiler.console.output(
                    f"Added {len(extracted_program.liveCode)} functions to program.liveCode"
                )
        else:
            if compiler.console:
                compiler.console.output("No liveCode found in extracted_program")
    else:
        source = getattr(compiler.extractor, "source_code", None)
        if isinstance(source, str):
            extracted_program = compiler.extractor.extract_from_source(source)
            program.class_hierarchy = extracted_program.class_hierarchy
            program.cross_module_resolver = extracted_program.cross_module_resolver
            program.frontend_telemetry = extracted_program.frontend_telemetry
            if extracted_program.liveCode:
                program.liveCode.update(extracted_program.liveCode)
        if compiler.console:
            compiler.console.output("Program extraction complete")

    # Process the interface declarations (functions and classes)
    if hasattr(program, "interface") and program.interface is not None:
        if not program.interface.translated:
            program.interface.translate(compiler.extractor)

        from pyflow.api.entrypoints import nullWrapper

        existing_codes = set(program.interface.entryCode())
        synthetic_codes = sorted(
            (
                code
                for code in getattr(program, "liveCode", ()) or ()
                if _is_synthetic_entry_code(code)
            ),
            key=lambda code: code.codeName(),
        )
        for code in synthetic_codes:
            if code in existing_codes:
                continue
            program.interface.createEntryPoint(
                code,
                nullWrapper,
                (),
                [],
                nullWrapper,
                nullWrapper,
                None,
            )
            existing_codes.add(code)

        # Set entry points from the interface
        program.entryPoints = program.interface.entryPoint


def create_interface_from_paths(python_files, args):
    """Create a basic interface from multiple Python files using enhanced dependency resolver."""
    from pyflow.api.entrypoints import (
        ClassDeclaration,
        ExistingWrapper,
        InterfaceDeclaration,
    )
    from pyflow.frontend.dependency_resolver import DependencyResolver
    from pyflow.frontend.class_hierarchy import ClassHierarchy

    def add_function_entries(interface_decl, functions, file_path):
        for func_name, func_obj in functions.items():
            if not _should_include_interface_function(func_name, args):
                if args.verbose:
                    print(f"DEBUG: Skipping '{func_name}' as an entry point")
                continue

            func_args, func_kwds = _default_entry_args(func_obj, ExistingWrapper)
            interface_decl.func.append((func_obj, func_args, func_kwds))
            if args.verbose:
                print(f"Added function '{func_name}' from {file_path}")

    def add_class_entries(interface_decl, classes, resolver, file_path):
        for cls_name, cls_obj in classes.items():
            class_decl = ClassDeclaration(cls_obj)
            init_args, init_kwds = _default_entry_args(
                cls_obj.__init__, ExistingWrapper, skip_first=True
            )
            class_decl.init(*init_args, kwds=init_kwds)
            interface_decl.cls.append(class_decl)

            for method_name, method_info in resolver.get_public_method_specs(cls_obj).items():
                if method_name.startswith("_"):
                    continue
                if method_info.get("is_property", False):
                    class_decl.attr(method_name)
                    continue
                skip_first = not method_info.get("is_staticmethod", False)
                method_obj = getattr(cls_obj, method_name)
                if method_info.get("is_classmethod", False):
                    method_obj = getattr(method_obj, "__func__", method_obj)
                method_args, method_kwds = _default_entry_args(
                    method_obj, ExistingWrapper, skip_first=skip_first
                )
                class_decl.method(
                    method_name,
                    *method_args,
                    kind=(
                        "staticmethod"
                        if method_info.get("is_staticmethod", False)
                        else "classmethod"
                        if method_info.get("is_classmethod", False)
                        else "instance"
                    ),
                    kwds=method_kwds,
                )

            if args.verbose:
                print(f"Added class '{cls_name}' from {file_path}")

    def process_file(file_path, resolver, all_source_code, interface_decl):
        source = _read_interface_source(file_path)
        all_source_code[str(file_path)] = source
        resolver.source_files[str(file_path)] = source

        functions = resolver.extract_functions(source, str(file_path))
        classes = resolver.get_module_classes(str(file_path))
        add_function_entries(interface_decl, functions, file_path)
        add_class_entries(interface_decl, classes, resolver, file_path)

        if args.verbose:
            print(
                f"Found {len(functions)} functions and {len(classes)} classes in {file_path}"
            )

    def report_resolver_state(resolver):
        if not args.verbose:
            return

        missing = resolver.get_missing_dependencies()
        if missing:
            print("\nMissing dependencies report:")
            for module, importing_files in missing.items():
                print(f"  {module}: imported by {len(importing_files)} file(s)")

        telemetry = resolver.get_telemetry()
        if telemetry:
            print("\nDependency resolver telemetry:")
            for key in sorted(telemetry):
                print(f"  {key}: {telemetry[key]}")

    interface_decl = InterfaceDeclaration()
    all_source_code = {}
    analysis_root = _infer_analysis_root([str(path) for path in python_files])

    # Create shared class hierarchy for cross-module analysis
    class_hierarchy = ClassHierarchy(verbose=getattr(args, "verbose", False))

    resolver = DependencyResolver(
        strategy=getattr(args, "dependency_strategy", "auto"),
        verbose=getattr(args, "verbose", False),
        safe_modules=["math", "os", "sys", "re", "json", "datetime", "collections"],
        search_paths=_get_interface_search_paths(args),
        class_hierarchy=class_hierarchy,
        source_files=all_source_code,
        analysis_root=analysis_root,
    )

    for file_path in python_files:
        try:
            process_file(file_path, resolver, all_source_code, interface_decl)
        except Exception as e:
            if args.verbose:
                print(f"Warning: Could not parse file {file_path}: {e}")

    report_resolver_state(resolver)

    return interface_decl, all_source_code
