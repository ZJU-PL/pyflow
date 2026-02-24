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
import re
from typing import Any, Dict, List, Optional, Set

from pyflow.application.program import Program
from pyflow.application.context import CompilerContext
from pyflow.language.python.program import Object
from pyflow.language.python.program import ImaginaryObject, AbstractObject

from .function_extractor import FunctionExtractor
from .object_manager import ObjectManager
from .stub_manager import StubManager
from .source_locator import best_source_for_callable
from .class_hierarchy import ClassHierarchy, ClassInfo, CrossModuleResolver


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
        self, compiler: CompilerContext, verbose: bool = True, source_code: str = None
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

    def extract_from_source(self, source: str, filename: str = "<string>") -> Program:
        """Extract program information from Python source code.

        Args:
            source: Python source code as a string.
            filename: Name of the source file (for error reporting).

        Returns:
            Program: Program object containing extracted information.
        """
        try:
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

        for filename, source in source_files.items():
            if self.verbose:
                print(f"Processing file: {filename}")

            try:
                file_program = self.extract_from_source(source, filename)
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

        return combined_program

    def _extract_from_ast(self, tree: ast.AST, filename: str) -> Program:
        """Extract program information from an AST."""
        program = Program()

        if self.verbose:
            print(f"DEBUG: Extracting from AST for {filename}")

        module_name = self._get_module_name(filename)
        self._current_file_path = filename  # Store for relative import resolution
        
        self._extract_imports(tree, module_name)

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
                self.function_extractor.extract_class(node, program, filename)

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
        being ``utils``).
        """
        import os
        if filename in ("<string>", "") or filename.startswith("<"):
            return "__main__"
        try:
            abs_path = os.path.realpath(filename)
            cwd = os.path.realpath(os.getcwd())
            rel = os.path.relpath(abs_path, cwd)
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

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name.split(".")[-1]
                    imports[local_name] = alias.name

            elif isinstance(node, ast.ImportFrom):
                source_module = node.module or ""
                level = node.level or 0

                # Build the effective module prefix for relative imports.
                if level > 0:
                    # Approximate: mark relative prefix so callers can detect it.
                    rel_prefix = "." * level + (source_module or "")
                    effective_module = f"<relative:{rel_prefix}>"
                else:
                    effective_module = source_module

                for alias in node.names:
                    if alias.name == "*":
                        # Record the star import so cross-module resolvers can
                        # widen this scope with all exported names from the module.
                        star_list = imports.setdefault(STAR_KEY, [])
                        star_list.append(effective_module)
                        continue
                    local_name = alias.asname or alias.name
                    if source_module:
                        qualified = f"{source_module}.{alias.name}"
                    else:
                        qualified = alias.name
                    imports[local_name] = qualified

        self._module_imports[module_name] = imports

        # Register imports with cross-module resolver
        if self.cross_module_resolver:
            self.cross_module_resolver.imports[module_name] = imports

    def _register_class_in_hierarchy(self, node: ast.ClassDef, module_name: str) -> None:
        """Register a class in the class hierarchy with enhanced MRO support."""
        class_name = node.name
        qualified_name = f"{module_name}.{class_name}"
        
        base_names = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                base_names.append(base.id)
            elif isinstance(base, ast.Attribute):
                parts = []
                current = base
                while isinstance(current, ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    parts.append(current.id)
                base_names.append(".".join(reversed(parts)))
        
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
        # Single file extraction (existing behavior)
        if compiler.console:
            compiler.console.output("Program extraction complete")

    # Process the interface declarations (functions and classes)
    if hasattr(program, "interface") and program.interface:
        if not program.interface.translated:
            program.interface.translate(compiler.extractor)
            # Set entry points from the interface
            program.entryPoints = program.interface.entryPoint


def create_interface_from_paths(python_files, args):
    """Create a basic interface from multiple Python files using enhanced dependency resolver."""
    from pyflow.api.entrypoints import InterfaceDeclaration
    from pyflow.frontend.dependency_resolver import DependencyResolver
    from pyflow.frontend.class_hierarchy import ClassHierarchy

    interface_decl = InterfaceDeclaration()
    all_source_code = {}

    # Create shared class hierarchy for cross-module analysis
    class_hierarchy = ClassHierarchy(verbose=getattr(args, "verbose", False))
    
    # Get search paths from args if available
    search_paths = getattr(args, "search_paths", None)
    if search_paths is None:
        import sys
        search_paths = list(sys.path)

    resolver = DependencyResolver(
        strategy=getattr(args, "dependency_strategy", "auto"),
        verbose=getattr(args, "verbose", False),
        safe_modules=["math", "os", "sys", "re", "json", "datetime", "collections"],
        search_paths=search_paths,
        class_hierarchy=class_hierarchy,
    )

    for file_path in python_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
            all_source_code[str(file_path)] = source

            functions = resolver.extract_functions(source, str(file_path))

            for func_name, func_obj in functions.items():
                # Skip driver/main function from being treated as analysis entry point
                if func_name == "main":
                    if args.verbose:
                        print(f"DEBUG: Skipping '{func_name}' as an entry point")
                    continue

                interface_decl.func.append((func_obj, []))
                if args.verbose:
                    print(f"Added function '{func_name}' from {file_path}")

            if args.verbose:
                print(
                    f"Found {len(functions)} callable objects in {file_path}: {list(functions.keys())}"
                )

        except Exception as e:
            if args.verbose:
                print(f"Warning: Could not parse file {file_path}: {e}")

    # Report missing dependencies if verbose
    if args.verbose:
        missing = resolver.get_missing_dependencies()
        if missing:
            print("\nMissing dependencies report:")
            for module, importing_files in missing.items():
                print(f"  {module}: imported by {len(importing_files)} file(s)")

    return interface_decl, all_source_code
