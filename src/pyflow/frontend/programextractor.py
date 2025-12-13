"""Program extractor for static analysis.

This module provides functionality to extract program information
from Python source code for static analysis purposes.

The Extractor class processes Python source code and builds internal
representations suitable for static analysis, including function and
class extraction, AST processing, and object management.

FIXME: very likely to be buggy (Maybe we need to repalce it with
the dir in src/pyflow/decompile)
"""

import ast
import re
from typing import Any, Dict, List, Optional

from pyflow.application.program import Program
from pyflow.application.context import CompilerContext
from pyflow.language.python.program import Object
from pyflow.language.python.program import ImaginaryObject, AbstractObject

from .function_extractor import FunctionExtractor
from .object_manager import ObjectManager
from .stub_manager import StubManager


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

        # Initialize desc attribute (program description)
        from pyflow.language.python.program import ProgramDescription

        self.desc = ProgramDescription()

        # Initialize component managers
        self.stub_manager = StubManager(compiler)
        self.function_extractor = FunctionExtractor(verbose)
        self.object_manager = ObjectManager(
            verbose, self.function_extractor, self.stub_manager
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
                if hasattr(file_program, 'liveCode') and file_program.liveCode:
                    if not hasattr(combined_program, 'liveCode') or combined_program.liveCode is None:
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

        # Walk through the AST to find functions and classes
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if self.verbose:
                    print(f"DEBUG: Found function definition: {node.name}")
                self.function_extractor.extract_function(node, program)
            elif isinstance(node, ast.ClassDef):
                if self.verbose:
                    print(f"DEBUG: Found class definition: {node.name}")
                self.function_extractor.extract_class(node, program)

        if self.verbose:
            print(f"DEBUG: Extraction complete, liveCode has {len(program.liveCode)} functions")

        return program


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
        if self.verbose:
            print(f"DEBUG: getCall called for {obj}, source_code type: {type(self.source_code)}")
            if isinstance(self.source_code, dict):
                print(f"DEBUG: source_code keys: {list(self.source_code.keys())}")
        return self.object_manager.get_call(obj, self.source_code)

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
                # Multiple files - try to find the source for this function
                # First try to find the function by checking if it has a __code__ attribute
                # that can help us identify which file it came from
                func_file = None
                if hasattr(func, '__code__') and hasattr(func.__code__, 'co_filename'):
                    func_file = func.__code__.co_filename

                if func_file and func_file in self.source_code:
                    # We found the file this function came from
                    source = self.source_code[func_file]
                else:
                    # Fallback: search for function name in source files
                    # Use a more sophisticated approach to avoid false matches
                    for filename, file_source in self.source_code.items():
                        # Look for function definition pattern: def function_name(
                        pattern = rf'\bdef\s+{re.escape(func.__name__)}\s*\('
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

    This is a simplified version that focuses on static analysis
    rather than bytecode decompilation.
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
        if hasattr(extracted_program, 'liveCode') and extracted_program.liveCode:
            if not hasattr(program, 'liveCode') or program.liveCode is None:
                program.liveCode = set()
            program.liveCode.update(extracted_program.liveCode)
            print(f"DEBUG: Added {len(extracted_program.liveCode)} functions to program.liveCode")
        else:
            print(f"DEBUG: No liveCode found in extracted_program")
    else:
        # Single file extraction (existing behavior)
        if compiler.console:
            compiler.console.output("Program extraction complete")

    # Process the interface declarations (functions and classes)
    if hasattr(program, 'interface') and program.interface:
        if not program.interface.translated:
            program.interface.translate(compiler.extractor)
            # Set entry points from the interface
            program.entryPoints = program.interface.entryPoint


def create_interface_from_paths(python_files, args):
    """Create a basic interface from multiple Python files using dependency resolver."""
    from pyflow.application import interface
    from pyflow.frontend.dependency_resolver import DependencyResolver

    interface_decl = interface.InterfaceDeclaration()
    all_source_code = {}

    for file_path in python_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
            all_source_code[str(file_path)] = source

            # Try to get real function objects by executing the source in a controlled environment
            try:
                import builtins

                # Create a safe globals dict with builtins
                exec_globals = dict(vars(builtins))

                # Set the __file__ variable so functions get the correct filename
                exec_globals['__file__'] = str(file_path)

                # Add safe modules
                safe_modules = ['math', 'os', 'sys', 're', 'json', 'datetime', 'collections']
                for mod_name in safe_modules:
                    try:
                        exec_globals[mod_name] = __import__(mod_name)
                    except ImportError:
                        pass

                # Execute the source code with filename preserved in code objects
                compiled = compile(source, str(file_path), 'exec')
                exec(compiled, exec_globals)

                # Extract functions that were defined in this file
                functions = {}
                for name, obj in exec_globals.items():
                    if not name.startswith('_') and callable(obj) and hasattr(obj, '__code__'):
                        if args.verbose:
                            print(f"DEBUG: Function '{name}' has code with filename: '{obj.__code__.co_filename}' (expected: '{file_path}')")
                        # Accept functions with either the correct filename or '<string>' (from exec)
                        # Since we executed this specific source file, any function found here came from it
                        functions[name] = obj

                if args.verbose:
                    print(f"DEBUG: Successfully executed source and found {len(functions)} functions with correct code objects")

            except Exception as exec_error:
                if args.verbose:
                    print(f"DEBUG: Source execution failed: {exec_error}, using dependency resolver")

                # Fallback to dependency resolver
                resolver = DependencyResolver(
                    strategy='stubs',  # Try stubs strategy which should give better results
                    verbose=args.verbose,
                    safe_modules=['math', 'os', 'sys', 're', 'json', 'datetime', 'collections']
                )
                functions = resolver.extract_functions(source, file_path)

            for func_name, func_obj in functions.items():
                # Skip driver/main function from being treated as analysis entry point
                if func_name == 'main':
                    if args.verbose:
                        print(f"DEBUG: Skipping '{func_name}' as an entry point")
                    continue
                # Debug: check if function has code object
                if hasattr(func_obj, '__code__') and func_obj.__code__:
                    if args.verbose:
                        print(f"DEBUG: Function '{func_name}' has code object with filename: {func_obj.__code__.co_filename}")
                else:
                    if args.verbose:
                        print(f"DEBUG: Function '{func_name}' has no code object or it's None")

                interface_decl.func.append((func_obj, []))
                if args.verbose:
                    print(f"Added function '{func_name}' from {file_path}")

            if args.verbose:
                print(f"Found {len(functions)} callable objects in {file_path}: {list(functions.keys())}")

        except Exception as e:
            if args.verbose:
                print(f"Warning: Could not parse file {file_path}: {e}")

    return interface_decl, all_source_code