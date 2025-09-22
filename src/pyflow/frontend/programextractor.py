"""
Program extractor for static analysis.

This module provides functionality to extract program information
from Python source code for static analysis purposes.

FIXME: very likely to be buggy (Maybe we need to repalce it with
the dir in src/pyflow/decompile)
"""

import ast
import inspect
from typing import Any, Dict, List, Optional

from pyflow.application.program import Program
from pyflow.application.context import CompilerContext
from pyflow.language.python import ast as pyflow_ast
from pyflow.language.python.program import Object
from pyflow.language.python.program import ImaginaryObject, AbstractObject


class Extractor:
    """Extracts program information from Python code for static analysis."""

    def __init__(
        self, compiler: CompilerContext, verbose: bool = True, source_code: str = None
    ):
        self.compiler = compiler
        self.verbose = verbose
        self.source_code = (
            source_code  # Can be a single string or dict of {filename: source}
        )
        self.functions = []
        self.builtin = 0
        self.errors = 0
        self.failures = 0
        self._object_cache = {}
        self._source_files = {}  # Track source files for better error reporting

        # Initialize desc attribute (program description)
        from pyflow.language.python.program import ProgramDescription

        self.desc = ProgramDescription()

        # Initialize proper stub system
        from pyflow.stubs.stubcollector import makeStubs

        try:
            self.stubs = makeStubs(compiler)
        except Exception as e:
            # Fallback to minimal stubs if full system fails
            from ..language.python import ast as pyflow_ast

            def create_stub_code(name):
                # Create a minimal code object that satisfies the type requirements
                params = pyflow_ast.CodeParameters(
                    None, [], [], [], None, None, [pyflow_ast.Local("internal_return")]
                )
                body = pyflow_ast.Suite([])
                code = pyflow_ast.Code(name, params, body)
                code.annotation = type(
                    "Annotation",
                    (),
                    {
                        "origin": [f"stub_{name}"],
                        "interpreter": True,
                        "runtime": False,
                        "staticFold": None,
                        "dynamicFold": None,
                        "primitive": False,
                        "descriptive": False,
                    },
                )()
                return code

            self.stubs = type(
                "Stubs",
                (),
                {
                    "exports": {
                        "interpreter_getattribute": create_stub_code(
                            "interpreter_getattribute"
                        ),
                        "interpreter__mul__": create_stub_code("interpreter__mul__"),
                        "interpreter__add__": create_stub_code("interpreter__add__"),
                        "interpreter__sub__": create_stub_code("interpreter__sub__"),
                        "interpreter__div__": create_stub_code("interpreter__div__"),
                        "interpreter__mod__": create_stub_code("interpreter__mod__"),
                        "interpreter__pow__": create_stub_code("interpreter__pow__"),
                        "interpreter__and__": create_stub_code("interpreter__and__"),
                        "interpreter__or__": create_stub_code("interpreter__or__"),
                        "interpreter__xor__": create_stub_code("interpreter__xor__"),
                        "interpreter__lshift__": create_stub_code(
                            "interpreter__lshift__"
                        ),
                        "interpreter__rshift__": create_stub_code(
                            "interpreter__rshift__"
                        ),
                        "interpreter__floordiv__": create_stub_code(
                            "interpreter__floordiv__"
                        ),
                        "interpreter__eq__": create_stub_code("interpreter__eq__"),
                        "interpreter__ne__": create_stub_code("interpreter__ne__"),
                        "interpreter__lt__": create_stub_code("interpreter__lt__"),
                        "interpreter__le__": create_stub_code("interpreter__le__"),
                        "interpreter__gt__": create_stub_code("interpreter__gt__"),
                        "interpreter__ge__": create_stub_code("interpreter__ge__"),
                        "interpreter_getitem": create_stub_code("interpreter_getitem"),
                        "interpreter_call": create_stub_code("interpreter_call"),
                        "object__getattribute__": create_stub_code(
                            "object__getattribute__"
                        ),
                        "object__setattribute__": create_stub_code(
                            "object__setattribute__"
                        ),
                        "object__call__": create_stub_code("object__call__"),
                        "function__get__": create_stub_code("function__get__"),
                        "function__call__": create_stub_code("function__call__"),
                        "method__get__": create_stub_code("method__get__"),
                        "method__call__": create_stub_code("method__call__"),
                        "methoddescriptor__get__": create_stub_code(
                            "methoddescriptor__get__"
                        ),
                        "methoddescriptor__call__": create_stub_code(
                            "methoddescriptor__call__"
                        ),
                    }
                },
            )()

    def extract_from_source(self, source: str, filename: str = "<string>") -> Program:
        """Extract program information from Python source code."""
        try:
            tree = ast.parse(source, filename)
            return self._extract_from_ast(tree, filename)
        except SyntaxError as e:
            if self.verbose:
                print(f"Syntax error in {filename}: {e}")
            self.errors += 1
            return Program()

    def extract_from_file(self, filename: str) -> Program:
        """Extract program information from a Python file."""
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
                # The Program class doesn't have functions/classes attributes
                # The actual extraction is handled through the interface
                # This is a placeholder for future enhancement
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
                self._extract_function(node, program)
            elif isinstance(node, ast.ClassDef):
                if self.verbose:
                    print(f"DEBUG: Found class definition: {node.name}")
                self._extract_class(node, program)

        if self.verbose:
            print(f"DEBUG: Extraction complete, liveCode has {len(program.liveCode)} functions")

        return program

    def _extract_function(self, node: ast.FunctionDef, program: Program):
        """Extract information from a function definition."""
        try:
            if self.verbose:
                print(f"Found function: {node.name}")
            
            # Convert Python AST function to pyflow AST
            pyflow_code = self._convert_python_function_to_pyflow(node, None)
            
            # Add to program
            if hasattr(program, 'liveCode'):
                program.liveCode.add(pyflow_code)
            else:
                # Create liveCode if it doesn't exist
                program.liveCode = {pyflow_code}
                
            if self.verbose:
                print(f"Added function {node.name} to program")
                
        except Exception as e:
            if self.verbose:
                print(f"Error processing function {node.name}: {e}")
                import traceback
                traceback.print_exc()
            self.errors += 1

    def _extract_class(self, node: ast.ClassDef, program: Program):
        """Extract information from a class definition."""
        try:
            if self.verbose:
                print(f"Found class: {node.name}")
        except Exception as e:
            if self.verbose:
                print(f"Error processing class {node.name}: {e}")
            self.errors += 1

    def getObject(self, obj: Any) -> Object:
        """Get or create an object representation for static analysis."""
        if obj in self._object_cache:
            return self._object_cache[obj]

        # Create an Object wrapper for the Python object
        try:
            pyflow_obj = Object(obj)
            self._object_cache[obj] = pyflow_obj
            return pyflow_obj
        except Exception as e:
            if self.verbose:
                print(f"Error creating Object for {obj}: {e}")
            # Return a fallback object
            return obj

    def getObjectCall(self, func: Any) -> tuple:
        """Get object call information for a function."""
        # print(f"DEBUG: getObjectCall called with {func.__name__ if hasattr(func, '__name__') else 'unknown'}")

        if hasattr(func, "__name__"):
            # Use proper function conversion instead of SimpleCodeObject hack
            code_obj = self.convertFunction(func)
            if code_obj:
                # print(f"DEBUG: getObjectCall returning {type(code_obj)} for {func.__name__}")
                
                # Add the converted function to the program's live code
                if hasattr(self, 'program') and self.program:
                    if hasattr(self.program, 'liveCode'):
                        self.program.liveCode.add(code_obj)
                        # print(f"DEBUG: Added {func.__name__} to program.liveCode")
                    else:
                        self.program.liveCode = {code_obj}
                        # print(f"DEBUG: Created program.liveCode with {func.__name__}")
                
            return func, code_obj

    def makeImaginary(
        self, name: str, t: AbstractObject, preexisting: bool
    ) -> ImaginaryObject:
        return ImaginaryObject(name, t, preexisting)

    def ensureLoaded(self, obj: AbstractObject) -> None:
        """Ensure an abstract object is loaded. Initialize typeinfo for type objects."""
        from ..language.python.program import TypeInfo, ImaginaryObject

        # If this object doesn't have a type set, we need to initialize it
        if not hasattr(obj, "type") or obj.type is None:
            if hasattr(obj, "pyobj"):
                # Set the type to be the type of the Python object
                obj.type = self.getObject(type(obj.pyobj))

        # If this is a type object and doesn't have typeinfo, create it
        if obj.isType() and (not hasattr(obj, "typeinfo") or obj.typeinfo is None):
            obj.typeinfo = TypeInfo()

            # Create an abstract instance for this type
            # The abstract instance represents instances of this type
            abstract_instance = ImaginaryObject(
                f"abstract_instance_of_{obj.pyobj.__name__}", obj, False
            )
            obj.typeinfo.abstractInstance = abstract_instance

        return None

    def getObject(self, obj):
        """Get an object from the cache or create a new one."""
        if obj in self._object_cache:
            return self._object_cache[obj]

        # Create a simple object wrapper
        from ..language.python.program import Object

        wrapped_obj = Object(obj)
        self._object_cache[obj] = wrapped_obj

        # Ensure the object is properly loaded
        self.ensureLoaded(wrapped_obj)

        return wrapped_obj

    def getCall(self, obj):
        """Get call information for an object."""
        if hasattr(obj, "pyobj") and callable(obj.pyobj):
            # For callable objects, return the second element from getObjectCall
            func_obj, code_obj = self.getObjectCall(obj.pyobj)
            return code_obj
        return None

    def convertFunction(
        self,
        func: Any,
        trace: bool = False,
        ssa: bool = True,
        descriptive: bool = False,
    ) -> Any:
        """Convert a Python function to PyFlow AST for static analysis."""
        # print(f"DEBUG: convertFunction called with {func.__name__}")

        try:
            # Get the source code of the function
            import inspect
            import ast as python_ast
            from ..language.python import ast as pyflow_ast

            # Try to get source code from the extractor's source_code first
            source = None
            if hasattr(self, "source_code") and self.source_code:
                if isinstance(self.source_code, dict):
                    # Multiple files - try to find the source for this function
                    for filename, file_source in self.source_code.items():
                        if func.__name__ in file_source:
                            source = file_source
                            break
                else:
                    # Single source file
                    source = self.source_code

            if not source:
                # Fallback to inspect.getsource
                try:
                    source = inspect.getsource(func)
                except (OSError, TypeError):
                    pass

            if not source:
                print(f"DEBUG: Could not get source code for {func.__name__}")
                return self._create_minimal_code(func)

            # print(f"DEBUG: Source code for {func.__name__}:")
            # print(source[:200] + "..." if len(source) > 200 else source)

            # Parse it into a Python AST
            tree = python_ast.parse(source)

            # Find the function definition
            func_node = None
            for node in python_ast.walk(tree):
                if (
                    isinstance(node, python_ast.FunctionDef)
                    and node.name == func.__name__
                ):
                    func_node = node
                    break

            if func_node is None:
                print(f"DEBUG: Could not find function definition for {func.__name__}")
                return self._create_minimal_code(func)

            # print(f"DEBUG: Found function node for {func.__name__}, body has {len(func_node.body)} statements")

            # Convert Python AST to pyflow AST
            result = self._convert_python_function_to_pyflow(func_node, func)
            # print(f"DEBUG: Converted AST for {func.__name__}: {type(result)}")
            return result

        except Exception as e:
            print(f"DEBUG: Error analyzing function {func.__name__}: {e}")
            import traceback
            traceback.print_exc()
            # Fallback: create a minimal code stub
            return self._create_minimal_code(func)

    def _create_minimal_code(self, func: Any) -> Any:
        """Create a minimal pyflow AST Code node with an empty Suite."""
        from ..language.python import ast as pyflow_ast

        codeparams = pyflow_ast.CodeParameters(None, [], [], [], None, None, [])
        suite = pyflow_ast.Suite([])
        code = pyflow_ast.Code(func.__name__, codeparams, suite)

        # Initialize the annotation properly
        from ..language.python.annotations import CodeAnnotation

        code.annotation = CodeAnnotation(
            contexts=None,
            descriptive=False,
            primitive=False,
            staticFold=False,
            dynamicFold=False,
            origin=[f"minimal_code({func.__name__})"],
            live=None,
            killed=None,
            codeReads=None,
            codeModifies=None,
            codeAllocates=None,
            lowered=False,
            runtime=False,
            interpreter=False,
        )

        return code

    def _convert_python_function_to_pyflow(self, func_node, func: Any) -> Any:
        """Convert a Python AST FunctionDef to a pyflow AST Code node."""
        import ast as python_ast
        from ..language.python import ast as pyflow_ast

        # Convert function parameters
        codeparams = self._convert_function_args(func_node.args, func)
        
        # Convert function body
        body = self._convert_python_ast_to_pyflow(func_node.body)
        
        # Use func_node.name if func is None
        func_name = func.__name__ if func else func_node.name
        
        code = pyflow_ast.Code(func_name, codeparams, body)
        
        # Initialize the annotation properly
        from ..language.python.annotations import CodeAnnotation
        
        code.annotation = CodeAnnotation(
            contexts=None,
            descriptive=False,
            primitive=False,
            staticFold=False,
            dynamicFold=False,
            origin=[f"converted_function({func_name})"],
            live=None,
            killed=None,
            codeReads=None,
            codeModifies=None,
            codeAllocates=None,
            lowered=False,
            runtime=False,
            interpreter=False,
        )
        
        return code

    def _convert_function_args(self, args_node, func: Any) -> Any:
        """Convert Python AST arguments to pyflow AST CodeParameters."""
        from ..language.python import ast as pyflow_ast
        
        # Get default values
        defaults = []
        if args_node.defaults:
            for default in args_node.defaults:
                defaults.append(self._convert_expression(default))
        
        # Get parameter names
        param_names = [arg.arg for arg in args_node.args]
        
        # Create Local objects for parameters
        params = [pyflow_ast.Local(name) for name in param_names]
        
        # Handle *args and **kwargs
        vararg = None
        if args_node.vararg:
            vararg = pyflow_ast.Local(args_node.vararg.arg)
        
        kwarg = None
        if args_node.kwarg:
            kwarg = pyflow_ast.Local(args_node.kwarg.arg)
        
        return pyflow_ast.CodeParameters(
            selfparam=None,  # No self for regular functions
            params=params,
            paramnames=param_names,
            defaults=tuple(defaults),
            vparam=vararg,
            kparam=kwarg,
            returnparams=[]
        )

    def _convert_python_ast_to_pyflow(self, python_nodes):
        """Convert Python AST nodes to pyflow AST nodes."""
        import ast as python_ast
        from ..language.python import ast as pyflow_ast

        if self.verbose:
            print(f"DEBUG: Converting {len(python_nodes)} Python AST nodes")

        if not python_nodes:
            return pyflow_ast.Suite([])

        blocks = []
        for i, node in enumerate(python_nodes):
            # print(f"DEBUG: Converting node {i}: {type(node).__name__}")
            # if hasattr(node, 'lineno'):
            #     print(f"DEBUG: Node at line {node.lineno}")
            converted = self._convert_node(node)
            if converted is not None:
                # print(f"DEBUG: Converted to: {type(converted).__name__}")
                blocks.append(converted)
            # else:
            #     print(f"DEBUG: Node {i} converted to None")

        if self.verbose:
            print(f"DEBUG: Final blocks: {len(blocks)}")
        return pyflow_ast.Suite(blocks)

    def _convert_node(self, node):
        """Convert a single Python AST node to pyflow AST."""
        import ast as python_ast
        from ..language.python import ast as pyflow_ast

        if isinstance(node, python_ast.Return):
            if node.value:
                expr = self._convert_expression(node.value)
                return pyflow_ast.Return([expr])
            else:
                return pyflow_ast.Return([])
        
        elif isinstance(node, python_ast.Assign):
            # Handle assignment: target = value
            targets = []
            for target in node.targets:
                if isinstance(target, python_ast.Name):
                    targets.append(pyflow_ast.Local(target.id))
                else:
                    # For more complex targets, create a generic local
                    targets.append(pyflow_ast.Local(f"target_{id(target)}"))
            
            value = self._convert_expression_safe(node.value)
            return pyflow_ast.Assign(value, targets)
        
        elif isinstance(node, python_ast.If):
            # Handle if statements
            condition = self._convert_expression_safe(node.test)
            
            then_body = self._convert_python_ast_to_pyflow(node.body)
            else_body = self._convert_python_ast_to_pyflow(node.orelse)
            
            # Create a Switch node for the condition
            return pyflow_ast.Switch(
                condition=pyflow_ast.Condition(pyflow_ast.Suite([]), condition),
                t=then_body,
                f=else_body
            )
        
        elif isinstance(node, python_ast.Expr):
            # Handle expression statements (like function calls)
            return pyflow_ast.Discard(self._convert_expression_safe(node.value))
        
        elif isinstance(node, python_ast.Pass):
            # Handle pass statements
            return pyflow_ast.Suite([])
        
        else:
            # For unhandled node types, create a generic discard
            if hasattr(node, 'value'):
                return pyflow_ast.Discard(self._convert_expression(node.value))
            else:
                return pyflow_ast.Suite([])

    def _convert_expression(self, node):
        """Convert Python AST expressions to pyflow AST expressions."""
        import ast as python_ast
        from ..language.python import ast as pyflow_ast

        if isinstance(node, python_ast.Name):
            return pyflow_ast.Local(node.id)
        
        elif isinstance(node, python_ast.Constant):
            from ..language.python.program import Object
            return pyflow_ast.Existing(Object(node.value))
        
        elif isinstance(node, python_ast.Num):  # Python < 3.8
            from ..language.python.program import Object
            return pyflow_ast.Existing(Object(node.n))
        
        elif isinstance(node, python_ast.Str):  # Python < 3.8
            from ..language.python.program import Object
            return pyflow_ast.Existing(Object(node.s))
        
        elif isinstance(node, python_ast.NameConstant):  # Python < 3.8
            from ..language.python.program import Object
            return pyflow_ast.Existing(Object(node.value))
        
        elif isinstance(node, python_ast.Call):
            # Handle function calls
            func = self._convert_expression_safe(node.func)
            args = [self._convert_expression_safe(arg) for arg in node.args]
            keywords = []
            if node.keywords:
                for kw in node.keywords:
                    if kw.arg is not None:  # Skip **kwargs
                        converted_value = self._convert_expression_safe(kw.value)
                        keywords.append((kw.arg, converted_value))
            
            return pyflow_ast.Call(func, args, keywords, None, None)
        
        elif isinstance(node, python_ast.Compare):
            # Handle comparisons (==, !=, <, >, etc.)
            left = self._convert_expression(node.left)
            if len(node.ops) == 1 and len(node.comparators) == 1:
                op = node.ops[0]
                right = self._convert_expression(node.comparators[0])
                
                # Map Python comparison operators to pyflow operators
                op_map = {
                    python_ast.Eq: 'interpreter__eq__',
                    python_ast.NotEq: 'interpreter__ne__',
                    python_ast.Lt: 'interpreter__lt__',
                    python_ast.LtE: 'interpreter__le__',
                    python_ast.Gt: 'interpreter__gt__',
                    python_ast.GtE: 'interpreter__ge__',
                    python_ast.Is: 'interpreter__is__',
                    python_ast.IsNot: 'interpreter__is_not__',
                }
                
                if type(op) in op_map:
                    op_name = op_map[type(op)]
                    from ..language.python.program import Object
                    return pyflow_ast.Call(
                        pyflow_ast.Existing(Object(op_name)),
                        [left, right], [], None, None
                    )
            
            # Fallback for complex comparisons
            from ..language.python.program import Object
            return pyflow_ast.Existing(Object(None))
        
        elif isinstance(node, python_ast.BinOp):
            # Handle binary operations (+, -, *, /, etc.)
            left = self._convert_expression(node.left)
            right = self._convert_expression(node.right)
            
            op_map = {
                python_ast.Add: 'interpreter__add__',
                python_ast.Sub: 'interpreter__sub__',
                python_ast.Mult: 'interpreter__mul__',
                python_ast.Div: 'interpreter__truediv__',
                python_ast.FloorDiv: 'interpreter__floordiv__',
                python_ast.Mod: 'interpreter__mod__',
                python_ast.Pow: 'interpreter__pow__',
            }
            
            if type(node.op) in op_map:
                op_name = op_map[type(node.op)]
                from ..language.python.program import Object
                return pyflow_ast.Call(
                    pyflow_ast.Existing(Object(op_name)),
                    [left, right], [], None, None
                )
            
            # Fallback
            from ..language.python.program import Object
            return pyflow_ast.Existing(Object(None))
        
        elif isinstance(node, python_ast.Subscript):
            # Handle array/list indexing: arr[index]
            value = self._convert_expression(node.value)
            if isinstance(node.slice, python_ast.Index):  # Python < 3.9
                index = self._convert_expression(node.slice.value)
            else:
                index = self._convert_expression(node.slice)
            
            from ..language.python.program import Object
            return pyflow_ast.Call(
                pyflow_ast.Existing(Object('interpreter__getitem__')),
                [value, index], [], None, None
            )
        
        else:
            # Fallback for unhandled expressions
            from ..language.python.program import Object
            return pyflow_ast.Existing(Object(None))
    
    def _convert_expression_safe(self, node):
        """Convert Python AST expressions to pyflow AST expressions with None protection."""
        result = self._convert_expression(node)
        if result is None:
            from ..language.python.program import Object
            from ..language.python import ast as pyflow_ast
            return pyflow_ast.Existing(Object(None))
        return result


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

        # The Program class doesn't have functions/classes attributes
        # The actual extraction is handled through the interface
        # This is a placeholder for future enhancement
    else:
        # Single file extraction (existing behavior)
        if compiler.console:
            compiler.console.output("Program extraction complete")
