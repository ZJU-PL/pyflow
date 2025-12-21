"""
Function Extractor for converting Python functions to PyFlow AST.

This module handles the extraction and conversion of Python functions
to PyFlow's internal representation for static analysis.
"""

import ast as python_ast
import inspect
import textwrap
from typing import Any, Optional

from pyflow.language.python import ast as pyflow_ast
from pyflow.language.python.annotations import CodeAnnotation
from pyflow.language.python.pythonbase import PythonASTNode
from pyflow.application.program import Program

from .ast_converter import ASTConverter


class FunctionExtractor:
    """Extracts and converts Python functions to PyFlow AST."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.ast_converter = ASTConverter(verbose)

    def convert_function(
        self,
        func: Any,
        source_code: Optional[str] = None,
        trace: bool = False,
        ssa: bool = True,
        descriptive: bool = False,
    ) -> PythonASTNode:
        """Convert a Python function to PyFlow AST for static analysis."""
        try:
            # Try to get source code from the provided source_code first
            source = source_code
            if self.verbose and source_code:
                print(f"DEBUG: Using provided source code for {func.__name__}")
            elif self.verbose:
                print(f"DEBUG: No source code provided for {func.__name__}")

            if not source:
                # Fallback to inspect.getsource
                try:
                    source = inspect.getsource(func)
                    if self.verbose:
                        print(f"DEBUG: Got source from inspect.getsource for {func.__name__}")
                except (OSError, TypeError):
                    if self.verbose:
                        print(f"DEBUG: inspect.getsource failed for {func.__name__}")

            if not source:
                if self.verbose:
                    print(f"DEBUG: Could not get source code for {func.__name__}")
                return self._create_minimal_code(func)

            if self.verbose:
                print(f"DEBUG: Processing source code for {func.__name__} (length: {len(source)})")

            # Dedent the source code to handle class-level indentation
            try:
                source = textwrap.dedent(source)
            except Exception as e:
                if self.verbose:
                    print(f"DEBUG: Error dedenting source for {func.__name__}: {e}")

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
                if self.verbose:
                    print(f"DEBUG: Could not find function definition for {func.__name__}")
                return self._create_minimal_code(func)

            # Convert Python AST to pyflow AST
            result = self._convert_python_function_to_pyflow(func_node, func)
            return result

        except Exception as e:
            if self.verbose:
                print(f"DEBUG: Error analyzing function {func.__name__}: {e}")
                import traceback
                traceback.print_exc()
            # Fallback: create a minimal code stub
            return self._create_minimal_code(func)

    def _create_minimal_code(self, func: Any) -> pyflow_ast.Code:
        """Create a minimal pyflow AST Code node with an empty Suite."""
        # Provide a default single return param to satisfy IPA's visitReturn assertions
        codeparams = pyflow_ast.CodeParameters(None, [], [], [], None, None, [pyflow_ast.Local("ret0")])
        suite = pyflow_ast.Suite([])
        code = pyflow_ast.Code(func.__name__, codeparams, suite)

        # Initialize the annotation properly
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

    def _convert_python_function_to_pyflow(self, func_node: python_ast.FunctionDef, func: Any) -> pyflow_ast.Code:
        """Convert a Python AST FunctionDef to a pyflow AST Code node."""
        # Convert function parameters
        codeparams = self._convert_function_args(func_node.args, func)
        
        # Convert function body
        body = self.ast_converter.convert_python_ast_to_pyflow(func_node.body)
        
        # Use func_node.name if func is None
        func_name = func.__name__ if func else func_node.name
        
        # Ensure at least one return parameter for IPA
        if not codeparams.returnparams:
            codeparams = pyflow_ast.CodeParameters(
                codeparams.selfparam,
                codeparams.params,
                codeparams.paramnames,
                tuple(codeparams.defaults),
                codeparams.vparam,
                codeparams.kparam,
                [pyflow_ast.Local("ret0")]
            )

        code = pyflow_ast.Code(func_name, codeparams, body)
        
        # Initialize the annotation properly
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

    def _convert_function_args(self, args_node: python_ast.arguments, func: Any) -> pyflow_ast.CodeParameters:
        """Convert Python AST arguments to pyflow AST CodeParameters."""
        # Get default values - defaults must be Existing objects, not expression nodes
        defaults = []
        if args_node.defaults:
            # Try to get actual default values from the function object if available
            if func and hasattr(func, '__defaults__') and func.__defaults__:
                # Use the actual default values from the function
                from pyflow.language.python.program import Object
                for default_value in func.__defaults__:
                    # Create an Object from the default value and wrap it in Existing
                    obj = Object(default_value)
                    defaults.append(pyflow_ast.Existing(obj))
            else:
                # Fallback: evaluate the AST default expressions if we can't get them from func
                # This is less ideal but necessary when we only have AST
                import ast as python_ast_eval
                for default_node in args_node.defaults:
                    try:
                        # Try to evaluate the default expression as a constant
                        # This works for literals but not for complex expressions
                        default_value = python_ast_eval.literal_eval(default_node)
                        from pyflow.language.python.program import Object
                        obj = Object(default_value)
                        defaults.append(pyflow_ast.Existing(obj))
                    except (ValueError, TypeError):
                        # If we can't evaluate it, skip this default
                        # This is a limitation when we only have AST without the function object
                        if self.verbose:
                            print(f"DEBUG: Could not evaluate default value from AST, skipping")
                        pass
        
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
            # Provide a default single return param
            returnparams=[pyflow_ast.Local("ret0")]
        )

    def extract_function(self, node: python_ast.FunctionDef, program: Program) -> None:
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

    def extract_class(self, node: python_ast.ClassDef, program: Program) -> None:
        """Extract information from a class definition."""
        try:
            if self.verbose:
                print(f"Found class: {node.name}")
        except Exception as e:
            if self.verbose:
                print(f"Error processing class {node.name}: {e}")
