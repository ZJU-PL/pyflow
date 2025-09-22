"""
Function Extractor for converting Python functions to PyFlow AST.

This module handles the extraction and conversion of Python functions
to PyFlow's internal representation for static analysis.
"""

import ast as python_ast
import inspect
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
            if not source:
                # Fallback to inspect.getsource
                try:
                    source = inspect.getsource(func)
                except (OSError, TypeError):
                    pass

            if not source:
                if self.verbose:
                    print(f"DEBUG: Could not get source code for {func.__name__}")
                return self._create_minimal_code(func)

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
        codeparams = pyflow_ast.CodeParameters(None, [], [], [], None, None, [])
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
        # Get default values
        defaults = []
        if args_node.defaults:
            for default in args_node.defaults:
                defaults.append(self.ast_converter._convert_expression_safe(default))
        
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
