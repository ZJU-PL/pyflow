"""AST-based call graph extraction algorithm.

This algorithm parses Python source code directly using Python's AST module.
It's simple and doesn't require external dependencies, but may miss some
complex call patterns that require runtime analysis or more sophisticated
static analysis techniques.
"""

import ast as python_ast
from typing import Set, Dict, Any, Optional

from .base import CallGraphAlgorithm, CallGraphData


class ASTBasedAlgorithm(CallGraphAlgorithm):
    """Extracts call graphs using Python's AST module.
    
    This algorithm uses Python's built-in AST parser to analyze source code
    and extract function definitions and call relationships. It's suitable
    for basic call graph extraction but may miss dynamic dispatch patterns.
    """

    @property
    def name(self) -> str:
        """Return the algorithm name.
        
        Returns:
            str: Algorithm identifier "ast".
        """
        return "ast"

    @property
    def description(self) -> str:
        """Return a description of the algorithm.
        
        Returns:
            str: Human-readable description of the AST-based approach.
        """
        return "AST-based call graph extraction using Python's built-in AST module"

    def extract_from_program(self, program, compiler, args) -> CallGraphData:
        """Extract call graph from a pyflow program.
        
        Args:
            program: PyFlow program object to analyze.
            compiler: Compiler context containing source code.
            args: Command-line arguments for configuration.
            
        Returns:
            CallGraphData: Extracted call graph information.
        """
        return self.extract_from_source(compiler.extractor.source_code, args)

    def extract_from_source(self, source_code: str, args) -> CallGraphData:
        """Extract call graph directly from Python source code.
        
        Args:
            source_code: Python source code as a string.
            args: Command-line arguments for configuration.
            
        Returns:
            CallGraphData: Extracted call graph with functions and call relationships.
        """
        call_graph = CallGraphData()
        call_graph.functions = set()
        call_graph.invocations = {}
        call_graph.invocation_contexts = {}
        call_graph.function_contexts = {}

        # Parse the source code to find all functions
        function_map = {}
        try:
            tree = python_ast.parse(source_code)

            class FunctionFinder(python_ast.NodeVisitor):
                def __init__(self):
                    self.functions = {}

                def visit_FunctionDef(self, node):
                    # Create a mock function object
                    class MockFunction:
                        def __init__(self, name):
                            self.name = name
                            self.__name__ = name

                        def codeName(self):
                            return self.name

                    func = MockFunction(node.name)
                    self.functions[node.name] = func
                    self.generic_visit(node)

            finder = FunctionFinder()
            finder.visit(tree)
            function_map = finder.functions

            # Add all functions to the call graph
            for func in function_map.values():
                call_graph.functions.add(func)
                call_graph.invocations[func] = set()
                call_graph.function_contexts[func] = {None}

            # Extract call relationships
            for func_name, func in function_map.items():
                try:
                    # Extract the source for this specific function
                    func_source = self._extract_function_source_from_file(
                        func_name, source_code
                    )
                    if func_source:
                        calls = self._extract_calls_from_source(
                            func_source, function_map
                        )
                        call_graph.invocations[func].update(calls)

                        if self.verbose:
                            call_names = [self._get_function_name(c) for c in calls]
                            print(f"Function {func_name} calls: {call_names}")
                except Exception as e:
                    if self.verbose:
                        print(f"Error processing function {func_name}: {e}")

        except Exception as e:
            if self.verbose:
                print(f"Error parsing source code: {e}")

        return call_graph

    def _get_function_name(self, code) -> str:
        """Get the name of a function from a Code object."""
        if hasattr(code, "codeName"):
            return code.codeName()
        elif hasattr(code, "__name__"):
            return code.__name__
        elif hasattr(code, "func_name"):
            return code.func_name
        else:
            return str(code)

    def _get_function_source(self, code, compiler) -> Optional[str]:
        """Get the source code for a function."""
        func_name = self._get_function_name(code)

        if isinstance(compiler.extractor.source_code, dict):
            for filename, file_source in compiler.extractor.source_code.items():
                if func_name in file_source:
                    return self._extract_function_source_from_file(
                        func_name, file_source
                    )
        else:
            if (
                compiler.extractor.source_code
                and func_name in compiler.extractor.source_code
            ):
                return self._extract_function_source_from_file(
                    func_name, compiler.extractor.source_code
                )

        return None

    def _extract_function_source_from_file(
        self, func_name: str, file_source: str
    ) -> Optional[str]:
        """Extract the source code of a specific function from file source."""
        try:
            tree = python_ast.parse(file_source)

            class FunctionExtractor(python_ast.NodeVisitor):
                def __init__(self, target_name):
                    self.target_name = target_name
                    self.function_source = None
                    self.lines = file_source.splitlines()

                def visit_FunctionDef(self, node):
                    if node.name == self.target_name:
                        start_line = node.lineno - 1
                        end_line = (
                            node.end_lineno
                            if hasattr(node, "end_lineno")
                            else start_line + 1
                        )
                        self.function_source = "\n".join(
                            self.lines[start_line:end_line]
                        )
                    self.generic_visit(node)

            extractor = FunctionExtractor(func_name)
            extractor.visit(tree)
            return extractor.function_source
        except Exception as e:
            if self.verbose:
                print(f"Error extracting function source for {func_name}: {e}")
            return None

    def _extract_calls_from_source(
        self, source: str, function_map: Dict[str, Any]
    ) -> Set[Any]:
        """Extract function calls from Python source code."""
        calls = set()
        try:
            tree = python_ast.parse(source)

            class CallVisitor(python_ast.NodeVisitor):
                def visit_Call(self, node):
                    if isinstance(node.func, python_ast.Name):
                        func_name = node.func.id
                        if func_name in function_map:
                            calls.add(function_map[func_name])
                    elif isinstance(node.func, python_ast.Attribute):
                        # Skip method calls for now
                        pass
                    self.generic_visit(node)

            visitor = CallVisitor()
            visitor.visit(tree)
        except Exception as e:
            if self.verbose:
                print(f"Error parsing source: {e}")

        return calls
