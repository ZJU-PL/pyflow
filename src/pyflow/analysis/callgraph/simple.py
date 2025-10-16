"""
Simple call graph extraction for Python code.

This module provides straightforward call graph analysis without complex
abstraction layers. It focuses on the core functionality: finding functions
and their call relationships in Python source code.
"""

import ast
from typing import Dict, Set, List, Tuple, Any
from collections import defaultdict

from .types import SimpleFunction, CallGraphData


def extract_call_graph(source_code: str) -> CallGraphData:
    """
    Extract call graph from Python source code.

    This is a simple AST-based approach that finds function definitions
    and direct function calls within the same file.
    """
    graph = CallGraphData()
    function_map = {}  # name -> function object

    try:
        tree = ast.parse(source_code)

        # First pass: collect all function definitions
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func = SimpleFunction(node.name)
                function_map[node.name] = func
                graph.add_function(func)

        # Second pass: find calls within functions
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                caller = function_map.get(node.name)
                if not caller:
                    continue

                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Name):
                            # Direct function call
                            callee_name = child.func.id
                            callee = function_map.get(callee_name)
                            if callee:
                                graph.add_call(caller, callee)

    except SyntaxError:
        # If parsing fails, return empty graph
        pass

    return graph


def analyze_file(filepath: str) -> str:
    """Analyze a Python file and return call graph as text."""
    try:
        with open(filepath, 'r') as f:
            source = f.read()
        graph = extract_call_graph(source)
        from .formats import generate_text_output
        return generate_text_output(graph, None)
    except Exception as e:
        return f"Error analyzing {filepath}: {e}"


