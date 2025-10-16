"""
PyCG-based call graph extraction algorithm.

This algorithm uses the PyCG library for more sophisticated call graph analysis.
It can handle more complex Python constructs and provides better accuracy.
"""

import os

from typing import Set, Dict, Any, Optional, List
from pyflow.machinery.callgraph import CallGraph

try:
    import pycg  # type: ignore
    from pycg.pycg import CallGraphGenerator as CallGraphGeneratorPyCG  # type: ignore
    PYCG_AVAILABLE = True
except ImportError:
    PYCG_AVAILABLE = False


def extract_call_graph_pycg(source_code: str, verbose: bool = False) -> CallGraph:
    """
    Extract call graph from Python source code using PyCG.

    This is a more sophisticated approach that can handle complex Python constructs.
    """
    if not PYCG_AVAILABLE:
        raise ImportError("PyCG library is not available. Install it with: pip install pycg")

    graph = CallGraph()

    try:
        import tempfile

        # PyCG works with files, so we need to create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(source_code)
            temp_file_path = f.name

        try:
            # Use PyCG to generate call graph
            cg = CallGraphGeneratorPyCG([temp_file_path], 0)  # 0 = maximum depth
            pycg_calls = cg.generate()

            # Process PyCG results
            for caller, callees in pycg_calls.items():
                graph.add_node(caller)
                for callee in callees:
                    graph.add_edge(caller, callee)

        finally:
            # Clean up temporary file
            os.unlink(temp_file_path)

    except Exception as e:
        if verbose:
            print(f"Error in PyCG analysis: {e}")

    return graph


def analyze_file_pycg(filepath: str, verbose: bool = False) -> str:
    """Analyze a Python file using PyCG and return call graph as text."""
    try:
        with open(filepath, 'r') as f:
            source = f.read()
        graph = extract_call_graph_pycg(source, verbose)
        from .formats import generate_text_output
        return generate_text_output(graph, None)
    except Exception as e:
        return f"Error analyzing {filepath}: {e}"


