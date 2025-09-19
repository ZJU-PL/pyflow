"""
Output format generators for call graphs.
"""

import json
from typing import Any, Dict, Set, List


def generate_text_output(call_graph, args) -> str:
    """Generate text output for the call graph."""
    output = []
    output.append("Call Graph Analysis")
    output.append("=" * 50)
    output.append("")

    # List all functions
    output.append(f"Functions ({len(call_graph.functions)}):")
    for func in sorted(
        call_graph.functions, key=lambda x: getattr(x, "codeName", lambda: str(x))()
    ):
        func_name = getattr(func, "codeName", lambda: str(func))()
        output.append(f"  - {func_name}")
    output.append("")

    # Show call relationships
    output.append("Call Relationships:")
    for caller in sorted(
        call_graph.functions, key=lambda x: getattr(x, "codeName", lambda: str(x))()
    ):
        caller_name = getattr(caller, "codeName", lambda: str(caller))()
        callees = call_graph.invocations.get(caller, set())

        if callees:
            callee_names = [
                getattr(callee, "codeName", lambda: str(callee))() for callee in callees
            ]
            output.append(f"  {caller_name} -> {', '.join(sorted(callee_names))}")
        else:
            output.append(f"  {caller_name} -> (no calls)")

    # Show cycles if detected
    if hasattr(call_graph, "cycles") and call_graph.cycles:
        output.append("")
        output.append("Cycles detected:")
        for i, cycle in enumerate(call_graph.cycles):
            cycle_names = [
                getattr(func, "codeName", lambda: str(func))() for func in cycle
            ]
            output.append(f"  Cycle {i+1}: {' -> '.join(cycle_names)}")

    return "\n".join(output)


def generate_dot_output(call_graph, args) -> str:
    """Generate DOT format output for the call graph."""
    lines = []
    lines.append("digraph CallGraph {")
    lines.append("    rankdir=TB;")
    lines.append("    node [shape=box, style=filled, fillcolor=lightblue];")
    lines.append("")

    # Add nodes
    for func in call_graph.functions:
        func_name = getattr(func, "codeName", lambda: str(func))()
        # Escape special characters for DOT
        safe_name = func_name.replace('"', '\\"')
        lines.append(f'    "{safe_name}" [label="{safe_name}"];')

    lines.append("")

    # Add edges
    for caller in call_graph.functions:
        caller_name = getattr(caller, "codeName", lambda: str(caller))()
        callees = call_graph.invocations.get(caller, set())

        for callee in callees:
            callee_name = getattr(callee, "codeName", lambda: str(callee))()
            caller_safe = caller_name.replace('"', '\\"')
            callee_safe = callee_name.replace('"', '\\"')
            lines.append(f'    "{caller_safe}" -> "{callee_safe}";')

    lines.append("}")
    return "\n".join(lines)


def generate_json_output(call_graph, args) -> str:
    """Generate JSON output for the call graph."""
    data = {
        "functions": [],
        "invocations": {},
        "cycles": getattr(call_graph, "cycles", []),
    }

    # Convert functions to serializable format
    for func in call_graph.functions:
        func_name = getattr(func, "codeName", lambda: str(func))()
        data["functions"].append(func_name)

    # Convert invocations to serializable format
    for caller in call_graph.functions:
        caller_name = getattr(caller, "codeName", lambda: str(caller))()
        callees = call_graph.invocations.get(caller, set())
        callee_names = [
            getattr(callee, "codeName", lambda: str(callee))() for callee in callees
        ]
        data["invocations"][caller_name] = callee_names

    return json.dumps(data, indent=2)
