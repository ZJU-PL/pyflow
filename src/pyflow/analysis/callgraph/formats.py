"""
Call graph output format generators.

This module provides functions to generate call graphs in various output
formats: text, DOT (Graphviz), and JSON.
"""

import json
from typing import Any


def generate_text_output(call_graph, args) -> str:
    """Generate text output for the call graph."""
    output = []
    output.append("Call Graph Analysis")
    output.append("=" * 50)
    output.append("")

    # Get the underlying CallGraph data
    cg_data = call_graph.get_callgraph().get()
    modules = call_graph.get_callgraph().get_modules()

    # List all functions
    output.append(f"Functions ({len(cg_data)}):")
    for func_name in sorted(cg_data.keys()):
        modname = modules.get(func_name, "")
        if modname:
            output.append(f"  - {func_name} (from {modname})")
        else:
            output.append(f"  - {func_name}")
    output.append("")

    # Show call relationships
    output.append("Call Relationships:")
    for caller_name in sorted(cg_data.keys()):
        callees = cg_data.get(caller_name, set())
        if callees:
            callee_names = sorted(callees)
            output.append(f"  {caller_name} -> {', '.join(callee_names)}")
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

    # Get the underlying CallGraph data
    cg_data = call_graph.get_callgraph().get()

    # Add nodes
    for func_name in cg_data.keys():
        # Escape special characters for DOT
        safe_name = func_name.replace('"', '\\"')
        lines.append(f'    "{safe_name}" [label="{safe_name}"];')

    lines.append("")

    # Add edges
    for caller_name, callees in cg_data.items():
        for callee_name in callees:
            caller_safe = caller_name.replace('"', '\\"')
            callee_safe = callee_name.replace('"', '\\"')
            lines.append(f'    "{caller_safe}" -> "{callee_safe}";')

    lines.append("}")
    return "\n".join(lines)


def generate_json_output(call_graph, args) -> str:
    """Generate JSON output for the call graph."""
    # Get the underlying CallGraph data
    cg_data = call_graph.get_callgraph().get()
    modules = call_graph.get_callgraph().get_modules()
    
    data = {
        "functions": [],
        "invocations": {},
        "modules": {},
        "cycles": getattr(call_graph, "cycles", []),
    }

    # Convert functions to serializable format
    for func_name in cg_data.keys():
        data["functions"].append(func_name)
        modname = modules.get(func_name, "")
        if modname:
            data["modules"][func_name] = modname

    # Convert invocations to serializable format
    for caller_name, callees in cg_data.items():
        data["invocations"][caller_name] = list(callees)

    return json.dumps(data, indent=2)
