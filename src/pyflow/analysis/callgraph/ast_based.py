"""
AST-based call graph extraction for Python code.

This module provides straightforward call graph analysis using Python's AST
module. It focuses on the core functionality: finding functions and their
call relationships in Python source code.
"""

import ast
from typing import Dict, Set, List, Tuple, Any
from collections import defaultdict

from .callgraph import CallGraph


def extract_call_graph(source_code: str, module_name: str = "main") -> CallGraph:
    """Extract a lexical call graph with conservative local method dispatch.

    Attribute calls include all same-named local methods because this lightweight
    algorithm does not infer receiver types. Use the constraint engine for
    interprocedural value flow and external module resolution.
    """
    graph = CallGraph()
    graph.add_node(module_name)
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return graph

    definitions = {}
    methods = defaultdict(set)
    classes = set()

    class Collector(ast.NodeVisitor):
        scope = module_name
        in_class = False

        def visit_ClassDef(self, node):
            previous, was_class = self.scope, self.in_class
            self.scope = f"{previous}.{node.name}"
            classes.add(self.scope)
            definitions[node] = self.scope
            self.in_class = True
            self.generic_visit(node)
            self.scope, self.in_class = previous, was_class

        def visit_FunctionDef(self, node):
            previous, was_class = self.scope, self.in_class
            name = f"{previous}.{node.name}"
            definitions[node] = name
            graph.add_node(name)
            if was_class:
                methods[node.name].add(name)
            self.scope, self.in_class = name, False
            self.generic_visit(node)
            self.scope, self.in_class = previous, was_class

        visit_AsyncFunctionDef = visit_FunctionDef

    Collector().visit(tree)
    functions = set(definitions.values()) - classes
    aliases = defaultdict(set)

    class Calls(ast.NodeVisitor):
        scope = module_name

        def resolve(self, name):
            scope = self.scope
            while scope:
                qualified = f"{scope}.{name}"
                if qualified in functions or qualified in classes:
                    return {qualified}
                if qualified in aliases:
                    return aliases[qualified]
                scope = scope.rpartition(".")[0]
            return set()

        def visit_FunctionDef(self, node):
            # Decorators and defaults execute in the enclosing scope.
            for value in (*node.decorator_list, *node.args.defaults, *node.args.kw_defaults):
                if value is not None:
                    self.visit(value)
            previous = self.scope
            self.scope = definitions[node]
            for statement in node.body:
                self.visit(statement)
            self.scope = previous

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            for value in (*node.decorator_list, *node.bases):
                self.visit(value)
            previous = self.scope
            self.scope = definitions[node]
            for statement in node.body:
                self.visit(statement)
            self.scope = previous

        def visit_Assign(self, node):
            if isinstance(node.value, ast.Name):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        aliases[f"{self.scope}.{target.id}"].update(self.resolve(node.value.id))
            self.generic_visit(node)

        def visit_Call(self, node):
            targets = set()
            if isinstance(node.func, ast.Name):
                targets = self.resolve(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                targets = methods[node.func.attr]
            for target in targets:
                if target in classes:
                    target = f"{target}.__init__"
                    if target not in functions:
                        continue
                graph.add_edge(self.scope, target)
            self.generic_visit(node)

    Calls().visit(tree)
    return graph


def _analyze_function_calls(func_node, caller_name, function_names, graph):
    """Analyze function calls within a function definition."""
    # Use qualified name for the caller
    qualified_caller = f"main.{func_node.name}"

    for child in ast.walk(func_node):
        if isinstance(child, ast.Call):
            _analyze_call_node(child, qualified_caller, function_names, graph)


def _analyze_module_calls(module_node, caller_name, function_names, graph):
    """Analyze function calls at module level."""
    # Set parent references for easier navigation
    for child in ast.walk(module_node):
        child._parent = module_node

    for child in ast.iter_child_nodes(module_node):
        if isinstance(child, ast.Assign):
            # Handle cases like: a = func; a()()
            _analyze_assignment_and_call(child, caller_name, function_names, graph)
        elif isinstance(child, ast.Expr) and isinstance(child.value, ast.Call):
            # Handle direct calls like func()
            _analyze_call_node(child.value, caller_name, function_names, graph)


def _analyze_call_node(call_node, caller_name, function_names, graph):
    """Analyze a single call node and add edges to the graph."""
    if isinstance(call_node.func, ast.Name):
        # Direct function call like func()
        callee_name = call_node.func.id
        # Use qualified callee name
        qualified_callee = f"main.{callee_name}"
        if qualified_callee in function_names:
            graph.add_edge(caller_name, qualified_callee)
        elif callee_name in function_names:
            # Fallback to simple name for backwards compatibility
            graph.add_edge(caller_name, callee_name)
    elif isinstance(call_node.func, ast.Attribute):
        # Method call like obj.method()
        if isinstance(call_node.func.value, ast.Name):
            # This could be a module attribute access, skip for now
            pass


def _find_subsequent_calls(assign_node, var_name, func_name, caller_name, function_names, graph):
    """Find calls to a variable after it's been assigned a function."""
    parent = getattr(assign_node, "_parent", None)
    if parent and hasattr(parent, "body"):
        try:
            assign_idx = parent.body.index(assign_node)
            # Look at subsequent statements
            for i in range(assign_idx + 1, len(parent.body)):
                next_node = parent.body[i]
                if isinstance(next_node, ast.Expr) and isinstance(next_node.value, ast.Call):
                    call = next_node.value
                    if isinstance(call.func, ast.Name) and call.func.id == var_name:
                        # This is a call like a()
                        if not call.args and not call.keywords:
                            # Simple call like a() - treat as calling the assigned function
                            qualified_func = f"main.{func_name}"
                            if qualified_func in function_names:
                                graph.add_edge(caller_name, qualified_func)
                            else:
                                graph.add_edge(caller_name, func_name)
                        # Handle a()() pattern - the inner call returns a function
                        # that gets called by the outer call
                        if call.args and len(call.args) == 1 and isinstance(call.args[0], ast.Call):
                            inner_call = call.args[0]
                            if (
                                isinstance(inner_call.func, ast.Name)
                                and inner_call.func.id == var_name
                            ):
                                # This is a()() where a() returns a function that gets called
                                # The inner a() should call func_name
                                qualified_func = f"main.{func_name}"
                                if qualified_func in function_names:
                                    graph.add_edge(caller_name, qualified_func)
                                else:
                                    graph.add_edge(caller_name, func_name)
        except (ValueError, AttributeError):
            pass


def _analyze_assignment_and_call(assign_node, caller_name, function_names, graph):
    """Analyze assignment followed by calls, like a = func; a()()."""
    # Check if this is an assignment of a function to a variable
    for target in assign_node.targets:
        if isinstance(target, ast.Name) and isinstance(assign_node.value, ast.Name):
            var_name = target.id
            func_name = assign_node.value.id
            if func_name in function_names:
                # This is like: a = func
                # Mark this as a call from main to func
                # Try both simple and qualified function names
                qualified_func = f"main.{func_name}"
                if qualified_func in function_names:
                    graph.add_edge(caller_name, qualified_func)
                else:
                    graph.add_edge(caller_name, func_name)

                # Look for subsequent calls to this variable
                _find_subsequent_calls(
                    assign_node, var_name, func_name, caller_name, function_names, graph
                )


def analyze_file(filepath: str, *, format: str = "text") -> str:
    """Analyze a Python file and render text or a JSON adjacency map."""
    try:
        with open(filepath, "r") as f:
            source = f.read()
        from pathlib import Path

        graph = extract_call_graph(source, module_name=Path(filepath).stem)
        from .formats import generate_text_output, generate_adjacency_json

        if format == "json":
            return generate_adjacency_json(graph)
        return generate_text_output(graph, None)
    except Exception as e:
        return f"Error analyzing {filepath}: {e}"
