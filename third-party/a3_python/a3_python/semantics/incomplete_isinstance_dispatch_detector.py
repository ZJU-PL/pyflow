"""
AST-based detector for incomplete isinstance dispatch in loops.

Detects patterns where a for-loop iterates over a collection attribute and
uses isinstance to handle some types but silently ignores others.

Key bug pattern (BugsInPy fastapi#15):
    # BUGGY: handles APIRoute but silently drops WebSocketRoute
    for route in router.routes:
        if isinstance(route, APIRoute):
            self.add_api_route(prefix + route.path, route.endpoint, ...)
        # No elif/else for other route types!

    # FIXED: adds elif for WebSocketRoute
    for route in router.routes:
        if isinstance(route, APIRoute):
            self.add_api_route(prefix + route.path, route.endpoint, ...)
        elif isinstance(route, routing.WebSocketRoute):
            self.add_websocket_route(prefix + route.path, route.endpoint, ...)
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set


@dataclass
class IncompleteIsinstanceDispatchBug:
    """A bug found via AST incomplete isinstance dispatch analysis."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'incomplete_isinstance_dispatch'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_incomplete_isinstance_dispatch_bugs(
    file_path: Path,
) -> List[IncompleteIsinstanceDispatchBug]:
    """Scan a Python file for incomplete isinstance dispatch in loops."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return []

    tree = None
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        pass

    if tree is None:
        try:
            from ..cfg.call_graph import _try_parse_multi_hunk
            tree = _try_parse_multi_hunk(source, str(file_path))
        except Exception:
            pass

    if tree is None:
        return []

    visitor = _IncompleteDispatchVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


class _IncompleteDispatchVisitor(ast.NodeVisitor):
    """AST visitor detecting incomplete isinstance dispatch in for-loops."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[IncompleteIsinstanceDispatchBug] = []
        self._current_function: Optional[str] = None
        self._current_class: Optional[str] = None

    def visit_ClassDef(self, node: ast.ClassDef):
        old = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_func(node)

    def _visit_func(self, node):
        old = self._current_function
        if self._current_class:
            self._current_function = f"{self._current_class}.{node.name}"
        else:
            self._current_function = node.name
        self._check_for_loops(node.body)
        self.generic_visit(node)
        self._current_function = old

    def _check_for_loops(self, stmts: list):
        """Find for-loops with incomplete isinstance dispatch."""
        for stmt in stmts:
            if isinstance(stmt, ast.For):
                self._analyze_for_loop(stmt)
            # Recurse into nested blocks
            if isinstance(stmt, (ast.For, ast.While)):
                self._check_for_loops(stmt.body)
                self._check_for_loops(stmt.orelse)
            elif isinstance(stmt, ast.If):
                self._check_for_loops(stmt.body)
                self._check_for_loops(stmt.orelse)
            elif isinstance(stmt, ast.With):
                self._check_for_loops(stmt.body)
            elif isinstance(stmt, ast.Try):
                self._check_for_loops(stmt.body)
                for handler in stmt.handlers:
                    self._check_for_loops(handler.body)
                self._check_for_loops(stmt.orelse)
                self._check_for_loops(stmt.finalbody)

    def _analyze_for_loop(self, for_node: ast.For):
        """Analyze a for-loop for incomplete isinstance dispatch."""
        loop_var = _extract_loop_var_name(for_node.target)
        if not loop_var:
            return

        # The iterable should be an attribute access (obj.routes, obj.items, etc.)
        # to suggest a heterogeneous collection
        collection_name = _extract_collection_source(for_node.iter)
        if not collection_name:
            return

        # Find the top-level isinstance-guarded if-statements in the loop body
        isinstance_info = self._find_isinstance_dispatch(for_node.body, loop_var)
        if not isinstance_info:
            return

        checked_types, has_else, has_else_work, branch_count, if_node = isinstance_info

        # Must have at least one isinstance check but no else clause (or empty else)
        if has_else and has_else_work:
            return  # else clause handles remaining types

        # If there are 2+ isinstance branches, the developer is aware of type
        # diversity — much less likely to be a bug
        if branch_count >= 2:
            return

        # The isinstance branch must do significant work (not just pass/continue)
        if not self._branch_does_significant_work(if_node.body):
            return

        # The loop body shouldn't have significant work outside the isinstance
        # chain — if it does, items aren't "silently dropped"
        if self._has_significant_work_outside_isinstance(for_node.body, if_node):
            return

        checked_str = ", ".join(sorted(checked_types))
        self.bugs.append(IncompleteIsinstanceDispatchBug(
            file_path=self.file_path,
            line_number=for_node.lineno,
            function_name=self._current_function or "<module>",
            pattern="incomplete_isinstance_dispatch",
            reason=(
                f"For-loop iterates over '{collection_name}' and handles "
                f"isinstance({loop_var}, {checked_str}) but has no "
                f"else/elif branch for other types. Items of unhandled "
                f"types are silently ignored."
            ),
            confidence=0.55,
            variable=loop_var,
        ))

    def _find_isinstance_dispatch(self, stmts: list, loop_var: str):
        """Find isinstance-based dispatch on loop_var in statements.

        Returns (checked_types, has_else, has_else_work, isinstance_branch_count, if_node) or None.
        """
        for stmt in stmts:
            if not isinstance(stmt, ast.If):
                continue

            # Check if the top-level if is isinstance(loop_var, ...)
            checked = _extract_isinstance_types(stmt.test, loop_var)
            if not checked:
                continue

            # Walk elif chain to collect all checked types
            all_checked = set(checked)
            isinstance_branch_count = 1
            current = stmt
            while current.orelse and len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                elif_node = current.orelse[0]
                elif_checked = _extract_isinstance_types(elif_node.test, loop_var)
                if elif_checked:
                    isinstance_branch_count += 1
                    all_checked.update(elif_checked)
                current = elif_node

            # Determine if there's an effective else clause
            has_else = bool(current.orelse)
            has_else_work = has_else and _has_meaningful_statements(current.orelse)

            return all_checked, has_else, has_else_work, isinstance_branch_count, stmt

        return None

    @staticmethod
    def _branch_does_significant_work(stmts: list) -> bool:
        """Check if a branch body does significant work (method calls, etc.)."""
        for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if isinstance(node, ast.Call):
                return True
            if isinstance(node, ast.Assign) and not isinstance(node.value, ast.Constant):
                return True
        return False

    @staticmethod
    def _has_significant_work_outside_isinstance(stmts: list, isinstance_if: ast.If) -> bool:
        """Check if the loop body has significant work outside the isinstance if.

        If there is, items aren't truly "silently dropped" — they just skip the
        isinstance-specific processing but still go through other code.
        """
        for stmt in stmts:
            if stmt is isinstance_if:
                continue
            # Skip simple assignments, pass, continue, comments
            if isinstance(stmt, ast.Pass):
                continue
            if isinstance(stmt, ast.Continue):
                continue
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                continue  # docstring/comment
            # Any other statement means items aren't silently dropped
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    return True
                if isinstance(node, ast.Assign):
                    return True
                if isinstance(node, ast.AugAssign):
                    return True
        return False


def _extract_loop_var_name(target: ast.expr) -> Optional[str]:
    """Extract the loop variable name from a for-loop target."""
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Tuple) and len(target.elts) == 2:
        if isinstance(target.elts[1], ast.Name):
            return target.elts[1].id
    return None


def _extract_collection_source(iter_expr: ast.expr) -> Optional[str]:
    """Extract a description of the collection being iterated.

    Returns a string like 'router.routes' or 'self.items' for attribute
    accesses, or None if the iterable is not an attribute/method access.
    """
    # Direct attribute: obj.attr
    if isinstance(iter_expr, ast.Attribute):
        owner = _expr_to_name(iter_expr.value)
        if owner:
            return f"{owner}.{iter_expr.attr}"
        return iter_expr.attr

    # Method call: obj.method() or func(obj.attr)
    if isinstance(iter_expr, ast.Call):
        if isinstance(iter_expr.func, ast.Attribute):
            owner = _expr_to_name(iter_expr.func.value)
            if owner:
                return f"{owner}.{iter_expr.func.attr}()"
        # list(obj.attr), iter(obj.attr), etc.
        if (isinstance(iter_expr.func, ast.Name)
                and iter_expr.func.id in ('list', 'iter', 'tuple', 'sorted', 'reversed')
                and len(iter_expr.args) == 1):
            return _extract_collection_source(iter_expr.args[0])

    return None


def _expr_to_name(expr: ast.expr) -> Optional[str]:
    """Convert a simple expression to a dotted name string."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = _expr_to_name(expr.value)
        if base:
            return f"{base}.{expr.attr}"
    return None


def _extract_isinstance_types(test: ast.expr, var_name: str) -> Optional[Set[str]]:
    """Extract type names from isinstance(var_name, T) in an if-test.

    Handles:
      isinstance(x, Foo)
      isinstance(x, (Foo, Bar))
      isinstance(x, Foo) and ...
      isinstance(x, module.Foo)

    Returns set of type names or None if test doesn't check var_name.
    """
    # Direct isinstance call
    if isinstance(test, ast.Call):
        if (isinstance(test.func, ast.Name)
                and test.func.id == 'isinstance'
                and len(test.args) >= 2):
            first_arg = test.args[0]
            if isinstance(first_arg, ast.Name) and first_arg.id == var_name:
                return _extract_type_names(test.args[1])

    # BoolOp: isinstance(x, Foo) and/or ...
    if isinstance(test, ast.BoolOp):
        for value in test.values:
            result = _extract_isinstance_types(value, var_name)
            if result:
                return result

    # Not: not isinstance(x, Foo)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _extract_isinstance_types(test.operand, var_name)

    return None


def _extract_type_names(type_arg: ast.expr) -> Set[str]:
    """Extract type names from the second arg of isinstance()."""
    names: Set[str] = set()
    if isinstance(type_arg, ast.Name):
        names.add(type_arg.id)
    elif isinstance(type_arg, ast.Attribute):
        # module.ClassName -> use just the class name
        names.add(type_arg.attr)
    elif isinstance(type_arg, ast.Tuple):
        for elt in type_arg.elts:
            if isinstance(elt, ast.Name):
                names.add(elt.id)
            elif isinstance(elt, ast.Attribute):
                names.add(elt.attr)
    return names


def _has_meaningful_statements(stmts: list) -> bool:
    """Check if a list of statements does meaningful work (not just pass)."""
    for stmt in stmts:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue  # docstring
        return True
    return False
