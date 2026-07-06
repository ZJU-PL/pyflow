"""
AST-based next()-on-non-iterator detector.

Detects patterns where ``next(var)`` is called on a variable that was
assigned directly from a parameter or another variable without first
wrapping it with ``iter()``.  When the value is a ``Sequence`` (has
``__getitem__``/``__len__`` but NOT ``__next__``), calling ``next()``
raises ``TypeError``.

Key bug pattern (BugsInPy keras#34):
    def fit_generator(self, generator, ...):
        ...
        output_generator = generator   # Sequence, not an iterator
        ...
        generator_output = next(output_generator)  # TypeError!

Fix pattern:
    if isinstance(generator, Sequence):
        output_generator = iter(generator)
    else:
        output_generator = generator
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set


@dataclass
class NextOnNonIteratorBug:
    """A next()-on-non-iterator bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'next_on_non_iterator'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_next_on_non_iterator_bugs(file_path: Path) -> List[NextOnNonIteratorBug]:
    """Scan a single Python file for next()-on-non-iterator patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _NextOnNonIteratorVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


class _NextOnNonIteratorVisitor(ast.NodeVisitor):
    """AST visitor detecting next() calls on variables not wrapped with iter()."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[NextOnNonIteratorBug] = []
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
        old_func = self._current_function
        if self._current_class:
            self._current_function = f"{self._current_class}.{node.name}"
        else:
            self._current_function = node.name

        # Collect parameter names
        param_names: Set[str] = set()
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            param_names.add(arg.arg)
        if node.args.vararg:
            param_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            param_names.add(node.args.kwarg.arg)

        self._analyze_function_body(node.body, param_names)
        self._current_function = old_func

    def _analyze_function_body(
        self, body: list, param_names: Set[str]
    ):
        """Analyze a function body for next()-on-non-iterator patterns.

        Tracks variables that are directly assigned from parameters (or from
        other param-derived variables) and checks if ``next()`` is called on
        them without a prior ``iter()`` wrapping or ``isinstance`` guard.
        """
        # Map variable -> set of source param names it flows from
        param_derived: dict[str, Set[str]] = {}
        # Track variables that have been wrapped with iter()
        iter_wrapped: Set[str] = set()
        # Track variables guarded by isinstance checks
        isinstance_guarded: Set[str] = set()

        all_stmts = list(_flatten_stmts(body))

        # First pass: collect assignments and iter()/isinstance guards
        for stmt in all_stmts:
            # Track direct assignments: var = param  or  var = other_param_derived
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if isinstance(target, ast.Name):
                    var_name = target.id
                    # var = param
                    if isinstance(stmt.value, ast.Name):
                        src = stmt.value.id
                        if src in param_names:
                            param_derived[var_name] = {src}
                        elif src in param_derived:
                            param_derived[var_name] = param_derived[src].copy()
                    # var = iter(x) — marks var as iter-wrapped
                    elif _is_iter_call(stmt.value):
                        iter_wrapped.add(var_name)
                        # Also clear param_derived since iter() produces iterator
                        param_derived.pop(var_name, None)

            # Track isinstance guards
            if isinstance(stmt, ast.If):
                guarded = _extract_isinstance_guarded_vars(stmt.test)
                isinstance_guarded.update(guarded)

        # Second pass: find next() calls on param-derived, non-iter-wrapped vars
        reported: Set[tuple] = set()  # (line, var) to deduplicate
        for stmt in all_stmts:
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call):
                    continue
                target_var = _extract_next_call_arg(node)
                if target_var is None:
                    continue

                # Deduplicate by (line, variable)
                key = (node.lineno, target_var)
                if key in reported:
                    continue

                # Is target_var param-derived and NOT iter-wrapped?
                if target_var not in param_derived:
                    continue
                if target_var in iter_wrapped:
                    continue
                if target_var in isinstance_guarded:
                    continue
                # Also check if the source param itself is isinstance-guarded
                source_params = param_derived[target_var]
                if source_params & isinstance_guarded:
                    continue

                reported.add(key)
                source_desc = ', '.join(sorted(source_params))
                self.bugs.append(NextOnNonIteratorBug(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    function_name=self._current_function or '<module>',
                    pattern='next_on_non_iterator',
                    reason=(
                        f"next({target_var}) is called but '{target_var}' "
                        f"was assigned directly from parameter '{source_desc}' "
                        f"without calling iter() first. If the argument is a "
                        f"Sequence (has __getitem__/__len__ but not __next__), "
                        f"this raises TypeError."
                    ),
                    confidence=0.70,
                    variable=target_var,
                ))

        self._current_function = self._current_function  # Keep for recursion


# ======================================================================
# Helpers
# ======================================================================

def _flatten_stmts(stmts: list):
    """Yield all statements from a block, recursing into compound statements."""
    for stmt in stmts:
        yield stmt
        if isinstance(stmt, ast.If):
            yield from _flatten_stmts(stmt.body)
            yield from _flatten_stmts(stmt.orelse)
        elif isinstance(stmt, (ast.For, ast.While)):
            yield from _flatten_stmts(stmt.body)
            yield from _flatten_stmts(stmt.orelse)
        elif isinstance(stmt, ast.With):
            yield from _flatten_stmts(stmt.body)
        elif isinstance(stmt, ast.Try):
            yield from _flatten_stmts(stmt.body)
            for handler in stmt.handlers:
                yield from _flatten_stmts(handler.body)
            yield from _flatten_stmts(stmt.orelse)
            yield from _flatten_stmts(stmt.finalbody)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Don't recurse into nested functions
            pass


def _is_iter_call(node: ast.expr) -> bool:
    """Return True if *node* is ``iter(x)``."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == 'iter'
        and len(node.args) >= 1
    )


def _extract_next_call_arg(node: ast.Call) -> Optional[str]:
    """If *node* is ``next(var)``, return the variable name."""
    func = node.func
    if not (isinstance(func, ast.Name) and func.id == 'next'):
        return None
    if len(node.args) != 1:
        return None
    arg = node.args[0]
    if isinstance(arg, ast.Name):
        return arg.id
    return None


def _extract_isinstance_guarded_vars(test: ast.expr) -> Set[str]:
    """Extract variable names guarded by isinstance() in a test expression.

    Handles:
    - isinstance(var, Type)
    - isinstance(var, Type) and ...
    - not isinstance(var, Type)
    """
    guarded: Set[str] = set()

    if isinstance(test, ast.Call):
        func = test.func
        if isinstance(func, ast.Name) and func.id == 'isinstance':
            if len(test.args) >= 1 and isinstance(test.args[0], ast.Name):
                guarded.add(test.args[0].id)

    elif isinstance(test, ast.BoolOp):
        for value in test.values:
            guarded.update(_extract_isinstance_guarded_vars(value))

    elif isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        guarded.update(_extract_isinstance_guarded_vars(test.operand))

    return guarded
