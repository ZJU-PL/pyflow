"""
AST-based maketrans length-mismatch detector.

Detects patterns where ``maketrans(a, b)`` is called with two string arguments
whose lengths are not guaranteed to match, leading to ``ValueError``.

Key bug pattern (BugsInPy keras#33):
    translate_map = maketrans(filters, split * len(filters))

The two-argument form of ``str.maketrans`` / ``string.maketrans`` requires
both arguments to have equal length.  When the second argument is built via
``var * len(first_arg)``, the lengths match **only** when ``len(var) == 1``.
If ``var`` originates from a function parameter (and therefore may be
multi-character), the call can crash at runtime.

The fix either:
  - Guards with ``len(var) == 1`` before calling the two-arg form, or
  - Uses the single-arg dict form ``maketrans({c: replacement for c in …})``.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set


@dataclass
class MaketransMisuseBug:
    """A maketrans length-mismatch bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'maketrans_length_mismatch'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_maketrans_misuse_bugs(file_path: Path) -> List[MaketransMisuseBug]:
    """Scan a single Python file for maketrans length-mismatch patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return []

    visitor = _MaketransMisuseVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

class _MaketransMisuseVisitor(ast.NodeVisitor):
    """Visits functions looking for two-arg maketrans with length mismatch."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[MaketransMisuseBug] = []
        self._current_function: Optional[str] = None
        self._current_func_node = None
        self._current_params: Set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def _visit_func(self, node):
        old_func = self._current_function
        old_params = self._current_params
        old_node = self._current_func_node

        self._current_function = node.name
        self._current_func_node = node
        self._current_params = {
            arg.arg for arg in node.args.args
        }
        # Include *args and **kwargs names
        if node.args.vararg:
            self._current_params.add(node.args.vararg.arg)
        if node.args.kwarg:
            self._current_params.add(node.args.kwarg.arg)

        self.generic_visit(node)

        self._current_function = old_func
        self._current_params = old_params
        self._current_func_node = old_node

    def visit_Call(self, node: ast.Call) -> None:
        if self._current_function and self._is_maketrans_call(node):
            self._check_maketrans(node)
        self.generic_visit(node)

    # -- helpers --

    @staticmethod
    def _is_maketrans_call(node: ast.Call) -> bool:
        """Return True if *node* is a call to ``maketrans``."""
        func = node.func
        # Direct: maketrans(...)
        if isinstance(func, ast.Name) and func.id == 'maketrans':
            return True
        # Attribute: str.maketrans(...) or string.maketrans(...)
        if isinstance(func, ast.Attribute) and func.attr == 'maketrans':
            if isinstance(func.value, ast.Name) and func.value.id in ('str', 'string'):
                return True
        return False

    def _check_maketrans(self, node: ast.Call) -> None:
        """Check a maketrans call for the length-mismatch pattern."""
        # Only the two-argument form has the equal-length requirement.
        if len(node.args) != 2:
            return

        second_arg = node.args[1]

        # Pattern: var * expr  (BinOp with Mult)
        if not isinstance(second_arg, ast.BinOp):
            return
        if not isinstance(second_arg.op, ast.Mult):
            return

        # Identify the "repeated" variable (the one whose length must be 1).
        repeat_var = self._extract_var_name(second_arg.left)
        if repeat_var is None:
            # Maybe the operands are swapped: expr * var
            repeat_var = self._extract_var_name(second_arg.right)

        if repeat_var is None:
            return

        # Only flag when the variable comes from a function parameter (hence
        # its length is not locally guaranteed).
        if repeat_var not in self._current_params:
            return

        # Check whether there is a dominating guard ``len(var) == 1``.
        if self._has_length_guard(repeat_var):
            return

        first_arg_name = self._extract_var_name(node.args[0]) or '<expr>'
        self.bugs.append(MaketransMisuseBug(
            file_path=self.file_path,
            line_number=node.lineno,
            function_name=self._current_function or '<module>',
            pattern='maketrans_length_mismatch',
            reason=(
                f"maketrans({first_arg_name}, {repeat_var} * len({first_arg_name})) "
                f"requires len({repeat_var}) == 1. "
                f"Parameter '{repeat_var}' may be multi-character, causing "
                f"ValueError at runtime. Add a guard for len({repeat_var}) == 1 "
                f"or use the single-argument dict form of maketrans."
            ),
            confidence=0.80,
            variable=repeat_var,
        ))

    @staticmethod
    def _extract_var_name(node) -> Optional[str]:
        """Extract a simple variable name from an AST node, if possible."""
        if isinstance(node, ast.Name):
            return node.id
        return None

    def _has_length_guard(self, var_name: str) -> bool:
        """Check if the current function has a ``len(var) == 1`` guard."""
        if self._current_func_node is None:
            return False
        for node in ast.walk(self._current_func_node):
            if isinstance(node, ast.If):
                if _if_has_length_guard(node, var_name):
                    return True
        return False


def _if_has_length_guard(if_node: ast.If, var_name: str) -> bool:
    """Check whether an ``if`` test is ``len(var) == 1`` or similar."""
    return _test_checks_length(if_node.test, var_name)


def _test_checks_length(test: ast.expr, var_name: str) -> bool:
    """Return True if *test* constrains ``len(var_name)``."""
    # len(var) == 1, len(var) != 1, len(var) > 1, etc.
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        left = test.left
        if _is_len_call_of(left, var_name):
            return True
        if test.comparators and _is_len_call_of(test.comparators[0], var_name):
            return True

    # BoolOp: ... and len(var) == 1
    if isinstance(test, ast.BoolOp):
        return any(_test_checks_length(v, var_name) for v in test.values)

    # not <expr>
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _test_checks_length(test.operand, var_name)

    return False


def _is_len_call_of(node, var_name: str) -> bool:
    """Return True if *node* is ``len(var_name)``."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == 'len':
            if node.args and isinstance(node.args[0], ast.Name):
                return node.args[0].id == var_name
    return False
