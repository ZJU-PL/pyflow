"""
AST-based inconsistent comparison operator detector.

Detects classes where rich comparison methods (__lt__, __gt__, __le__, __ge__)
are implemented with incorrect logical relationships, which can cause
ValueErrors or incorrect ordering behavior.

Key bug pattern (BugsInPy ansible#2):
    class _Alpha:
        def __lt__(self, other):
            ...

        # BUG: not __lt__ == __ge__, NOT __gt__
        def __gt__(self, other):
            return not self.__lt__(other)

        # FIX:
        def __gt__(self, other):
            return not self.__le__(other)

When a == b, a.__lt__(b) is False, so `not a.__lt__(b)` is True,
but a.__gt__(b) should be False.  This inconsistency can cause
ValueError, infinite loops in sorting, or wrong results.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class ComparisonOperatorBug:
    """An inconsistent comparison operator bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'gt_negates_lt', 'ge_uses_gt_or_eq'
    reason: str
    confidence: float
    class_name: Optional[str] = None


def scan_file_for_comparison_operator_bugs(file_path: Path) -> List[ComparisonOperatorBug]:
    """Scan a single Python file for inconsistent comparison operator patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _ComparisonOperatorVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


class _ComparisonOperatorVisitor(ast.NodeVisitor):
    """AST visitor that detects inconsistent comparison operator implementations."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[ComparisonOperatorBug] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        methods = {}
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name in ('__lt__', '__gt__', '__le__', '__ge__', '__eq__', '__ne__'):
                    methods[item.name] = item

        # Pattern 1: __gt__ defined as `not self.__lt__(other)`
        # This is wrong: not(__lt__) == __ge__, not __gt__
        if '__gt__' in methods and '__lt__' in methods:
            gt_node = methods['__gt__']
            if self._is_negation_of_dunder_call(gt_node, '__lt__'):
                self.bugs.append(ComparisonOperatorBug(
                    file_path=self.file_path,
                    line_number=gt_node.lineno,
                    function_name=f"{node.name}.__gt__",
                    pattern='gt_negates_lt',
                    reason=(
                        f"Class '{node.name}' defines __gt__ as 'not self.__lt__(other)'. "
                        f"This is logically __ge__, not __gt__. "
                        f"When a == b, a.__lt__(b) is False so not __lt__ is True, "
                        f"but a.__gt__(b) should be False. "
                        f"Fix: use 'not self.__le__(other)' instead."
                    ),
                    confidence=0.9,
                    class_name=node.name,
                ))

        # Pattern 2: __ge__ defined as `self.__gt__(other) or self.__eq__(other)`
        # when __gt__ is itself `not self.__lt__` — compounding the error
        if '__ge__' in methods and '__gt__' in methods:
            ge_node = methods['__ge__']
            if self._is_or_of_dunder_calls(ge_node, '__gt__', '__eq__'):
                # This is only a bug when __gt__ is also wrong
                if '__gt__' in methods and self._is_negation_of_dunder_call(methods['__gt__'], '__lt__'):
                    self.bugs.append(ComparisonOperatorBug(
                        file_path=self.file_path,
                        line_number=ge_node.lineno,
                        function_name=f"{node.name}.__ge__",
                        pattern='ge_uses_gt_or_eq',
                        reason=(
                            f"Class '{node.name}' defines __ge__ as "
                            f"'self.__gt__(other) or self.__eq__(other)' "
                            f"while __gt__ is incorrectly defined as 'not self.__lt__(other)'. "
                            f"Fix: use 'not self.__lt__(other)' for __ge__."
                        ),
                        confidence=0.85,
                        class_name=node.name,
                    ))

        # Pattern 3: __le__ defined as `not self.__gt__(other)` (symmetric error)
        if '__le__' in methods and '__gt__' in methods:
            le_node = methods['__le__']
            if self._is_negation_of_dunder_call(le_node, '__gt__'):
                # not(__gt__) == __le__ only when __gt__ is correct;
                # this is actually valid. But flag if __gt__ is already buggy.
                if '__gt__' in methods and self._is_negation_of_dunder_call(methods['__gt__'], '__lt__'):
                    self.bugs.append(ComparisonOperatorBug(
                        file_path=self.file_path,
                        line_number=le_node.lineno,
                        function_name=f"{node.name}.__le__",
                        pattern='le_negates_buggy_gt',
                        reason=(
                            f"Class '{node.name}' defines __le__ as 'not self.__gt__(other)' "
                            f"while __gt__ is incorrectly 'not self.__lt__(other)'. "
                            f"This compounds the comparison inconsistency."
                        ),
                        confidence=0.8,
                        class_name=node.name,
                    ))

        self.generic_visit(node)

    def _is_negation_of_dunder_call(self, func_node: ast.FunctionDef, target_method: str) -> bool:
        """Check if function body is `return not self.<target_method>(other)`."""
        body = self._get_effective_body(func_node)
        if not body:
            return False

        stmt = body[-1]
        if not isinstance(stmt, ast.Return) or stmt.value is None:
            return False

        return self._expr_is_not_self_call(stmt.value, target_method)

    def _expr_is_not_self_call(self, expr: ast.expr, target_method: str) -> bool:
        """Check if expr matches `not self.<target_method>(other)`."""
        if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
            return self._expr_is_self_call(expr.operand, target_method)
        return False

    def _expr_is_self_call(self, expr: ast.expr, target_method: str) -> bool:
        """Check if expr matches `self.<target_method>(...)`."""
        if not isinstance(expr, ast.Call):
            return False
        func = expr.func
        if not isinstance(func, ast.Attribute):
            return False
        if func.attr != target_method:
            return False
        if not isinstance(func.value, ast.Name):
            return False
        if func.value.id != 'self':
            return False
        return True

    def _is_or_of_dunder_calls(
        self, func_node: ast.FunctionDef, method_a: str, method_b: str
    ) -> bool:
        """Check if function body is `return self.<a>(other) or self.<b>(other)`."""
        body = self._get_effective_body(func_node)
        if not body:
            return False

        stmt = body[-1]
        if not isinstance(stmt, ast.Return) or stmt.value is None:
            return False

        expr = stmt.value
        if not isinstance(expr, ast.BoolOp) or not isinstance(expr.op, ast.Or):
            return False

        if len(expr.values) != 2:
            return False

        a_match = self._expr_is_self_call(expr.values[0], method_a)
        b_match = self._expr_is_self_call(expr.values[1], method_b)
        return a_match and b_match

    def _get_effective_body(self, func_node: ast.FunctionDef) -> list:
        """Get the effective body of a function, skipping docstrings."""
        body = func_node.body
        if not body:
            return []
        # Skip leading docstring
        start = 0
        if (isinstance(body[0], ast.Expr) and
                isinstance(body[0].value, (ast.Constant, ast.Str))):
            start = 1
        return body[start:]
