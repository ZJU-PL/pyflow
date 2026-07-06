"""
AST-based str.find() result misuse detector.

Detects patterns where str.find() returns -1 (not found) and the result
is used with an incorrect fallback in string slicing, leading to incorrect
slice bounds.

Key bug pattern (BugsInPy keras#9):
    ending_point = docstring.find('\\n\\n', starting_point)
    block = docstring[starting_point:(None if ending_point == -1 else
                                      ending_point - 1)]

The bug: when find() returns -1, using None as slice end means "to end of
string", which can exceed the intended boundary (section_end). The fix uses
section_end instead of None as the fallback.

More generally, this detects:
- find() result checked against -1 in a conditional
- The -1 branch uses None as a slice bound (unbounded slicing)
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set


@dataclass
class FindResultMisuseBug:
    """A find-result-misuse bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'find_none_slice_fallback'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_find_result_misuse_bugs(file_path: Path) -> List[FindResultMisuseBug]:
    """Scan a single Python file for str.find() result misuse patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _FindResultMisuseVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


class _FindResultMisuseVisitor(ast.NodeVisitor):
    """Visits functions looking for find() result misused in slicing."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[FindResultMisuseBug] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def _check_function(self, func_node: ast.FunctionDef) -> None:
        """Check a single function for find-result misuse patterns."""
        # Step 1: Find variables assigned from .find() calls
        find_vars: Set[str] = set()
        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and _is_find_call(node.value):
                    find_vars.add(target.id)

        if not find_vars:
            return

        # Step 2: Look for conditional expressions (ternary) that check
        # a find-var against -1 and use None as a fallback for slicing
        for node in ast.walk(func_node):
            if not isinstance(node, ast.Subscript):
                continue
            # Check if the slice uses a conditional with find-var and None
            bug_info = self._check_subscript_for_find_misuse(
                node, find_vars, func_node.name
            )
            if bug_info:
                self.bugs.append(bug_info)

    def _check_subscript_for_find_misuse(
        self,
        subscript: ast.Subscript,
        find_vars: Set[str],
        func_name: str,
    ) -> Optional[FindResultMisuseBug]:
        """Check if a subscript uses a find-var conditional with None fallback."""
        slice_node = subscript.slice

        # Handle Slice node: obj[start:end] where end might be conditional
        if isinstance(slice_node, ast.Slice):
            for bound in (slice_node.lower, slice_node.upper):
                result = self._check_ifexp_for_find_none(bound, find_vars)
                if result:
                    find_var = result
                    return FindResultMisuseBug(
                        file_path=self.file_path,
                        line_number=subscript.lineno,
                        function_name=func_name,
                        pattern='find_none_slice_fallback',
                        reason=(
                            f"str.find() result '{find_var}' used in slice with "
                            f"None fallback when find returns -1. None means "
                            f"'to end of string' which may exceed the intended "
                            f"boundary. Use an explicit bound instead of None."
                        ),
                        confidence=0.85,
                        variable=find_var,
                    )

        # Also check if the slice itself is a conditional (non-slice subscript)
        result = self._check_ifexp_for_find_none(slice_node, find_vars)
        if result:
            find_var = result
            return FindResultMisuseBug(
                file_path=self.file_path,
                line_number=subscript.lineno,
                function_name=func_name,
                pattern='find_none_slice_fallback',
                reason=(
                    f"str.find() result '{find_var}' used in subscript with "
                    f"None fallback when find returns -1."
                ),
                confidence=0.85,
                variable=find_var,
            )

        return None

    def _check_ifexp_for_find_none(
        self, node: Optional[ast.expr], find_vars: Set[str]
    ) -> Optional[str]:
        """Check if an expression is a conditional that uses a find-var
        with None as the -1 fallback.

        Patterns matched:
          - None if var == -1 else expr     (None in body, -1 check)
          - expr if var != -1 else None     (None in orelse, != -1 check)
          - expr if var > -1 else None      (None in orelse, > -1 check)
        """
        if not isinstance(node, ast.IfExp):
            return None

        test = node.test
        body = node.body
        orelse = node.orelse

        # Extract the find-var and which branch has None
        find_var = self._extract_find_var_from_compare(test, find_vars)
        if find_var is None:
            return None

        cmp_kind = self._get_compare_kind(test, find_var)

        # Pattern: (None if var == -1 else expr)
        if cmp_kind == 'eq_neg1' and _is_none(body):
            return find_var

        # Pattern: (expr if var != -1 else None)
        if cmp_kind == 'neq_neg1' and _is_none(orelse):
            return find_var

        # Pattern: (expr if var > -1 else None)
        if cmp_kind == 'gt_neg1' and _is_none(orelse):
            return find_var

        # Pattern: (expr if var >= 0 else None)
        if cmp_kind == 'gte_zero' and _is_none(orelse):
            return find_var

        return None

    def _extract_find_var_from_compare(
        self, test: ast.expr, find_vars: Set[str]
    ) -> Optional[str]:
        """Extract the find-variable from a comparison expression."""
        if not isinstance(test, ast.Compare) or len(test.ops) != 1:
            return None

        left = test.left
        comparator = test.comparators[0]

        # Check if left is a find-var
        if isinstance(left, ast.Name) and left.id in find_vars:
            return left.id
        # Check if comparator is a find-var (e.g., -1 == var)
        if isinstance(comparator, ast.Name) and comparator.id in find_vars:
            return comparator.id

        return None

    def _get_compare_kind(
        self, test: ast.Compare, find_var: str
    ) -> Optional[str]:
        """Determine the kind of comparison (eq_neg1, neq_neg1, etc.)."""
        if not isinstance(test, ast.Compare) or len(test.ops) != 1:
            return None

        op = test.ops[0]
        left = test.left
        comparator = test.comparators[0]

        # Normalize: ensure find_var is on the left
        if isinstance(comparator, ast.Name) and comparator.id == find_var:
            # Swap and mirror the operator
            left, comparator = comparator, left
            op = _mirror_op(op)

        if not (isinstance(left, ast.Name) and left.id == find_var):
            return None

        # Check what we're comparing against
        if _is_neg_one(comparator):
            if isinstance(op, ast.Eq):
                return 'eq_neg1'
            elif isinstance(op, ast.NotEq):
                return 'neq_neg1'
            elif isinstance(op, ast.Gt):
                return 'gt_neg1'
            elif isinstance(op, ast.GtE):
                return 'gte_neg1'
        elif _is_zero(comparator):
            if isinstance(op, ast.GtE):
                return 'gte_zero'

        return None


def _is_find_call(node: ast.expr) -> bool:
    """Check if an expression is a .find() or .rfind() method call."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in ('find', 'rfind'):
        return True
    return False


def _is_none(node: Optional[ast.expr]) -> bool:
    """Check if an AST node represents None."""
    if node is None:
        return False
    if isinstance(node, ast.Constant) and node.value is None:
        return True
    if isinstance(node, ast.Name) and node.id == 'None':
        return True
    return False


def _is_neg_one(node: ast.expr) -> bool:
    """Check if an AST node represents -1."""
    # Literal -1
    if isinstance(node, ast.Constant) and node.value == -1:
        return True
    # UnaryOp: -1 as USub(1)
    if (isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub)
            and isinstance(node.operand, ast.Constant)
            and node.operand.value == 1):
        return True
    return False


def _is_zero(node: ast.expr) -> bool:
    """Check if an AST node represents 0."""
    return isinstance(node, ast.Constant) and node.value == 0


def _mirror_op(op: ast.cmpop) -> ast.cmpop:
    """Mirror a comparison operator (for swapping left/right)."""
    mirrors = {
        ast.Lt: ast.Gt,
        ast.Gt: ast.Lt,
        ast.LtE: ast.GtE,
        ast.GtE: ast.LtE,
        ast.Eq: ast.Eq,
        ast.NotEq: ast.NotEq,
    }
    return mirrors.get(type(op), op)()
