"""
AST-based hasattr-without-type-check detector.

Detects patterns where ``hasattr(obj, 'attr')`` guards attribute existence
but the code inside the guarded branch passes ``obj.attr`` to a function
call without checking its type via ``isinstance``.

Key bug pattern (BugsInPy keras#24):
    if hasattr(layer, 'output'):
        tf.summary.histogram('{}_out'.format(layer.name), layer.output)

``layer.output`` may be a ``list`` (multi-output layers) or a single tensor.
Passing a list where a scalar is expected causes ``TypeError``.

Fix pattern:
    if hasattr(layer, 'output'):
        if isinstance(layer.output, list):
            for i, output in enumerate(layer.output):
                tf.summary.histogram(...)
        else:
            tf.summary.histogram(...)
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple


@dataclass
class HasattrTypeCheckBug:
    """A hasattr-without-type-check bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'hasattr_no_isinstance'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_hasattr_type_check_bugs(file_path: Path) -> List[HasattrTypeCheckBug]:
    """Scan a single Python file for hasattr-without-type-check patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _HasattrTypeCheckVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


class _HasattrTypeCheckVisitor(ast.NodeVisitor):
    """AST visitor detecting missing isinstance guard inside hasattr blocks."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[HasattrTypeCheckBug] = []
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
        self._scan_stmts(node.body)
        self._current_function = old

    # ------------------------------------------------------------------

    def _scan_stmts(self, stmts: list):
        """Walk statements looking for ``if hasattr(obj, 'attr'):`` blocks."""
        for stmt in stmts:
            if isinstance(stmt, ast.If):
                result = _extract_hasattr(stmt.test)
                if result:
                    obj_name, attr_name = result
                    self._check_guarded_body(
                        stmt.body, obj_name, attr_name, stmt.lineno,
                    )
                # Recurse into if/else bodies
                self._scan_stmts(stmt.body)
                self._scan_stmts(stmt.orelse)
            elif isinstance(stmt, (ast.For, ast.While)):
                self._scan_stmts(stmt.body)
                self._scan_stmts(stmt.orelse)
            elif isinstance(stmt, ast.With):
                self._scan_stmts(stmt.body)
            elif isinstance(stmt, ast.Try):
                self._scan_stmts(stmt.body)
                for handler in stmt.handlers:
                    self._scan_stmts(handler.body)
                self._scan_stmts(stmt.orelse)
                self._scan_stmts(stmt.finalbody)

    def _check_guarded_body(
        self,
        body: list,
        obj_name: str,
        attr_name: str,
        hasattr_line: int,
    ):
        """Check whether the hasattr-guarded body uses obj.attr as a call arg
        without an isinstance check on obj.attr."""

        # Collect call sites where obj.attr is an argument
        call_uses = _find_attr_as_call_arg(body, obj_name, attr_name)
        if not call_uses:
            return

        # Check whether an isinstance guard covers obj.attr in the body
        if _has_isinstance_on_attr(body, obj_name, attr_name):
            return

        for line_no in call_uses:
            self.bugs.append(HasattrTypeCheckBug(
                file_path=self.file_path,
                line_number=line_no,
                function_name=self._current_function or '<module>',
                pattern='hasattr_no_isinstance',
                reason=(
                    f"'{obj_name}.{attr_name}' is passed to a function call "
                    f"inside a hasattr('{obj_name}', '{attr_name}') guard "
                    f"(line {hasattr_line}) without an isinstance check. "
                    f"The attribute may have a polymorphic type (e.g. list vs "
                    f"scalar) causing TypeError in the callee."
                ),
                confidence=0.65,
                variable=f"{obj_name}.{attr_name}",
            ))


# ======================================================================
# Helpers
# ======================================================================

def _extract_hasattr(test: ast.expr) -> Optional[Tuple[str, str]]:
    """If *test* is ``hasattr(obj, 'attr')``, return ``(obj_name, attr_name)``.

    Also handles ``hasattr(obj, 'attr') and ...`` (BoolOp with And).
    """
    if isinstance(test, ast.Call):
        return _extract_hasattr_call(test)

    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        for value in test.values:
            result = _extract_hasattr(value)
            if result:
                return result

    return None


def _extract_hasattr_call(node: ast.Call) -> Optional[Tuple[str, str]]:
    """Return (obj_name, attr_name) from ``hasattr(obj, 'attr')`` call."""
    func = node.func
    if not (isinstance(func, ast.Name) and func.id == 'hasattr'):
        return None
    if len(node.args) < 2:
        return None
    obj_arg = node.args[0]
    attr_arg = node.args[1]
    if not isinstance(obj_arg, ast.Name):
        return None
    if not (isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str)):
        return None
    return obj_arg.id, attr_arg.value


def _find_attr_as_call_arg(
    stmts: list, obj_name: str, attr_name: str
) -> List[int]:
    """Find lines where ``obj.attr`` appears as a function-call argument.

    Returns a deduplicated list of line numbers.
    """
    lines: Set[int] = set()
    for stmt in stmts:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue
            for arg in node.args:
                if _is_attr_access(arg, obj_name, attr_name):
                    lines.add(node.lineno)
            for kw in node.keywords:
                if kw.value and _is_attr_access(kw.value, obj_name, attr_name):
                    lines.add(node.lineno)
    return sorted(lines)


def _is_attr_access(node: ast.expr, obj_name: str, attr_name: str) -> bool:
    """Return True if *node* is ``obj_name.attr_name``."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == attr_name
        and isinstance(node.value, ast.Name)
        and node.value.id == obj_name
    )


def _has_isinstance_on_attr(
    stmts: list, obj_name: str, attr_name: str
) -> bool:
    """Return True if any statement contains ``isinstance(obj.attr, ...)``.

    Also returns True if there is an ``if isinstance(obj.attr, list):``
    or any isinstance check on the same attribute expression, indicating
    the code already handles type polymorphism.
    """
    for stmt in stmts:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Name) and func.id == 'isinstance'):
                continue
            if len(node.args) < 1:
                continue
            first_arg = node.args[0]
            if _is_attr_access(first_arg, obj_name, attr_name):
                return True
    return False
