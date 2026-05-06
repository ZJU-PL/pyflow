"""
AST-based detector for inconsistent error/exception guard patterns.

Detects patterns where:
1. A method has a flag attribute (e.g., ``self.auto_error``) that guards
   some ``raise`` statements via ``if self.flag: raise ... else: return None``
2. Other ``raise`` statements of the same exception type in the same method
   are NOT guarded by the same flag
3. The method's return type annotation is ``Optional[...]`` or it has
   ``return None`` statements, indicating the caller expects None on error

Key bug pattern (BugsInPy fastapi#12):
    # BUGGY: second raise is not guarded by self.auto_error
    async def __call__(self, request):
        if not (authorization and scheme and credentials):
            if self.auto_error:
                raise HTTPException(...)
            else:
                return None
        if scheme.lower() != "bearer":
            raise HTTPException(...)    # BUG: missing auto_error guard
        return HTTPAuthorizationCredentials(...)

    # FIXED: both raises guarded consistently
    async def __call__(self, request):
        if not (authorization and scheme and credentials):
            if self.auto_error:
                raise HTTPException(...)
            else:
                return None
        if scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(...)
            else:
                return None
        return HTTPAuthorizationCredentials(...)
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple


@dataclass
class InconsistentErrorGuardBug:
    """A bug found via AST inconsistent-error-guard analysis."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'inconsistent_error_guard'
    reason: str
    confidence: float
    guard_attribute: Optional[str] = None


def scan_file_for_inconsistent_error_guard_bugs(
    file_path: Path,
) -> List[InconsistentErrorGuardBug]:
    """Scan a single Python file for inconsistent error guard patterns."""
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

    visitor = _InconsistentGuardVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


class _InconsistentGuardVisitor(ast.NodeVisitor):
    """Visits methods to find inconsistent exception guard patterns."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[InconsistentErrorGuardBug] = []
        self._current_class: Optional[str] = None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        old = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_method(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_method(node)
        self.generic_visit(node)

    # ------------------------------------------------------------------

    def _check_method(self, node: ast.FunctionDef) -> None:
        """Check a method for inconsistent error guard patterns."""
        # Only consider methods (has 'self' parameter)
        if not node.args.args or node.args.args[0].arg != "self":
            return

        # Collect guarded and unguarded raises
        guarded_raises = _collect_guarded_raises(node)
        if not guarded_raises:
            return  # no guarded raise patterns → nothing inconsistent

        unguarded_raises = _collect_unguarded_raises(node, guarded_raises)
        if not unguarded_raises:
            return

        # Must also have a return-None path (indicating caller expects None)
        if not _has_return_none(node):
            return

        func_name = node.name
        if self._current_class:
            func_name = f"{self._current_class}.{func_name}"

        for raise_node, guard_attr, exc_name in unguarded_raises:
            reason = (
                f"raise {exc_name} at line {raise_node.lineno} is not guarded by "
                f"self.{guard_attr}, but other raises of {exc_name} in this method "
                f"are guarded — caller may expect None instead of an exception"
            )
            self.bugs.append(InconsistentErrorGuardBug(
                file_path=self.file_path,
                line_number=raise_node.lineno,
                function_name=func_name,
                pattern="inconsistent_error_guard",
                reason=reason,
                confidence=0.75,
                guard_attribute=guard_attr,
            ))


def _collect_guarded_raises(func: ast.FunctionDef) -> List[Tuple[str, str]]:
    """Find (guard_attribute, exception_name) pairs for guarded raise patterns.

    Looks for the pattern:
        if self.<attr>:
            raise <ExcType>(...)
        else:
            return None
    """
    results: List[Tuple[str, str]] = []

    for node in ast.walk(func):
        if not isinstance(node, ast.If):
            continue
        guard_attr = _extract_self_attr_test(node.test)
        if guard_attr is None:
            continue

        # Check if the if-body contains a raise
        exc_name = _find_raise_exception_name(node.body)
        if exc_name is None:
            continue

        # Check if the else-body contains return None
        if not _body_has_return_none(node.orelse):
            continue

        results.append((guard_attr, exc_name))

    return results


def _collect_unguarded_raises(
    func: ast.FunctionDef,
    guarded_raises: List[Tuple[str, str]],
) -> List[Tuple[ast.Raise, str, str]]:
    """Find raise statements that should be guarded but aren't.

    Returns list of (raise_node, guard_attr, exc_name).
    """
    # Build set of (guard_attr, exc_name) that we've seen guarded
    guarded_set: Set[Tuple[str, str]] = set(guarded_raises)

    results: List[Tuple[ast.Raise, str, str]] = []

    for node in ast.walk(func):
        if not isinstance(node, ast.Raise) or node.exc is None:
            continue

        exc_name = _get_exception_name(node.exc)
        if exc_name is None:
            continue

        # Check if this raise is already inside a guarded if-block
        if _raise_is_guarded(func, node):
            continue

        # Check if there exists a guarded raise with the same exception name
        for guard_attr, guarded_exc in guarded_set:
            if guarded_exc == exc_name:
                results.append((node, guard_attr, exc_name))
                break

    return results


def _extract_self_attr_test(test: ast.expr) -> Optional[str]:
    """Extract attribute name from ``self.<attr>`` test expression."""
    # Direct: if self.auto_error:
    if isinstance(test, ast.Attribute):
        if isinstance(test.value, ast.Name) and test.value.id == "self":
            return test.attr
    # Negated: if not self.auto_error:  (we still record the attr)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _extract_self_attr_test(test.operand)
    return None


def _find_raise_exception_name(body: List[ast.stmt]) -> Optional[str]:
    """Find exception class name in raise statements within a body."""
    for stmt in body:
        if isinstance(stmt, ast.Raise) and stmt.exc is not None:
            return _get_exception_name(stmt.exc)
        # Also check nested if/else blocks
        if isinstance(stmt, ast.If):
            name = _find_raise_exception_name(stmt.body)
            if name:
                return name
            name = _find_raise_exception_name(stmt.orelse)
            if name:
                return name
    return None


def _get_exception_name(exc: ast.expr) -> Optional[str]:
    """Get the exception class name from a raise expression."""
    # raise ExcType(...)
    if isinstance(exc, ast.Call):
        if isinstance(exc.func, ast.Name):
            return exc.func.id
        if isinstance(exc.func, ast.Attribute):
            return exc.func.attr
    # raise exc_variable
    if isinstance(exc, ast.Name):
        return exc.id
    return None


def _body_has_return_none(body: List[ast.stmt]) -> bool:
    """Check if a body contains 'return None' or bare 'return'."""
    for stmt in body:
        if isinstance(stmt, ast.Return):
            if stmt.value is None:
                return True
            if isinstance(stmt.value, ast.Constant) and stmt.value.value is None:
                return True
    return False


def _has_return_none(func: ast.FunctionDef) -> bool:
    """Check if the function has any return-None path."""
    for node in ast.walk(func):
        if isinstance(node, ast.Return):
            if node.value is None:
                return True
            if isinstance(node.value, ast.Constant) and node.value.value is None:
                return True
    return False


def _raise_is_guarded(func: ast.FunctionDef, raise_node: ast.Raise) -> bool:
    """Check if a raise node is inside a self.<attr> guarded if-block."""
    # Walk the function body to find if-blocks that contain this raise
    return _check_guarded_in_body(func.body, raise_node)


def _check_guarded_in_body(body: List[ast.stmt], raise_node: ast.Raise) -> bool:
    """Recursively check if raise_node is inside a self.<attr> guard."""
    for stmt in body:
        if isinstance(stmt, ast.If):
            guard_attr = _extract_self_attr_test(stmt.test)
            if guard_attr is not None:
                # This is a self.<attr> guarded block
                if _contains_node(stmt, raise_node):
                    return True
            # Recurse into the if body and else body
            if _check_guarded_in_body(stmt.body, raise_node):
                return True
            if _check_guarded_in_body(stmt.orelse, raise_node):
                return True
        elif isinstance(stmt, (ast.For, ast.While, ast.With, ast.Try)):
            # Check nested blocks
            for child_body in _get_child_bodies(stmt):
                if _check_guarded_in_body(child_body, raise_node):
                    return True
    return False


def _contains_node(parent: ast.AST, target: ast.AST) -> bool:
    """Check if target node is contained anywhere inside parent."""
    for node in ast.walk(parent):
        if node is target:
            return True
    return False


def _get_child_bodies(node: ast.stmt) -> List[List[ast.stmt]]:
    """Get child statement bodies from compound statements."""
    bodies = []
    if hasattr(node, 'body'):
        bodies.append(node.body)
    if hasattr(node, 'orelse'):
        bodies.append(node.orelse)
    if hasattr(node, 'handlers'):
        for h in node.handlers:
            bodies.append(h.body)
    if hasattr(node, 'finalbody'):
        bodies.append(node.finalbody)
    return bodies
