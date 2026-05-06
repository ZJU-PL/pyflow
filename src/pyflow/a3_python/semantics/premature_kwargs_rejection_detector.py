"""
AST-based premature keyword argument rejection detector.

Detects patterns where a function accepts **kwargs but immediately rejects
all keyword arguments without first extracting valid keys via .pop(), del,
or similar operations.

Key bug pattern (BugsInPy keras#18):
    class Function(object):
        def __init__(self, inputs, outputs, updates=None, name=None,
                     **session_kwargs):
            ...
            self.session_kwargs = session_kwargs
            # BUG: all kwargs rejected — valid keys like 'options' not extracted
            if session_kwargs:
                raise ValueError('Some keys in session_kwargs are not '
                                 'supported at this time: ...')

    # FIXED: valid keys extracted before rejection check
    class Function(object):
        def __init__(self, inputs, outputs, updates=None, name=None,
                     **session_kwargs):
            ...
            self.session_kwargs = session_kwargs.copy()
            self.run_options = session_kwargs.pop('options', None)
            self.run_metadata = session_kwargs.pop('run_metadata', None)
            if session_kwargs:
                raise ValueError('Some keys in session_kwargs are not '
                                 'supported at this time: ...')

The detector flags functions where:
1. A **kwargs parameter is declared
2. The kwargs dict is stored/used (e.g., self.x = kwargs)
3. An ``if kwargs: raise ValueError/TypeError(...)`` check rejects all kwargs
4. No .pop(), del, or key-extraction calls modify the dict before the check
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set


# Exception types that indicate kwarg rejection
_REJECTION_EXCEPTIONS = {'ValueError', 'TypeError'}


@dataclass
class PrematureKwargsRejectionBug:
    """A bug found via AST premature-kwargs-rejection analysis."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'premature_kwargs_rejection'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_premature_kwargs_rejection_bugs(
    file_path: Path,
) -> List[PrematureKwargsRejectionBug]:
    """Scan a single Python file for premature kwargs rejection patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
    except (OSError, UnicodeDecodeError):
        return []

    tree = None
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        pass

    # Fallback: try multi-hunk parsing for diff fragments
    if tree is None:
        try:
            from ..cfg.call_graph import _try_parse_multi_hunk
            tree = _try_parse_multi_hunk(source, str(file_path))
        except Exception:
            pass

    if tree is None:
        return []

    visitor = _PrematureKwargsRejectionVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


class _PrematureKwargsRejectionVisitor(ast.NodeVisitor):
    """AST visitor that detects premature kwargs rejection."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[PrematureKwargsRejectionBug] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def _check_function(self, node: ast.FunctionDef) -> None:
        """Check a single function for premature kwargs rejection."""
        # Step 1: Does the function have a **kwargs parameter?
        if not node.args.kwarg:
            return
        kwargs_name = node.args.kwarg.arg

        # Step 2: Find 'if kwargs_name: raise ValueError/TypeError(...)' patterns
        rejection_ifs = self._find_rejection_ifs(node, kwargs_name)
        if not rejection_ifs:
            return

        # Step 3: Check that kwargs dict is stored/used (not just checked)
        if not self._is_kwargs_stored_or_used(node, kwargs_name):
            return

        # Step 4: For each rejection if, check that no .pop()/del/extraction
        # occurs before it
        for if_node in rejection_ifs:
            if not self._has_key_extraction_before(node, kwargs_name, if_node):
                self.bugs.append(PrematureKwargsRejectionBug(
                    file_path=self.file_path,
                    line_number=if_node.lineno,
                    function_name=node.name,
                    pattern='premature_kwargs_rejection',
                    reason=(
                        f"Function '{node.name}' accepts **{kwargs_name} "
                        f"and stores/uses it, but rejects ALL keyword "
                        f"arguments without first extracting valid keys "
                        f"via .pop() or similar; callers passing valid "
                        f"kwargs will get a spurious ValueError"
                    ),
                    confidence=0.75,
                    variable=kwargs_name,
                ))

    def _find_rejection_ifs(
        self, func_node: ast.FunctionDef, kwargs_name: str
    ) -> List[ast.If]:
        """Find 'if kwargs: raise ValueError/TypeError(...)' patterns."""
        results = []
        for node in ast.walk(func_node):
            if not isinstance(node, ast.If):
                continue
            # Test must be just the kwargs name (truthiness check)
            if not isinstance(node.test, ast.Name):
                continue
            if node.test.id != kwargs_name:
                continue
            # Body must contain a raise of ValueError or TypeError
            if self._body_has_rejection_raise(node.body):
                results.append(node)
        return results

    def _body_has_rejection_raise(self, body: list) -> bool:
        """Check if a block contains raise ValueError/TypeError."""
        for stmt in body:
            if isinstance(stmt, ast.Raise) and stmt.exc is not None:
                exc_name = self._get_exception_name(stmt.exc)
                if exc_name in _REJECTION_EXCEPTIONS:
                    return True
        return False

    def _get_exception_name(self, exc_node: ast.expr) -> Optional[str]:
        """Extract exception class name from a raise expression."""
        # raise ValueError(...)
        if isinstance(exc_node, ast.Call):
            if isinstance(exc_node.func, ast.Name):
                return exc_node.func.id
            if isinstance(exc_node.func, ast.Attribute):
                return exc_node.func.attr
        # raise ValueError
        if isinstance(exc_node, ast.Name):
            return exc_node.id
        return None

    def _is_kwargs_stored_or_used(
        self, func_node: ast.FunctionDef, kwargs_name: str
    ) -> bool:
        """Check if kwargs dict is stored or used beyond the rejection check.

        Looks for patterns like:
        - self.x = kwargs
        - self.x = kwargs.copy()
        - some_func(kwargs) or some_func(**kwargs)
        - x = kwargs[key] / kwargs.get(key)
        """
        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                # self.x = kwargs or self.x = kwargs.copy()
                if self._expr_uses_kwargs(node.value, kwargs_name):
                    return True
            elif isinstance(node, ast.Call):
                # kwargs passed as argument
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id == kwargs_name:
                        return True
                # **kwargs unpacking
                for kw in node.keywords:
                    if kw.arg is None and isinstance(kw.value, ast.Name) and kw.value.id == kwargs_name:
                        return True
        return False

    def _expr_uses_kwargs(self, expr: ast.expr, kwargs_name: str) -> bool:
        """Check if an expression directly references the kwargs dict."""
        if isinstance(expr, ast.Name) and expr.id == kwargs_name:
            return True
        # kwargs.copy()
        if (isinstance(expr, ast.Call)
                and isinstance(expr.func, ast.Attribute)
                and isinstance(expr.func.value, ast.Name)
                and expr.func.value.id == kwargs_name):
            return True
        return False

    def _has_key_extraction_before(
        self,
        func_node: ast.FunctionDef,
        kwargs_name: str,
        if_node: ast.If,
    ) -> bool:
        """Check if .pop(), del, or key extraction occurs before the if check.

        Looks for patterns before if_node.lineno:
        - kwargs.pop(...)
        - del kwargs[key]
        - key = kwargs.pop(...)
        """
        if_line = if_node.lineno
        for node in ast.walk(func_node):
            if not hasattr(node, 'lineno') or node.lineno >= if_line:
                continue

            # kwargs.pop(...)
            if isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Attribute)
                        and node.func.attr == 'pop'
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == kwargs_name):
                    return True

            # del kwargs[key]
            if isinstance(node, ast.Delete):
                for target in node.targets:
                    if (isinstance(target, ast.Subscript)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == kwargs_name):
                        return True

        return False
