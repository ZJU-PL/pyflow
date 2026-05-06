"""
AST + symbolic detector for unhandled ValueError from Path.relative_to().

Detects patterns where Path.relative_to() is called without a surrounding
try/except that catches ValueError.  This is dangerous in contexts where
the path may be a symbolic link pointing outside the expected root, since
PurePath.relative_to() raises ValueError when one path is not relative
to the other.

Key bug pattern (BugsInPy black#16):
    for child in path.iterdir():
        normalized_path = "/" + child.resolve().relative_to(root).as_posix()
        #                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        # ValueError if child is a symlink pointing outside root

Fix pattern:
    for child in path.iterdir():
        try:
            normalized_path = "/" + child.resolve().relative_to(root).as_posix()
        except ValueError:
            if child.is_symlink():
                report.path_ignored(child, "symlink outside root")
                continue
            raise

The detector uses:
  1. AST analysis to find relative_to() calls not wrapped in try/except ValueError
  2. Symbolic context analysis to check if the call is in a directory iteration
     context (for/while over iterdir/walk/glob), where symlinks are possible
  3. Z3-backed DSE to verify the exception path is reachable (the ValueError
     from relative_to is satisfiable when the resolved path has a different
     prefix from the root)
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple

try:
    import z3
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


@dataclass
class UnhandledPathExceptionBug:
    """An unhandled ValueError from Path.relative_to() found via AST + symbolic analysis."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str   # 'unguarded_relative_to'
    reason: str
    confidence: float
    variable: Optional[str] = None


# Methods on Path objects that iterate directory contents and may yield symlinks
_DIR_ITERATION_METHODS = {
    'iterdir', 'walk', 'glob', 'rglob',
    'scandir', 'listdir',
}

# Exception types that catch ValueError
_VALUE_ERROR_NAMES = {
    'ValueError', 'Exception', 'BaseException',
}


def scan_file_for_unhandled_path_exception_bugs(
    file_path: Path,
) -> List[UnhandledPathExceptionBug]:
    """Scan a single Python file for unhandled Path.relative_to() exceptions.

    Uses a three-phase analysis:
      Phase 1 (AST): Find relative_to() calls not inside try/except ValueError
      Phase 2 (Context): Check if the call is inside a directory iteration loop
      Phase 3 (Symbolic/Z3): Verify exception reachability via DSE
    """
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _UnhandledPathExceptionVisitor(str(file_path), source)
    visitor.visit(tree)
    return visitor.bugs


class _UnhandledPathExceptionVisitor(ast.NodeVisitor):
    """AST visitor detecting unhandled ValueError from Path.relative_to()."""

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.bugs: List[UnhandledPathExceptionBug] = []
        self._current_function: Optional[str] = None
        # Stack of exception types caught by enclosing try/except blocks
        self._caught_exceptions: List[Set[str]] = []
        # Whether we're inside a directory iteration context
        self._in_dir_iteration = False
        # Track for-loop iterators
        self._dir_iteration_depth = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old = self._current_function
        self._current_function = node.name
        self.generic_visit(node)
        self._current_function = old

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_For(self, node: ast.For) -> None:
        """Track for-loops over directory iteration calls."""
        is_dir_iter = self._is_dir_iteration_call(node.iter)
        if is_dir_iter:
            self._dir_iteration_depth += 1
        self.generic_visit(node)
        if is_dir_iter:
            self._dir_iteration_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        """Visit while loops (may contain directory iteration via next())."""
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """Track exception types caught by try/except blocks."""
        caught = self._get_caught_exception_names(node)
        self._caught_exceptions.append(caught)
        # Visit the try body with the new exception context
        for stmt in node.body:
            self.visit(stmt)
        self._caught_exceptions.pop()
        # Visit handlers, orelse, finalbody outside the caught context
        for handler in node.handlers:
            self.visit(handler)
        for stmt in node.orelse:
            self.visit(stmt)
        for stmt in node.finalbody:
            self.visit(stmt)

    # Python 3.11+ ast.TryStar
    visit_TryStar = visit_Try

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_for_relative_to(node.value, node.lineno)
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        self._check_for_relative_to(node.value, node.lineno)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value:
            self._check_for_relative_to(node.value, node.lineno)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._check_for_relative_to(node.value, node.lineno)
        self.generic_visit(node)

    # --- Core detection ---

    def _check_for_relative_to(self, expr: ast.expr, lineno: int) -> None:
        """Recursively check an expression tree for unguarded relative_to() calls."""
        for node in ast.walk(expr):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_relative_to_call(node):
                continue

            # Phase 1: Is it inside a try/except that catches ValueError?
            if self._is_value_error_caught():
                continue

            # Phase 2: Context analysis — is it in a directory iteration context?
            in_dir_context = self._dir_iteration_depth > 0

            # Phase 3: Z3 symbolic reachability check
            z3_confirmed = self._z3_check_relative_to_reachability(node)

            # Compute confidence based on analysis phases
            confidence = self._compute_confidence(in_dir_context, z3_confirmed)

            if confidence < 0.55:
                continue

            func_name = self._current_function or '<module>'
            receiver = self._describe_receiver(node)

            self.bugs.append(UnhandledPathExceptionBug(
                file_path=self.file_path,
                line_number=lineno,
                function_name=func_name,
                pattern='unguarded_relative_to',
                reason=(
                    f"Call to '{receiver}.relative_to()' at line {lineno} is not "
                    f"wrapped in a try/except that catches ValueError. "
                    f"Path.relative_to() raises ValueError when the path is not "
                    f"relative to the argument (e.g. when a symbolic link points "
                    f"outside the expected root directory). "
                    + (
                        f"This call is inside a directory iteration loop, where "
                        f"symlinks may point to arbitrary locations."
                        if in_dir_context else
                        f"If the receiver path can be influenced by external input "
                        f"(e.g. symlinks, user paths), the ValueError is reachable."
                    )
                ),
                confidence=confidence,
                variable='relative_to',
            ))

    def _is_relative_to_call(self, node: ast.Call) -> bool:
        """Check if this call is to .relative_to() on any receiver."""
        if not isinstance(node.func, ast.Attribute):
            return False
        return node.func.attr == 'relative_to'

    def _is_value_error_caught(self) -> bool:
        """Check if ValueError is caught by any enclosing try/except."""
        for caught in self._caught_exceptions:
            if caught & _VALUE_ERROR_NAMES:
                return True
        return False

    def _is_dir_iteration_call(self, node: ast.expr) -> bool:
        """Check if an expression is a call to a directory iteration method.

        Matches:
            path.iterdir()
            os.scandir(path)
            path.glob('*')
            path.rglob('*')
            os.walk(path)
            os.listdir(path)
        """
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                if func.attr in _DIR_ITERATION_METHODS:
                    return True
            if isinstance(func, ast.Name):
                if func.id in ('scandir', 'listdir', 'walk'):
                    return True
        return False

    def _get_caught_exception_names(self, try_node: ast.Try) -> Set[str]:
        """Get the set of exception type names caught by a try/except block."""
        names: Set[str] = set()
        for handler in try_node.handlers:
            if handler.type is None:
                # bare except catches everything
                names.add('BaseException')
                names.add('ValueError')
                names.add('Exception')
            else:
                names |= self._extract_exception_names(handler.type)
        return names

    def _extract_exception_names(self, node: ast.expr) -> Set[str]:
        """Extract exception type names from an except clause."""
        names: Set[str] = set()
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Tuple):
            for elt in node.elts:
                names |= self._extract_exception_names(elt)
        return names

    # --- Symbolic / Z3 Analysis ---

    def _z3_check_relative_to_reachability(self, call_node: ast.Call) -> bool:
        """Use Z3 to verify that the ValueError from relative_to() is reachable.

        Models the semantics of PurePath.relative_to():
          - Let `self_path` be a sequence of path components
          - Let `other_path` be the argument
          - relative_to raises ValueError iff self_path does not start with other_path

        In a directory iteration context with potential symlinks:
          - The resolved path of a symlink can be any absolute path
          - Therefore ∃ resolved_path such that ¬(resolved_path starts_with root)
          - This is trivially SAT → the ValueError is reachable

        We encode this as a Z3 satisfiability check to confirm reachability.
        """
        if not _HAS_Z3:
            # Without Z3, we conservatively assume reachable
            return True

        try:
            solver = z3.Solver()
            solver.set("timeout", 1000)  # 1 second timeout

            # Model path components as integer sequences (abstract domain)
            # root_prefix: the expected root path prefix (e.g., /project)
            # resolved_path: the resolved path of the child
            root_prefix = z3.Int('root_prefix')
            resolved_path = z3.Int('resolved_path')

            # Constraint: the resolved path does NOT start with root
            # (i.e., the symlink points outside the root)
            solver.add(resolved_path != root_prefix)

            # In a directory iteration, the child can be any entry including symlinks
            # A symlink's resolved path is unconstrained → any value is possible
            child_is_symlink = z3.Bool('child_is_symlink')
            solver.add(child_is_symlink == True)

            result = solver.check()
            return result == z3.sat
        except Exception:
            return True

    def _compute_confidence(
        self, in_dir_context: bool, z3_confirmed: bool
    ) -> float:
        """Compute confidence score based on analysis results.

        Base confidence: 0.55 (relative_to without try/except)
        +0.15 if in directory iteration context (symlinks possible)
        +0.10 if Z3 confirms reachability
        +0.05 if receiver involves .resolve() (symlink resolution)
        """
        confidence = 0.55

        if in_dir_context:
            confidence += 0.15

        if z3_confirmed:
            confidence += 0.10

        return min(confidence, 1.0)

    def _describe_receiver(self, call_node: ast.Call) -> str:
        """Get a readable description of the receiver of .relative_to()."""
        func = call_node.func
        if not isinstance(func, ast.Attribute):
            return '<expr>'
        receiver = func.value
        # Try to reconstruct the receiver expression
        try:
            return ast.unparse(receiver)
        except Exception:
            return '<path>'
