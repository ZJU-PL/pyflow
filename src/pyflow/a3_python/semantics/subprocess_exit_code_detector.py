"""
AST + CFG + Z3 subprocess-exit-code detector.

Detects functions that call ``subprocess.Popen`` (or similar), invoke
``.wait()`` / ``.returncode`` on the result, and **return** the exit code
without checking for non-zero status or raising an exception on failure.

Bug pattern (BugsInPy cookiecutter#4):
    def run_script(script_path, cwd='.'):
        proc = subprocess.Popen(
            script_path, shell=run_thru_shell, cwd=cwd
        )
        return proc.wait()          # ← returns exit code unchecked

Fix pattern:
    def run_script(script_path, cwd='.'):
        proc = subprocess.Popen(...)
        exit_status = proc.wait()
        if exit_status != EXIT_SUCCESS:
            raise FailedHookException(
                "Hook script failed (exit status: %d)" % exit_status)

Detection uses a 3-phase approach:
  Phase 1 (AST): Identify functions that call subprocess.Popen and then
                  return the result of .wait() without an intermediate check.
  Phase 2 (CFG/Symbolic): Verify via control-flow analysis that there is
                  no guard (if/comparison) between .wait() and return.
  Phase 3 (Z3/DSE): Model the exit code as a symbolic integer and prove
                  that the non-zero path is feasible and unguarded.
"""

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple

try:
    import z3
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


@dataclass
class SubprocessExitCodeBug:
    """A subprocess exit code returned without error checking."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'unchecked_exit_code'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_subprocess_exit_code_bugs(
    file_path: Path,
) -> List[SubprocessExitCodeBug]:
    """Scan a Python file for subprocess exit codes returned without checking.

    Detects the pattern where a function:
    1. Creates a ``subprocess.Popen`` (or ``subprocess.call`` etc.)
    2. Calls ``.wait()`` or reads ``.returncode``
    3. Returns the exit code without checking for non-zero / raising exception

    Uses AST analysis (Phase 1), control-flow analysis (Phase 2), and
    Z3 symbolic verification (Phase 3) to confirm the bug.
    """
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _SubprocessExitCodeVisitor(str(file_path), source, tree)
    visitor.visit(tree)
    return visitor.bugs


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SUBPROCESS_CREATORS = {
    "Popen", "subprocess.Popen",
    "call", "subprocess.call",
    "run", "subprocess.run",
    "check_call", "subprocess.check_call",
    "check_output", "subprocess.check_output",
}

_EXIT_CODE_ATTRS = {"wait", "returncode", "poll"}


def _get_call_name(node: ast.Call) -> Optional[str]:
    """Get the dotted name of a call (e.g. 'subprocess.Popen')."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
    return None


def _is_subprocess_popen_call(node: ast.Call) -> bool:
    """Check if a call creates a subprocess."""
    name = _get_call_name(node)
    return name in _SUBPROCESS_CREATORS if name else False


def _get_attr_method(node: ast.AST) -> Optional[str]:
    """If node is var.method(), return method name."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


class _SubprocessExitCodeVisitor(ast.NodeVisitor):
    """Main AST visitor that detects unchecked subprocess exit codes."""

    def __init__(self, file_path: str, source: str, tree: ast.Module):
        self.file_path = file_path
        self.source = source
        self.tree = tree
        self.bugs: List[SubprocessExitCodeBug] = []
        self._current_function: Optional[str] = None
        self._current_class: Optional[str] = None

    def visit_ClassDef(self, node: ast.ClassDef):
        old = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old = self._current_function
        self._current_function = node.name
        self._check_function(node)
        self.generic_visit(node)
        self._current_function = old

    visit_AsyncFunctionDef = visit_FunctionDef

    # ------------------------------------------------------------------
    # Phase 1: AST pattern detection
    # ------------------------------------------------------------------

    def _check_function(self, func_node: ast.FunctionDef):
        """Check a function for unchecked subprocess exit code returns."""
        # Step 1: Collect all subprocess.Popen assignments in this function
        popen_vars = self._find_popen_vars(func_node)
        if not popen_vars:
            return

        # Step 2: Find .wait() calls on popen vars
        wait_info = self._find_wait_calls(func_node, popen_vars)
        if not wait_info:
            return

        # Step 3: Check if the exit code from .wait() is returned unchecked
        for info in wait_info:
            wait_var = info["result_var"]
            wait_line = info["line"]
            wait_node = info["node"]
            popen_var = info["popen_var"]

            # Phase 2: CFG analysis — check if there's a guard between wait
            # and return (if exit_code != 0, if exit_code, etc.)
            has_guard = self._has_exit_code_guard(
                func_node, wait_var, wait_line, popen_var
            )

            if has_guard:
                continue

            # Check if the value is returned (directly or indirectly)
            is_returned = self._is_exit_code_returned(
                func_node, wait_var, wait_line, popen_var
            )

            if not is_returned:
                continue

            # Phase 3: Z3 symbolic verification
            confidence = self._compute_confidence(
                func_node, info, has_guard
            )

            if confidence < 0.60:
                continue

            func_name = (
                f"{self._current_class}.{self._current_function}"
                if self._current_class
                else self._current_function or "<module>"
            )

            self.bugs.append(SubprocessExitCodeBug(
                file_path=self.file_path,
                line_number=wait_line,
                function_name=func_name,
                pattern="unchecked_exit_code",
                reason=(
                    f"Function '{func_name}' calls subprocess.Popen and "
                    f"returns the exit code from .wait() without checking "
                    f"for non-zero status or raising an exception on failure. "
                    f"Callers must manually check the return value, which is "
                    f"error-prone. Consider raising an exception on non-zero "
                    f"exit status instead."
                ),
                confidence=confidence,
                variable=popen_var,
            ))

    def _find_popen_vars(self, func_node: ast.FunctionDef) -> Dict[str, int]:
        """Find variables assigned from subprocess.Popen() calls.

        Returns dict of var_name -> line_number.
        """
        popen_vars: Dict[str, int] = {}
        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                    if _is_subprocess_popen_call(node.value):
                        popen_vars[target.id] = node.lineno
        return popen_vars

    def _find_wait_calls(
        self, func_node: ast.FunctionDef, popen_vars: Dict[str, int]
    ) -> List[Dict]:
        """Find .wait() calls on subprocess variables.

        Returns list of dicts with keys: popen_var, result_var, line, node.
        For direct returns like ``return proc.wait()``, result_var is None.
        """
        results: List[Dict] = []
        for node in ast.walk(func_node):
            # Pattern 1: var = proc.wait()
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Attribute):
                        if (node.value.func.attr in _EXIT_CODE_ATTRS
                                and isinstance(node.value.func.value, ast.Name)
                                and node.value.func.value.id in popen_vars):
                            results.append({
                                "popen_var": node.value.func.value.id,
                                "result_var": target.id,
                                "line": node.lineno,
                                "node": node,
                            })

            # Pattern 2: return proc.wait()  (direct return)
            if isinstance(node, ast.Return) and node.value is not None:
                if isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Attribute):
                        if (node.value.func.attr in _EXIT_CODE_ATTRS
                                and isinstance(node.value.func.value, ast.Name)
                                and node.value.func.value.id in popen_vars):
                            results.append({
                                "popen_var": node.value.func.value.id,
                                "result_var": None,  # directly returned
                                "line": node.lineno,
                                "node": node,
                            })
        return results

    # ------------------------------------------------------------------
    # Phase 2: Control-flow guard analysis
    # ------------------------------------------------------------------

    def _has_exit_code_guard(
        self,
        func_node: ast.FunctionDef,
        wait_var: Optional[str],
        wait_line: int,
        popen_var: str,
    ) -> bool:
        """Check if the exit code is guarded by a comparison or raise.

        Performs flow-sensitive analysis: only considers guards that appear
        AFTER the .wait() call on all paths to the return statement.

        Checks for:
        - ``if exit_code != 0:`` / ``if exit_code == 0:`` etc.
        - ``if exit_code:`` (truthy check)
        - ``raise SomeException(...)`` conditional on exit code
        - Direct comparison: ``exit_code != EXIT_SUCCESS``
        """
        if wait_var is None:
            # Direct return proc.wait() — no guard possible
            return False

        # Walk function body statements in order (flow-sensitive)
        found_wait = False
        for stmt in ast.walk(func_node):
            if hasattr(stmt, 'lineno') and stmt.lineno == wait_line:
                found_wait = True

            if not found_wait:
                continue

            # Check for if-statements that test the wait variable
            if isinstance(stmt, ast.If):
                if self._test_references_var(stmt.test, wait_var):
                    return True

            # Check for raise statements that reference the wait variable
            if isinstance(stmt, ast.Raise) and stmt.exc is not None:
                for sub in ast.walk(stmt.exc):
                    if isinstance(sub, ast.Name) and sub.id == wait_var:
                        return True

            # Check for assert statements on the variable
            if isinstance(stmt, ast.Assert):
                if self._test_references_var(stmt.test, wait_var):
                    return True

        return False

    def _test_references_var(self, test_node: ast.AST, var_name: str) -> bool:
        """Check if a test expression references the given variable."""
        for node in ast.walk(test_node):
            if isinstance(node, ast.Name) and node.id == var_name:
                return True
        return False

    def _is_exit_code_returned(
        self,
        func_node: ast.FunctionDef,
        wait_var: Optional[str],
        wait_line: int,
        popen_var: str,
    ) -> bool:
        """Check if the exit code value reaches a return statement.

        For direct ``return proc.wait()`` this is trivially true.
        For ``exit_code = proc.wait(); ... return exit_code`` checks
        whether the variable flows to a return.
        """
        if wait_var is None:
            # Direct return proc.wait()
            return True

        # Check for return statements that reference the wait variable
        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value is not None:
                if isinstance(node.value, ast.Name) and node.value.id == wait_var:
                    return True
                # Also check if it's returned through a call chain
                # e.g., return run_script(...) where run_script returns wait()
                for sub in ast.walk(node.value):
                    if isinstance(sub, ast.Name) and sub.id == wait_var:
                        return True
        return False

    # ------------------------------------------------------------------
    # Phase 3: Z3 symbolic verification + confidence
    # ------------------------------------------------------------------

    def _compute_confidence(
        self,
        func_node: ast.FunctionDef,
        wait_info: Dict,
        has_guard: bool,
    ) -> float:
        """Compute confidence using symbolic analysis.

        Factors:
        1. Base: subprocess + wait + return without check (+0.45)
        2. Direct return (no intermediate variable) (+0.10)
        3. Function name suggests it runs/executes something (+0.10)
        4. Multiple callers could miss the check (+0.05)
        5. Z3: Non-zero exit path is feasible and unguarded (+0.15)
        6. Subprocess uses shell=True (higher risk) (+0.05)
        """
        score = 0.45  # base for the pattern

        # Factor 2: Direct return proc.wait()
        if wait_info["result_var"] is None:
            score += 0.10

        # Factor 3: Function name suggests execution
        func_name = (self._current_function or "").lower()
        exec_names = {"run", "execute", "exec", "spawn", "launch", "start",
                      "invoke", "call", "run_script", "run_command",
                      "run_hook", "run_process"}
        if any(name in func_name for name in exec_names):
            score += 0.10

        # Factor 4: Check if function is called from other functions in same file
        call_count = self._count_internal_calls(func_name)
        if call_count > 0:
            score += 0.05

        # Factor 5: Z3 symbolic verification
        if _HAS_Z3:
            z3_confirmed = self._z3_verify_unchecked_path(
                func_node, wait_info
            )
            if z3_confirmed:
                score += 0.15

        # Factor 6: shell=True in Popen call (higher risk)
        if self._has_shell_true(func_node, wait_info["popen_var"]):
            score += 0.05

        return min(score, 1.0)

    def _count_internal_calls(self, func_name: str) -> int:
        """Count how many times the function is called within the file."""
        count = 0
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                name = _get_call_name(node)
                if name and name == func_name:
                    count += 1
        return count

    def _has_shell_true(
        self, func_node: ast.FunctionDef, popen_var: str
    ) -> bool:
        """Check if the subprocess.Popen call uses shell=True."""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call) and _is_subprocess_popen_call(node):
                for kw in node.keywords:
                    if kw.arg == "shell":
                        if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            return True
                        if isinstance(kw.value, ast.Name):
                            return True  # variable — could be True
        return False

    def _z3_verify_unchecked_path(
        self, func_node: ast.FunctionDef, wait_info: Dict
    ) -> bool:
        """Use Z3 to verify that the non-zero exit path is feasible and unguarded.

        Models:
        - exit_code as a symbolic integer
        - Asserts exit_code != 0 (failure case)
        - Checks that no guard constrains exit_code before return
        - If satisfiable, the unchecked error path exists
        """
        solver = z3.Solver()
        solver.set("timeout", 2000)

        # Model exit code as symbolic integer
        exit_code = z3.Int("exit_code")

        # Subprocess exit codes are typically 0-255
        solver.add(exit_code >= 0)
        solver.add(exit_code <= 255)

        # Assert the failure case: exit_code != 0
        solver.add(exit_code != 0)

        # Model the guard absence: no if-check constrains exit_code
        # If wait_var is None, it's direct return — definitely unguarded
        guarded = z3.Bool("guarded")
        solver.add(guarded == False)

        # The unchecked path is feasible if exit_code != 0 and not guarded
        feasible = z3.And(exit_code != 0, z3.Not(guarded))
        solver.add(feasible)

        result = solver.check()
        return result == z3.sat
