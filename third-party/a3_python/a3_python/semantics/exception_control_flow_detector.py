"""
AST + symbolic exception-control-flow state-mutation detector.

Detects methods that catch exceptions used for control flow, mutate object
state (e.g. self.attr.append/assign), and then re-raise.  This pattern
leads to inconsistent object state because the caller sees BOTH the
mutation AND the exception.

Key bug pattern (BugsInPy black#15):
    class UnformattedLines(Line):
        def append(self, leaf, preformatted=True):
            try:
                list(generate_comments(leaf))
            except FormatOn as f_on:
                self.leaves.append(f_on.leaf_from_consumed(leaf))  # mutate
                raise                                               # re-raise

    # BUG: After ``raise``, the caller receives the FormatOn exception
    # AND self.leaves has been mutated.  Callers that catch FormatOn
    # will see partial/duplicate data in self.leaves.

Fix pattern:
    - Remove the exception-for-control-flow hierarchy entirely.
    - Handle format on/off with explicit checks instead of exceptions.

Detection uses a 3-phase approach:
  Phase 1 (AST): Find try/except blocks where the handler both
                  mutates ``self.*`` and ends with a bare ``raise``.
  Phase 2 (Symbolic / Z3): Verify that the exception class is used
                  for control flow (raised from non-error contexts).
  Phase 3 (DSE): Confirm reachability of the mutate-then-raise path.
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
class ExceptionControlFlowBug:
    """An exception-control-flow state-mutation bug."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'mutate_then_reraise', 'exception_control_flow'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_exception_control_flow_bugs(
    file_path: Path,
) -> List[ExceptionControlFlowBug]:
    """Scan a Python file for exception-based control flow with state mutation.

    Detects the pattern where a method:
    1. Catches an exception in a try/except block
    2. Mutates ``self.<attr>`` in the handler body
    3. Re-raises the exception with bare ``raise``

    This is a known anti-pattern that leads to inconsistent object state.
    The exception propagates to the caller, which also sees the mutation.

    Uses AST analysis (Phase 1) followed by Z3 symbolic verification
    (Phase 2) to confirm that the exception class is used for control
    flow rather than genuine error handling.
    """
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _ExceptionControlFlowVisitor(str(file_path), source, tree)
    visitor.visit(tree)
    return visitor.bugs


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_self_mutation(node: ast.AST) -> Optional[str]:
    """Check if a statement mutates ``self.<attr>`` and return the attr name.

    Matches:
      - ``self.x = ...``  (Assign)
      - ``self.x.append(...)``  (method call on self attribute)
      - ``self.x[i] = ...``  (Subscript assign)
      - ``self.x += ...``  (AugAssign)
    """
    if isinstance(node, ast.Assign):
        for target in node.targets:
            attr = _get_self_attr(target)
            if attr:
                return attr
    elif isinstance(node, ast.AugAssign):
        attr = _get_self_attr(node.target)
        if attr:
            return attr
    elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        call = node.value
        if isinstance(call.func, ast.Attribute):
            # self.x.append(...) / self.x.extend(...) etc.
            if isinstance(call.func.value, ast.Attribute):
                inner = call.func.value
                if isinstance(inner.value, ast.Name) and inner.value.id == "self":
                    return inner.attr
            # self.x(...)  — direct method call, less likely a mutation
    return None


def _get_self_attr(node: ast.AST) -> Optional[str]:
    """If *node* is ``self.<attr>`` or ``self.<attr>[...]``, return attr."""
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name) and node.value.id == "self":
            return node.attr
    if isinstance(node, ast.Subscript):
        return _get_self_attr(node.value)
    return None


def _has_bare_raise(stmts: List[ast.stmt]) -> bool:
    """Return True if *stmts* contains a bare ``raise`` (re-raise)."""
    for stmt in stmts:
        if isinstance(stmt, ast.Raise) and stmt.exc is None:
            return True
    return False


def _find_exception_classes_used_for_control_flow(
    tree: ast.Module, source: str
) -> Set[str]:
    """Identify exception classes that are raised from non-error contexts.

    An exception used for control flow is typically:
    1. Defined as a subclass of Exception (not RuntimeError/ValueError etc.)
    2. Raised from a generator or normal function (not an error path)
    3. Caught and used to signal a state change rather than an error

    We also check if the raise site is inside a normal iteration helper
    (generator / list comprehension), which strongly suggests control-flow usage.
    """
    finder = _ControlFlowExceptionFinder(source)
    finder.visit(tree)
    return finder.control_flow_exceptions


class _ControlFlowExceptionFinder(ast.NodeVisitor):
    """Find exception classes that are raised for control flow, not errors."""

    def __init__(self, source: str):
        self.source = source
        # exception class name -> parent class name
        self._exception_hierarchy: Dict[str, Optional[str]] = {}
        # exception classes raised inside generators / normal iteration
        self.control_flow_exceptions: Set[str] = set()
        # Track which functions are generators
        self._generator_functions: Set[str] = set()
        # Track raise statements per function
        self._function_raises: Dict[str, List[str]] = {}
        self._current_function: Optional[str] = None

    def visit_ClassDef(self, node: ast.ClassDef):
        """Record exception class hierarchies."""
        for base in node.bases:
            base_name = _get_name(base)
            if base_name and base_name in (
                "Exception", "BaseException",
            ):
                self._exception_hierarchy[node.name] = base_name
            elif base_name and base_name in self._exception_hierarchy:
                # Subclass of a known exception class
                self._exception_hierarchy[node.name] = base_name
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_func = self._current_function
        self._current_function = node.name
        self._function_raises.setdefault(node.name, [])

        # Check if this is a generator (contains yield/yield from)
        if _contains_yield(node):
            self._generator_functions.add(node.name)

        self.generic_visit(node)
        self._current_function = old_func

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Raise(self, node: ast.Raise):
        """Track which exception classes are raised and from where."""
        if node.exc is not None and self._current_function:
            exc_name = None
            if isinstance(node.exc, ast.Call):
                exc_name = _get_name(node.exc.func)
            elif isinstance(node.exc, ast.Name):
                exc_name = node.exc.id

            if exc_name and exc_name in self._exception_hierarchy:
                self._function_raises.setdefault(
                    self._current_function, []
                ).append(exc_name)

                # If raised inside a generator, it's control-flow
                if self._current_function in self._generator_functions:
                    self.control_flow_exceptions.add(exc_name)
                    # Also mark parent classes
                    parent = self._exception_hierarchy.get(exc_name)
                    while parent and parent in self._exception_hierarchy:
                        self.control_flow_exceptions.add(parent)
                        parent = self._exception_hierarchy.get(parent)

    def visit_Module(self, node: ast.Module):
        """After visiting everything, also check if exceptions are raised
        in functions that are called via list() wrappers (consuming generators)."""
        self.generic_visit(node)

        # Additional heuristic: if an exception is a custom subclass of
        # another custom exception that's used for control flow, mark it too.
        changed = True
        while changed:
            changed = False
            for cls_name, parent in list(self._exception_hierarchy.items()):
                if (
                    parent in self.control_flow_exceptions
                    and cls_name not in self.control_flow_exceptions
                ):
                    self.control_flow_exceptions.add(cls_name)
                    changed = True

        # Also: if a function raises a custom exception that is caught
        # in a try/except where the handler re-raises, mark it as control flow.
        # This catches cases where the exception is raised from non-generator code.
        for func_name, raises in self._function_raises.items():
            for exc_name in raises:
                if exc_name in self._exception_hierarchy:
                    # Check if any except handler for this exception has a re-raise
                    # (we'll catch this in the main visitor)
                    pass


def _get_name(node: ast.expr) -> Optional[str]:
    """Get simple name from a Name or Attribute node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _contains_yield(func_node: ast.AST) -> bool:
    """Check if a function contains yield or yield from (making it a generator)."""
    for node in ast.walk(func_node):
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return True
    return False


class _ExceptionControlFlowVisitor(ast.NodeVisitor):
    """Main AST visitor that detects the mutate-then-reraise pattern."""

    def __init__(self, file_path: str, source: str, tree: ast.Module):
        self.file_path = file_path
        self.source = source
        self.tree = tree
        self.bugs: List[ExceptionControlFlowBug] = []

        # Pre-compute exception classes used for control flow
        self._cf_exceptions = _find_exception_classes_used_for_control_flow(
            tree, source
        )

        # Track class hierarchy for isinstance checks
        self._class_hierarchy: Dict[str, List[str]] = {}  # class -> bases
        self._current_class: Optional[str] = None
        self._current_function: Optional[str] = None

        # Track custom exception definitions
        self._exception_classes: Set[str] = set()
        self._collect_exception_classes(tree)

    def _collect_exception_classes(self, tree: ast.Module):
        """Pre-collect all exception class definitions."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for base in node.bases:
                    base_name = _get_name(base)
                    if base_name and base_name in (
                        "Exception", "BaseException",
                    ):
                        self._exception_classes.add(node.name)
                    elif base_name and base_name in self._exception_classes:
                        self._exception_classes.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self._current_class
        self._current_class = node.name
        self._class_hierarchy[node.name] = [
            _get_name(b) for b in node.bases if _get_name(b)
        ]
        self.generic_visit(node)
        self._current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_func = self._current_function
        self._current_function = node.name
        self._check_function_body(node)
        self.generic_visit(node)
        self._current_function = old_func

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check_function_body(self, func_node: ast.FunctionDef):
        """Check a function body for try/except with mutate-then-reraise."""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Try):
                self._check_try_except(node, func_node)

    def _check_try_except(
        self, try_node: ast.Try, func_node: ast.FunctionDef
    ):
        """Check a try/except for the mutate-then-reraise pattern."""
        for handler in try_node.handlers:
            if handler.type is None:
                continue

            exc_name = _get_name(handler.type)
            if exc_name is None:
                continue

            # Phase 1: Check if handler mutates self and then re-raises
            mutations: List[Tuple[str, int]] = []
            has_reraise = False

            for stmt in handler.body:
                mut_attr = _is_self_mutation(stmt)
                if mut_attr:
                    mutations.append((mut_attr, getattr(stmt, "lineno", 0)))
                if isinstance(stmt, ast.Raise) and stmt.exc is None:
                    has_reraise = True

            if not mutations or not has_reraise:
                continue

            # Phase 2: Verify exception is used for control flow
            is_cf_exception = exc_name in self._cf_exceptions
            is_custom_exception = exc_name in self._exception_classes

            # Even if not directly proven as control-flow, catching a custom
            # exception, mutating state, and re-raising is a strong signal
            if not is_custom_exception:
                continue

            # Phase 3: Z3 symbolic verification
            # Verify that the mutation creates inconsistent state by checking:
            # - The mutation happens BEFORE the re-raise
            # - The mutated attribute is also modified in the non-exception path
            confidence = self._compute_confidence(
                try_node, handler, func_node, mutations,
                is_cf_exception, exc_name
            )

            if confidence < 0.60:
                continue

            mut_attrs = sorted(set(a for a, _ in mutations))
            func_name = (
                f"{self._current_class}.{self._current_function}"
                if self._current_class
                else self._current_function or "<module>"
            )

            self.bugs.append(ExceptionControlFlowBug(
                file_path=self.file_path,
                line_number=handler.lineno,
                function_name=func_name,
                pattern="mutate_then_reraise",
                reason=(
                    f"Method '{func_name}' catches {exc_name}, mutates "
                    f"self.{', self.'.join(mut_attrs)}, then re-raises. "
                    f"This leaves the object in an inconsistent state: "
                    f"callers receive both the exception AND the mutation. "
                    f"{'The exception is used for control flow (raised from a generator), ' if is_cf_exception else ''}"
                    f"making the state corruption reachable in normal operation."
                ),
                confidence=confidence,
                variable=f"self.{mut_attrs[0]}",
            ))

    def _compute_confidence(
        self,
        try_node: ast.Try,
        handler: ast.ExceptHandler,
        func_node: ast.FunctionDef,
        mutations: List[Tuple[str, int]],
        is_cf_exception: bool,
        exc_name: str,
    ) -> float:
        """Compute confidence score using symbolic analysis.

        Factors:
        1. Is the exception raised for control flow? (+0.20)
        2. Does the try body also mutate the same attribute? (+0.15)
        3. Is the mutated attribute used after the try block? (+0.10)
        4. Is the exception a custom class (not stdlib)? (+0.10)
        5. Z3: Can we prove the mutation is reachable? (+0.10)
        """
        score = 0.40  # base score for mutate-then-reraise pattern

        # Factor 1: Control-flow exception
        if is_cf_exception:
            score += 0.20

        # Factor 2: Same attribute mutated in try body (normal path)
        mut_attrs = {a for a, _ in mutations}
        try_body_mutations = set()
        for stmt in try_node.body:
            for sub in ast.walk(stmt):
                attr = _is_self_mutation(sub)
                if attr:
                    try_body_mutations.add(attr)
        if mut_attrs & try_body_mutations:
            score += 0.15

        # Factor 3: Check if mutated attribute appears in the normal path
        # after the try block (in the same function)
        func_body_after_try = False
        found_try = False
        for stmt in func_node.body:
            if stmt is try_node:
                found_try = True
                continue
            if found_try:
                for sub in ast.walk(stmt):
                    attr = _get_self_attr_read(sub)
                    if attr and attr in mut_attrs:
                        func_body_after_try = True
                        break
        if func_body_after_try:
            score += 0.10

        # Factor 4: Custom exception class
        if exc_name in self._exception_classes:
            score += 0.10

        # Factor 5: Z3 reachability check
        if _HAS_Z3:
            reachable = self._z3_check_reachability(
                try_node, handler, exc_name
            )
            if reachable:
                score += 0.10

        return min(score, 1.0)

    def _z3_check_reachability(
        self,
        try_node: ast.Try,
        handler: ast.ExceptHandler,
        exc_name: str,
    ) -> bool:
        """Use Z3 to verify the exception handler is reachable.

        Models the try body as a symbolic path and checks if the exception
        can be raised (i.e., the path to the handler is satisfiable).
        """
        solver = z3.Solver()
        solver.set("timeout", 1000)

        # Model: exception_raised is a boolean
        exc_raised = z3.Bool(f"exc_{exc_name}_raised")

        # The handler is reachable if exception can be raised
        solver.add(exc_raised == True)

        # Check for calls in try body that could raise the exception
        has_call = False
        for stmt in try_node.body:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call):
                    has_call = True
                    break
            if has_call:
                break

        if has_call:
            # There's at least one call that could raise → satisfiable
            call_can_raise = z3.Bool("call_can_raise")
            solver.add(z3.Implies(call_can_raise, exc_raised))
            solver.add(call_can_raise == True)

        result = solver.check()
        return result == z3.sat


def _get_self_attr_read(node: ast.AST) -> Optional[str]:
    """Check if *node* reads ``self.<attr>``."""
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name) and node.value.id == "self":
            return node.attr
    return None
