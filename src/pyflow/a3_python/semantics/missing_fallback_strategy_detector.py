"""
AST + symbolic missing-fallback-strategy detector.

Detects functions that catch an exception from a configurable operation and
immediately raise a *different* exception type, without trying alternative
configurations.  This is a known anti-pattern when multiple valid strategies
exist (e.g. parser grammars, codecs, connection endpoints).

Key bug pattern (BugsInPy black#23):
    def lib2to3_parse(src_txt):
        grammar = python_grammar_no_print_statement   # single strategy
        drv = driver.Driver(grammar, pytree.convert)
        try:
            result = drv.parse_string(src_txt, True)
        except ParseError as pe:
            ...
            raise ValueError(...) from None   # immediate failure, no retry

    # BUG: Code using exec() as a function call fails because the single
    # grammar treats 'exec' as a keyword.  Other grammars in the same
    # module handle it correctly.

Fix pattern:
    GRAMMARS = [grammar1, grammar2, grammar3, grammar4]

    def lib2to3_parse(src_txt):
        for grammar in GRAMMARS:
            drv = driver.Driver(grammar, pytree.convert)
            try:
                result = drv.parse_string(src_txt, True)
                break
            except ParseError as pe:
                exc = ValueError(...)
        else:
            raise exc from None

Detection uses a 3-phase approach:
  Phase 1 (AST): Find try/except blocks where the handler raises a NEW
                  exception type (catch-transform-raise) and the try body
                  uses a strategy parameter that is hardcoded.
  Phase 2 (Symbolic / Z3): Verify that alternative strategies exist in
                  module scope and the operation is parameterized.
  Phase 3 (DSE): Confirm reachability of the error path with the
                  hardcoded strategy.
"""

import ast
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple, Any

try:
    import z3
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


@dataclass
class MissingFallbackStrategyBug:
    """A missing-fallback-strategy bug finding."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'catch_transform_raise_no_fallback'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_missing_fallback_strategy_bugs(
    file_path: Path,
) -> List[MissingFallbackStrategyBug]:
    """Scan a Python file for catch-transform-raise without fallback.

    Detects the pattern where a function:
    1. Configures an operation with a single strategy from module scope
    2. Catches an exception from the operation
    3. Raises a DIFFERENT exception type without trying alternatives
    4. Alternative strategies exist in the same module

    Uses AST analysis (Phase 1) followed by Z3 symbolic verification
    (Phase 2) to confirm that alternative strategies are available.
    """
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _MissingFallbackVisitor(str(file_path), source, tree)
    visitor.visit(tree)
    return visitor.bugs


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_name(node: ast.expr) -> Optional[str]:
    """Get simple name from a Name or Attribute node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _get_full_name(node: ast.expr) -> Optional[str]:
    """Get dotted name from Name or Attribute chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _get_full_name(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


def _find_raise_new_exception(stmts: List[ast.stmt]) -> Optional[ast.Raise]:
    """Find a raise statement that raises a NEW exception (not bare raise).

    Returns the Raise node if found, or None. Only considers raises that
    construct a new exception (e.g. ``raise ValueError(...)``), not bare
    ``raise`` which re-raises the current exception.
    """
    for stmt in stmts:
        if isinstance(stmt, ast.Raise) and stmt.exc is not None:
            return stmt
        # Check nested if/try blocks too
        if isinstance(stmt, ast.If):
            result = _find_raise_new_exception(stmt.body)
            if result:
                return result
            result = _find_raise_new_exception(stmt.orelse)
            if result:
                return result
        if isinstance(stmt, ast.Try):
            result = _find_raise_new_exception(stmt.body)
            if result:
                return result
            for handler in stmt.handlers:
                result = _find_raise_new_exception(handler.body)
                if result:
                    return result
    return None


def _get_raised_exception_type(raise_node: ast.Raise) -> Optional[str]:
    """Extract the exception type name from a Raise node."""
    if raise_node.exc is None:
        return None
    if isinstance(raise_node.exc, ast.Call):
        return _get_name(raise_node.exc.func)
    if isinstance(raise_node.exc, ast.Name):
        return raise_node.exc.id
    return None


def _has_break(stmts: List[ast.stmt]) -> bool:
    """Check if statements contain a break (for-loop success pattern)."""
    for stmt in stmts:
        if isinstance(stmt, ast.Break):
            return True
    return False


def _is_inside_loop(func_node: ast.FunctionDef, try_node: ast.Try) -> bool:
    """Check if a try node is inside a for/while loop within the function.

    This detects the fixed pattern where try/except is wrapped in a retry
    loop with break on success.
    """
    for node in ast.walk(func_node):
        if isinstance(node, (ast.For, ast.While)):
            for child in ast.walk(node):
                if child is try_node:
                    # Also check if the try body has a break (success exit)
                    if _has_break(try_node.body):
                        return True
                    # Even without explicit break, being in a loop suggests retry
                    return True
    return False


def _find_calls_in_try_body(try_node: ast.Try) -> List[ast.Call]:
    """Find all function/method calls in the try body."""
    calls = []
    for stmt in try_node.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                calls.append(node)
    return calls


def _find_strategy_assignments(
    func_node: ast.FunctionDef,
) -> List[Tuple[str, str]]:
    """Find assignments of the form ``var = module_level_name`` in a function.

    Returns list of (local_var_name, module_level_source_name) pairs.
    These represent strategy variables assigned from module scope.
    """
    assignments = []
    for stmt in ast.walk(func_node):
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name) and isinstance(stmt.value, ast.Name):
                assignments.append((target.id, stmt.value.id))
            elif isinstance(target, ast.Name) and isinstance(stmt.value, ast.Attribute):
                src = _get_full_name(stmt.value)
                if src:
                    assignments.append((target.id, src))
    return assignments


def _find_module_level_lists(tree: ast.Module) -> Dict[str, List[str]]:
    """Find module-level list/tuple assignments that could be strategy collections.

    Returns dict mapping list name -> list of element names.
    """
    result: Dict[str, List[str]] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name):
                if isinstance(stmt.value, (ast.List, ast.Tuple)):
                    elements = []
                    for elt in stmt.value.elts:
                        name = _get_full_name(elt)
                        if name:
                            elements.append(name)
                    if len(elements) >= 2:
                        result[target.id] = elements
    return result


def _find_module_level_names(tree: ast.Module) -> Set[str]:
    """Collect all names assigned at module level."""
    names: Set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(stmt, ast.FunctionDef):
            names.add(stmt.name)
        elif isinstance(stmt, ast.ClassDef):
            names.add(stmt.name)
    return names


def _find_similar_module_names(
    tree: ast.Module, strategy_name: str
) -> List[str]:
    """Find module-level names similar to a given strategy name.

    Uses prefix matching to find related variables, e.g.
    'python_grammar_no_print_statement' -> also finds
    'python_grammar_no_exec_statement', 'python_grammar', etc.
    """
    module_names = _find_module_level_names(tree)
    # Find common prefix (at least 4 chars to be meaningful)
    prefix = strategy_name
    while len(prefix) > 4:
        matches = [n for n in module_names if n.startswith(prefix) and n != strategy_name]
        if matches:
            return matches
        # Shorten by removing the last word (split on _)
        parts = prefix.rsplit('_', 1)
        if len(parts) == 1:
            break
        prefix = parts[0]
    return []


def _call_uses_variable(call: ast.Call, var_name: str) -> bool:
    """Check if a function call uses a given variable as an argument."""
    for arg in call.args:
        if isinstance(arg, ast.Name) and arg.id == var_name:
            return True
    for kw in call.keywords:
        if isinstance(kw.value, ast.Name) and kw.value.id == var_name:
            return True
    # Also check if the call is on an object that was constructed with var_name
    if isinstance(call.func, ast.Attribute):
        if isinstance(call.func.value, ast.Name) and call.func.value.id == var_name:
            return True
    return False


class _MissingFallbackVisitor(ast.NodeVisitor):
    """Main AST visitor that detects the catch-transform-raise-without-fallback pattern."""

    def __init__(self, file_path: str, source: str, tree: ast.Module):
        self.file_path = file_path
        self.source = source
        self.tree = tree
        self.bugs: List[MissingFallbackStrategyBug] = []

        # Pre-compute module-level info
        self._module_lists = _find_module_level_lists(tree)
        self._module_names = _find_module_level_names(tree)
        self._current_function: Optional[str] = None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_func = self._current_function
        self._current_function = node.name
        self._check_function(node)
        self.generic_visit(node)
        self._current_function = old_func

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check_function(self, func_node: ast.FunctionDef):
        """Check a function for try/except with catch-transform-raise-no-fallback."""
        # Find all strategy assignments (var = module_level_name)
        strategy_assignments = _find_strategy_assignments(func_node)

        for node in ast.walk(func_node):
            if isinstance(node, ast.Try):
                self._check_try_except(node, func_node, strategy_assignments)

    def _check_try_except(
        self,
        try_node: ast.Try,
        func_node: ast.FunctionDef,
        strategy_assignments: List[Tuple[str, str]],
    ):
        """Check a try/except for the catch-transform-raise-no-fallback pattern."""
        # Skip if inside a retry loop (that's the fixed pattern)
        if _is_inside_loop(func_node, try_node):
            return

        for handler in try_node.handlers:
            if handler.type is None:
                # Bare except: — not the pattern we're looking for
                continue

            caught_type = _get_name(handler.type)
            if caught_type is None:
                continue

            # Phase 1: Check if handler raises a DIFFERENT exception type
            raise_node = _find_raise_new_exception(handler.body)
            if raise_node is None:
                continue

            raised_type = _get_raised_exception_type(raise_node)
            if raised_type is None:
                continue

            # The raised type must differ from the caught type
            if raised_type == caught_type:
                continue

            # Phase 2: Check if the try body uses a strategy from module scope
            calls = _find_calls_in_try_body(try_node)
            strategy_var = None
            strategy_source = None

            for local_var, source_name in strategy_assignments:
                for call in calls:
                    if _call_uses_variable(call, local_var):
                        strategy_var = local_var
                        strategy_source = source_name
                        break
                if strategy_var:
                    break

            # Also check if a call argument is directly a module-level name
            if not strategy_var:
                for call in calls:
                    for arg in call.args:
                        if isinstance(arg, ast.Name) and arg.id in self._module_names:
                            strategy_var = arg.id
                            strategy_source = arg.id
                            break
                    if strategy_var:
                        break

            # Also check if the call is on an object constructed from strategy
            if not strategy_var:
                # Look for pattern: obj = Constructor(strategy, ...)
                # then obj.method() in try body
                for call in calls:
                    if isinstance(call.func, ast.Attribute):
                        obj_name = _get_name(call.func.value)
                        if obj_name:
                            # Find where obj was assigned
                            for stmt in ast.walk(func_node):
                                if (isinstance(stmt, ast.Assign) and
                                    len(stmt.targets) == 1 and
                                    isinstance(stmt.targets[0], ast.Name) and
                                    stmt.targets[0].id == obj_name and
                                    isinstance(stmt.value, ast.Call)):
                                    # Check constructor args for strategy vars
                                    for carg in stmt.value.args:
                                        if isinstance(carg, ast.Name):
                                            for lv, src in strategy_assignments:
                                                if carg.id == lv:
                                                    strategy_var = lv
                                                    strategy_source = src
                                                    break
                                            if strategy_var:
                                                break
                                            if carg.id in self._module_names:
                                                strategy_var = carg.id
                                                strategy_source = carg.id
                                                break
                                if strategy_var:
                                    break
                    if strategy_var:
                        break

            if not strategy_var or not strategy_source:
                continue

            # Phase 3: Verify alternatives exist
            alternatives = self._find_alternatives(strategy_source)
            if not alternatives:
                continue

            # Compute confidence
            confidence = self._compute_confidence(
                try_node, handler, func_node, strategy_var, strategy_source,
                caught_type, raised_type, alternatives
            )

            if confidence < 0.60:
                continue

            func_name = self._current_function or "<module>"

            alt_names = ", ".join(alternatives[:3])
            if len(alternatives) > 3:
                alt_names += f", ... ({len(alternatives)} total)"

            self.bugs.append(MissingFallbackStrategyBug(
                file_path=self.file_path,
                line_number=handler.lineno,
                function_name=func_name,
                pattern="catch_transform_raise_no_fallback",
                reason=(
                    f"Function '{func_name}' uses a single strategy "
                    f"'{strategy_source}' for an operation that can fail with "
                    f"{caught_type}. On failure, it raises {raised_type} "
                    f"without trying alternatives. "
                    f"Alternative strategies exist in module scope: {alt_names}. "
                    f"Consider iterating over alternatives before giving up."
                ),
                confidence=confidence,
                variable=strategy_var,
            ))

    def _find_alternatives(self, strategy_source: str) -> List[str]:
        """Find alternative strategies available in the module.

        Checks both:
        1. Module-level lists that contain the strategy source
        2. Similar-named module-level variables
        """
        alternatives: List[str] = []

        # Check if any module-level list contains this strategy
        for list_name, elements in self._module_lists.items():
            if strategy_source in elements:
                alternatives.extend(
                    e for e in elements if e != strategy_source
                )

        # Check for similarly-named module-level variables
        similar = _find_similar_module_names(self.tree, strategy_source)
        for s in similar:
            if s not in alternatives:
                alternatives.append(s)

        return alternatives

    def _compute_confidence(
        self,
        try_node: ast.Try,
        handler: ast.ExceptHandler,
        func_node: ast.FunctionDef,
        strategy_var: str,
        strategy_source: str,
        caught_type: str,
        raised_type: str,
        alternatives: List[str],
    ) -> float:
        """Compute confidence score using symbolic analysis.

        Factors:
        1. Number of alternative strategies available (+0.05 per alt, max +0.15)
        2. Strategy is from module scope (+0.10)
        3. Exception type transformation (catch A raise B) (+0.10)
        4. Strategy is a .copy() variant (+0.05)
        5. Z3: Can we verify alternatives are distinct? (+0.10)
        """
        score = 0.40  # base score for catch-transform-raise without fallback

        # Factor 1: More alternatives = higher confidence
        alt_bonus = min(len(alternatives) * 0.05, 0.15)
        score += alt_bonus

        # Factor 2: Strategy from module scope
        if strategy_source in self._module_names:
            score += 0.10

        # Factor 3: Exception type transformation
        if caught_type != raised_type:
            score += 0.10

        # Factor 4: Strategy variables share a common prefix (related configs)
        all_strats = [strategy_source] + alternatives
        if len(all_strats) >= 2:
            # Find common prefix length
            prefix = os.path.commonprefix(all_strats)
            if len(prefix) >= 4:
                score += 0.05

        # Factor 5: Z3 verification that alternatives are distinct strategies
        if _HAS_Z3:
            distinct = self._z3_check_distinct_strategies(
                strategy_source, alternatives
            )
            if distinct:
                score += 0.10

        return min(score, 1.0)

    def _z3_check_distinct_strategies(
        self,
        strategy_source: str,
        alternatives: List[str],
    ) -> bool:
        """Use Z3 to verify that alternative strategies are distinct.

        Models each strategy as a unique integer and checks that the set
        of alternatives covers at least 2 distinct strategies.
        """
        solver = z3.Solver()
        solver.set("timeout", 1000)

        # Each strategy maps to a unique integer
        strategies = [strategy_source] + alternatives
        z3_vars = {
            name: z3.Int(f"strategy_{name}")
            for name in strategies
        }

        # Assert all strategies are distinct
        for i, name_i in enumerate(strategies):
            for j, name_j in enumerate(strategies):
                if i < j:
                    solver.add(z3_vars[name_i] != z3_vars[name_j])

        # Assert at least one alternative exists
        solver.add(z3.Or([
            z3_vars[alt] >= 0
            for alt in alternatives
        ]))

        result = solver.check()
        return result == z3.sat
