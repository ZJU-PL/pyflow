"""
AST-based argument mismatch detector.

Detects patterns where a function/method call passes an argument that doesn't
match the expected parameter name, especially when the correct variable IS
available in the caller's scope.

Key bug pattern (BugsInPy ansible#6):
    # Definition:
    def add_requirement(self, parent, requirement):
        ...

    # BUGGY call site:
    existing[0].add_requirement(to_text(collection_info), requirement)
    # should be:
    existing[0].add_requirement(parent, requirement)
    # 'parent' is available in scope but 'to_text(collection_info)' is passed instead.

Also detects scope/indentation logic errors where control-flow statements
(break/continue with guards) are nested inside an if-block but likely belong
at the enclosing loop level — a common copy-paste / indentation mistake in Python.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple


@dataclass
class ArgumentMismatchBug:
    """A bug found via AST argument-mismatch / scope analysis."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'wrong_argument', 'misscoped_control_flow'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_argument_mismatch_bugs(file_path: Path) -> List[ArgumentMismatchBug]:
    """Scan a single Python file for argument mismatch patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _ArgumentMismatchVisitor(str(file_path), source)
    visitor.visit(tree)
    return visitor.bugs


# ============================================================================
# WRONG ARGUMENT DETECTOR
# ============================================================================

class _ArgumentMismatchVisitor(ast.NodeVisitor):
    """
    AST visitor detecting argument mismatches and misscoped control flow.

    Strategy:
    1. First pass: collect all function/method definitions and their parameter names.
    2. Second pass: at each call site, check if the argument is a different
       variable than the parameter name, AND the parameter-named variable is
       actually available in the caller's scope.
    3. Also detect control-flow statements (break/continue) guarded by conditions
       that reference variables from an outer scope but are nested too deeply.
    """

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.source_lines = source.splitlines()
        self.bugs: List[ArgumentMismatchBug] = []
        self._current_function: Optional[str] = None
        self._current_class: Optional[str] = None

        # Map: (class_name or None, method_name) -> list of param names (excluding self/cls)
        self._func_params: Dict[Tuple[Optional[str], str], List[str]] = {}

        # Map: function_name -> set of local variable names
        self._func_locals: Dict[str, Set[str]] = {}

        # Map: function_name -> set of parameter names only
        self._func_param_names: Dict[str, Set[str]] = {}

        # First pass: collect definitions
        self._collect_definitions(ast.parse(source, filename=file_path))

    def _collect_definitions(self, tree: ast.Module):
        """Collect all function/method definitions and their parameters."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                class_name = None
                # Check if this function is inside a class
                for parent_node in ast.walk(tree):
                    if isinstance(parent_node, ast.ClassDef):
                        for item in parent_node.body:
                            if item is node:
                                class_name = parent_node.name
                                break

                params = []
                for arg in node.args.args:
                    if arg.arg not in ('self', 'cls'):
                        params.append(arg.arg)

                self._func_params[(class_name, node.name)] = params

                # Collect local variable names (parameters + assignments)
                func_key = f"{class_name}.{node.name}" if class_name else node.name
                locals_set = set(params)
                # Store parameter names separately for confidence boosting
                self._func_param_names[func_key] = set(params)
                # Also include 'self'/'cls' params
                for arg in node.args.args:
                    locals_set.add(arg.arg)
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and isinstance(getattr(child, 'ctx', None), ast.Store):
                        locals_set.add(child.id)
                    elif isinstance(child, ast.For) and isinstance(child.target, ast.Name):
                        locals_set.add(child.target.id)
                    elif isinstance(child, ast.For) and isinstance(child.target, ast.Tuple):
                        for elt in child.target.elts:
                            if isinstance(elt, ast.Name):
                                locals_set.add(elt.id)
                self._func_locals[func_key] = locals_set

    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_func = self._current_function
        if self._current_class:
            self._current_function = f"{self._current_class}.{node.name}"
        else:
            self._current_function = node.name

        # Check for misscoped control flow
        self._check_misscoped_control_flow(node)

        self.generic_visit(node)
        self._current_function = old_func

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call):
        """Check if a call site has argument mismatches."""
        self._check_argument_mismatch(node)
        self.generic_visit(node)

    def _check_argument_mismatch(self, call_node: ast.Call):
        """
        Detect when a function is called with an argument that doesn't match
        the parameter name, especially when the correct variable is in scope.
        """
        if not self._current_function:
            return

        # Get the callee name and resolve its parameter list
        callee_name = None
        callee_class = None

        if isinstance(call_node.func, ast.Attribute):
            callee_name = call_node.func.attr
            # Try to find which class this method belongs to by checking
            # all class definitions for this method name
            for (cls, fname), params in self._func_params.items():
                if fname == callee_name and cls is not None:
                    callee_class = cls
                    break
        elif isinstance(call_node.func, ast.Name):
            callee_name = call_node.func.id

        if callee_name is None:
            return

        # Look up parameter names for this function
        param_names = None
        if callee_class:
            param_names = self._func_params.get((callee_class, callee_name))
        if param_names is None:
            param_names = self._func_params.get((None, callee_name))
        if param_names is None:
            # Try all classes
            for (cls, fname), params in self._func_params.items():
                if fname == callee_name:
                    param_names = params
                    break

        if not param_names:
            return

        # Get the caller's local variables
        caller_locals = self._func_locals.get(self._current_function, set())
        # Get the caller's parameter names (higher signal than arbitrary locals)
        caller_params = self._func_param_names.get(self._current_function, set())

        # Check each positional argument
        for i, arg in enumerate(call_node.args):
            if i >= len(param_names):
                break

            expected_param = param_names[i]
            actual_arg_name = self._get_arg_name(arg)

            if actual_arg_name is None:
                # Argument is a complex expression (function call, etc.)
                # Check if the expected param name is available in scope
                # and the arg is NOT using it
                if expected_param in caller_locals:
                    # The expected variable is in scope but a different
                    # expression is being passed
                    if self._is_wrapped_call(arg):
                        # e.g., to_text(collection_info) when 'parent' is in scope
                        inner_name = self._get_inner_call_arg_name(arg)
                        if inner_name and inner_name != expected_param:
                            # Higher confidence if expected param is a caller parameter
                            confidence = 0.75 if expected_param in caller_params else 0.60
                            self.bugs.append(ArgumentMismatchBug(
                                file_path=self.file_path,
                                line_number=call_node.lineno,
                                function_name=self._current_function or '<module>',
                                pattern='wrong_argument',
                                reason=(
                                    f"Call to '{callee_name}()' passes "
                                    f"'{self._unparse_arg(arg)}' as argument "
                                    f"'{expected_param}' (parameter #{i+1}), but "
                                    f"variable '{expected_param}' is available in scope. "
                                    f"This may be a copy-paste error where the wrong "
                                    f"variable was used."
                                ),
                                confidence=confidence,
                                variable=expected_param,
                            ))
                continue

            # Simple name argument: check if it matches parameter name
            if actual_arg_name != expected_param:
                if expected_param in caller_locals:
                    # The expected variable IS in scope but a DIFFERENT variable
                    # is passed. This is suspicious.
                    # Lower confidence if names are similar
                    confidence = 0.55
                    if not self._names_are_related(actual_arg_name, expected_param):
                        # Higher confidence if expected param is a caller's parameter
                        # (the programmer received it by name and chose not to pass it)
                        if expected_param in caller_params:
                            confidence = 0.75
                        else:
                            confidence = 0.60

                    self.bugs.append(ArgumentMismatchBug(
                        file_path=self.file_path,
                        line_number=call_node.lineno,
                        function_name=self._current_function or '<module>',
                        pattern='wrong_argument',
                        reason=(
                            f"Call to '{callee_name}()' passes variable "
                            f"'{actual_arg_name}' as argument '{expected_param}' "
                            f"(parameter #{i+1}), but '{expected_param}' is "
                            f"available in the caller's scope. Possible argument swap."
                        ),
                        confidence=confidence,
                        variable=expected_param,
                    ))

        # Also check keyword arguments for potential mismatches
        # (less common but still possible)

    def _check_misscoped_control_flow(self, func_node: ast.FunctionDef):
        """
        Detect control-flow statements (break/continue) that are likely at the
        wrong indentation level.

        Pattern: A for-loop contains an if-block, and inside that if-block there
        is another if/elif that checks loop-level variables and does break/continue.
        This often indicates the inner if/elif should be at the for-loop level,
        not nested inside the outer if.

        Example (BugsInPy ansible#6):
            for req in self._requirements:
                if req != '*':
                    ...
                    # BUG: This should be at the for-loop level
                    if parent and version == '*' and requirement != '*':
                        break
                    elif requirement == '*' or version == '*':
                        continue
        """
        for node in ast.walk(func_node):
            if not isinstance(node, ast.For):
                continue

            # Get the loop variable(s)
            loop_vars = self._get_assigned_names(node.target)

            for stmt in node.body:
                if not isinstance(stmt, ast.If):
                    continue

                # Look for nested if/elif with break/continue inside this if
                self._check_nested_break_continue(
                    stmt, node, loop_vars, func_node, depth=0
                )

    def _check_nested_break_continue(
        self,
        if_node: ast.If,
        for_node: ast.For,
        loop_vars: Set[str],
        func_node: ast.FunctionDef,
        depth: int,
    ):
        """
        Recursively check for break/continue inside nested if-blocks that
        probably belong at the for-loop level.
        """
        if depth > 3:
            return

        # Check the body of this if-block for nested if/elif that contain
        # break or continue
        for stmt in if_node.body:
            if isinstance(stmt, ast.If):
                has_break_or_continue = False
                break_continue_count = 0
                for child in ast.walk(stmt):
                    if isinstance(child, (ast.Break, ast.Continue)):
                        has_break_or_continue = True
                        break_continue_count += 1

                if has_break_or_continue:
                    # Check if the condition references variables that are NOT
                    # derived from the outer if's test — suggesting it's a
                    # loop-level check, not a refinement of the outer condition
                    outer_test_vars = self._get_referenced_names(if_node.test)
                    inner_test_vars = self._get_referenced_names(stmt.test)

                    # If the inner test uses different variables than the outer
                    # test, it's likely misscoped
                    unique_inner_vars = inner_test_vars - outer_test_vars
                    shared_vars = inner_test_vars & outer_test_vars

                    # High suspicion: inner test uses completely different vars
                    # and contains break/continue affecting the loop
                    if unique_inner_vars and len(unique_inner_vars) >= len(shared_vars):
                        # Check column offsets to confirm nesting
                        if hasattr(stmt, 'col_offset') and hasattr(for_node, 'col_offset'):
                            indent_diff = stmt.col_offset - for_node.col_offset
                            # If nested 2+ levels deep (8+ spaces beyond for)
                            if indent_diff >= 8:
                                # Also check if the elif/else also has break/continue
                                elif_has_flow = False
                                if stmt.orelse:
                                    for orelse_stmt in stmt.orelse:
                                        for child in ast.walk(orelse_stmt):
                                            if isinstance(child, (ast.Break, ast.Continue)):
                                                elif_has_flow = True
                                                break

                                confidence = 0.55
                                if elif_has_flow:
                                    confidence = 0.70  # Both branches have flow control

                                self.bugs.append(ArgumentMismatchBug(
                                    file_path=self.file_path,
                                    line_number=stmt.lineno,
                                    function_name=self._current_function or '<module>',
                                    pattern='misscoped_control_flow',
                                    reason=(
                                        f"Control flow statement (break/continue) inside "
                                        f"nested if-block at line {stmt.lineno} may be at "
                                        f"the wrong indentation level. The condition tests "
                                        f"variables ({', '.join(sorted(unique_inner_vars))}) "
                                        f"unrelated to the enclosing if-block's condition "
                                        f"({', '.join(sorted(outer_test_vars))}), suggesting "
                                        f"it should be at the for-loop level (line {for_node.lineno})."
                                    ),
                                    confidence=confidence,
                                    variable=None,
                                ))

                self._check_nested_break_continue(
                    stmt, for_node, loop_vars, func_node, depth + 1
                )

        # Also check orelse (elif/else branches)
        for stmt in if_node.orelse:
            if isinstance(stmt, ast.If):
                self._check_nested_break_continue(
                    stmt, for_node, loop_vars, func_node, depth + 1
                )

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    @staticmethod
    def _get_arg_name(node: ast.expr) -> Optional[str]:
        """Extract simple variable name from an argument, or None if complex."""
        if isinstance(node, ast.Name):
            return node.id
        return None

    @staticmethod
    def _is_wrapped_call(node: ast.expr) -> bool:
        """Check if the node is a function call wrapping another expression."""
        return isinstance(node, ast.Call)

    @staticmethod
    def _get_inner_call_arg_name(node: ast.expr) -> Optional[str]:
        """For a Call node, get the name of its first argument if simple."""
        if isinstance(node, ast.Call) and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name):
                return first_arg.id
        return None

    @staticmethod
    def _unparse_arg(node: ast.expr) -> str:
        """Get a string representation of an AST expression."""
        try:
            return ast.unparse(node)
        except Exception:
            return '<expression>'

    @staticmethod
    def _names_are_related(name1: str, name2: str) -> bool:
        """Check if two variable names are semantically related."""
        n1, n2 = name1.lower(), name2.lower()
        if n1 in n2 or n2 in n1:
            return True
        # Check if they share a common prefix of length >= 3
        prefix_len = 0
        for c1, c2 in zip(n1, n2):
            if c1 == c2:
                prefix_len += 1
            else:
                break
        if prefix_len >= 3:
            return True
        # Check underscore-separated word overlap (e.g., b_abs_path vs b_path)
        parts1 = set(n1.split('_'))
        parts2 = set(n2.split('_'))
        # Filter out empty parts and very short parts (single chars like 'b')
        meaningful1 = {p for p in parts1 if len(p) >= 2}
        meaningful2 = {p for p in parts2 if len(p) >= 2}
        if meaningful1 and meaningful2:
            shared = meaningful1 & meaningful2
            # If the shorter name's meaningful parts are a subset of the longer's,
            # or they share a significant word, they're related
            shorter = meaningful1 if len(meaningful1) <= len(meaningful2) else meaningful2
            if shared and len(shared) >= len(shorter):
                return True
            # Also: if one name's last word (the "type" suffix) matches
            last1 = n1.rsplit('_', 1)[-1]
            last2 = n2.rsplit('_', 1)[-1]
            if len(last1) >= 3 and last1 == last2:
                return True
        return False

    @staticmethod
    def _get_assigned_names(target: ast.expr) -> Set[str]:
        """Get all names assigned by a for-loop target."""
        names = set()
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Tuple):
            for elt in target.elts:
                if isinstance(elt, ast.Name):
                    names.add(elt.id)
        return names

    @staticmethod
    def _get_referenced_names(node: ast.expr) -> Set[str]:
        """Get all variable names referenced in an expression."""
        names = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                names.add(child.id)
        return names
