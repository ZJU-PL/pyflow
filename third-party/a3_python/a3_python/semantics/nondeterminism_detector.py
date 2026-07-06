"""
AST-based non-deterministic iteration detector.

Detects patterns where dict/set iteration order is used in contexts that
require deterministic output (error messages, string formatting, comparisons).

Key bug pattern:
    # BUG: dict iteration order used directly in join() for error message
    missing = []
    for k, v in some_dict.items():
        if condition:
            missing.append(k)
    msg = ", ".join(missing)   # Non-deterministic order!
    raise TypeError(msg)

    # FIX: sort before joining
    msg = ", ".join(sorted(missing))

This detects BugsInPy ansible#5 and similar non-deterministic ordering bugs.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Dict


@dataclass
class NondeterminismBug:
    """A non-deterministic iteration bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'unsorted_join', 'unsorted_format', 'unsorted_comparison'
    reason: str
    confidence: float
    collection_var: Optional[str] = None


def scan_file_for_nondeterminism_bugs(file_path: Path) -> List[NondeterminismBug]:
    """Scan a single Python file for non-deterministic iteration patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _NondeterminismVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


class _NondeterminismVisitor(ast.NodeVisitor):
    """AST visitor that detects non-deterministic iteration patterns."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[NondeterminismBug] = []
        self._current_function: Optional[str] = None
        self._current_class: Optional[str] = None

        # Track variables that accumulate from dict/set iteration
        # Maps variable name -> set of evidence types
        self._dict_derived_lists: Dict[str, _CollectionInfo] = {}

    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_func = self._current_function
        old_derived = self._dict_derived_lists.copy()
        if self._current_class:
            self._current_function = f"{self._current_class}.{node.name}"
        else:
            self._current_function = node.name
        self._dict_derived_lists = {}

        # Analyze the function body for the pattern
        self._analyze_function_body(node)

        self.generic_visit(node)
        self._current_function = old_func
        self._dict_derived_lists = old_derived

    visit_AsyncFunctionDef = visit_FunctionDef

    def _analyze_function_body(self, func_node: ast.FunctionDef):
        """
        Analyze a function body for non-deterministic iteration patterns.

        Pattern we're looking for:
        1. A list variable is initialized (e.g., missing = [])
        2. A for loop iterates over a dict (e.g., for k, v in d.items())
        3. Inside the loop, items are appended to the list
        4. After the loop, the list is joined WITHOUT sorting
        5. The result is used in a raise or error message
        """
        stmts = func_node.body
        self._scan_statements(stmts)

    def _scan_statements(self, stmts: list):
        """Scan a list of statements for the nondeterminism pattern."""
        # Track: list vars initialized as empty, dict-iteration loops, joins
        list_vars: Set[str] = set()         # vars assigned to []
        dict_loop_appended: Set[str] = set() # vars appended to inside dict loops

        for stmt in stmts:
            # Step 1: Detect empty list initialization: x = []
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and isinstance(stmt.value, ast.List) and len(stmt.value.elts) == 0:
                        list_vars.add(target.id)

            # Step 2: Detect for loop over dict and append to tracked list
            if isinstance(stmt, ast.For):
                iter_source = stmt.iter
                is_dict_iter = self._is_dict_iteration(iter_source)

                if is_dict_iter:
                    # Check loop body for appends to tracked list vars
                    appended_vars = self._find_appended_vars(stmt.body, list_vars)
                    dict_loop_appended.update(appended_vars)

                    # Also check for list comprehension patterns in loop
                    # (less common but possible)

            # Step 3: Detect join() on dict-derived list WITHOUT sorted()
            # and used in raise or string formatting for error messages
            if dict_loop_appended:
                join_bugs = self._check_for_unsorted_join(stmt, dict_loop_appended, list_vars)
                self.bugs.extend(join_bugs)

            # Also scan nested if/else blocks
            if isinstance(stmt, ast.If):
                self._scan_if_for_joins(stmt, dict_loop_appended, list_vars)

        # Also check for list comprehension patterns at function level
        for stmt in stmts:
            self._check_listcomp_patterns(stmt, stmts)

    def _is_dict_iteration(self, node: ast.expr) -> bool:
        """Check if an expression is iterating over a dict."""
        # Pattern: d.items(), d.keys(), d.values()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ('items', 'keys', 'values'):
                return True

        # Pattern: iterating directly over a variable (could be dict)
        # We're conservative here - direct iteration over a variable
        # is dict iteration if variable name suggests it
        if isinstance(node, ast.Name):
            name = node.id.lower()
            if any(hint in name for hint in ('dict', 'spec', 'params', 'options',
                                              'config', 'settings', 'mapping',
                                              'kwargs', 'attributes', 'fields',
                                              'argument', 'schema')):
                return True

        return False

    def _find_appended_vars(self, body: list, tracked_lists: Set[str]) -> Set[str]:
        """Find which tracked list variables are appended to in a loop body."""
        appended = set()
        for stmt in body:
            # Direct append: missing.append(k)
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                if (isinstance(call.func, ast.Attribute) and
                    call.func.attr == 'append' and
                    isinstance(call.func.value, ast.Name) and
                    call.func.value.id in tracked_lists):
                    appended.add(call.func.value.id)

            # Append inside if block: if cond: missing.append(k)
            if isinstance(stmt, ast.If):
                appended.update(self._find_appended_vars(stmt.body, tracked_lists))
                if stmt.orelse:
                    appended.update(self._find_appended_vars(stmt.orelse, tracked_lists))

        return appended

    def _check_for_unsorted_join(self, stmt: ast.stmt, dict_derived: Set[str],
                                  list_vars: Set[str]) -> List[NondeterminismBug]:
        """Check if a statement uses join() on a dict-derived list without sorting."""
        bugs = []

        # Check raise statements
        if isinstance(stmt, ast.Raise) and stmt.exc is not None:
            bugs.extend(self._check_expr_for_unsorted_join(stmt.exc, dict_derived, stmt.lineno))

        # Check assignments that lead to raises (e.g., msg = "..." % join(...))
        if isinstance(stmt, ast.Assign):
            bugs.extend(self._check_expr_for_unsorted_join(stmt.value, dict_derived, stmt.lineno))

        # Check expression statements (e.g., standalone join calls)
        if isinstance(stmt, ast.Expr):
            bugs.extend(self._check_expr_for_unsorted_join(stmt.value, dict_derived, stmt.lineno))

        return bugs

    def _check_expr_for_unsorted_join(self, node: ast.expr, dict_derived: Set[str],
                                       lineno: int) -> List[NondeterminismBug]:
        """Recursively check an expression for unsorted join on dict-derived list."""
        bugs = []

        if node is None:
            return bugs

        # Pattern: ", ".join(var) where var is dict-derived and NOT sorted
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == 'join' and len(node.args) == 1:
                arg = node.args[0]

                # Check if the argument is a dict-derived variable (unsorted)
                if isinstance(arg, ast.Name) and arg.id in dict_derived:
                    bugs.append(NondeterminismBug(
                        file_path=self.file_path,
                        line_number=lineno,
                        function_name=self._current_function or '<module>',
                        pattern='unsorted_join',
                        reason=(
                            f"'{arg.id}' is populated from dict/set iteration and passed "
                            f"to str.join() without sorting. Dict iteration order may vary, "
                            f"causing non-deterministic output. Use sorted({arg.id}) instead."
                        ),
                        confidence=0.82,
                        collection_var=arg.id,
                    ))

                # Check if wrapped in sorted() - if so, it's fine
                # sorted(var) is ast.Call with func=Name('sorted')
                if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                    if arg.func.id == 'sorted':
                        pass  # Already sorted - no bug

        # Check string formatting: "..." % join(var)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            bugs.extend(self._check_expr_for_unsorted_join(node.right, dict_derived, lineno))
            bugs.extend(self._check_expr_for_unsorted_join(node.left, dict_derived, lineno))

        # Check f-strings
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    bugs.extend(self._check_expr_for_unsorted_join(val.value, dict_derived, lineno))

        # Check function calls (e.g., TypeError("..." % join(var)))
        if isinstance(node, ast.Call):
            for arg in node.args:
                bugs.extend(self._check_expr_for_unsorted_join(arg, dict_derived, lineno))
            for kw in node.keywords:
                bugs.extend(self._check_expr_for_unsorted_join(kw.value, dict_derived, lineno))
            # Also check the function itself for join
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == 'join':
                    pass  # Already handled above
                else:
                    bugs.extend(self._check_expr_for_unsorted_join(node.func, dict_derived, lineno))

        # Check attribute access chains
        if isinstance(node, ast.Attribute):
            bugs.extend(self._check_expr_for_unsorted_join(node.value, dict_derived, lineno))

        return bugs

    def _scan_if_for_joins(self, if_stmt: ast.If, dict_derived: Set[str],
                            list_vars: Set[str]):
        """Scan if/else bodies for unsorted join patterns."""
        for stmt in if_stmt.body:
            join_bugs = self._check_for_unsorted_join(stmt, dict_derived, list_vars)
            self.bugs.extend(join_bugs)
            if isinstance(stmt, ast.If):
                self._scan_if_for_joins(stmt, dict_derived, list_vars)

        for stmt in if_stmt.orelse:
            join_bugs = self._check_for_unsorted_join(stmt, dict_derived, list_vars)
            self.bugs.extend(join_bugs)
            if isinstance(stmt, ast.If):
                self._scan_if_for_joins(stmt, dict_derived, list_vars)

    def _check_listcomp_patterns(self, stmt: ast.stmt, all_stmts: list):
        """
        Check for list comprehension patterns producing non-deterministic output.

        Pattern: [k for k in d if condition] used in join without sorting.
        """
        # This handles a different style of the same bug:
        # missing = [k for k, v in spec.items() if v.get('required')]
        # msg = ", ".join(missing)  # Bug!
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and isinstance(stmt.value, ast.ListComp):
                    comp = stmt.value
                    # Check if the comprehension iterates over a dict
                    for gen in comp.generators:
                        if self._is_dict_iteration(gen.iter):
                            # This list is derived from dict iteration
                            var_name = target.id
                            # Now check subsequent statements for unsorted join
                            found_stmt = False
                            for s in all_stmts:
                                if s is stmt:
                                    found_stmt = True
                                    continue
                                if found_stmt:
                                    join_bugs = self._check_for_unsorted_join(
                                        s, {var_name}, set())
                                    self.bugs.extend(join_bugs)
                                    if isinstance(s, ast.If):
                                        self._scan_if_for_joins(
                                            s, {var_name}, set())


@dataclass
class _CollectionInfo:
    """Tracks info about a collection variable."""
    name: str
    source: str  # 'empty_list', 'listcomp_dict', 'setcomp_dict'
    line: int
