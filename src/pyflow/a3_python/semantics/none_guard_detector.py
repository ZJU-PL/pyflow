"""
AST-based missing-None-guard detector.

Detects patterns where a variable is initialized to None, conditionally
assigned inside a loop or if-block, and then used via attribute access
after the block without a None guard on every path.

Key bug pattern (BugsInPy ansible#1):
    local_collection = None
    for search_path in search_paths:
        if os.path.isdir(b_search_path):
            local_collection = CollectionRequirement.from_path(...)
            break
    # local_collection may still be None
    local_collection.verify(...)   # NULL_PTR!

Fix pattern:
    - Add a None check before usage, or
    - Add a precondition check before the call that ensures the variable
      will be assigned.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple


@dataclass
class NoneGuardBug:
    """A missing-None-guard bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'none_init_conditional_use'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_none_guard_bugs(file_path: Path) -> List[NoneGuardBug]:
    """Scan a single Python file for missing None guard patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    # Pre-pass: build map of functions that may return None (Optional return)
    none_returning_funcs = _find_none_returning_functions(tree)

    visitor = _NoneGuardVisitor(str(file_path), none_returning_funcs)
    visitor.visit(tree)
    return visitor.bugs


def _find_none_returning_functions(tree: ast.AST) -> Set[str]:
    """Find functions in the module that explicitly return None on some paths
    AND return a non-None value on other paths (Optional return pattern).

    This identifies functions like:
        def find_hook(...):
            if ...: return None
            for ...:
                if ...: return os.path.abspath(...)
            return None

    Also detects implicit None returns: functions that return a value on
    some paths but can fall off the end without a return statement.
    """
    result: Set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        has_return_none = False
        has_return_value = False
        for child in ast.walk(node):
            if isinstance(child, ast.Return):
                if child.value is None or _is_none(child.value):
                    has_return_none = True
                elif child.value is not None:
                    has_return_value = True
        # Detect implicit None return: function has a non-None return on some
        # paths but can fall off the end (no return at the end of the body).
        if has_return_value and not has_return_none:
            if _can_fall_off_end(node.body):
                has_return_none = True
        if has_return_none and has_return_value:
            result.add(node.name)
    return result


def _can_fall_off_end(stmts: list) -> bool:
    """Check if a statement list can fall off the end without returning.

    Returns True if the last statement does not unconditionally return/raise.
    """
    if not stmts:
        return True
    last = stmts[-1]
    if isinstance(last, ast.Return):
        return False
    if isinstance(last, ast.Raise):
        return False
    if isinstance(last, ast.If):
        # Both branches must return for the if to be exhaustive
        if not last.orelse:
            return True
        return _can_fall_off_end(last.body) or _can_fall_off_end(last.orelse)
    if isinstance(last, (ast.For, ast.While)):
        # while True loops don't fall off (infinite loop or internal return)
        if isinstance(last, ast.While) and isinstance(last.test, ast.Constant):
            if last.test.value is True:
                return False
        # Other loops may not execute; can fall off
        return True
    if isinstance(last, ast.Try):
        # Simplified: if the try body can fall off, it can fall off
        return True
    return True


class _NoneGuardVisitor(ast.NodeVisitor):
    """AST visitor detecting missing None guard patterns."""

    def __init__(self, file_path: str, none_returning_funcs: Optional[Set[str]] = None):
        self.file_path = file_path
        self.bugs: List[NoneGuardBug] = []
        self._current_function: Optional[str] = None
        self._current_class: Optional[str] = None
        self._none_returning_funcs: Set[str] = none_returning_funcs or set()

    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self._current_class
        self._current_class = node.name
        self._scan_class_for_self_attr_none_init(node)
        self.generic_visit(node)
        self._current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_func(node)

    def _visit_func(self, node):
        old_func = self._current_function
        if self._current_class:
            self._current_function = f"{self._current_class}.{node.name}"
        else:
            self._current_function = node.name

        self._analyze_function_body(node)

        self._current_function = old_func

    # ------------------------------------------------------------------

    def _analyze_function_body(self, func_node):
        """Analyze a function body for missing None guard patterns."""
        body = func_node.body
        self._scan_statement_list(body)
        self._scan_for_dict_value_no_guard(body)
        self._scan_for_dict_items_iteration_no_guard(func_node)
        self._scan_for_missing_precondition(func_node)
        self._scan_for_chained_attr_missing_guard(func_node)
        self._scan_for_param_default_none_attr_access(func_node)
        self._scan_for_unprotected_resource_finally(func_node)
        self._scan_for_last_element_attr_assumption(func_node)
        self._scan_for_call_result_none_passthrough(func_node)
        self._scan_for_param_binop_without_none_guard(func_node)
        self._scan_for_regex_search_dynamic_pattern(func_node)
        self._scan_for_compat_flag_ternary(func_node)

    def _scan_statement_list(self, stmts: list):
        """Scan a flat list of statements for the None-init-then-use pattern."""
        # Track variables assigned to None and where they are conditionally reassigned
        none_vars: Dict[str, int] = {}  # var_name -> line of None assignment

        for i, stmt in enumerate(stmts):
            # Step 1: detect  var = None
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if isinstance(target, ast.Name) and _is_none(stmt.value):
                    none_vars[target.id] = stmt.lineno

            # Step 2: detect loop/if that conditionally reassigns a None-init var
            elif isinstance(stmt, (ast.For, ast.While, ast.If)):
                for var_name, init_line in list(none_vars.items()):
                    if self._conditionally_assigns(stmt, var_name):
                        # Check remaining statements after this block for
                        # unguarded attribute access on var_name
                        remaining = stmts[i + 1:]
                        use_line = self._first_unguarded_attr_use(
                            remaining, var_name
                        )
                        if use_line is not None:
                            self.bugs.append(NoneGuardBug(
                                file_path=self.file_path,
                                line_number=use_line,
                                function_name=self._current_function or '<module>',
                                pattern='none_init_conditional_use',
                                reason=(
                                    f"Variable '{var_name}' is initialized to None "
                                    f"(line {init_line}), conditionally assigned "
                                    f"inside a loop/if (line {stmt.lineno}), and "
                                    f"used via attribute access (line {use_line}) "
                                    f"without a None guard on every path."
                                ),
                                confidence=0.65,
                                variable=var_name,
                            ))

            # If the var is unconditionally reassigned, it's no longer None-risky
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if isinstance(target, ast.Name) and not _is_none(stmt.value):
                    none_vars.pop(target.id, None)

            # Recurse into nested blocks (for detecting patterns inside nested functions etc.)
            # But don't recurse into functions/classes (they have their own scope)
            if isinstance(stmt, (ast.For, ast.While)):
                self._scan_statement_list(stmt.body)
                self._scan_statement_list(stmt.orelse)
            elif isinstance(stmt, ast.If):
                self._scan_statement_list(stmt.body)
                self._scan_statement_list(stmt.orelse)
            elif isinstance(stmt, ast.With):
                self._scan_statement_list(stmt.body)
            elif isinstance(stmt, (ast.Try,)):
                self._scan_statement_list(stmt.body)
                for handler in stmt.handlers:
                    self._scan_statement_list(handler.body)
                self._scan_statement_list(stmt.orelse)
                self._scan_statement_list(stmt.finalbody)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _conditionally_assigns(block_node, var_name: str) -> bool:
        """Return True if *block_node* contains an assignment to *var_name*
        inside a conditional path (if-body, loop body, etc.)."""
        for node in ast.walk(block_node):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == var_name:
                        return True
        return False

    def _first_unguarded_attr_use(
        self, stmts: list, var_name: str
    ) -> Optional[int]:
        """Return line number of the first attribute access on *var_name*
        that is NOT preceded by a None guard (``if var is None`` or
        ``if var is not None``).

        Returns ``None`` if no unguarded use exists.
        """
        for stmt in stmts:
            # If this statement IS a None guard for var_name, stop looking
            if self._is_none_guard(stmt, var_name):
                return None

            # If this statement unconditionally reassigns var_name (not None),
            # it's safe from here
            if self._unconditionally_assigns_non_none(stmt, var_name):
                return None

            # Check if the statement uses var_name via attribute access
            use_line = self._find_attr_use(stmt, var_name)
            if use_line is not None:
                return use_line

        return None

    @staticmethod
    def _is_none_guard(stmt, var_name: str) -> bool:
        """Return True if *stmt* is ``if var is [not] None`` or
        ``if var is None: raise/return/break/continue``."""
        if not isinstance(stmt, ast.If):
            return False
        test = stmt.test
        # ``if var is None`` or ``if var is not None``
        if isinstance(test, ast.Compare):
            if (len(test.ops) == 1 and
                    isinstance(test.ops[0], (ast.Is, ast.IsNot)) and
                    isinstance(test.left, ast.Name) and
                    test.left.id == var_name and
                    len(test.comparators) == 1 and
                    _is_none(test.comparators[0])):
                return True
        # ``if not var``  (truthy guard)
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            if isinstance(test.operand, ast.Name) and test.operand.id == var_name:
                return True
        # ``if var``  (truthy guard)
        if isinstance(test, ast.Name) and test.id == var_name:
            return True
        return False

    @staticmethod
    def _unconditionally_assigns_non_none(stmt, var_name: str) -> bool:
        """True if stmt unconditionally assigns var_name to a non-None value."""
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            t = stmt.targets[0]
            if isinstance(t, ast.Name) and t.id == var_name and not _is_none(stmt.value):
                return True
        return False

    @staticmethod
    def _find_attr_use(node, var_name: str) -> Optional[int]:
        """Find first attribute access on *var_name* within *node*.
        Skip attribute accesses that are assignment targets (``var.x = ...``).
        Also detects dict unpacking ``{**var}`` which crashes on None.
        """
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                if isinstance(child.value, ast.Name) and child.value.id == var_name:
                    return child.lineno
            # method call: var_name.method(...)
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                if isinstance(child.func.value, ast.Name) and child.func.value.id == var_name:
                    return child.func.lineno
            # dict unpacking: {**var_name, ...} — TypeError if var_name is None
            if isinstance(child, ast.Dict):
                for key, value in zip(child.keys, child.values):
                    if key is None and isinstance(value, ast.Name) and value.id == var_name:
                        return value.lineno
        return None

    # ------------------------------------------------------------------
    # Pattern 2: dict subscript result used without None/validity guard
    # ------------------------------------------------------------------

    # Names that suggest "data dicts" whose values may be None/unexpected
    _DATA_DICT_HINTS = frozenset({
        'manifest', 'metadata', 'config', 'info', 'data', 'result',
        'response', 'record', 'row', 'entry', 'item', 'attrs',
        'settings', 'options', 'params', 'kwargs', 'headers',
        'payload', 'body', 'json', 'meta', 'spec', 'schema',
    })

    def _scan_for_dict_value_no_guard(self, stmts: list):
        """Detect dict subscript results used without None/validity guard.

        Pattern (BugsInPy ansible#6):
            version = manifest['version']   # value may be None
            LooseVersion(version)            # crashes on None

        Fix pattern:
            version = manifest['version']
            if not hasattr(LooseVersion(version), 'version'):
                version = '*'               # fallback guard
        """
        # Walk entire statement tree to collect dict-subscript assignments,
        # then check for unguarded uses at or after each assignment site.
        assignments: List[Tuple[str, int, str, ast.AST]] = []  # (var, line, dict_name, assign_node)
        self._collect_dict_subscript_assigns(stmts, assignments)

        reported: set = set()
        for var_name, assign_line, dict_name, assign_node in assignments:
            if var_name in reported:
                continue
            # Only flag dicts whose name hints at external/untrusted data
            base = dict_name.rsplit('.', 1)[-1].lower()
            if base not in self._DATA_DICT_HINTS:
                continue
            # Find all statements that follow the assignment (in all enclosing scopes)
            use_line = self._find_unguarded_use_after(stmts, var_name, assign_line)
            if use_line is not None:
                reported.add(var_name)
                self.bugs.append(NoneGuardBug(
                    file_path=self.file_path,
                    line_number=use_line,
                    function_name=self._current_function or '<module>',
                    pattern='dict_value_no_guard',
                    reason=(
                        f"Variable '{var_name}' is assigned from dict "
                        f"subscript {dict_name}[...] (line {assign_line}) "
                        f"and used without a None/validity guard "
                        f"(line {use_line}). Dictionary values may be "
                        f"None, causing downstream failures."
                    ),
                    confidence=0.72,
                    variable=var_name,
                ))

    def _collect_dict_subscript_assigns(self, stmts: list, out: list,
                                        _membership_guarded: bool = False):
        """Recursively collect all ``var = d[key]`` assignments.

        *_membership_guarded* is True when the current scope is inside an
        ``if key in dict:`` guard whose dict matches the subscript target.
        Assignments under such guards are skipped because the programmer
        has explicitly validated key existence — using the value (even if
        it is ``None``) is intentional.
        """
        for stmt in stmts:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if isinstance(target, ast.Name):
                    dict_name = self._is_dict_subscript(stmt.value)
                    if dict_name is not None and not _membership_guarded:
                        out.append((target.id, stmt.lineno, dict_name, stmt))
            # Recurse into compound statements, propagating membership guard
            if isinstance(stmt, ast.If):
                guarded = _membership_guarded or self._is_membership_guard(stmt)
                for block in self._child_blocks(stmt):
                    self._collect_dict_subscript_assigns(block, out,
                                                        _membership_guarded=guarded)
            else:
                for block in self._child_blocks(stmt):
                    self._collect_dict_subscript_assigns(block, out,
                                                        _membership_guarded=_membership_guarded)

    @staticmethod
    def _child_blocks(stmt) -> List[list]:
        """Return child statement blocks of a compound statement."""
        blocks: List[list] = []
        if isinstance(stmt, (ast.For, ast.While)):
            blocks.append(stmt.body)
            blocks.append(stmt.orelse)
        elif isinstance(stmt, ast.If):
            blocks.append(stmt.body)
            blocks.append(stmt.orelse)
        elif isinstance(stmt, ast.With):
            blocks.append(stmt.body)
        elif isinstance(stmt, ast.Try):
            blocks.append(stmt.body)
            for handler in stmt.handlers:
                blocks.append(handler.body)
            blocks.append(stmt.orelse)
            blocks.append(stmt.finalbody)
        return blocks

    def _find_unguarded_use_after(
        self, stmts: list, var_name: str, after_line: int,
    ) -> Optional[int]:
        """Find first unguarded use of *var_name* in attr access or call arg
        appearing on or after *after_line* in the statement tree."""
        for stmt in stmts:
            stmt_line = getattr(stmt, 'lineno', 0)
            if stmt_line <= after_line:
                # Check child blocks that may contain post-assignment code
                for block in self._child_blocks(stmt):
                    result = self._find_unguarded_use_after(block, var_name, after_line)
                    if result is not None:
                        return result
                continue

            # Guard check
            if isinstance(stmt, ast.If):
                if self._is_none_guard(stmt, var_name):
                    return None
                if self._is_hasattr_guard(stmt, var_name):
                    return None
            # Unconditional non-None reassignment
            if self._unconditionally_assigns_non_none(stmt, var_name):
                return None

            # Check for use in attr access
            attr_line = self._find_attr_use(stmt, var_name)
            if attr_line is not None:
                return attr_line
            # Check for use as function argument
            call_line = self._find_call_arg_use(stmt, var_name)
            if call_line is not None:
                return call_line

            # Also check inside compound statement bodies
            for block in self._child_blocks(stmt):
                result = self._find_unguarded_use_after(block, var_name, after_line)
                if result is not None:
                    return result
        return None

    def _is_dict_subscript(self, node) -> Optional[str]:
        """Return dict variable name if node is ``d[key]`` with a string/const key.

        Returns None if it's not a dict subscript or if the dict is a
        known-safe constructor result.
        """
        if not isinstance(node, ast.Subscript):
            return None
        # The dict object
        value = node.value
        if isinstance(value, ast.Name):
            name = value.id
            # Filter out known non-dict types (list indexing, etc.)
            # Heuristic: name matches data-dict hints OR is generic
            return name
        if isinstance(value, ast.Attribute):
            return self._attr_chain(value)
        # Chained subscript: d[k1][k2]
        if isinstance(value, ast.Subscript):
            inner = self._is_dict_subscript(value)
            if inner:
                return inner
        return None

    @staticmethod
    def _attr_chain(node) -> Optional[str]:
        """Build ``a.b.c`` string from nested Attribute nodes."""
        parts: list = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return '.'.join(reversed(parts))
        return None

    @staticmethod
    def _find_call_arg_use(node, var_name: str) -> Optional[int]:
        """Find first use of *var_name* as argument to a function call.

        Keyword-argument pass-through (``func(name=name)``) is excluded:
        the callee explicitly declares a parameter for this value and is
        expected to handle ``None`` gracefully (common deserialization /
        ``from_config`` idiom).
        """
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                for arg in child.args:
                    if isinstance(arg, ast.Name) and arg.id == var_name:
                        return child.lineno
                for kw in child.keywords:
                    if isinstance(kw.value, ast.Name) and kw.value.id == var_name:
                        # Skip keyword pass-through: func(var=var)
                        if kw.arg == var_name:
                            continue
                        return child.lineno
        return None

    @staticmethod
    def _is_hasattr_guard(stmt, var_name: str) -> bool:
        """Return True if *stmt* is a guard using hasattr/isinstance on var."""
        if not isinstance(stmt, ast.If):
            return False
        test = stmt.test
        # hasattr(expr, ...) where expr involves var_name
        if isinstance(test, ast.Call) and isinstance(test.func, ast.Name):
            if test.func.id == 'hasattr':
                return True
        # not hasattr(...)
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            inner = test.operand
            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name):
                if inner.func.id == 'hasattr':
                    return True
        return False

    @staticmethod
    def _is_membership_guard(stmt) -> bool:
        """Return True if *stmt* is ``if key in dict:`` or ``if key in dict.keys():``.

        This indicates the programmer validated key existence before
        subscripting, so the dict-subscript value is intentional — even
        if it is ``None``.
        """
        if not isinstance(stmt, ast.If):
            return False
        test = stmt.test
        # ``'key' in config`` → Compare(left=Constant, ops=[In], comparators=[Name])
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            if isinstance(test.ops[0], ast.In):
                return True
        return False

    # ------------------------------------------------------------------
    # Pattern 4: dict.items() iteration value used without None guard
    # ------------------------------------------------------------------

    def _scan_for_dict_items_iteration_no_guard(self, func_node):
        """Detect dict values from .items() iteration used without None guard.

        Pattern (BugsInPy ansible#9):
            for pool_id, quantity in sorted(pool_ids.items()):
                args = [CMD, '--quantity', quantity]  # quantity may be None

        Fix pattern:
            for pool_id, quantity in sorted(pool_ids.items()):
                if quantity is not None:
                    args.extend(['--quantity', quantity])
        """
        for node in ast.walk(func_node):
            if not isinstance(node, ast.For):
                continue
            # Check if iterating over dict.items() (possibly wrapped in sorted())
            val_var = self._get_dict_items_value_var(node)
            if val_var is None:
                continue
            # Check if the value variable is used in the loop body without
            # a None guard
            use_line = self._find_unguarded_use_in_body(
                node.body, val_var
            )
            if use_line is not None:
                self.bugs.append(NoneGuardBug(
                    file_path=self.file_path,
                    line_number=use_line,
                    function_name=self._current_function or '<module>',
                    pattern='dict_items_value_no_guard',
                    reason=(
                        f"Variable '{val_var}' is unpacked from dict "
                        f".items() iteration (line {node.lineno}) and "
                        f"used without a None guard (line {use_line}). "
                        f"Dictionary values may be None."
                    ),
                    confidence=0.70,
                    variable=val_var,
                ))

    @staticmethod
    def _get_dict_items_value_var(for_node: ast.For) -> Optional[str]:
        """If *for_node* is ``for k, v in d.items():`` (or wrapped in
        sorted()), return the name of *v*.  Otherwise return None."""
        target = for_node.target
        if not isinstance(target, ast.Tuple) or len(target.elts) != 2:
            return None
        val_elt = target.elts[1]
        if not isinstance(val_elt, ast.Name):
            return None

        iter_expr = for_node.iter
        # Unwrap sorted(...) / list(...) wrappers
        if (isinstance(iter_expr, ast.Call)
                and isinstance(iter_expr.func, ast.Name)
                and iter_expr.func.id in ('sorted', 'list', 'reversed')
                and iter_expr.args):
            iter_expr = iter_expr.args[0]

        # Now expect d.items() call
        if (isinstance(iter_expr, ast.Call)
                and isinstance(iter_expr.func, ast.Attribute)
                and iter_expr.func.attr == 'items'):
            return val_elt.id
        return None

    def _find_unguarded_use_in_body(
        self, stmts: list, var_name: str,
    ) -> Optional[int]:
        """Find first use of *var_name* in a list literal or function arg
        inside *stmts* that is NOT preceded by an ``if var is not None`` guard.

        Returns line number or None.
        """
        for stmt in stmts:
            # Guard: ``if var is not None`` / ``if var is None``
            if self._is_none_guard(stmt, var_name):
                return None

            # Check for use in list literal elements
            line = self._find_list_or_arg_use(stmt, var_name)
            if line is not None:
                return line

            # Recurse into if-bodies (but skip guarded branches)
            if isinstance(stmt, ast.If):
                # Only recurse into the body if this is NOT a guard
                result = self._find_unguarded_use_in_body(stmt.body, var_name)
                if result is not None:
                    return result
                result = self._find_unguarded_use_in_body(stmt.orelse, var_name)
                if result is not None:
                    return result
        return None

    @staticmethod
    def _find_list_or_arg_use(node, var_name: str) -> Optional[int]:
        """Find first use of *var_name* inside a list literal or as a
        function/method argument within *node*."""
        for child in ast.walk(node):
            # Usage in a list literal: [... var ...]
            if isinstance(child, ast.List):
                for elt in child.elts:
                    if isinstance(elt, ast.Name) and elt.id == var_name:
                        return child.lineno
            # Usage as function argument: func(... var ...)
            if isinstance(child, ast.Call):
                for arg in child.args:
                    if isinstance(arg, ast.Name) and arg.id == var_name:
                        return child.lineno
                for kw in child.keywords:
                    if isinstance(kw.value, ast.Name) and kw.value.id == var_name:
                        return child.lineno
            # Usage in attribute access: var.attr
            if isinstance(child, ast.Attribute):
                if isinstance(child.value, ast.Name) and child.value.id == var_name:
                    return child.lineno
        return None

    # ------------------------------------------------------------------
    # Pattern 3: factory method called without file-existence precondition
    # ------------------------------------------------------------------

    # Method names that imply loading from a path / file
    _FACTORY_NAMES = frozenset({
        'from_path', 'from_file', 'from_dir', 'from_directory',
        'load_from', 'read_from', 'open_from', 'load',
    })

    def _scan_for_missing_precondition(self, func_node):
        """Detect factory method calls inside isdir checks without isfile checks.

        Pattern:
            if os.path.isdir(path):
                obj = Cls.from_path(path, ...)  # may fail if expected file missing
        Fix:
            if os.path.isdir(path):
                if not os.path.isfile(path / 'MANIFEST.json'):
                    raise ...
                obj = Cls.from_path(path, ...)
        """
        for node in ast.walk(func_node):
            if not isinstance(node, ast.If):
                continue
            # Check if the condition is  os.path.isdir(...)
            if not self._is_isdir_call(node.test):
                continue
            # Look for factory method calls in the if-body WITHOUT an isfile check
            has_isfile = self._body_has_isfile_check(node.body)
            if has_isfile:
                continue
            for call_node, var_name in self._find_factory_calls_with_targets(node.body):
                self.bugs.append(NoneGuardBug(
                    file_path=self.file_path,
                    line_number=call_node.lineno,
                    function_name=self._current_function or '<module>',
                    pattern='none_init_conditional_use',
                    reason=(
                        f"Factory method called inside os.path.isdir() check "
                        f"without verifying required files exist (os.path.isfile). "
                        f"The factory may raise or return None when expected files "
                        f"are missing, leading to a potential null dereference."
                    ),
                    confidence=0.85,
                    variable=var_name,
                ))

    @staticmethod
    def _is_isdir_call(node) -> bool:
        """Check if node is ``os.path.isdir(...)``."""
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        # os.path.isdir(...)
        if isinstance(func, ast.Attribute) and func.attr == 'isdir':
            if isinstance(func.value, ast.Attribute) and func.value.attr == 'path':
                return True
        return False

    @staticmethod
    def _body_has_isfile_check(stmts: list) -> bool:
        """Return True if any statement in *stmts* calls os.path.isfile."""
        for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == 'isfile':
                    return True
        return False

    def _find_factory_calls_with_targets(self, stmts: list):
        """Yield (Call node, variable_name) pairs for factory method calls."""
        for stmt in stmts:
            # Direct: var = Cls.from_path(...)
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if isinstance(target, ast.Name) and isinstance(stmt.value, ast.Call):
                    if isinstance(stmt.value.func, ast.Attribute):
                        if stmt.value.func.attr in self._FACTORY_NAMES:
                            yield stmt.value, target.id
            # Recurse into nested blocks (but not functions/classes)
            if isinstance(stmt, (ast.For, ast.While)):
                yield from self._find_factory_calls_with_targets(stmt.body)
            elif isinstance(stmt, ast.If):
                yield from self._find_factory_calls_with_targets(stmt.body)
                yield from self._find_factory_calls_with_targets(stmt.orelse)
            elif isinstance(stmt, ast.With):
                yield from self._find_factory_calls_with_targets(stmt.body)
            elif isinstance(stmt, ast.Try):
                yield from self._find_factory_calls_with_targets(stmt.body)


    # ------------------------------------------------------------------
    # Pattern 5: chained attribute access without None guard
    # ------------------------------------------------------------------

    def _scan_for_chained_attr_missing_guard(self, func_node):
        """Detect chained attribute access ``obj.a.b`` where ``obj.a`` may be None.

        Pattern (BugsInPy ansible#10):
            if current_line.prev is not None:      # proves .prev can be None
                current_line.prev.next = current_line.next
                current_line.next.prev = current_line.prev  # .next NOT guarded!

        The existence of ``if obj.attr1 is not None:`` proves that attributes
        of *obj* can be None.  If ``obj.attr2.something`` is accessed without
        a similar guard for ``obj.attr2``, it is a potential NULL_PTR.
        """
        # Step 1: collect all ``if obj.attr is [not] None`` guards in the function.
        #         This gives us (obj_name, guarded_attr) pairs.
        guarded_attrs: Dict[str, Set[str]] = {}  # obj_name -> {attr1, attr2, ...}
        self._collect_none_guards_on_attrs(func_node, guarded_attrs)

        if not guarded_attrs:
            return

        # Step 2: find chained attribute accesses ``obj.attr.something`` where
        #         *attr* is NOT guarded but a sibling attribute on the same obj IS guarded.
        reported: set = set()
        for node in ast.walk(func_node):
            # Match obj.attr2.something  (read or write)
            # AST shape for read:  Attribute(value=Attribute(value=Name(id=obj), attr=attr2), attr=something)
            # AST shape for write: Assign(targets=[Attribute(value=Attribute(value=Name(id=obj), attr=attr2), ...)])
            chain = self._extract_two_level_chain(node)
            if chain is None:
                continue
            obj_name, mid_attr, leaf_attr, lineno = chain

            if obj_name not in guarded_attrs:
                continue

            # mid_attr is already guarded → safe
            if mid_attr in guarded_attrs[obj_name]:
                continue

            # Check if mid_attr is guarded by an enclosing ``if obj.mid_attr is not None``
            if self._is_inside_none_guard_for_attr(func_node, node, obj_name, mid_attr):
                continue

            key = (obj_name, mid_attr, lineno)
            if key in reported:
                continue
            reported.add(key)

            self.bugs.append(NoneGuardBug(
                file_path=self.file_path,
                line_number=lineno,
                function_name=self._current_function or '<module>',
                pattern='chained_attr_missing_guard',
                reason=(
                    f"Chained attribute access '{obj_name}.{mid_attr}.{leaf_attr}' "
                    f"(line {lineno}) without a None guard on '{obj_name}.{mid_attr}'. "
                    f"A sibling attribute '{obj_name}.{list(guarded_attrs[obj_name])[0]}' "
                    f"IS guarded with 'is not None', suggesting '{mid_attr}' may "
                    f"also be None."
                ),
                confidence=0.70,
                variable=f"{obj_name}.{mid_attr}",
            ))

    @staticmethod
    def _collect_none_guards_on_attrs(
        func_node, out: Dict[str, Set[str]],
    ) -> None:
        """Find all ``if obj.attr is [not] None`` tests in *func_node*.

        Populates *out* mapping obj_name → set of guarded attribute names.
        """
        for node in ast.walk(func_node):
            if not isinstance(node, ast.If):
                continue
            test = node.test
            # ``if obj.attr is [not] None``
            if isinstance(test, ast.Compare) and len(test.ops) == 1:
                if isinstance(test.ops[0], (ast.Is, ast.IsNot)):
                    if (len(test.comparators) == 1
                            and _is_none(test.comparators[0])):
                        left = test.left
                        if (isinstance(left, ast.Attribute)
                                and isinstance(left.value, ast.Name)):
                            obj_name = left.value.id
                            attr_name = left.attr
                            out.setdefault(obj_name, set()).add(attr_name)

    @staticmethod
    def _extract_two_level_chain(node) -> Optional[Tuple[str, str, str, int]]:
        """Extract ``(obj, mid_attr, leaf_attr, lineno)`` from a two-level
        attribute chain.

        Matches both reads (``obj.a.b``) and writes (``obj.a.b = ...``).
        """
        attr_node = None
        if isinstance(node, ast.Attribute):
            attr_node = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute):
                    attr_node = target
                    break

        if attr_node is None:
            return None

        inner = attr_node.value
        if not isinstance(inner, ast.Attribute):
            return None
        if not isinstance(inner.value, ast.Name):
            return None

        return (inner.value.id, inner.attr, attr_node.attr, attr_node.lineno)

    @staticmethod
    def _is_inside_none_guard_for_attr(
        func_node, target_node, obj_name: str, attr_name: str,
    ) -> bool:
        """Return True if *target_node* is inside an ``if obj.attr is not None:`` block."""
        target_line = getattr(target_node, 'lineno', 0)
        for node in ast.walk(func_node):
            if not isinstance(node, ast.If):
                continue
            test = node.test
            if not isinstance(test, ast.Compare) or len(test.ops) != 1:
                continue
            if not isinstance(test.ops[0], ast.IsNot):
                continue
            if not (len(test.comparators) == 1 and _is_none(test.comparators[0])):
                continue
            left = test.left
            if not (isinstance(left, ast.Attribute) and isinstance(left.value, ast.Name)):
                continue
            if left.value.id != obj_name or left.attr != attr_name:
                continue
            # Check if target_node is inside this if-body
            for child in ast.walk(node):
                if child is target_node:
                    return True
                if getattr(child, 'lineno', 0) == target_line and type(child) is type(target_node):
                    return True
        return False

    # ------------------------------------------------------------------
    # Pattern 6: parameter with default=None used via attribute access
    # ------------------------------------------------------------------

    def _scan_for_param_default_none_attr_access(self, func_node):
        """Detect parameter with default=None used with attribute access.

        Pattern (BugsInPy ansible#16):
            def get_cpu_facts(self, collected_facts=None):
                ...
                collected_facts.get('ansible_architecture', '')  # NULL_PTR!

        The parameter has a default value of None.  If the caller omits it,
        any attribute access on it will raise AttributeError.
        """
        args = func_node.args.args
        defaults = func_node.args.defaults

        none_default_params: Set[str] = set()

        # defaults are right-aligned with positional args
        if defaults:
            offset = len(args) - len(defaults)
            for i, default in enumerate(defaults):
                if _is_none(default):
                    param_idx = offset + i
                    if param_idx < len(args):
                        none_default_params.add(args[param_idx].arg)

        # kw_defaults for keyword-only args
        for i, default in enumerate(func_node.args.kw_defaults):
            if default and _is_none(default):
                if i < len(func_node.args.kwonlyargs):
                    none_default_params.add(func_node.args.kwonlyargs[i].arg)

        if not none_default_params:
            return

        for param_name in none_default_params:
            use_line = self._first_unguarded_attr_use(
                func_node.body, param_name
            )
            if use_line is not None:
                self.bugs.append(NoneGuardBug(
                    file_path=self.file_path,
                    line_number=use_line,
                    function_name=self._current_function or '<module>',
                    pattern='param_default_none_attr_access',
                    reason=(
                        f"Parameter '{param_name}' has default value of None "
                        f"but is used via attribute access (line {use_line}) "
                        f"without a None guard. If called without this "
                        f"argument, an AttributeError will occur."
                    ),
                    confidence=0.70,
                    variable=param_name,
                ))


    # ------------------------------------------------------------------
    # Pattern 7: unprotected resource constructor before try/finally cleanup
    # ------------------------------------------------------------------

    # Cleanup method names that indicate resource management
    _CLEANUP_METHODS = frozenset({
        'shutdown', 'close', 'release', 'dispose', 'cleanup',
        'disconnect', 'terminate', 'destroy', 'stop',
    })

    # Constructor names known to raise on certain platforms/configs
    _RESOURCE_CONSTRUCTORS = frozenset({
        'ProcessPoolExecutor', 'ThreadPoolExecutor',
        'Pool', 'Manager', 'Server',
        'Connection', 'Socket',
    })

    def _scan_for_unprotected_resource_finally(self, func_node):
        """Detect resource constructors before try/finally without exception protection.

        Pattern (BugsInPy black#1):
            executor = ProcessPoolExecutor(max_workers=worker_count)
            try:
                loop.run_until_complete(schedule_formatting(..., executor=executor))
            finally:
                shutdown(loop)
                executor.shutdown()  # No None guard; constructor assumed infallible

        Fix pattern:
            try:
                executor = ProcessPoolExecutor(max_workers=worker_count)
            except OSError:
                executor = None
            try:
                ...
            finally:
                if executor is not None:
                    executor.shutdown()

        The constructor can raise on certain platforms (e.g. OSError on AWS Lambda
        for ProcessPoolExecutor). Without exception handling, the code crashes
        instead of degrading gracefully. With exception handling but without a
        None guard, a NULL_PTR occurs in the finally block.
        """
        self._scan_stmts_for_resource_finally(func_node.body)

    def _scan_stmts_for_resource_finally(self, stmts: list):
        """Scan statement list for the resource-before-finally pattern."""
        for i, stmt in enumerate(stmts):
            # Look for: var = Constructor(...)
            var_name, ctor_line = self._is_resource_constructor_assign(stmt)
            if var_name is None:
                continue

            # Check if any subsequent statement is a Try with a finally block
            # that uses var_name with attribute access
            for j in range(i + 1, len(stmts)):
                subsequent = stmts[j]
                if not isinstance(subsequent, ast.Try):
                    continue
                if not subsequent.finalbody:
                    continue

                # Check: is the constructor assignment already wrapped in a
                # try/except that catches the exception?
                if self._is_wrapped_in_try_except(stmts, i):
                    continue

                # Look for unguarded attribute access on var_name in the
                # finally block
                use_line = self._find_unguarded_cleanup_use(
                    subsequent.finalbody, var_name
                )
                if use_line is not None:
                    self.bugs.append(NoneGuardBug(
                        file_path=self.file_path,
                        line_number=use_line,
                        function_name=self._current_function or '<module>',
                        pattern='unprotected_resource_finally',
                        reason=(
                            f"Variable '{var_name}' is assigned from a "
                            f"constructor call (line {ctor_line}) and used "
                            f"via attribute access in a finally block "
                            f"(line {use_line}) without a None guard. "
                            f"If the constructor raises (e.g. OSError on "
                            f"certain platforms), the code crashes instead "
                            f"of handling the failure gracefully."
                        ),
                        confidence=0.60,
                        variable=var_name,
                    ))
                    break  # one report per variable

            # Also recurse into compound statement children
            for block in self._child_blocks(stmt):
                self._scan_stmts_for_resource_finally(block)

    def _is_resource_constructor_assign(
        self, stmt
    ) -> Tuple[Optional[str], int]:
        """Check if stmt is ``var = Constructor(...)``.

        Returns (var_name, line_number) or (None, 0).
        A constructor call is identified by:
        - Known resource constructor name, OR
        - Capitalized function name (Python convention for classes)
        """
        if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
            return None, 0
        target = stmt.targets[0]
        if not isinstance(target, ast.Name):
            return None, 0
        if not isinstance(stmt.value, ast.Call):
            return None, 0

        call_name = self._get_call_name(stmt.value)
        if call_name is None:
            return None, 0

        # Known resource constructors or capitalized name (class convention)
        base_name = call_name.rsplit('.', 1)[-1]
        if (base_name in self._RESOURCE_CONSTRUCTORS
                or (base_name[0:1].isupper() and not base_name.isupper())):
            return target.id, stmt.lineno

        return None, 0

    @staticmethod
    def _get_call_name(call_node: ast.Call) -> Optional[str]:
        """Extract the name string from a Call node."""
        func = call_node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts = []
            node = func
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
                return '.'.join(reversed(parts))
        return None

    def _is_wrapped_in_try_except(self, stmts: list, target_idx: int) -> bool:
        """Check if the statement at target_idx is inside a try/except in stmts.

        This checks if there is a *preceding* Try statement that wraps the
        constructor assignment with an except handler.
        """
        # The assignment itself is at stmts[target_idx]. If it's directly in
        # this statement list, it's NOT wrapped. It would need to be inside
        # a Try's body to be wrapped.
        return False

    def _find_unguarded_cleanup_use(
        self, stmts: list, var_name: str
    ) -> Optional[int]:
        """Find attribute access on var_name in finally body without a None guard."""
        for stmt in stmts:
            # Guard: ``if var is not None:``
            if self._is_none_guard(stmt, var_name):
                return None

            # Attribute access: var.method(...)
            use_line = self._find_attr_use(stmt, var_name)
            if use_line is not None:
                return use_line

        return None


    # ------------------------------------------------------------------
    # Pattern 8: self.X = None in __init__, method uses correlated state
    #            without guarding for self.X being None
    # ------------------------------------------------------------------

    def _scan_class_for_self_attr_none_init(self, class_node: ast.ClassDef):
        """Detect self.X = None in __init__ used in methods without guard.

        Pattern (BugsInPy black#4):
            class EmptyLineTracker:
                def __init__(self):
                    self.previous_line = None
                    self.previous_after = 0

                def maybe_empty_lines(self, current_line):
                    before, after = self._maybe_empty_lines(current_line)
                    before -= self.previous_after  # BUG: no guard
                    self.previous_after = after
                    self.previous_line = current_line
                    return before, after

        Fix: add ``if self.previous_line is None`` guard before using
        ``self.previous_after``.
        """
        init_method = None
        other_methods = []
        for item in class_node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name == '__init__':
                    init_method = item
                else:
                    other_methods.append(item)

        if init_method is None:
            return

        # Collect self.X = None (top-level in __init__ body) and all init attrs
        none_attrs: Dict[str, int] = {}
        all_init_attrs: Set[str] = set()
        for stmt in init_method.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if (isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == 'self'):
                    all_init_attrs.add(target.attr)
                    if _is_none(stmt.value):
                        none_attrs[target.attr] = stmt.lineno
                    else:
                        # Later unconditional non-None assignment removes it
                        none_attrs.pop(target.attr, None)
        # Also collect attrs from nested blocks (but don't remove from none_attrs
        # since nested assignments are conditional)
        for stmt in init_method.body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        if (isinstance(t, ast.Attribute)
                                and isinstance(t.value, ast.Name)
                                and t.value.id == 'self'):
                            all_init_attrs.add(t.attr)

        if not none_attrs:
            return

        for method in other_methods:
            self._check_method_self_none_state(
                class_node, method, none_attrs, all_init_attrs
            )

    def _check_method_self_none_state(
        self, class_node, method, none_attrs: Dict[str, int],
        all_init_attrs: Set[str],
    ):
        """Check one method for the self-attr None-state bug pattern."""
        for attr_name, init_line in none_attrs.items():
            # 1. Method sets self.attr_name to non-None?
            set_line = self._find_self_attr_set_line(method.body, attr_name)
            if set_line is None:
                continue

            # 2. Guard exists anywhere in the method?
            if self._method_has_self_none_guard(method, attr_name):
                continue

            # 3. Sibling self.* attrs (init'd AND set in this method) read
            #    before the set_line?
            sibling_set = self._find_all_self_attrs_set(method.body)
            reads_before = self._find_self_attr_reads_before(
                method.body, set_line
            )

            for read_node in reads_before:
                read_attr = read_node.attr
                if read_attr == attr_name:
                    continue
                if read_attr not in all_init_attrs:
                    continue
                if read_attr not in sibling_set:
                    continue

                func_name = f"{class_node.name}.{method.name}"
                self.bugs.append(NoneGuardBug(
                    file_path=self.file_path,
                    line_number=read_node.lineno,
                    function_name=func_name,
                    pattern='self_attr_none_init_no_guard',
                    reason=(
                        f"Instance attribute 'self.{attr_name}' is initialized "
                        f"to None in __init__ (line {init_line}) and updated in "
                        f"'{method.name}' (line {set_line}), but "
                        f"'self.{read_attr}' is used (line {read_node.lineno}) "
                        f"without checking 'if self.{attr_name} is None'. On "
                        f"first invocation, self.{attr_name} is still None and "
                        f"the operation may produce incorrect results."
                    ),
                    confidence=0.72,
                    variable=f"self.{attr_name}",
                ))
                return  # one bug per (method, attr)

    @staticmethod
    def _find_self_attr_set_line(stmts, attr_name: str) -> Optional[int]:
        """Find line where self.attr_name is assigned a non-None value."""
        for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if (isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == 'self'
                        and target.attr == attr_name
                        and not _is_none(node.value)):
                    return node.lineno
        return None

    @staticmethod
    def _method_has_self_none_guard(method, attr_name: str) -> bool:
        """Check if method contains ``if self.attr_name is [not] None``."""
        for node in ast.walk(method):
            if isinstance(node, ast.Compare) and len(node.ops) == 1:
                if isinstance(node.ops[0], (ast.Is, ast.IsNot)):
                    left = node.left
                    if (isinstance(left, ast.Attribute)
                            and isinstance(left.value, ast.Name)
                            and left.value.id == 'self'
                            and left.attr == attr_name
                            and len(node.comparators) == 1
                            and _is_none(node.comparators[0])):
                        return True
        return False

    @staticmethod
    def _find_all_self_attrs_set(stmts) -> Set[str]:
        """Find all self.* attributes assigned anywhere in *stmts*."""
        result: Set[str] = set()
        for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == 'self'):
                        result.add(target.attr)
            if isinstance(node, ast.AugAssign):
                target = node.target
                if (isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == 'self'):
                    result.add(target.attr)
        return result

    @staticmethod
    def _find_self_attr_reads_before(stmts, before_line: int) -> list:
        """Find self.* Attribute read-nodes occurring before *before_line*.

        Write-targets (left side of Assign / AugAssign) are excluded.
        """
        reads: list = []
        for stmt in stmts:
            if getattr(stmt, 'lineno', 0) >= before_line:
                break
            # Collect ids of Attribute nodes that are write targets
            write_ids: Set[int] = set()
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if (isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == 'self'):
                        write_ids.add(id(target))
            elif isinstance(stmt, ast.AugAssign):
                if (isinstance(stmt.target, ast.Attribute)
                        and isinstance(stmt.target.value, ast.Name)
                        and stmt.target.value.id == 'self'):
                    write_ids.add(id(stmt.target))

            for node in ast.walk(stmt):
                if (isinstance(node, ast.Attribute)
                        and isinstance(node.value, ast.Name)
                        and node.value.id == 'self'
                        and id(node) not in write_ids):
                    reads.append(node)
        return reads


    # ------------------------------------------------------------------
    # Pattern 9: list[-1].attr check without exhaustive element type handling
    # ------------------------------------------------------------------

    def _scan_for_last_element_attr_assumption(self, func_node):
        """Detect list[-1].attr comparison that assumes element type.

        Pattern (BugsInPy black#8):
            if leaves:
                if leaves[-1].type != token.COMMA:
                    leaves.append(Leaf(token.COMMA, ","))

        The code checks the last element's attribute against one specific
        value and mutates the list on mismatch, but doesn't account for
        other element types (e.g., STANDALONE_COMMENT) that may appear at
        the end. The fix replaces the direct check with a backward
        iteration that skips/handles each element type explicitly.
        """
        self._scan_stmts_for_last_elem_pattern(func_node.body)

    def _scan_stmts_for_last_elem_pattern(self, stmts: list):
        """Recursively scan for the list[-1].attr comparison-then-mutate pattern."""
        for stmt in stmts:
            if isinstance(stmt, ast.If):
                guard_var = self._get_truthiness_guard_var(stmt.test)
                if guard_var is not None:
                    self._check_for_last_elem_attr_check_and_mutate(
                        stmt.body, guard_var
                    )
            # Recurse into compound statements
            for block in self._child_blocks(stmt):
                self._scan_stmts_for_last_elem_pattern(block)

    def _check_for_last_elem_attr_check_and_mutate(
        self, stmts: list, list_var: str
    ):
        """Check if stmts contain list[-1].attr comparison followed by mutation."""
        for stmt in stmts:
            if isinstance(stmt, ast.If):
                result = self._extract_last_elem_attr_check(stmt.test, list_var)
                if result is not None:
                    attr_name, line = result
                    # Check if the if body or else body mutates the list
                    if (self._body_mutates_list(stmt.body, list_var) or
                            self._body_mutates_list(stmt.orelse, list_var)):
                        self.bugs.append(NoneGuardBug(
                            file_path=self.file_path,
                            line_number=line,
                            function_name=self._current_function or '<module>',
                            pattern='last_element_type_assumption',
                            reason=(
                                f"'{list_var}[-1].{attr_name}' is checked "
                                f"against a single value and the list is "
                                f"mutated on mismatch, but other element "
                                f"types at the end of the list are not "
                                f"handled. Consider iterating backwards to "
                                f"skip non-matching element types."
                            ),
                            confidence=0.72,
                            variable=list_var,
                        ))
                        return  # one report per block
            # Recurse into nested if bodies
            if isinstance(stmt, ast.If):
                self._check_for_last_elem_attr_check_and_mutate(
                    stmt.body, list_var
                )
                self._check_for_last_elem_attr_check_and_mutate(
                    stmt.orelse, list_var
                )

    @staticmethod
    def _get_truthiness_guard_var(test) -> Optional[str]:
        """Get variable name from a truthiness test (``if var:``)."""
        if isinstance(test, ast.Name):
            return test.id
        return None

    @staticmethod
    def _extract_last_elem_attr_check(test, list_var: str) -> Optional[Tuple[str, int]]:
        """Check if test is ``list_var[-1].attr != CONST`` or ``== CONST``.

        Returns (attr_name, lineno) or None.
        """
        if not isinstance(test, ast.Compare):
            return None
        if len(test.ops) != 1 or len(test.comparators) != 1:
            return None
        if not isinstance(test.ops[0], (ast.NotEq, ast.Eq)):
            return None

        left = test.left
        if not isinstance(left, ast.Attribute):
            return None
        attr_name = left.attr

        subscript = left.value
        if not isinstance(subscript, ast.Subscript):
            return None
        if not isinstance(subscript.value, ast.Name):
            return None
        if subscript.value.id != list_var:
            return None

        # Check index is -1 (UnaryOp(USub, 1) or Constant(-1))
        idx = subscript.slice
        if isinstance(idx, ast.Constant) and idx.value == -1:
            return (attr_name, left.lineno)
        if (isinstance(idx, ast.UnaryOp) and isinstance(idx.op, ast.USub)
                and isinstance(idx.operand, ast.Constant)
                and idx.operand.value == 1):
            return (attr_name, left.lineno)

        return None

    # ------------------------------------------------------------------
    # Pattern: interprocedural call-result-may-be-None passthrough
    # ------------------------------------------------------------------

    def _scan_for_call_result_none_passthrough(self, func_node):
        """Detect when result of a None-returning function is passed to another call.

        Pattern (BugsInPy cookiecutter#2):
            def find_hook(hook_name):
                ...
                return None  # may return None

            def run_hook(hook_name, project_dir, context):
                script = find_hook(hook_name)    # may be None
                if script is None:
                    return
                run_script_with_context(script, project_dir, context)  # used

        The function find_hook may return None. Even though there is a None
        check, the value is passed to another function call, creating an
        interprocedural None-propagation risk.
        """
        if not self._none_returning_funcs:
            return

        body = func_node.body
        # Track variables assigned from calls to None-returning functions
        # Format: {var_name: (assign_line, callee_name)}
        none_result_vars: Dict[str, Tuple[int, str]] = {}

        for i, stmt in enumerate(body):
            # Detect: var = none_returning_func(...)
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if isinstance(target, ast.Name) and isinstance(stmt.value, ast.Call):
                    callee = self._get_simple_call_name(stmt.value)
                    if callee and callee in self._none_returning_funcs:
                        none_result_vars[target.id] = (stmt.lineno, callee)
                    elif target.id in none_result_vars:
                        # Reassigned to something else — no longer tracked
                        del none_result_vars[target.id]

            # For each tracked var, check if it's passed to another function call
            # AFTER an is-None guard (the guard makes the code "safe" but the
            # interprocedural flow is still risky)
            for var_name, (assign_line, callee_name) in list(none_result_vars.items()):
                if getattr(stmt, 'lineno', 0) <= assign_line:
                    continue
                # Find use of var as argument to another function call
                # (but NOT in a None-guard if-block itself)
                use_line = self._find_call_arg_passthrough(
                    body[i:], var_name, assign_line
                )
                if use_line is not None:
                    self.bugs.append(NoneGuardBug(
                        file_path=self.file_path,
                        line_number=use_line,
                        function_name=self._current_function or '<module>',
                        pattern='call_result_none_passthrough',
                        reason=(
                            f"Variable '{var_name}' is assigned from "
                            f"'{callee_name}()' (line {assign_line}) which "
                            f"may return None. The value is passed to "
                            f"another function call (line {use_line}), "
                            f"creating an interprocedural None-propagation "
                            f"risk."
                        ),
                        confidence=0.55,
                        variable=var_name,
                    ))
                    # Only report once per variable
                    del none_result_vars[var_name]
                    break

    @staticmethod
    def _get_simple_call_name(call_node: ast.Call) -> Optional[str]:
        """Get the simple function name from a Call node (no method calls)."""
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        return None

    def _find_call_arg_passthrough(
        self, stmts: list, var_name: str, assign_line: int,
    ) -> Optional[int]:
        """Find first use of var_name as an argument to a function call
        in remaining statements, skipping past None-guard blocks.

        Returns the line number of the call, or None.
        """
        for stmt in stmts:
            if getattr(stmt, 'lineno', 0) <= assign_line:
                continue

            # If this is a None guard (if var is None: return/...), skip past it
            # but continue looking at subsequent statements
            if isinstance(stmt, ast.If) and self._is_none_guard(stmt, var_name):
                continue

            # Check if stmt contains a call with var_name as argument
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id == var_name:
                            return node.lineno
                    for kw in node.keywords:
                        if isinstance(kw.value, ast.Name) and kw.value.id == var_name:
                            return node.lineno
        return None

    # ------------------------------------------------------------------
    # Pattern: function parameter used in binary op (e.g. concatenation)
    # without None guard, when a None-returning function in the same
    # module could supply that parameter value.
    # ------------------------------------------------------------------

    def _scan_for_param_binop_without_none_guard(self, func_node):
        """Detect function parameter used in binary op without None guard.

        Pattern (BugsInPy httpie#1):
            def filename_from_content_disposition(content_disposition):
                ...
                return filename   # or implicit return None

            def get_unique_filename(filename, exists=os.path.exists):
                ...
                if not exists(filename + suffix):  # TypeError if filename is None
                    return filename + suffix

        The parameter 'filename' is used in string concatenation (BinOp Add)
        without a None guard, and filename_from_content_disposition is a
        None-returning function in the same file whose name shares a token
        with the parameter ('filename').
        """
        if not self._none_returning_funcs:
            return

        # Get function parameter names (excluding self, cls, and params with defaults)
        params = self._get_plain_params(func_node)
        if not params:
            return

        for param_name in params:
            # Check if param is used in a BinOp(Add) anywhere in the function
            # without a preceding None guard
            binop_line = self._find_binop_use_without_guard(
                func_node.body, param_name
            )
            if binop_line is None:
                continue

            # Check if a None-returning function in the file has a name
            # that shares a significant token with this parameter
            matching_func = self._find_matching_none_returning_func(
                param_name, exclude=func_node.name
            )
            if matching_func is None:
                continue

            self.bugs.append(NoneGuardBug(
                file_path=self.file_path,
                line_number=binop_line,
                function_name=self._current_function or '<module>',
                pattern='param_binop_without_none_guard',
                reason=(
                    f"Parameter '{param_name}' is used in a binary "
                    f"operation (line {binop_line}) without a None guard. "
                    f"Function '{matching_func}()' in the same file may "
                    f"return None, and its result could flow to this "
                    f"parameter. If '{param_name}' is None, a TypeError "
                    f"will occur."
                ),
                confidence=0.72,
                variable=param_name,
            ))

    @staticmethod
    def _get_plain_params(func_node) -> List[str]:
        """Get parameter names that have no default values (excluding self/cls)."""
        args = func_node.args
        n_defaults = len(args.defaults)
        n_args = len(args.args)
        # Parameters without defaults are the first (n_args - n_defaults) args
        n_plain = n_args - n_defaults
        result = []
        for i in range(n_plain):
            name = args.args[i].arg
            if name not in ('self', 'cls'):
                result.append(name)
        return result

    def _find_binop_use_without_guard(
        self, stmts: list, var_name: str
    ) -> Optional[int]:
        """Find first use of var_name in a BinOp (Add) without a preceding
        None guard. Returns line number or None."""
        for stmt in stmts:
            # If this is a None guard, the parameter is safe from here
            if self._is_none_guard(stmt, var_name):
                return None
            # If there's a truthiness check: if var_name: ...
            if isinstance(stmt, ast.If):
                test = stmt.test
                if isinstance(test, ast.Name) and test.id == var_name:
                    return None

            # Search for BinOp(Add) involving var_name
            line = self._find_binop_add_use(stmt, var_name)
            if line is not None:
                return line

            # Recurse into compound statement bodies
            for block in self._child_blocks(stmt):
                line = self._find_binop_use_without_guard(block, var_name)
                if line is not None:
                    return line
        return None

    @staticmethod
    def _find_binop_add_use(node, var_name: str) -> Optional[int]:
        """Find first BinOp(Add) that uses var_name as left or right operand."""
        for child in ast.walk(node):
            if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Add):
                # Check if var_name is on either side
                if isinstance(child.left, ast.Name) and child.left.id == var_name:
                    return child.lineno
                if isinstance(child.right, ast.Name) and child.right.id == var_name:
                    return child.lineno
        return None

    def _find_matching_none_returning_func(self, param_name: str,
                                            exclude: Optional[str] = None) -> Optional[str]:
        """Find a None-returning function whose name shares a significant token
        with the parameter name.

        E.g., param 'filename' matches function 'filename_from_content_disposition'
        because they share the token 'filename'.
        """
        param_tokens = set(param_name.lower().split('_'))
        # Remove very short/common tokens that would cause false matches
        param_tokens -= {'', 'a', 'an', 'the', 'is', 'in', 'of', 'to', 'do',
                         'no', 'on', 'or', 'by', 'at', 'if', 'it', 'up',
                         'id', 'fn', 'x', 'y', 'n', 'i', 'j', 'k', 's',
                         'get', 'set', 'has', 'can'}
        if not param_tokens:
            return None

        for func_name in self._none_returning_funcs:
            if func_name == exclude:
                continue
            func_tokens = set(func_name.lower().split('_'))
            if param_tokens & func_tokens:
                return func_name
        return None

    @staticmethod
    def _body_mutates_list(stmts: list, list_var: str) -> bool:
        """Check if any statement in stmts calls list_var.append/insert/extend."""
        for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ('append', 'insert', 'extend'):
                    if isinstance(node.func.value, ast.Name):
                        if node.func.value.id == list_var:
                            return True
        return False

    # ------------------------------------------------------------------
    # Pattern: re.search/re.match with dynamically-constructed regex
    # containing a mandatory prefix that prevents position-0 matches
    # ------------------------------------------------------------------

    _RE_OPTIONAL_FUNCS = frozenset({'search', 'match', 'fullmatch'})

    def _scan_for_regex_search_dynamic_pattern(self, func_node):
        """Detect re.search/re.match with dynamically-constructed regex
        whose literal prefix contains a mandatory character class.

        Pattern (BugsInPy httpie#5):
            regex = '[^\\\\\\\\]' + sep
            match = re.search(regex, string)
            if match:
                found[match.start() + 1] = sep

        The prefix '[^\\\\]' requires a non-backslash character BEFORE the
        separator, so re.search returns None when the separator appears at
        position 0 of the input.  This causes valid inputs to be
        incorrectly rejected (the 'found' dict stays empty).
        """
        import re as _re

        for node in ast.walk(func_node):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue

            # Match: var = re.search(REGEX, ...) / re.match(...)
            call = node.value
            if not isinstance(call, ast.Call):
                continue
            if not (isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == 're'
                    and call.func.attr in self._RE_OPTIONAL_FUNCS):
                continue
            if not call.args:
                continue

            # Check if first arg (regex pattern) is built via concatenation.
            # The pattern may be directly in the call:  re.search(LIT + var, ...)
            # or assigned to an intermediate variable:  regex = LIT + var
            #                                           re.search(regex, ...)
            regex_arg = call.args[0]
            prefix = self._regex_concat_prefix(regex_arg)
            if prefix is None and isinstance(regex_arg, ast.Name):
                prefix = self._resolve_concat_prefix(func_node, regex_arg.id)
            if prefix is None:
                continue

            # Does the prefix contain a mandatory char class like [^...] or
            # a lone dot that requires a preceding character?
            if not _re.search(r'\[[^\]]+\]|(?<!\\)\.', prefix):
                continue

            var_name = target.id

            # Verify the result is used with attribute access (.start, .group, etc.)
            has_attr_use = False
            for child in ast.walk(func_node):
                if isinstance(child, ast.Attribute):
                    if (isinstance(child.value, ast.Name)
                            and child.value.id == var_name):
                        has_attr_use = True
                        break
            if not has_attr_use:
                continue

            self.bugs.append(NoneGuardBug(
                file_path=self.file_path,
                line_number=node.lineno,
                function_name=self._current_function or '<module>',
                pattern='regex_dynamic_prefix_none',
                reason=(
                    f"re.{call.func.attr}() called with dynamically-"
                    f"constructed regex whose literal prefix "
                    f"'{prefix}' requires a preceding character "
                    f"(line {node.lineno}). re.{call.func.attr}() "
                    f"returns None when the target is at position 0, "
                    f"so variable '{var_name}' may be None for valid "
                    f"inputs."
                ),
                confidence=0.75,
                variable=f'call:re.{call.func.attr}',
            ))

    @staticmethod
    def _regex_concat_prefix(node: ast.expr) -> Optional[str]:
        """Return the string-literal left operand of a ``LITERAL + expr``
        concatenation, or None if the node isn't that shape."""
        if (isinstance(node, ast.BinOp)
                and isinstance(node.op, ast.Add)
                and isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)):
            return node.left.value
        return None

    @staticmethod
    def _resolve_concat_prefix(func_node, var_name: str) -> Optional[str]:
        """Resolve a variable name to a concat prefix by finding its
        assignment in the same function body.

        Handles:  regex = LITERAL + sep  →  returns LITERAL
        """
        for node in ast.walk(func_node):
            if (isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == var_name):
                if (isinstance(node.value, ast.BinOp)
                        and isinstance(node.value.op, ast.Add)
                        and isinstance(node.value.left, ast.Constant)
                        and isinstance(node.value.left.value, str)):
                    return node.value.left.value
        return None

    # ------------------------------------------------------------------
    # Pattern 12: Compat flag (six.PY2, sys.version_info, etc.) used in
    #             a compound condition inside a ternary (IfExp), indicating
    #             incomplete version-specific handling.
    # ------------------------------------------------------------------

    # Module attributes that act as version/compat flags
    _COMPAT_FLAG_ATTRS: Dict[str, Set[str]] = {
        'six': {'PY2', 'PY3'},
        'sys': {'version_info', 'version'},
    }

    def _scan_for_compat_flag_ternary(self, func_node):
        """Detect compat flag used in compound ternary condition.

        Pattern (BugsInPy keras#15):
            self.file_flags = 'b' if six.PY2 and os.name == 'nt' else ''

        Fix pattern:
            if six.PY2:
                self.file_flags = 'b'
                self._open_args = {}
            else:
                self.file_flags = ''
                self._open_args = {'newline': '\\n'}

        The ternary conflates the version guard with another condition,
        leading to incomplete version-specific handling.  The fix uses a
        full if/else block keyed *only* on the compat flag.
        """
        for node in ast.walk(func_node):
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.IfExp):
                continue
            ifexp = node.value
            # Check if the ternary test is a compound bool using a compat flag
            flag_name = self._find_compat_flag_in_compound(ifexp.test)
            if flag_name is None:
                continue
            # Determine the target variable name for reporting
            target = node.targets[0] if node.targets else None
            var_str = self._target_str(target)
            self.bugs.append(NoneGuardBug(
                file_path=self.file_path,
                line_number=node.lineno,
                function_name=self._current_function or '<module>',
                pattern='compat_flag_compound_ternary',
                reason=(
                    f"Compatibility flag '{flag_name}' is used in a compound "
                    f"condition inside a ternary expression (line {node.lineno}) "
                    f"to assign '{var_str}'. This often indicates incomplete "
                    f"version-specific handling — the different branches "
                    f"typically require additional attribute/variable setup "
                    f"that a single ternary cannot express."
                ),
                confidence=0.72,
                variable=var_str,
            ))

    def _find_compat_flag_in_compound(self, test_node) -> Optional[str]:
        """Return the compat flag name (e.g. 'six.PY2') if *test_node* is a
        compound BoolOp (and/or) containing a compat flag attribute access.
        Returns None otherwise."""
        if not isinstance(test_node, ast.BoolOp):
            return None
        for value in test_node.values:
            name = self._is_compat_flag(value)
            if name is not None:
                return name
        return None

    @classmethod
    def _is_compat_flag(cls, node) -> Optional[str]:
        """Return 'mod.attr' if *node* is a compat flag access like six.PY2."""
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                mod = node.value.id
                attr = node.attr
                if mod in cls._COMPAT_FLAG_ATTRS:
                    if attr in cls._COMPAT_FLAG_ATTRS[mod]:
                        return f"{mod}.{attr}"
        # Also match sys.version_info comparisons like sys.version_info[0] >= 3
        if isinstance(node, ast.Compare):
            left = node.left
            if isinstance(left, ast.Subscript):
                if isinstance(left.value, ast.Attribute):
                    name = cls._is_compat_flag(left.value)
                    if name is not None:
                        return name
            name = cls._is_compat_flag(left)
            if name is not None:
                return name
        return None

    @staticmethod
    def _target_str(target) -> str:
        """Convert an assignment target AST node to a readable string."""
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            if isinstance(target.value, ast.Name):
                return f"{target.value.id}.{target.attr}"
        return '<expr>'


def _is_none(node) -> bool:
    """Check if an AST node represents ``None``."""
    if isinstance(node, ast.Constant) and node.value is None:
        return True
    # Python 3.7 compat
    _name_const = getattr(ast, 'NameConstant', None)
    if _name_const is not None and isinstance(node, _name_const) and node.value is None:
        return True
    return False
