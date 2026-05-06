"""
AST-based incomplete keyword argument forwarding detector.

Detects patterns where:
1. A deprecated/renamed keyword argument is used instead of the modern name
   (e.g., ``include_none=False`` → ``exclude_none=True``,
         ``skip_defaults=True`` → ``exclude_defaults=True``)
2. A function forwards a subset of kwargs from a known group to a callee,
   indicating the caller should also accept and forward additional related kwargs.
3. A polymorphic constructor variable (assigned via if/elif/else) is called
   with ``None`` as a positional arg instead of using ``**kwargs_dict``,
   preventing conditional keyword argument forwarding (BugsInPy fastapi#9).

Key bug pattern (BugsInPy fastapi#1):
    # BUGGY: uses deprecated pydantic parameter name
    jsonable_encoder(model, by_alias=True, include_none=False)
    # FIXED: uses modern parameter name
    jsonable_encoder(model, by_alias=True, exclude_none=True)

    # BUGGY: function missing params that should be forwarded
    def _prepare_response_content(res, *, by_alias=True, exclude_unset=False):
        return res.dict(by_alias=by_alias, exclude_unset=exclude_unset)
    # FIXED: adds exclude_defaults and exclude_none
    def _prepare_response_content(res, *, by_alias=True, exclude_unset=False,
                                  exclude_defaults=False, exclude_none=False):
        return res.dict(by_alias=by_alias, exclude_unset=exclude_unset,
                       exclude_defaults=exclude_defaults, exclude_none=exclude_none)

Key bug pattern (BugsInPy fastapi#9):
    # BUGGY: positional None prevents forwarding additional kwargs
    if condition_a:
        Schema = ClassA
    else:
        Schema = ClassB
    result = Schema(None)

    # FIXED: kwargs dict allows conditional keyword forwarding
    kwargs = dict(default=None)
    if condition_a:
        Schema = ClassA
    else:
        Schema = ClassB
        kwargs["media_type"] = value
    result = Schema(**kwargs)
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple


# Known deprecated → modern parameter renames (callee kwarg names)
_DEPRECATED_KWARG_RENAMES: Dict[str, Tuple[str, str]] = {
    # deprecated_name -> (modern_name, explanation)
    "include_none": ("exclude_none", "pydantic/fastapi renamed include_none to exclude_none"),
    "skip_defaults": ("exclude_defaults", "pydantic/fastapi renamed skip_defaults to exclude_defaults"),
    "response_model_skip_defaults": (
        "response_model_exclude_unset",
        "fastapi renamed response_model_skip_defaults to response_model_exclude_unset",
    ),
}

# Groups of kwargs that typically appear together.  If a call forwards some
# members of a group but not others, the missing ones are likely bugs.
_KWARG_GROUPS: List[Set[str]] = [
    {"exclude_unset", "exclude_defaults", "exclude_none"},
    {"response_model_exclude_unset", "response_model_exclude_defaults", "response_model_exclude_none"},
]


@dataclass
class IncompleteKwargForwardingBug:
    """A bug found via AST kwarg-forwarding analysis."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'deprecated_kwarg' | 'incomplete_forwarding'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_incomplete_kwarg_forwarding_bugs(
    file_path: Path,
) -> List[IncompleteKwargForwardingBug]:
    """Scan a single Python file for incomplete keyword argument forwarding.

    Handles both regular Python files and diff-extracted multi-hunk fragments
    (produced by BugsInPy patch extraction).
    """
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
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

    bugs: List[IncompleteKwargForwardingBug] = []

    if tree is not None:
        visitor = _KwargForwardingVisitor(str(file_path), source)
        visitor.visit(tree)
        bugs.extend(visitor.bugs)

    # Additionally try merged-hunk parsing for cross-hunk pattern detection.
    # Multi-hunk wrapping splits each hunk into separate functions, so patterns
    # spanning multiple hunks (e.g. polymorphic assignment in one hunk, call in
    # another) are missed.  Merging hunks recovers the full control-flow context.
    if '# @@ hunk @@' in source:
        merged_tree = _try_parse_merged_hunks(source, str(file_path))
        if merged_tree is not None:
            visitor2 = _KwargForwardingVisitor(str(file_path), source)
            visitor2.visit(merged_tree)
            # Only add bugs not already found (by line+pattern dedup)
            existing = {(b.line_number, b.pattern) for b in bugs}
            for b in visitor2.bugs:
                if (b.line_number, b.pattern) not in existing:
                    bugs.append(b)

    return bugs


def _try_parse_merged_hunks(source: str, filename: str) -> Optional[ast.AST]:
    """Merge all hunks into a single function for cross-hunk analysis.

    Strips diff metadata and hunk markers, inserts ``pass`` for incomplete
    blocks (e.g. elif with body in a different part of the file), dedents,
    and wraps into ``def _merged_hunk(): ...``.
    """
    import re
    import textwrap

    cleaned_lines: List[str] = []
    for line in source.splitlines():
        stripped = line.strip()
        if re.match(r'^index\s+[0-9a-f]+\.\.[0-9a-f]+', stripped):
            continue
        if re.match(r'^(old|new) mode \d+', stripped):
            continue
        if stripped == '# @@ hunk @@':
            continue
        cleaned_lines.append(line)

    # Insert ``pass`` after block-opening statements whose body is missing
    fixed_lines: List[str] = []
    _BLOCK_KW = ('if ', 'elif ', 'else:', 'for ', 'while ', 'def ', 'class ',
                 'try:', 'except', 'finally:')
    for i, line in enumerate(cleaned_lines):
        fixed_lines.append(line)
        stripped = line.rstrip()
        if stripped.endswith(':') and any(stripped.lstrip().startswith(kw) for kw in _BLOCK_KW):
            curr_indent = len(line) - len(line.lstrip())
            if i + 1 < len(cleaned_lines):
                next_line = cleaned_lines[i + 1]
                next_stripped = next_line.strip()
                if next_stripped:
                    next_indent = len(next_line) - len(next_line.lstrip())
                    if next_indent <= curr_indent:
                        fixed_lines.append(' ' * (curr_indent + 4) + 'pass')
            else:
                fixed_lines.append(' ' * (curr_indent + 4) + 'pass')

    result = '\n'.join(fixed_lines)
    dedented = textwrap.dedent(result)
    if not dedented.strip():
        return None
    wrapped = 'def _merged_hunk():\n' + textwrap.indent(dedented, '    ') + '\n'

    try:
        return ast.parse(wrapped, filename=filename)
    except SyntaxError:
        return None


class _KwargForwardingVisitor(ast.NodeVisitor):
    """AST visitor that detects deprecated kwargs and incomplete forwarding."""

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.bugs: List[IncompleteKwargForwardingBug] = []
        self._current_function: Optional[str] = None
        self._current_function_params: Set[str] = set()
        # Track all function definitions and their params for cross-reference
        self._func_params: Dict[str, Set[str]] = {}
        # Track if we're inside an else branch (backward-compat code path)
        self._in_else_branch: bool = False
        # Track variables assigned through if/elif/else chains (polymorphic constructors)
        self._polymorphic_vars: Set[str] = set()

    # ── First pass: collect function signatures ──

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def _visit_func(self, node: ast.FunctionDef) -> None:
        params = _extract_param_names(node)
        self._func_params[node.name] = params

        old_func = self._current_function
        old_params = self._current_function_params
        self._current_function = node.name
        self._current_function_params = params

        self.generic_visit(node)

        self._current_function = old_func
        self._current_function_params = old_params

    # ── Second pass: check call sites ──

    def visit_If(self, node: ast.If) -> None:
        """Track if/else branches for backward-compat detection and polymorphic vars."""
        # Detect variables assigned in multiple branches (polymorphic constructors)
        self._detect_polymorphic_assignments(node)
        # Visit the if-body normally
        for child in node.body:
            self.visit(child)
        # Visit the else-body with flag set
        old = self._in_else_branch
        self._in_else_branch = True
        for child in node.orelse:
            self.visit(child)
        self._in_else_branch = old

    def visit_Call(self, node: ast.Call) -> None:
        self._check_deprecated_kwargs(node)
        self._check_incomplete_forwarding(node)
        self._check_positional_none_to_polymorphic(node)
        self.generic_visit(node)

    def _check_deprecated_kwargs(self, node: ast.Call) -> None:
        """Flag deprecated keyword argument names."""
        for kw in node.keywords:
            if kw.arg and kw.arg in _DEPRECATED_KWARG_RENAMES:
                modern, explanation = _DEPRECATED_KWARG_RENAMES[kw.arg]
                # Check that the modern name is NOT also present
                call_kwargs = {k.arg for k in node.keywords if k.arg}
                if modern not in call_kwargs:
                    # Lower confidence in else branches (likely backward-compat)
                    conf = 0.45 if self._in_else_branch else 0.80
                    self.bugs.append(IncompleteKwargForwardingBug(
                        file_path=self.file_path,
                        line_number=kw.value.lineno if hasattr(kw.value, "lineno") else node.lineno,
                        function_name=self._current_function or "<module>",
                        pattern="deprecated_kwarg",
                        reason=(
                            f"Deprecated keyword argument '{kw.arg}' used; "
                            f"should use '{modern}' instead ({explanation})"
                        ),
                        confidence=conf,
                        variable=kw.arg,
                    ))

    def _check_incomplete_forwarding(self, node: ast.Call) -> None:
        """Flag calls that forward some but not all kwargs from a known group."""
        call_kwargs = {k.arg for k in node.keywords if k.arg}
        if not call_kwargs:
            return

        for group in _KWARG_GROUPS:
            present = call_kwargs & group
            missing = group - call_kwargs
            # Only flag if ≥1 member is present and ≥1 is missing
            if present and missing and len(present) >= 1:
                # Extra heuristic: the missing kwargs should also be absent
                # from the enclosing function's parameters (otherwise they
                # are just not forwarded, which is intentional)
                if self._current_function_params:
                    # If the caller also doesn't have the missing params in its
                    # own signature, it's likely an incomplete API
                    caller_also_missing = missing - self._current_function_params
                    if caller_also_missing:
                        missing_str = ", ".join(sorted(caller_also_missing))
                        present_str = ", ".join(sorted(present))
                        self.bugs.append(IncompleteKwargForwardingBug(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            function_name=self._current_function or "<module>",
                            pattern="incomplete_forwarding",
                            reason=(
                                f"Call forwards {present_str} but is missing "
                                f"related kwargs {missing_str} from the same group"
                            ),
                            confidence=0.72,
                            variable=next(iter(caller_also_missing)),
                        ))

    def _detect_polymorphic_assignments(self, node: ast.If) -> None:
        """Detect variables assigned in multiple branches of if/elif/else.

        When the same variable is assigned in ≥2 branches to different class
        references (e.g., ``Schema = ClassA`` in if, ``Schema = ClassB`` in
        else), it is a polymorphic constructor variable.  Calling such a
        variable with a bare positional ``None`` prevents additional keyword
        arguments from being forwarded conditionally.
        """
        assigned_in_branches: Dict[str, int] = {}

        def _collect_assigned_names(stmts: list) -> Set[str]:
            names: Set[str] = set()
            for stmt in stmts:
                if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                    targets = stmt.targets if isinstance(stmt, ast.Assign) else ([stmt.target] if stmt.target else [])
                    for t in targets:
                        if isinstance(t, ast.Name):
                            names.add(t.id)
            return names

        # Collect from if-body
        if_names = _collect_assigned_names(node.body)
        for n in if_names:
            assigned_in_branches[n] = assigned_in_branches.get(n, 0) + 1

        # Collect from elif/else chain
        else_part = node.orelse
        while else_part:
            if len(else_part) == 1 and isinstance(else_part[0], ast.If):
                elif_node = else_part[0]
                elif_names = _collect_assigned_names(elif_node.body)
                for n in elif_names:
                    assigned_in_branches[n] = assigned_in_branches.get(n, 0) + 1
                else_part = elif_node.orelse
            else:
                else_names = _collect_assigned_names(else_part)
                for n in else_names:
                    assigned_in_branches[n] = assigned_in_branches.get(n, 0) + 1
                break

        for var, count in assigned_in_branches.items():
            if count >= 2:
                self._polymorphic_vars.add(var)

    def _check_positional_none_to_polymorphic(self, node: ast.Call) -> None:
        """Detect ``PolymorphicVar(None)`` – positional None to a polymorphic constructor.

        When a variable is assigned different classes through an if/elif/else
        chain and then called with a bare ``None`` positional argument, the
        caller cannot conditionally attach extra keyword arguments (like
        ``media_type``).  The fix is to use a kwargs dict:
        ``PolymorphicVar(**kwargs_dict)`` where the dict is built with
        conditional entries.

        This does NOT fire when the call already uses ``**kwargs`` unpacking,
        because that indicates the caller is properly forwarding keyword
        arguments.
        """
        # Only interested in calls of the form  VarName(None)
        if not isinstance(node.func, ast.Name):
            return
        var_name = node.func.id
        if var_name not in self._polymorphic_vars:
            return

        # Check: does the call already use **kwargs unpacking?
        has_kwargs_unpack = any(
            kw.arg is None for kw in node.keywords
        )
        if has_kwargs_unpack:
            return  # Fixed pattern – no bug

        # Check: is there a positional None argument?
        has_positional_none = any(
            isinstance(arg, ast.Constant) and arg.value is None
            for arg in node.args
        )
        if not has_positional_none:
            return

        self.bugs.append(IncompleteKwargForwardingBug(
            file_path=self.file_path,
            line_number=node.lineno,
            function_name=self._current_function or "<module>",
            pattern="positional_none_to_polymorphic",
            reason=(
                f"Polymorphic constructor '{var_name}' called with positional "
                f"None instead of **kwargs dict; this prevents conditional "
                f"keyword argument forwarding (e.g. media_type)"
            ),
            confidence=0.75,
            variable=var_name,
        ))


def _extract_param_names(node: ast.FunctionDef) -> Set[str]:
    """Extract all parameter names from a function definition."""
    names: Set[str] = set()
    for arg in node.args.args:
        names.add(arg.arg)
    for arg in node.args.posonlyargs:
        names.add(arg.arg)
    for arg in node.args.kwonlyargs:
        names.add(arg.arg)
    if node.args.vararg:
        names.add(node.args.vararg.arg)
    if node.args.kwarg:
        names.add(node.args.kwarg.arg)
    return names
