"""
AST-based detector for missing isinstance guard on Any-typed parameters.

Detects patterns where:
1. A function has a parameter explicitly annotated as ``Any``
2. The function also has boolean parameters suggesting type-specific behavior
   (e.g., ``skip_defaults``, ``exclude_unset``, ``by_alias``)
3. The Any-typed value (or a derived variable) is forwarded to a call along
   with one of these boolean flags
4. No ``isinstance`` check guards the Any-typed value

Key bug pattern (BugsInPy fastapi#10):
    # BUGGY: passes Any-typed value without type dispatch
    def serialize_response(*, response_content: Any, skip_defaults: bool = False):
        value = field.validate(response_content, ...)
        return jsonable_encoder(value, skip_defaults=skip_defaults)

    # FIXED: adds isinstance check for type-specific handling
    def serialize_response(*, response_content: Any, skip_defaults: bool = False):
        value = field.validate(response_content, ...)
        if skip_defaults and isinstance(value, BaseModel):
            value = value.dict(skip_defaults=skip_defaults)
        return jsonable_encoder(value, skip_defaults=skip_defaults)
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Dict


# Boolean parameter names that suggest type-specific serialization/dispatch
_TYPE_DISPATCH_BOOL_PARAMS: Set[str] = {
    "skip_defaults",
    "exclude_defaults",
    "exclude_unset",
    "exclude_none",
    "by_alias",
    "validate",
    "strict",
    "recursive",
    "deep",
    "include_defaults",
}


@dataclass
class MissingIsinstanceAnyBug:
    """A bug found via AST isinstance-guard analysis on Any-typed params."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'missing_isinstance_any'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_missing_isinstance_any_bugs(
    file_path: Path,
) -> List[MissingIsinstanceAnyBug]:
    """Scan a Python file for missing isinstance guards on Any-typed params."""
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

    if tree is None:
        return []

    visitor = _MissingIsinstanceVisitor(str(file_path), source)
    visitor.visit(tree)
    return visitor.bugs


class _MissingIsinstanceVisitor(ast.NodeVisitor):
    """AST visitor detecting missing isinstance guard on Any-typed parameters."""

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.bugs: List[MissingIsinstanceAnyBug] = []
        self._current_function: Optional[str] = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def _visit_func(self, node) -> None:
        old_func = self._current_function
        self._current_function = node.name
        self._analyze_function(node)
        self.generic_visit(node)
        self._current_function = old_func

    # ------------------------------------------------------------------

    def _analyze_function(self, func_node) -> None:
        """Main analysis: find Any-typed params without isinstance guards."""
        # Step 1: Find params annotated as Any
        any_params = self._find_any_typed_params(func_node)
        if not any_params:
            return

        # Step 2: Find boolean params that suggest type-dispatch behavior
        bool_params = self._find_bool_params(func_node)
        dispatch_bools = bool_params & _TYPE_DISPATCH_BOOL_PARAMS
        if not dispatch_bools:
            return

        # Step 3: Collect derived variables (simple assignment tracking)
        derived_vars = self._collect_derived_vars(func_node.body, any_params)
        all_any_vars = any_params | derived_vars

        # Step 4: Check if any isinstance guard exists for any_vars
        isinstance_guarded = self._collect_isinstance_guarded_vars(
            func_node.body
        )
        if all_any_vars & isinstance_guarded:
            return  # At least one Any-typed var is guarded

        # Step 5: Find calls that forward both an Any-typed value and a
        #         dispatch boolean flag — these are the suspicious sites
        suspicious_calls = self._find_suspicious_calls(
            func_node.body, all_any_vars, dispatch_bools
        )

        for call_line, callee_name, forwarded_flags in suspicious_calls:
            flags_str = ", ".join(sorted(forwarded_flags))
            any_str = ", ".join(sorted(any_params))
            self.bugs.append(MissingIsinstanceAnyBug(
                file_path=self.file_path,
                line_number=call_line,
                function_name=self._current_function or "<module>",
                pattern="missing_isinstance_any",
                reason=(
                    f"Parameter '{any_str}' has type Any and is forwarded "
                    f"to '{callee_name}' with type-dispatch flag(s) "
                    f"({flags_str}) but no isinstance guard checks the "
                    f"runtime type. Different types may need different "
                    f"preprocessing (e.g., BaseModel.dict())."
                ),
                confidence=0.55,
                variable=any_str,
            ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_any_typed_params(func_node) -> Set[str]:
        """Find parameters explicitly annotated as ``Any``."""
        any_params: Set[str] = set()
        all_args = (
            func_node.args.args
            + func_node.args.posonlyargs
            + func_node.args.kwonlyargs
        )
        for arg in all_args:
            if arg.annotation and _is_any_annotation(arg.annotation):
                any_params.add(arg.arg)
        return any_params

    @staticmethod
    def _find_bool_params(func_node) -> Set[str]:
        """Find parameters with ``bool`` type or ``False``/``True`` defaults."""
        bool_params: Set[str] = set()
        all_args = (
            func_node.args.args
            + func_node.args.posonlyargs
            + func_node.args.kwonlyargs
        )
        defaults = func_node.args.defaults + func_node.args.kw_defaults
        # kw_defaults may have None placeholders for kwargs without defaults
        # Build a map from arg name to its default value
        # For regular args: defaults align to the LAST len(defaults) args
        n_regular = len(func_node.args.args) + len(func_node.args.posonlyargs)
        n_defaults = len(func_node.args.defaults)
        regular_args = func_node.args.posonlyargs + func_node.args.args

        for i, arg in enumerate(regular_args):
            default_idx = i - (n_regular - n_defaults)
            if default_idx >= 0 and default_idx < n_defaults:
                default = func_node.args.defaults[default_idx]
                if isinstance(default, ast.Constant) and isinstance(
                    default.value, bool
                ):
                    bool_params.add(arg.arg)

            # Check annotation
            if arg.annotation and _is_bool_annotation(arg.annotation):
                bool_params.add(arg.arg)

        for i, arg in enumerate(func_node.args.kwonlyargs):
            if i < len(func_node.args.kw_defaults):
                default = func_node.args.kw_defaults[i]
                if (
                    default
                    and isinstance(default, ast.Constant)
                    and isinstance(default.value, bool)
                ):
                    bool_params.add(arg.arg)
            if arg.annotation and _is_bool_annotation(arg.annotation):
                bool_params.add(arg.arg)

        return bool_params

    @staticmethod
    def _collect_derived_vars(stmts: list, any_params: Set[str]) -> Set[str]:
        """Track variables derived from Any-typed params via simple assignment.

        Handles patterns like:
            value = field.validate(response_content, ...)
            value, errors = field.validate(response_content, ...)
        """
        derived: Set[str] = set()
        any_and_derived = set(any_params)

        for stmt in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if isinstance(stmt, ast.Assign):
                # Check if RHS references any Any-typed variable
                if _expr_references_any(stmt.value, any_and_derived):
                    for target in stmt.targets:
                        names = _extract_assign_target_names(target)
                        derived.update(names)
                        any_and_derived.update(names)
        return derived

    @staticmethod
    def _collect_isinstance_guarded_vars(stmts: list) -> Set[str]:
        """Collect variable names that appear in isinstance() calls."""
        guarded: Set[str] = set()
        for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "isinstance"
                and len(node.args) >= 1
                and isinstance(node.args[0], ast.Name)
            ):
                guarded.add(node.args[0].id)
        return guarded

    @staticmethod
    def _find_suspicious_calls(
        stmts: list,
        any_vars: Set[str],
        dispatch_bools: Set[str],
    ) -> List[tuple]:
        """Find calls forwarding both Any-typed values and dispatch booleans.

        Returns list of (line_number, callee_name, forwarded_flags).
        """
        results = []
        for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if not isinstance(node, ast.Call):
                continue

            # Check if any positional arg references an Any-typed variable
            has_any_arg = any(
                _expr_references_any(arg, any_vars) for arg in node.args
            )

            # Check which dispatch-bool kwargs are forwarded
            forwarded_flags: Set[str] = set()
            for kw in node.keywords:
                if kw.arg and kw.arg in dispatch_bools:
                    # The kwarg value should reference the bool param itself
                    if isinstance(kw.value, ast.Name) and kw.value.id == kw.arg:
                        forwarded_flags.add(kw.arg)

            if has_any_arg and forwarded_flags:
                callee_name = _get_callee_name(node.func)
                results.append((node.lineno, callee_name, forwarded_flags))

        return results


# ======================================================================
# Module-level helpers
# ======================================================================


def _is_any_annotation(ann: ast.expr) -> bool:
    """Check if an annotation is ``Any`` (from typing import Any)."""
    if isinstance(ann, ast.Name) and ann.id == "Any":
        return True
    if isinstance(ann, ast.Attribute) and ann.attr == "Any":
        return True
    return False


def _is_bool_annotation(ann: ast.expr) -> bool:
    """Check if an annotation is ``bool``."""
    if isinstance(ann, ast.Name) and ann.id == "bool":
        return True
    return False


def _expr_references_any(expr: ast.expr, var_names: Set[str]) -> bool:
    """Check if an expression references any variable in var_names."""
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in var_names:
            return True
    return False


def _extract_assign_target_names(target: ast.expr) -> Set[str]:
    """Extract variable names from an assignment target."""
    names: Set[str] = set()
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, ast.Tuple):
        for elt in target.elts:
            names.update(_extract_assign_target_names(elt))
    return names


def _get_callee_name(func_expr: ast.expr) -> str:
    """Extract a human-readable callee name from a call's func expression."""
    if isinstance(func_expr, ast.Name):
        return func_expr.id
    if isinstance(func_expr, ast.Attribute):
        return func_expr.attr
    return "<unknown>"
