"""Conservative source-to-source optimizations for Python modules.

The older optimizers in :mod:`pyflow.optimization` work on PyFlow's internal
IR.  That is useful to the analyser, but it is not a source-code backend: the
IR deliberately contains analysis-only operations which cannot be emitted as
valid Python.  This module provides the small, sound subset needed by the CLI
when a user asks for an optimized Python file.

Only expressions made entirely of Python literals are evaluated.  Evaluation
failures (for example ``1 / 0``) leave the original tree in place, so the
emitted program retains the original runtime behaviour.
"""

from __future__ import annotations

import ast
import copy
from dataclasses import dataclass
import math
import operator
from pathlib import Path
from typing import Any, Iterable, Mapping


_MAX_FOLDED_REPR_LENGTH = 10_000
_MAX_PROPAGATION_PASSES = 16


@dataclass(frozen=True)
class SourceOptimizationResult:
    """Summary of an optimized source module."""

    source: str
    constant_folds: int
    dead_branches_removed: int
    unreachable_statements_removed: int
    redundant_assertions_removed: int
    boolean_simplifications: int
    constant_propagations: int
    guarded_functions: int
    legacy_candidates_applied: int
    legacy_candidates_rejected: int
    legacy_candidate_rejections: tuple[tuple[str, int], ...]

    @property
    def changed(self) -> bool:
        return (
            self.constant_folds > 0
            or self.dead_branches_removed > 0
            or self.unreachable_statements_removed > 0
            or self.redundant_assertions_removed > 0
            or self.boolean_simplifications > 0
            or self.constant_propagations > 0
            or self.legacy_candidates_applied > 0
        )


class _ScopeEffectVisitor(ast.NodeVisitor):
    """Detect bindings whose removal can change Python name resolution."""

    def __init__(self) -> None:
        self.has_scope_effect = False

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.has_scope_effect = True

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.has_scope_effect = True

    def visit_Global(self, node: ast.Global) -> None:
        self.has_scope_effect = True

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.has_scope_effect = True

    def visit_Import(self, node: ast.Import) -> None:
        self.has_scope_effect = True

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.has_scope_effect = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.has_scope_effect = True

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.has_scope_effect = True

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.has_scope_effect = True

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name is not None:
            self.has_scope_effect = True
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name is not None:
            self.has_scope_effect = True
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name is not None:
            self.has_scope_effect = True


def _has_scope_effect(nodes: Iterable[ast.AST]) -> bool:
    """Whether removing nodes can alter the enclosing scope's bindings."""
    visitor = _ScopeEffectVisitor()
    for node in nodes:
        visitor.visit(node)
        if visitor.has_scope_effect:
            return True
    return False


class _LiteralFolder(ast.NodeTransformer):
    """Fold literal-only expressions and remove statically dead branches."""

    def __init__(self) -> None:
        self.constant_folds = 0
        self.dead_branches_removed = 0
        self.redundant_assertions_removed = 0
        self.boolean_simplifications = 0

    def _literal_value(self, node: ast.AST) -> tuple[bool, Any]:
        """Return a value only when evaluating *node* cannot run user code."""
        if isinstance(node, ast.Constant):
            return True, node.value

        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            values = []
            for element in node.elts:
                known, value = self._literal_value(element)
                if not known:
                    return False, None
                values.append(value)
            if isinstance(node, ast.Tuple):
                return True, tuple(values)
            if isinstance(node, ast.List):
                return True, list(values)
            return True, set(values)

        if isinstance(node, ast.Dict):
            result = {}
            for key, value in zip(node.keys, node.values):
                if key is None:  # ``**mapping`` can invoke arbitrary code.
                    return False, None
                key_known, key_value = self._literal_value(key)
                value_known, value_value = self._literal_value(value)
                if not key_known or not value_known:
                    return False, None
                result[key_value] = value_value
            return True, result

        if isinstance(node, ast.UnaryOp):
            known, value = self._literal_value(node.operand)
            unary_ops = {
                ast.UAdd: operator.pos,
                ast.USub: operator.neg,
                ast.Invert: operator.invert,
                ast.Not: operator.not_,
            }
            operation = unary_ops.get(type(node.op))
            if not known or operation is None:
                return False, None
            try:
                return True, operation(value)
            except (ArithmeticError, TypeError, ValueError):
                return False, None

        if isinstance(node, ast.BinOp):
            left_known, left = self._literal_value(node.left)
            right_known, right = self._literal_value(node.right)
            binary_ops = {
                ast.Add: operator.add,
                ast.Sub: operator.sub,
                ast.Mult: operator.mul,
                ast.Div: operator.truediv,
                ast.FloorDiv: operator.floordiv,
                ast.Mod: operator.mod,
                ast.Pow: operator.pow,
                ast.LShift: operator.lshift,
                ast.RShift: operator.rshift,
                ast.BitOr: operator.or_,
                ast.BitXor: operator.xor,
                ast.BitAnd: operator.and_,
            }
            operation = binary_ops.get(type(node.op))
            if not left_known or not right_known or operation is None:
                return False, None
            # Avoid expensive exponentiation before it gets a chance to exceed
            # the rendered-source limit below.
            if (
                isinstance(node.op, ast.Pow)
                and isinstance(right, int)
                and abs(right) > 10_000
            ):
                return False, None
            try:
                return True, operation(left, right)
            except (ArithmeticError, MemoryError, OverflowError, TypeError, ValueError):
                return False, None

        if isinstance(node, ast.BoolOp):
            values = []
            for value_node in node.values:
                known, value = self._literal_value(value_node)
                if not known:
                    return False, None
                values.append(value)
            result = values[0]
            for value in values[1:]:
                if isinstance(node.op, ast.And):
                    result = value if result else result
                elif isinstance(node.op, ast.Or):
                    result = result if result else value
                else:
                    return False, None
            return True, result

        if isinstance(node, ast.Compare):
            left_known, left = self._literal_value(node.left)
            if not left_known:
                return False, None
            comparison_ops = {
                ast.Eq: operator.eq,
                ast.NotEq: operator.ne,
                ast.Lt: operator.lt,
                ast.LtE: operator.le,
                ast.Gt: operator.gt,
                ast.GtE: operator.ge,
                ast.Is: operator.is_,
                ast.IsNot: operator.is_not,
                ast.In: lambda a, b: a in b,
                ast.NotIn: lambda a, b: a not in b,
            }
            for operation_node, comparator_node in zip(node.ops, node.comparators):
                right_known, right = self._literal_value(comparator_node)
                operation = comparison_ops.get(type(operation_node))
                if not right_known or operation is None:
                    return False, None
                try:
                    if not operation(left, right):
                        return True, False
                except (TypeError, ValueError):
                    return False, None
                left = right
            return True, True

        if isinstance(node, ast.IfExp):
            test_known, test = self._literal_value(node.test)
            if not test_known:
                return False, None
            return self._literal_value(node.body if test else node.orelse)

        return False, None

    def _try_fold_expression(self, node: ast.expr) -> ast.expr:
        """Fold an expression after its children have been normalized."""
        known, value = self._literal_value(node)
        if not known:
            return node

        # Avoid turning a compact expression into a huge source file.
        if (
            not _is_renderable_literal(value)
            or len(repr(value)) > _MAX_FOLDED_REPR_LENGTH
        ):
            return node

        self.constant_folds += 1
        return ast.copy_location(ast.parse(repr(value), mode="eval").body, node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.expr:
        return self._try_fold_expression(self.generic_visit(node))

    def visit_BinOp(self, node: ast.BinOp) -> ast.expr:
        return self._try_fold_expression(self.generic_visit(node))

    def visit_BoolOp(self, node: ast.BoolOp) -> ast.expr:
        node = self.generic_visit(node)

        for index, value_node in enumerate(node.values):
            known, value = self._literal_value(value_node)
            if not known:
                if index and all(
                    self._literal_value(prefix)[0]
                    and bool(self._literal_value(prefix)[1])
                    for prefix in node.values[:index]
                ) and isinstance(node.op, ast.And):
                    self.boolean_simplifications += 1
                    return value_node
                if index and all(
                    self._literal_value(prefix)[0]
                    and not bool(self._literal_value(prefix)[1])
                    for prefix in node.values[:index]
                ) and isinstance(node.op, ast.Or):
                    self.boolean_simplifications += 1
                    return value_node
                return self._try_fold_expression(node)

            short_circuits = (isinstance(node.op, ast.And) and not value) or (
                isinstance(node.op, ast.Or) and value
            )
            if short_circuits:
                skipped = node.values[index + 1 :]
                if not _has_scope_effect(skipped):
                    self.boolean_simplifications += 1
                    return ast.copy_location(
                        ast.parse(repr(value), mode="eval").body, node
                    )
                return node

        return self._try_fold_expression(node)

    def visit_Compare(self, node: ast.Compare) -> ast.expr:
        return self._try_fold_expression(self.generic_visit(node))

    def visit_IfExp(self, node: ast.IfExp) -> ast.expr:
        node = self.generic_visit(node)
        known, value = self._literal_value(node.test)
        if known:
            removed_branch = node.orelse if value else node.body
            if _has_scope_effect([removed_branch]):
                return node
            self.dead_branches_removed += 1
            return ast.copy_location(node.body if value else node.orelse, node)
        return self._try_fold_expression(node)

    def visit_If(self, node: ast.If) -> ast.stmt | list[ast.stmt]:
        node = self.generic_visit(node)
        known, value = self._literal_value(node.test)
        removed_branch = node.orelse if value else node.body
        if not known or _has_scope_effect(removed_branch):
            return node
        self.dead_branches_removed += 1
        return node.body if value else node.orelse

    def visit_While(self, node: ast.While) -> ast.stmt | list[ast.stmt]:
        node = self.generic_visit(node)
        known, value = self._literal_value(node.test)
        if not known or value or _has_scope_effect(node.body):
            return node
        # ``while False: ... else: ...`` still runs its ``else`` suite.
        self.dead_branches_removed += 1
        return node.orelse

    def visit_Assert(self, node: ast.Assert) -> ast.stmt | list[ast.stmt]:
        node = self.generic_visit(node)
        known, value = self._literal_value(node.test)
        if not known or not value or (
            node.msg is not None and _has_scope_effect([node.msg])
        ):
            return node
        # Python never evaluates an assert message when the condition holds,
        # so deleting a statically true assertion is semantics-preserving.
        self.redundant_assertions_removed += 1
        return []


class _UnreachableStatementPruner(ast.NodeTransformer):
    """Remove statements after unconditional control-flow terminators."""

    _TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)

    def __init__(self) -> None:
        self.removed = 0

    def generic_visit(self, node: ast.AST) -> ast.AST:
        node = super().generic_visit(node)
        for field, value in ast.iter_fields(node):
            if not isinstance(value, list) or not all(
                isinstance(item, ast.stmt) for item in value
            ):
                continue
            for index, statement in enumerate(value):
                if isinstance(statement, self._TERMINATORS):
                    if _has_scope_effect(value[index + 1 :]):
                        break
                    self.removed += len(value) - index - 1
                    setattr(node, field, value[: index + 1])
                    break
        return node


def _source_span(node: ast.AST) -> tuple[int, int, int | None, int | None] | None:
    """Return a comparable CPython AST source span, if location data exists."""
    if not hasattr(node, "lineno") or not hasattr(node, "col_offset"):
        return None
    return (
        node.lineno,
        node.col_offset,
        getattr(node, "end_lineno", None),
        getattr(node, "end_col_offset", None),
    )


def _candidate_span(candidate: Mapping[str, Any]):
    origin = candidate.get("origin")
    if not isinstance(origin, Mapping):
        return None
    try:
        return (
            int(origin["start_line"]),
            int(origin["start_column"]),
            (
                int(origin["end_line"])
                if origin.get("end_line") is not None
                else None
            ),
            (
                int(origin["end_column"])
                if origin.get("end_column") is not None
                else None
            ),
        )
    except (KeyError, TypeError, ValueError):
        return None


class _LegacyCandidateRewriter(ast.NodeTransformer):
    """Apply only legacy candidates with a source-level safety proof.

    An IR fold becomes source output only when its original source expression is
    literal-only.  An IR DCE discard becomes source output only for a non-string
    literal expression statement.  This deliberately rejects assignment and
    memory-operation candidates: their IR proof alone does not preserve Python
    scope, descriptor, or reflective-frame semantics.
    """

    def __init__(self, candidates: Iterable[Mapping[str, Any]]) -> None:
        self._by_span: dict[tuple[int, int, int | None, int | None], list[int]] = {}
        self._candidates = list(candidates)
        self._handled: set[int] = set()
        self._applied: set[int] = set()
        self._rejections: dict[int, str] = {}
        for index, candidate in enumerate(self._candidates):
            span = _candidate_span(candidate)
            if span is not None:
                self._by_span.setdefault(span, []).append(index)

    def _candidate_indexes(self, node: ast.AST, kind: str) -> list[int]:
        span = _source_span(node)
        if span is None:
            return []
        return [
            index
            for index in self._by_span.get(span, ())
            if self._candidates[index].get("kind") == kind
        ]

    def _fold_if_confirmed(self, node: ast.expr) -> ast.expr:
        indexes = self._candidate_indexes(node, "fold")
        if not indexes:
            return node
        folder = _LiteralFolder()
        replacement = folder._try_fold_expression(node)
        self._handled.update(indexes)
        if replacement is node:
            for index in indexes:
                self._rejections[index] = "not_literal_only"
            return node
        self._applied.update(indexes)
        return replacement

    def visit_BinOp(self, node: ast.BinOp) -> ast.expr:
        return self._fold_if_confirmed(self.generic_visit(node))

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.expr:
        return self._fold_if_confirmed(self.generic_visit(node))

    def visit_BoolOp(self, node: ast.BoolOp) -> ast.expr:
        return self._fold_if_confirmed(self.generic_visit(node))

    def visit_Compare(self, node: ast.Compare) -> ast.expr:
        return self._fold_if_confirmed(self.generic_visit(node))

    def visit_IfExp(self, node: ast.IfExp) -> ast.expr:
        return self._fold_if_confirmed(self.generic_visit(node))

    def visit_Expr(self, node: ast.Expr) -> ast.stmt | list[ast.stmt]:
        node = self.generic_visit(node)
        indexes = self._candidate_indexes(node, "dce_discard")
        if not indexes:
            return node
        self._handled.update(indexes)
        known, value = _LiteralFolder()._literal_value(node.value)
        if known and _is_renderable_literal(value) and not isinstance(value, str):
            self._applied.update(indexes)
            return []
        for index in indexes:
            self._rejections[index] = "not_pure_literal_discard"
        return node

    @property
    def applied(self) -> int:
        return len(self._applied)

    @property
    def rejection_counts(self) -> dict[str, int]:
        for index, candidate in enumerate(self._candidates):
            if index in self._applied or index in self._rejections:
                continue
            if _candidate_span(candidate) is None:
                reason = "missing_source_span"
            elif candidate.get("kind") not in {"fold", "dce_discard"}:
                reason = "unsupported_source_kind"
            else:
                reason = "span_did_not_match_source_ast"
            self._rejections[index] = reason
        counts: dict[str, int] = {}
        for reason in self._rejections.values():
            counts[reason] = counts.get(reason, 0) + 1
        return counts

    @property
    def rejected(self) -> int:
        return sum(self.rejection_counts.values())


class _O2SafetyGuard(ast.NodeVisitor):
    """Reject functions whose dynamic scope features defeat local propagation."""

    _DYNAMIC_BUILTINS = {"eval", "exec", "globals", "locals", "vars"}

    def __init__(self) -> None:
        self.unsafe = False

    def visit_Global(self, node: ast.Global) -> None:
        self.unsafe = True

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.unsafe = True

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.unsafe = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.unsafe = True

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.unsafe = True

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.unsafe = True

    def visit_Try(self, node: ast.Try) -> None:
        self.unsafe = True

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self.unsafe = True

    def visit_With(self, node: ast.With) -> None:
        self.unsafe = True

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.unsafe = True

    def visit_Yield(self, node: ast.Yield) -> None:
        self.unsafe = True

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        self.unsafe = True

    def visit_Await(self, node: ast.Await) -> None:
        self.unsafe = True

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.unsafe = True

    def visit_Import(self, node: ast.Import) -> None:
        self.unsafe = True

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.unsafe = True

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self.unsafe = True

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self.unsafe = True

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self.unsafe = True

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self.unsafe = True

    def visit_Match(self, node: ast.Match) -> None:
        self.unsafe = True

    def visit_Call(self, node: ast.Call) -> None:
        function = node.func
        if isinstance(function, ast.Name) and function.id in self._DYNAMIC_BUILTINS:
            self.unsafe = True
        elif (
            isinstance(function, ast.Attribute)
            and function.attr in self._DYNAMIC_BUILTINS
        ):
            self.unsafe = True
        self.generic_visit(node)


def _can_propagate_in_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    guard = _O2SafetyGuard()
    for statement in node.body:
        guard.visit(statement)
        if guard.unsafe:
            return False
    return True


class _BasicBlockConstantPropagator(ast.NodeTransformer):
    """Propagate immutable literals through straight-line function code.

    Assignments are intentionally retained: deleting them changes the result of
    ``locals()`` and frame inspection.  The pass only replaces names used in
    arithmetic, unary, and non-identity comparison expressions; those use the
    value rather than the local object's identity.
    """

    _IMMUTABLE_CONSTANTS = (type(None), bool, int, float, complex, str, bytes)

    def __init__(self) -> None:
        self.constants: dict[str, ast.Constant] = {}
        self.function_depth = 0
        self.constant_propagations = 0
        self.guarded_functions = 0

    @staticmethod
    def _contains_call(node: ast.AST) -> bool:
        return any(isinstance(child, ast.Call) for child in ast.walk(node))

    def _replace_name(self, node: ast.expr) -> ast.expr:
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
            return node
        value = self.constants.get(node.id)
        if value is None:
            return node
        self.constant_propagations += 1
        return ast.copy_location(copy.deepcopy(value), node)

    def _visit_statement_list(self, statements: list[ast.stmt]) -> list[ast.stmt]:
        return [self.visit(statement) for statement in statements]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        return self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        return self._visit_function(node)

    def _visit_function(self, node):
        if self.function_depth or not _can_propagate_in_function(node):
            self.guarded_functions += 1
            return node
        saved_constants = self.constants
        self.constants = {}
        self.function_depth += 1
        node.body = self._visit_statement_list(node.body)
        self.function_depth -= 1
        self.constants = saved_constants
        return node

    def visit_Assign(self, node: ast.Assign) -> ast.Assign:
        if not self.function_depth:
            return self.generic_visit(node)
        node.value = self.visit(node.value)
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            self.constants.clear()
            return node
        target = node.targets[0]
        if isinstance(node.value, ast.Constant) and isinstance(
            node.value.value, self._IMMUTABLE_CONSTANTS
        ):
            self.constants[target.id] = copy.deepcopy(node.value)
        else:
            self.constants.pop(target.id, None)
        if self._contains_call(node.value):
            self.constants.clear()
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AnnAssign:
        if not self.function_depth:
            return self.generic_visit(node)
        if node.value is None or not isinstance(node.target, ast.Name):
            self.constants.clear()
            return node
        node.value = self.visit(node.value)
        if isinstance(node.value, ast.Constant) and isinstance(
            node.value.value, self._IMMUTABLE_CONSTANTS
        ):
            self.constants[node.target.id] = copy.deepcopy(node.value)
        else:
            self.constants.pop(node.target.id, None)
        return node

    def visit_AugAssign(self, node: ast.AugAssign) -> ast.AugAssign:
        if not self.function_depth:
            return self.generic_visit(node)
        node.value = self.visit(node.value)
        self.constants.clear()
        return node

    def visit_Delete(self, node: ast.Delete) -> ast.Delete:
        if not self.function_depth:
            return self.generic_visit(node)
        self.constants.clear()
        return node

    def visit_BinOp(self, node: ast.BinOp) -> ast.BinOp:
        node.left = self._replace_name(self.visit(node.left))
        node.right = self._replace_name(self.visit(node.right))
        return node

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.UnaryOp:
        node.operand = self._replace_name(self.visit(node.operand))
        return node

    def visit_Compare(self, node: ast.Compare) -> ast.Compare:
        if any(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops):
            return self.generic_visit(node)
        node.left = self._replace_name(self.visit(node.left))
        node.comparators = [
            self._replace_name(self.visit(comparator))
            for comparator in node.comparators
        ]
        return node

    def visit_If(self, node: ast.If) -> ast.If:
        node.test = self.visit(node.test)
        entry_constants = self.constants
        self.constants = entry_constants.copy()
        node.body = self._visit_statement_list(node.body)
        self.constants = entry_constants.copy()
        node.orelse = self._visit_statement_list(node.orelse)
        self.constants = {}
        return node

    def visit_While(self, node: ast.While) -> ast.While:
        node.test = self.visit(node.test)
        self.constants.clear()
        return node

    def visit_For(self, node: ast.For) -> ast.For:
        node.iter = self.visit(node.iter)
        self.constants.clear()
        return node

    def visit_AsyncFor(self, node: ast.AsyncFor) -> ast.AsyncFor:
        node.iter = self.visit(node.iter)
        self.constants.clear()
        return node

    def visit_Expr(self, node: ast.Expr) -> ast.Expr:
        node.value = self.visit(node.value)
        if self._contains_call(node.value):
            self.constants.clear()
        return node


def optimize_source(
    source: str,
    *,
    filename: str = "<unknown>",
    level: int = 1,
    legacy_candidates: Iterable[Mapping[str, Any]] = (),
) -> SourceOptimizationResult:
    """Return optimized, syntactically valid Python source for one module."""
    if level not in (0, 1, 2):
        raise ValueError("optimization level must be 0, 1, or 2")

    tree = ast.parse(source, filename=filename)
    optimized = tree
    constant_folds = 0
    dead_branches_removed = 0
    unreachable_statements_removed = 0
    redundant_assertions_removed = 0
    boolean_simplifications = 0
    constant_propagations = 0
    guarded_functions = 0
    legacy_candidates_applied = 0
    legacy_candidates_rejected = 0
    legacy_candidate_rejections: tuple[tuple[str, int], ...] = ()

    candidate_list = tuple(legacy_candidates)
    if level >= 1:
        candidate_rewriter = _LegacyCandidateRewriter(candidate_list)
        optimized = candidate_rewriter.visit(optimized)
        legacy_candidates_applied = candidate_rewriter.applied
        legacy_candidates_rejected = candidate_rewriter.rejected
        legacy_candidate_rejections = tuple(
            sorted(candidate_rewriter.rejection_counts.items())
        )
    else:
        legacy_candidates_rejected = len(candidate_list)
        legacy_candidate_rejections = (
            ("optimization_level_disabled", len(candidate_list)),
        )

    if level >= 1:
        folder = _LiteralFolder()
        optimized = folder.visit(optimized)
        pruner = _UnreachableStatementPruner()
        optimized = pruner.visit(optimized)
        constant_folds += folder.constant_folds
        dead_branches_removed += folder.dead_branches_removed
        unreachable_statements_removed += pruner.removed
        redundant_assertions_removed += folder.redundant_assertions_removed
        boolean_simplifications += folder.boolean_simplifications

    if level >= 2:
        for attempt in range(_MAX_PROPAGATION_PASSES):
            propagator = _BasicBlockConstantPropagator()
            optimized = propagator.visit(optimized)
            folder = _LiteralFolder()
            optimized = folder.visit(optimized)
            pruner = _UnreachableStatementPruner()
            optimized = pruner.visit(optimized)
            constant_folds += folder.constant_folds
            dead_branches_removed += folder.dead_branches_removed
            unreachable_statements_removed += pruner.removed
            redundant_assertions_removed += folder.redundant_assertions_removed
            boolean_simplifications += folder.boolean_simplifications
            constant_propagations += propagator.constant_propagations
            if attempt == 0:
                guarded_functions = propagator.guarded_functions
            if not propagator.constant_propagations:
                break

    ast.fix_missing_locations(optimized)
    rendered = ast.unparse(optimized)
    if source.endswith(("\n", "\r")):
        rendered += "\n"
    return SourceOptimizationResult(
        source=rendered,
        constant_folds=constant_folds,
        dead_branches_removed=dead_branches_removed,
        unreachable_statements_removed=unreachable_statements_removed,
        redundant_assertions_removed=redundant_assertions_removed,
        boolean_simplifications=boolean_simplifications,
        constant_propagations=constant_propagations,
        guarded_functions=guarded_functions,
        legacy_candidates_applied=legacy_candidates_applied,
        legacy_candidates_rejected=legacy_candidates_rejected,
        legacy_candidate_rejections=legacy_candidate_rejections,
    )


def _is_renderable_literal(value: Any) -> bool:
    """Whether ``repr(value)`` parses back into a Python literal expression."""
    if isinstance(value, float) and not math.isfinite(value):
        return False
    if isinstance(value, (type(None), bool, int, float, complex, str, bytes)):
        return True
    if isinstance(value, (tuple, list, set, frozenset)):
        return all(_is_renderable_literal(item) for item in value)
    if isinstance(value, dict):
        return all(
            _is_renderable_literal(key) and _is_renderable_literal(item)
            for key, item in value.items()
        )
    return False


def _candidate_matches_source(candidate: Mapping[str, Any], source_path: Path) -> bool:
    origin = candidate.get("origin")
    if not isinstance(origin, Mapping) or not origin.get("path"):
        return False
    try:
        return Path(origin["path"]).resolve() == source_path.resolve()
    except (OSError, TypeError):
        return False


def emit_optimized_sources(
    sources: Iterable[Path],
    input_path: Path,
    output_path: Path,
    *,
    level: int = 1,
    legacy_candidates: Iterable[Mapping[str, Any]] = (),
) -> dict[Path, SourceOptimizationResult]:
    """Optimize source files and write them under an explicit destination.

    A file input maps directly to ``output_path``.  A directory input preserves
    relative paths under ``output_path``.  In-place output is rejected so that
    optimization never silently overwrites a user's source tree.
    """
    input_path = input_path.resolve()
    output_path = output_path.resolve()
    if output_path == input_path:
        raise ValueError("--emit-optimized must not overwrite the input path")

    if input_path.is_dir():
        try:
            output_path.relative_to(input_path)
        except ValueError:
            pass
        else:
            raise ValueError("--emit-optimized must be outside the input directory")

    source_paths = [Path(source).resolve() for source in sources]
    candidates = tuple(legacy_candidates)
    if input_path.is_dir() and output_path.is_file():
        raise ValueError("--emit-optimized must name a directory for directory input")

    results = {}
    for source_path in source_paths:
        destination = (
            output_path
            if input_path.is_file()
            else output_path / source_path.relative_to(input_path)
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = optimize_source(
            source_path.read_text(encoding="utf-8"),
            filename=str(source_path),
            level=level,
            legacy_candidates=(
                candidate
                for candidate in candidates
                if _candidate_matches_source(candidate, source_path)
            ),
        )
        destination.write_text(result.source, encoding="utf-8")
        results[destination] = result
    return results


def _report_origin(origin: object | None) -> dict[str, Any] | None:
    """Convert public IR source metadata to a stable JSON representation."""
    if origin is None:
        return None
    span = getattr(origin, "span", None)
    if span is not None:
        return {
            "kind": "source",
            "path": span.path,
            "start_line": span.start_line,
            "start_column": span.start_column,
            "end_line": span.end_line,
            "end_column": span.end_column,
            "name": getattr(origin, "name", None),
            "construct_kind": getattr(origin, "construct_kind", None),
        }
    reason = getattr(origin, "reason", None)
    if reason is not None:
        return {"kind": "synthetic", "reason": reason}
    return {"kind": "unknown", "description": str(origin)}


def legacy_transformation_report(program) -> dict[str, Any]:
    """Summarize provenance recorded by the legacy IR optimization pipeline.

    This is intentionally an audit trail, not a source-emission plan.  An IR
    rewrite can introduce direct calls, temporaries, or representation-specific
    stores that have no generally valid spelling in Python source.  The source
    optimizer therefore only emits rules it can independently prove safe.
    """
    catalog = getattr(program, "ir", None)
    nodes = getattr(catalog, "nodes", None)
    provenance_of = getattr(catalog, "provenance_of", None)
    source_of = getattr(catalog, "source_of", None)
    if not callable(nodes) or not callable(provenance_of):
        return {"count": 0, "by_kind": {}, "records": []}

    records = []
    for node_id, _node in nodes():
        try:
            frames = provenance_of(node_id)
        except (KeyError, TypeError, ValueError):
            continue
        for frame in frames:
            origin = getattr(frame, "source", None)
            if origin is None and callable(source_of):
                try:
                    origin = source_of(node_id)
                except (KeyError, TypeError, ValueError):
                    origin = None
            records.append(
                {
                    "node": str(node_id),
                    "transform": getattr(frame, "kind", "unknown"),
                    "inputs": [str(item) for item in getattr(frame, "inputs", ())],
                    "detail": getattr(frame, "detail", ""),
                    "origin": _report_origin(origin),
                    "source_emission": "not_directly_emitted",
                }
            )

    records.sort(key=lambda record: (record["transform"], record["node"]))
    by_kind: dict[str, int] = {}
    for record in records:
        kind = record["transform"]
        by_kind[kind] = by_kind.get(kind, 0) + 1
    return {"count": len(records), "by_kind": by_kind, "records": records}


def legacy_source_candidate_report(
    candidates: Iterable[Mapping[str, Any]],
    *,
    applied: int,
    rejected: int,
    not_routed: int,
    rejection_reasons: Mapping[str, int],
) -> dict[str, Any]:
    """Report source-addressable candidates produced by legacy passes."""
    records = [dict(candidate) for candidate in candidates]
    from pyflow.optimization.source_candidates import source_candidate_coverage
    by_kind: dict[str, int] = {}
    for candidate in records:
        kind = str(candidate.get("kind", "unknown"))
        by_kind[kind] = by_kind.get(kind, 0) + 1
    return {
        "recorded": len(records),
        "applied": applied,
        "rejected": rejected,
        "not_routed": not_routed,
        "rejection_reasons": dict(sorted(rejection_reasons.items())),
        "by_kind": by_kind,
        "source_span_coverage": source_candidate_coverage(records),
        "records": records,
    }


def optimization_report(
    results: dict[Path, SourceOptimizationResult],
    *,
    level: int,
    legacy_results=None,
    program=None,
    legacy_candidates: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Return a JSON-serializable report for source and legacy rewrites.

    ``legacy_passes`` says whether a pass ran and changed the internal IR.
    ``legacy_transformations`` contains the provenance the IR preserves.  The
    two are deliberately separate from emitted source counts: source rewriting
    is restricted to independently validated Python-level transformations.
    """
    fields = (
        "constant_folds",
        "dead_branches_removed",
        "unreachable_statements_removed",
        "redundant_assertions_removed",
        "boolean_simplifications",
        "constant_propagations",
        "guarded_functions",
        "legacy_candidates_applied",
        "legacy_candidates_rejected",
    )
    files = []
    totals = {field: 0 for field in fields}
    for path, result in sorted(results.items()):
        counts = {field: getattr(result, field) for field in fields}
        for field, value in counts.items():
            totals[field] += value
        files.append({"path": str(path), "changed": result.changed, **counts})
    legacy_passes = []
    for name, result in (legacy_results or {}).items():
        if name in {"simplify", "simplify_final", "dce"}:
            emission = "safe_subset_emitted"
        elif name in {
            "ipa",
            "cpa",
            "lifetime",
            "ipa_refresh",
            "cpa_path_sensitive",
            "lifetime_refresh",
            "ipa_after_simplify",
            "cpa_after_simplify",
            "lifetime_after_simplify",
        }:
            emission = "analysis_only"
        else:
            emission = "ir_only"
        legacy_passes.append(
            {
                "name": name,
                "success": bool(getattr(result, "success", False)),
                "changed": bool(getattr(result, "changed", False)),
                "emission": emission,
                "time_seconds": getattr(result, "time", None),
                "error": getattr(result, "error", None),
            }
        )
    candidate_list = tuple(legacy_candidates)
    rejection_reasons: dict[str, int] = {}
    for result in results.values():
        for reason, count in result.legacy_candidate_rejections:
            rejection_reasons[reason] = rejection_reasons.get(reason, 0) + count
    not_routed = max(
        0,
        len(candidate_list)
        - totals["legacy_candidates_applied"]
        - totals["legacy_candidates_rejected"],
    )
    return {
        "optimization_level": level,
        "files": files,
        "totals": totals,
        "legacy_passes": legacy_passes,
        "legacy_transformations": legacy_transformation_report(program),
        "legacy_source_candidates": legacy_source_candidate_report(
            candidate_list,
            applied=totals["legacy_candidates_applied"],
            rejected=totals["legacy_candidates_rejected"],
            not_routed=not_routed,
            rejection_reasons=rejection_reasons,
        ),
    }


__all__ = [
    "SourceOptimizationResult",
    "emit_optimized_sources",
    "legacy_source_candidate_report",
    "legacy_transformation_report",
    "optimization_report",
    "optimize_source",
]
