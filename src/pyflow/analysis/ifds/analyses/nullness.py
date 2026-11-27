"""Interprocedural nullness analysis over CFG-backed IFDS supergraphs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Mapping, Sequence

from pyflow.ir.cfg import graph as cfg_graph
from pyflow.ir.core import Capabilities
from pyflow.language.python import ast as py_ast

from ..modeling.calls import CallModelRegistry
from .base import AnnotatedFactProblemBase, build_entry_seeds
from ..frontend.cfg_adapter import CFGNode, CFGSupergraphAdapter, assigned_locals
from ..core.problem import IFDSProblem
from ..core.solver import IFDSSolver, SolverOptions
from ..core.transfers import actual_argument_expressions

ZERO_NULLNESS = "ZERO_NULLNESS"


@dataclass(frozen=True)
class NullnessConfiguration:
    """Name-based nullness models for calls whose bodies are not available."""

    nullable_return_names: FrozenSet[str] = frozenset()
    collection_mutator_names: FrozenSet[str] = frozenset({"append", "add", "extend", "update"})
    collection_accessor_names: FrozenSet[str] = frozenset({"get"})
    call_models: CallModelRegistry | None = None


@dataclass(frozen=True)
class NullFact:
    """A storage location that may hold ``None``, optionally scoped to a field chain."""

    location: object
    access_path: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExpressionNullFact:
    """A nullable intermediate result of a specific expression."""

    procedure: cfg_graph.Code
    expression: py_ast.PythonASTNode
    result_index: int = 0
    access_path: tuple[str, ...] = ()


@dataclass(frozen=True)
class NullnessFinding:
    """Potential null-dereference style issue."""

    node: CFGNode
    kind: str
    expression_label: str
    fact: object | None = None


class NullnessAnalysisResult:
    """Query wrapper for nullness results."""

    def __init__(self, ifds_result, findings: Sequence[NullnessFinding], problem) -> None:
        self._ifds_result = ifds_result
        self.findings = tuple(findings)
        self._problem = problem

    def may_be_null(self, node: CFGNode, local: py_ast.Local) -> bool:
        return any(
            self._ifds_result.is_reached(node, NullFact(location))
            for location in self._problem.local_locations(node.procedure, local)
        )

    def nullable_locals_at(self, node: CFGNode):
        return frozenset(
            self._problem.describe_fact(fact)
            for fact in self._ifds_result.facts_at(node)
            if isinstance(fact, NullFact)
        )

    @property
    def statistics(self):
        return self._ifds_result.statistics

    def explain_fact(self, node: CFGNode, fact: object):
        return self._ifds_result.explain_fact(node, fact)

    def explain_path(self, node: CFGNode, fact: object):
        return self._ifds_result.explain_path(node, fact)

    @property
    def status(self):
        return self._ifds_result.status

    @property
    def termination_reason(self) -> str | None:
        return self._ifds_result.termination_reason

    @property
    def is_complete(self) -> bool:
        return self._ifds_result.is_complete


class InterproceduralNullnessProblem(
    AnnotatedFactProblemBase[object],
    IFDSProblem[cfg_graph.Code, CFGNode, object],
):
    """May-null analysis over CFG nodes."""

    analysis_name = "IFDS nullness"

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        configuration: NullnessConfiguration | None = None,
        entry_nodes: Sequence[CFGNode] | None = None,
    ) -> None:
        self.configuration = configuration or NullnessConfiguration()
        call_models = CallModelRegistry.from_nullness_configuration(self.configuration)
        if self.configuration.call_models is not None:
            call_models = call_models.merged(self.configuration.call_models)
        super().__init__(
            adapter,
            call_models=call_models,
        )
        if entry_nodes is None:
            raise ValueError(
                "IFDS nullness requires explicit entry_nodes; "
                "use program-backed IFDS APIs to derive roots automatically."
            )
        self.entry_nodes = tuple(entry_nodes)

    @property
    def supergraph(self):
        return self.adapter.supergraph

    @property
    def zero_fact(self):
        return ZERO_NULLNESS

    def initial_seeds(self) -> Mapping[CFGNode, frozenset[object]]:
        return build_entry_seeds(self.entry_nodes, ZERO_NULLNESS)

    def normal_flow(self, node: CFGNode, successor: CFGNode, fact: object):
        if node.kind == "call" and self.adapter.is_exceptional_successor(node, successor):
            return self._identity_outputs(fact, ())
        local_call_outputs = self._local_call_outputs(node, fact)
        if local_call_outputs is not None:
            return local_call_outputs

        condition_outputs = self._condition_outputs(node, successor, fact)
        if condition_outputs is not None:
            return condition_outputs

        effect = self.adapter.effect_of(node)
        operation = getattr(effect, "operation", self.adapter.operation_of(node))
        if operation is None:
            return self._identity_outputs(fact, ())

        killed = self._killed_locations_for_node(node)
        dynamic_setattr_locations = self._dynamic_setattr_locations(node.procedure, operation)
        if dynamic_setattr_locations:
            outputs = set(self._identity_outputs(fact, killed))
            value = self._dynamic_setattr_value(node.procedure, operation)
            if value is not None and (
                self._direct_expression_fact(value, fact) is not None
                or self._expr_is_nullable(node.procedure, value, fact)
            ):
                outputs.update(
                    self._make_location_fact(location) for location in dynamic_setattr_locations
                )
            return tuple(outputs)

        dynamic_subscript_locations = self._dynamic_subscript_write_locations(
            node.procedure, operation
        )
        if dynamic_subscript_locations:
            outputs = set(self._identity_outputs(fact, killed))
            value = self._dynamic_subscript_value(operation)
            if value is not None and (
                self._direct_expression_fact(value, fact) is not None
                or self._expr_is_nullable(node.procedure, value, fact)
            ):
                outputs.update(
                    self._facts_for_modified_operation(
                        operation,
                        procedure=node.procedure,
                    )
                )
                outputs.update(
                    self._make_location_fact(location) for location in dynamic_subscript_locations
                )
            return tuple(outputs)

        collection_locations, collection_values = self._collection_mutation(
            node.procedure,
            operation,
            self.configuration.collection_mutator_names,
        )
        if collection_locations:
            outputs = set(self._identity_outputs(fact, killed))
            copy_locations, copy_source_locations = self._collection_copy_mutation(
                node.procedure,
                operation,
                self.configuration.collection_mutator_names,
            )
            fact_location = self._location_from_fact(fact)
            if any(
                self._direct_expression_fact(value, fact) is not None
                or self._expr_is_nullable(node.procedure, value, fact)
                for value in collection_values
            ) or (fact_location is not None and fact_location in copy_source_locations):
                outputs.update(
                    self._make_location_fact(location) for location in collection_locations
                )
                outputs.update(self._make_location_fact(location) for location in copy_locations)
            return tuple(outputs)

        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)):
            outputs = set(self._identity_outputs(fact, killed))
            expr = getattr(operation, "expr", None)
            if isinstance(operation, py_ast.AnnAssign):
                expr = operation.value
            targets = self._assigned_locals(operation)
            self._update_aliases_for_assignment(node.procedure, targets, expr)

            direct_fact = self._direct_expression_fact(expr, fact)
            if direct_fact is not None:
                _procedure, _expr, result_index = direct_fact
                outputs.update(
                    self._facts_for_assigned_locals(
                        node.procedure,
                        targets,
                        result_index,
                    )
                )
                return tuple(outputs)
            constructor_writes = self._collection_constructor_writes(
                node.procedure,
                operation,
            )
            if (
                expr is not None
                and not constructor_writes
                and self._expr_is_nullable(node.procedure, expr, fact)
            ):
                outputs.update(
                    self._facts_for_locals_with_path(
                        node.procedure,
                        targets,
                        self._resulting_access_path(expr, fact),
                    )
                )
            outputs.update(
                self._make_location_fact(location)
                for location in (
                    *self._aliased_dynamic_locations_for_assignment(
                        node.procedure,
                        operation,
                        fact,
                    ),
                    *self._collection_copy_result_locations_for_assignment(
                        node.procedure,
                        operation,
                        fact,
                    ),
                )
            )
            for locations, value in constructor_writes:
                if self._direct_expression_fact(
                    value,
                    fact,
                ) is not None or self._expr_is_nullable(node.procedure, value, fact):
                    outputs.update(self._make_location_fact(location) for location in locations)
            return tuple(outputs)

        if isinstance(operation, py_ast.Return):
            outputs = set(self._identity_outputs(fact, ()))
            if len(operation.exprs) == 1:
                direct_fact = self._direct_expression_fact(operation.exprs[0], fact)
                if direct_fact is not None:
                    _procedure, _expr, result_index = direct_fact
                    path = self._access_path_from_fact(fact)
                    outputs.update(
                        self._facts_for_return_location(
                            node.procedure,
                            result_index,
                            access_path=path,
                        )
                    )
                    return tuple(outputs)
            for index, expr in enumerate(operation.exprs):
                if self._expr_is_nullable(node.procedure, expr, fact):
                    path = self._resulting_access_path(expr, fact)
                    outputs.update(
                        self._facts_for_return_location(
                            node.procedure,
                            index,
                            access_path=path,
                        )
                    )
            return tuple(outputs)

        if isinstance(
            operation,
            (
                py_ast.SetAttr,
                py_ast.SetSubscript,
                py_ast.SetSlice,
                py_ast.SetGlobal,
                py_ast.SetCellDeref,
                py_ast.Store,
            ),
        ):
            outputs = set(self._identity_outputs(fact, killed))
            value = getattr(operation, "value", None)
            if value is None:
                return tuple(outputs)
            if self._expr_is_nullable(node.procedure, value, fact):
                path = self._resulting_access_path(value, fact)
                outputs.update(
                    self._facts_for_modified_operation(
                        operation,
                        access_path=path,
                        procedure=node.procedure,
                    )
                )
            return tuple(outputs)

        return self._identity_outputs(fact, killed)

    def call_flow(self, call_node: CFGNode, callee: cfg_graph.Code, fact: object):
        outputs = set()
        if fact == ZERO_NULLNESS:
            outputs.add(ZERO_NULLNESS)

        call_effect = self._call_effect(call_node)
        call = call_effect.call_expression if call_effect is not None else None
        if call is None:
            return tuple(outputs)

        self._bind_callee_formals(call_node, callee)
        for actual, formal in self._bind_call_arguments_for_callee(call_node, callee):
            if self._expr_is_nullable(call_node.procedure, actual, fact):
                path = self._resulting_access_path(actual, fact)
                if path:
                    outputs.update(self._facts_for_locals_with_path(callee, (formal,), path))
                else:
                    outputs.update(self._facts_for_locals(callee, (formal,)))

        return tuple(outputs)

    def return_flow(
        self,
        call_node: CFGNode,
        callee: cfg_graph.Code,
        exit_node: CFGNode,
        return_site: CFGNode,
        call_fact: object,
        exit_fact: object,
    ):
        del exit_node, return_site, call_fact
        outputs = set()
        if exit_fact == ZERO_NULLNESS:
            outputs.add(ZERO_NULLNESS)

        return_index = self._return_fact_index(callee, exit_fact)
        if return_index is not None:
            call_effect = self._call_effect(call_node)
            operation = (
                call_effect.operation
                if call_effect is not None
                else self.adapter.operation_of(call_node)
            )
            call_expression = (
                call_effect.call_expression
                if call_effect is not None
                else self.adapter.call_expression_of(call_node)
            )
            outputs.update(
                self._facts_for_nested_call_result(
                    call_node.procedure,
                    operation,
                    call_expression,
                    return_index,
                    nested=False,
                )
            )
        projected = self._project_constructor_heap_fact_to_caller(call_node, exit_fact)
        if projected is not None:
            outputs.add(projected)

        return tuple(outputs)

    def call_to_return_flow(self, call_node: CFGNode, return_site: CFGNode, fact: object):
        del return_site
        call_effect = self._call_effect(call_node)
        call_expression = call_effect.call_expression if call_effect is not None else None
        self._mark_unresolved_call_arguments_escaped(call_node, call_expression)
        self._materialize_unresolved_call_summary(
            call_node,
            (
                call_effect.operation
                if call_effect is not None
                else self.adapter.operation_of(call_node)
            ),
            call_expression,
        )
        killed = self._killed_locations_for_node(call_node, include_semantic=False)
        return self._identity_outputs(fact, killed)

    @staticmethod
    def _is_definitely_non_null_expression(expr: object) -> bool:
        if isinstance(expr, py_ast.Existing):
            return getattr(expr.object, "pyobj", None) is not None
        return isinstance(
            expr,
            (
                py_ast.BuildList,
                py_ast.BuildTuple,
                py_ast.BuildMap,
                py_ast.BuildSet,
                py_ast.BuildSlice,
                py_ast.MakeFunction,
                py_ast.FunctionDef,
                py_ast.ClassDef,
            ),
        )

    def _call_has_non_null_default(
        self, call: py_ast.PythonASTNode | None, model_name: str
    ) -> bool:
        """True when a default-accepting getter call supplies a non-null fallback."""
        if call is None:
            return False
        leaf = model_name.rsplit(".", 1)[-1]
        kwds = {
            name: val
            for kw in getattr(call, "kwds", ())
            if isinstance(kw, tuple) and len(kw) == 2
            for name, val in (kw,)
        }
        actuals = actual_argument_expressions(call)
        default_expr: object | None = None
        if leaf in {"get", "getenv", "pop", "setdefault", "next"}:
            if "default" in kwds:
                default_expr = kwds["default"]
            elif "fallback" in kwds:
                default_expr = kwds["fallback"]
            elif len(actuals) >= 2:
                default_expr = actuals[1]
        elif leaf == "getattr":
            if len(actuals) >= 3:
                default_expr = actuals[2]
        elif leaf in {"getint", "getfloat", "getboolean"}:
            if "fallback" in kwds:
                default_expr = kwds["fallback"]
        return default_expr is not None and self._is_definitely_non_null_expression(default_expr)

    def _published_call_return_is_optional(
        self,
        procedure: cfg_graph.Code,
        call: py_ast.PythonASTNode | None,
    ) -> bool:
        """True when published TypeInfo facts mark *call* as returning ``Optional[T]``."""
        if call is None:
            return False
        catalog = self.adapter.catalog_by_procedure.get(procedure)
        if catalog is None or not catalog.facts.has(Capabilities.TYPE_CALL_RETURNS):
            return False
        if not catalog.has_node(call, procedure.code):
            return False
        fact_result = catalog.facts.query(
            Capabilities.TYPE_CALL_RETURNS,
            catalog.node_id(call, procedure.code),
        )
        if not fact_result.values:
            return False
        fact = next(iter(fact_result.values))
        return bool(fact.is_optional and not fact.is_gradual and fact.type_names)

    def _local_call_outputs(self, node: CFGNode, fact: object):
        call_effect = self._call_effect(node)
        if call_effect is None or call_effect.callees:
            return None

        outputs = set(self._identity_outputs(fact, self._killed_locations_for_node(node)))
        model = self._call_model_for_node(node)
        nullable_from_model = (
            model is not None
            and model.nullness_nullable_return
            and not self._call_has_non_null_default(call_effect.call_expression, model.name)
        )
        call_name = model.name if model is not None else (call_effect.call_name or "")
        nullable_from_typeinfo = (
            not nullable_from_model
            and self._published_call_return_is_optional(node.procedure, call_effect.call_expression)
            and not self._call_has_non_null_default(call_effect.call_expression, call_name)
        )
        if fact == ZERO_NULLNESS and (nullable_from_model or nullable_from_typeinfo):
            outputs.update(
                self._facts_for_nested_call_result(
                    node.procedure,
                    call_effect.operation,
                    call_effect.call_expression,
                    0,
                    nested=False,
                )
            )
        return tuple(outputs)

    def findings(self, result) -> tuple[NullnessFinding, ...]:
        findings: list[NullnessFinding] = []
        # Deduplicate by source expression identity: one AST occurrence must
        # yield one finding even when the supergraph represents it with
        # several CFG nodes (e.g. a call node plus its operation node).
        seen: set[tuple[int, str, str]] = set()

        def record(node: CFGNode, kind: str, expr, fact: object | None = None) -> None:
            label = self.describe_expression(expr)
            key = (id(node.procedure), kind, id(expr))
            if key in seen:
                return
            seen.add(key)
            findings.append(
                NullnessFinding(node=node, kind=kind, expression_label=label, fact=fact)
            )

        for node in self.adapter.supergraph.ordered_nodes():
            call_effect = self._call_effect(node)
            call = call_effect.call_expression if call_effect is not None else None
            effect = self.adapter.effect_of(node)
            operation = getattr(effect, "operation", self.adapter.operation_of(node))

            if call is not None:
                self._collect_null_risks(node, call, result, record, inspect_calls=True)
            elif operation is not None:
                self._collect_null_risks(node, operation, result, record, inspect_calls=False)

        return tuple(findings)

    def describe_fact(self, fact: object) -> str:
        if isinstance(fact, NullFact):
            return self.describe_location(fact.location)
        if isinstance(fact, ExpressionNullFact):
            return self.describe_expression(fact.expression)
        return "<expr>"

    def _make_location_fact(self, location: object, template_fact=None) -> object:
        return NullFact(location)

    def _make_location_fact_with_path(
        self, location: object, access_path: tuple[str, ...], template_fact=None
    ) -> object:
        return NullFact(location, access_path=access_path)

    def _make_expression_fact(
        self,
        procedure: cfg_graph.Code,
        expression: py_ast.PythonASTNode,
        result_index: int = 0,
        template_fact=None,
    ) -> object:
        return ExpressionNullFact(procedure, expression, result_index)

    def _location_from_fact(self, fact: object) -> object | None:
        if isinstance(fact, NullFact):
            return fact.location
        return None

    def _expression_fact_result(
        self, fact: object
    ) -> tuple[cfg_graph.Code, py_ast.PythonASTNode, int] | None:
        if isinstance(fact, ExpressionNullFact):
            return (fact.procedure, fact.expression, fact.result_index)
        return None

    def _identity_outputs(self, fact: object, killed: Sequence[object]):
        if fact == ZERO_NULLNESS:
            return (ZERO_NULLNESS,)
        if isinstance(fact, NullFact) and fact.location in killed:
            return ()
        return (fact,)

    def _resulting_access_path(self, expr: object, fact: object) -> tuple[str, ...]:
        """Compute the access path carried by evaluating *expr* under *fact*."""
        fact_path = self._access_path_from_fact(fact)
        if not fact_path:
            return ()
        expr_path = self._access_path_for_expression(expr)
        if expr_path and fact_path[: len(expr_path)] == expr_path:
            return fact_path[len(expr_path) :]
        return fact_path

    def _value_facts_for_expression(
        self, procedure: cfg_graph.Code, expr: object
    ) -> tuple[object, ...]:
        """Return nullness facts representing the value of *expr* (not its base/args)."""
        if expr is None or isinstance(expr, py_ast.leafTypes):
            return ()
        if isinstance(expr, py_ast.Local):
            return self._facts_for_expression_node(procedure, expr)
        if isinstance(expr, (py_ast.GetAttr, py_ast.Load)):
            attr_facts = tuple(
                self._make_location_fact(location)
                for location in self._static_attribute_read_locations(procedure, expr)
            )
            path_facts = (
                self._facts_for_expression_node(procedure, expr, extend_paths=True)
                if isinstance(expr, py_ast.GetAttr)
                else ()
            )
            return tuple(dict.fromkeys((*attr_facts, *path_facts)))
        if isinstance(expr, py_ast.GetSubscript):
            return tuple(
                self._make_location_fact(location)
                for location in self._dynamic_subscript_read_locations(procedure, expr)
            )
        if isinstance(expr, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            return self._facts_for_expression_node(procedure, expr)
        if isinstance(expr, (py_ast.GetGlobal, py_ast.GetCellDeref)):
            return self._facts_for_expression_node(procedure, expr)
        return ()

    def _expr_candidate_facts(
        self, procedure: cfg_graph.Code, expr: object
    ) -> tuple[frozenset[object], tuple[object, ...]]:
        heap = self._heap()
        self._sync_heap_caches(heap)
        key = (procedure, id(expr))
        cached = self._expr_facts_cache.get(key)
        if cached is not None:
            return cached
        collected: list[object] = []

        def visit(current) -> None:
            if current is None or isinstance(current, py_ast.leafTypes):
                return
            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if isinstance(current, py_ast.Code):
                return
            if isinstance(current, py_ast.ConditionalExpr):
                visit(getattr(current, "then_expr", None))
                visit(getattr(current, "else_expr", None))
                return
            if isinstance(current, py_ast.ShortCircutOr):
                terms = getattr(current, "terms", ())
                if terms:
                    # Earlier falsy terms (including None) fall through; only the
                    # final term can produce None as the value of ``a or b``.
                    visit(terms[-1])
                return
            if isinstance(current, py_ast.ShortCircutAnd):
                for term in getattr(current, "terms", ()):
                    visit(term)
                return
            if isinstance(
                current,
                (
                    py_ast.DirectCall,
                    py_ast.Call,
                    py_ast.MethodCall,
                    py_ast.Local,
                    py_ast.GetAttr,
                    py_ast.Load,
                    py_ast.GetSubscript,
                    py_ast.GetGlobal,
                    py_ast.GetCellDeref,
                ),
            ):
                # Do not descend into call arguments/receivers or attribute/subscript
                # base objects: their nullness does not make the expression evaluate
                # to None (dereferencing a null base raises AttributeError/TypeError
                # and is reported separately by _collect_null_risks).
                collected.extend(self._value_facts_for_expression(procedure, current))
                return
            if isinstance(
                current,
                (
                    py_ast.BuildList,
                    py_ast.BuildTuple,
                    py_ast.BuildMap,
                    py_ast.BuildSet,
                    py_ast.BuildSlice,
                    py_ast.MakeFunction,
                    py_ast.FunctionDef,
                    py_ast.ClassDef,
                    py_ast.BinaryOp,
                    py_ast.UnaryPrefixOp,
                    py_ast.Is,
                    py_ast.Not,
                    py_ast.ConvertToBool,
                ),
            ):
                return
            collected.extend(self._facts_for_expression_node(procedure, current))

        visit(expr)
        candidates = tuple(dict.fromkeys(collected))
        entry = (frozenset(candidates), candidates)
        self._sync_heap_caches(heap)
        self._expr_facts_cache[key] = entry
        return entry

    def _expr_is_nullable(self, procedure: cfg_graph.Code, expr: object, fact: object) -> bool:
        if fact == ZERO_NULLNESS:
            return self._expr_contains_explicit_null(expr)
        candidate_set, candidates = self._expr_candidate_facts(procedure, expr)
        if not candidates:
            return False
        if fact in candidate_set:
            return True
        return any(self._fact_prefix_matches(fact, candidate) for candidate in candidates)

    def _expr_contains_explicit_null(self, expr: object) -> bool:
        cache = getattr(self, "_explicit_null_cache", None)
        if cache is None:
            cache = {}
            self._explicit_null_cache = cache
        key = id(expr)
        cached = cache.get(key)
        if cached is not None:
            return cached
        result = self._evaluates_to_explicit_null(expr)
        cache[key] = result
        return result

    def _evaluates_to_explicit_null(self, expr: object) -> bool:
        """True only when *expr* itself directly evaluates to literal ``None``."""
        if expr is None or isinstance(expr, py_ast.leafTypes):
            return False
        if self._is_explicit_null_expression(expr):
            return True
        if isinstance(expr, py_ast.ConditionalExpr):
            return self._evaluates_to_explicit_null(
                getattr(expr, "then_expr", None)
            ) or self._evaluates_to_explicit_null(getattr(expr, "else_expr", None))
        if isinstance(expr, py_ast.ShortCircutOr):
            terms = getattr(expr, "terms", ())
            return bool(terms) and self._evaluates_to_explicit_null(terms[-1])
        if isinstance(expr, py_ast.ShortCircutAnd):
            return any(
                self._evaluates_to_explicit_null(term) for term in getattr(expr, "terms", ())
            )
        return False

    def _is_explicit_null_expression(self, expr: object) -> bool:
        return isinstance(expr, py_ast.Existing) and getattr(expr.object, "pyobj", object()) is None

    def _condition_outputs(
        self, node: CFGNode, successor: CFGNode, fact: object
    ) -> tuple[object, ...] | None:
        guard_effect = self._guard_effect(node)
        if guard_effect is None:
            return None
        exit_name = node.block.findExit(successor.block)
        if exit_name not in ("true", "false"):
            return None

        target_expr = guard_effect.nullable_target
        true_means_null = guard_effect.true_branch_means_null
        if target_expr is not None:
            target_facts = {
                candidate
                for candidate in self._value_facts_for_expression(node.procedure, target_expr)
                if isinstance(candidate, NullFact)
            }
            if not target_facts:
                return None

            branch_means_null = true_means_null if exit_name == "true" else not true_means_null
            if branch_means_null:
                outputs = set()
                if fact == ZERO_NULLNESS:
                    outputs.add(ZERO_NULLNESS)
                    outputs.update(target_facts)
                    return tuple(outputs)
                outputs.add(fact)
                return tuple(outputs)

            if fact == ZERO_NULLNESS:
                return (ZERO_NULLNESS,)
            if fact in target_facts:
                return ()
            return (fact,)

        non_null_expr = guard_effect.non_null_target
        true_means_non_null = guard_effect.true_branch_means_non_null
        if non_null_expr is not None and true_means_non_null is not None:
            target_facts = {
                candidate
                for candidate in self._value_facts_for_expression(node.procedure, non_null_expr)
                if isinstance(candidate, NullFact)
            }
            if not target_facts:
                return None
            branch_means_non_null = (
                true_means_non_null if exit_name == "true" else not true_means_non_null
            )
            if branch_means_non_null:
                if fact == ZERO_NULLNESS:
                    return (ZERO_NULLNESS,)
                if fact in target_facts:
                    return ()
                return (fact,)
            return (fact,)

        return None

    def _nullable_condition_target(self, expr: object):
        if isinstance(expr, py_ast.ConvertToBool):
            return self._nullable_condition_target(expr.expr)
        if isinstance(expr, py_ast.Is):
            if self._is_explicit_null_expression(expr.right):
                return expr.left, True
            if self._is_explicit_null_expression(expr.left):
                return expr.right, True
        call_target = self._nullable_condition_call_target(expr)
        if call_target is not None:
            return call_target
        if isinstance(expr, py_ast.Not):
            target, true_means_null = self._nullable_condition_target(expr.expr)
            if target is not None:
                return target, not true_means_null
        return None, False

    def _nullable_condition_call_target(self, expr: object) -> tuple[object, bool] | None:
        if not isinstance(expr, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return None
        call_name = self._call_name_from_expression(expr)
        if call_name not in {"interpreter__is__", "interpreter__is_not__"}:
            return None
        actuals = actual_argument_expressions(expr)
        if len(actuals) != 2:
            return None
        left, right = actuals
        if self._is_explicit_null_expression(right):
            return left, call_name == "interpreter__is__"
        if self._is_explicit_null_expression(left):
            return right, call_name == "interpreter__is__"
        return None

    def _collect_null_risks(
        self,
        node: CFGNode,
        root: object,
        result,
        record,
        *,
        inspect_calls: bool,
    ) -> None:
        def visit(current) -> None:
            if current is None or isinstance(current, py_ast.leafTypes):
                return
            if isinstance(current, py_ast.Call):
                if inspect_calls:
                    may_null, matched_fact = self._null_risk_at(node, current.expr, result)
                    if may_null:
                        record(node, "call_target", current.expr, matched_fact)
            elif isinstance(current, py_ast.MethodCall):
                if inspect_calls:
                    may_null, matched_fact = self._null_risk_at(node, current.expr, result)
                    if may_null:
                        record(node, "method_receiver", current.expr, matched_fact)
            elif isinstance(current, (py_ast.GetAttr, py_ast.Load)):
                may_null, matched_fact = self._null_risk_at(node, current.expr, result)
                if may_null:
                    record(node, "attribute_access", current.expr, matched_fact)
            elif isinstance(current, py_ast.GetSubscript):
                may_null, matched_fact = self._null_risk_at(node, current.expr, result)
                if may_null:
                    record(node, "subscript_access", current.expr, matched_fact)
            elif isinstance(
                current,
                (py_ast.SetAttr, py_ast.Store, py_ast.SetSubscript, py_ast.SetSlice),
            ):
                may_null, matched_fact = self._null_risk_at(node, current.expr, result)
                if may_null:
                    record(node, "mutation_target", current.expr, matched_fact)

            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if isinstance(current, py_ast.Code):
                return
            current.visitChildren(visit)

        visit(root)

    def _null_risk_at(self, node: CFGNode, expr: object, result) -> tuple[bool, object | None]:
        if self._expr_contains_explicit_null(expr):
            return True, None
        for fact in self._value_facts_for_expression(node.procedure, expr):
            if result.is_reached(node, fact):
                return True, fact
        return False, None

    def _expr_may_be_null_at(self, node: CFGNode, expr: object, result) -> bool:
        may_null, _ = self._null_risk_at(node, expr, result)
        return may_null


class InterproceduralNullnessAnalysis:
    """Concrete nullness analysis backed by the IFDS engine."""

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        configuration: NullnessConfiguration | None = None,
        *,
        entry_nodes: Sequence[CFGNode] | None = None,
        record_traces: bool = False,
        solver_options: SolverOptions | None = None,
    ) -> None:
        self.problem = InterproceduralNullnessProblem(
            adapter,
            configuration=configuration,
            entry_nodes=entry_nodes,
        )
        self.record_traces = record_traces
        self.solver_options = solver_options

    def solve(self) -> NullnessAnalysisResult:
        solver = (
            IFDSSolver(options=self.solver_options)
            if self.solver_options is not None
            else IFDSSolver(record_traces=self.record_traces)
        )
        result = solver.solve(self.problem)
        return NullnessAnalysisResult(result, self.problem.findings(result), self.problem)


def analyze_nullness(
    adapter: CFGSupergraphAdapter,
    configuration: NullnessConfiguration | None = None,
    *,
    entry_nodes: Sequence[CFGNode] | None = None,
    record_traces: bool = False,
    solver_options: SolverOptions | None = None,
) -> NullnessAnalysisResult:
    """Convenience entry point for interprocedural nullness analysis."""
    return InterproceduralNullnessAnalysis(
        adapter,
        configuration=configuration,
        entry_nodes=entry_nodes,
        record_traces=record_traces,
        solver_options=solver_options,
    ).solve()
