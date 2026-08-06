"""Concrete interprocedural taint analysis over CFG-backed supergraphs."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import FrozenSet, Literal, Mapping, Sequence

from pyflow.analysis.entrypoints import EntryPointOptions
from pyflow.analysis.taint import TaintRule, sink_behavior_is_active
from pyflow.ir.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast

from ..modeling.calls import (
    CallModel,
    CallModelRegistry,
    TaintModelPort,
    TaintPropagation,
)
from ..diagnostics import IFDSDiagnostic
from .base import AnnotatedFactProblemBase, build_entry_seeds
from ..frontend.cfg_adapter import CFGNode, CFGSupergraphAdapter, assigned_locals
from ...alias.flow_sensitive.model import HeapLocation, HeapObjectKind
from ..core.problem import IFDSProblem
from ..core.solver import IFDSSolver, SolverOptions
from ..core.transfers import (
    actual_argument_expressions,
    formal_parameters,
)

ZERO_TAINT = "ZERO_TAINT"
QUERY_TAINT_KIND = "<location-query>"
UnknownCallPolicy = Literal["drop", "preserve", "havoc"]

# Well-known taint categories.  Clients may define additional categories.
CATEGORY_USER_INPUT = "user_input"
CATEGORY_ENVIRONMENT = "env"
CATEGORY_FILE = "file"
CATEGORY_NETWORK = "network"
CATEGORY_DATABASE = "database"

_SHELL_OPTION_SUBPROCESS_CALLS = frozenset(
    {"call", "check_call", "check_output", "popen", "run"}
)
_SQL_QUERY_ARGUMENT_CALLS = frozenset({"execute", "executemany", "executescript"})
_RECEIVER_PRESERVING_METHODS = frozenset({"read", "readline", "readlines"})


def _entry_parameter_source_kinds(rules: Sequence[TaintRule]) -> FrozenSet[str]:
    """Choose the smallest useful kind set for generic boundary parameters.

    A file-public parameter has one unknown external origin, not one distinct
    origin for every spelling accepted by every rule.  Select representative
    kinds that collectively keep every rule eligible.  This avoids multiplying
    the complete IFDS state space when rule packs list broad equivalent source
    categories.
    """
    uncovered = set(range(len(rules)))
    selected: set[str] = set()
    candidates = {kind for rule in rules for kind in rule.source_kinds}
    preference = {
        CATEGORY_USER_INPUT: 0,
        "untrusted": 1,
        "userdata": 2,
    }
    while uncovered:
        best = min(
            candidates,
            key=lambda kind: (
                -sum(kind in rules[index].source_kinds for index in uncovered),
                preference.get(kind, 3),
                kind,
            ),
        )
        selected.add(best)
        uncovered = {
            index for index in uncovered if best not in rules[index].source_kinds
        }
        candidates.remove(best)
    return frozenset(selected)


def _preserving_intrinsic(name: str, *, parameter: int | None = None) -> CallModel:
    """Model a lowered Python operation whose result is derived from its inputs."""
    source = (
        TaintModelPort("all")
        if parameter is None
        else TaintModelPort("parameter", parameter=parameter)
    )
    return CallModel(
        name=name,
        taint_propagations=frozenset(
            {TaintPropagation(source, TaintModelPort("return"))}
        ),
    )


def _predicate_intrinsic(name: str) -> CallModel:
    """Model a lowered Python predicate as returning an untainted boolean."""
    return CallModel(name=name, sanitizer_kinds=frozenset({"*"}))


_PYTHON_SEMANTIC_CALL_MODELS = CallModelRegistry(
    [
        *(
            _preserving_intrinsic(name)
            for name in (
                "interpreter__add__",
                "interpreter__sub__",
                "interpreter__mul__",
                "interpreter__div__",
                "interpreter__truediv__",
                "interpreter__floordiv__",
                "interpreter__mod__",
                "interpreter__pow__",
                "interpreter__and__",
                "interpreter__or__",
                "interpreter__xor__",
                "interpreter__lshift__",
                "interpreter__rshift__",
                "interpreter__neg__",
                "interpreter__pos__",
                "interpreter__invert__",
                "interpreter_booland",
                "interpreter_boolor",
                "interpreter_ifexp",
                "interpreter_format",
                "interpreter_join_str",
                "interpreter_build_map",
                "interpreter_build_set",
            )
        ),
        _preserving_intrinsic("interpreter_getitem", parameter=0),
        _preserving_intrinsic("interpreter_getattr", parameter=0),
        _preserving_intrinsic("interpreter_getattribute", parameter=0),
        _preserving_intrinsic("object__getattribute__", parameter=0),
        _preserving_intrinsic("interpreter_match_rest", parameter=0),
        _preserving_intrinsic("interpreter_match_mapping_rest", parameter=0),
        *(
            _predicate_intrinsic(name)
            for name in (
                "interpreter__eq__",
                "interpreter__ne__",
                "interpreter__lt__",
                "interpreter__le__",
                "interpreter__gt__",
                "interpreter__ge__",
                "interpreter__is__",
                "interpreter__is_not__",
                "interpreter__contains__",
                "convertToBool",
                "invertedConvertToBool",
                "interpreter_match_sequence_len",
                "interpreter_match_sequence_len_min",
                "interpreter_match_mapping_len",
                "interpreter_match_class",
                "interpreter_exception_type",
                "interpreter_exit",
                "interpreter_aexit",
            )
        ),
    ]
)

_PYTHON_MUTATION_INTRINSICS = frozenset(
    {
        "interpreter_delitem",
        "interpreter_list_append",
        "interpreter_setattr",
        "interpreter_setitem",
    }
)


@dataclass(frozen=True)
class TaintConfiguration:
    """Strict typed call models and rules for IFDS taint analysis."""

    call_models: CallModelRegistry = field(default_factory=CallModelRegistry)
    rules: tuple[TaintRule, ...] = ()
    collection_mutator_names: FrozenSet[str] = frozenset(
        {"append", "add", "extend", "update"}
    )
    collection_accessor_names: FrozenSet[str] = frozenset({"get"})
    unknown_call_policy: UnknownCallPolicy = "drop"
    # Backward-compatible alias.  True upgrades the policy to ``havoc``.
    conservative_unresolved_call_side_effects: bool = False
    entry_point_options: EntryPointOptions = EntryPointOptions()

    def __post_init__(self) -> None:
        if self.unknown_call_policy not in {"drop", "preserve", "havoc"}:
            raise ValueError(
                "unknown_call_policy must be 'drop', 'preserve', or 'havoc'"
            )

    @property
    def effective_unknown_call_policy(self) -> UnknownCallPolicy:
        if self.conservative_unresolved_call_side_effects:
            return "havoc"
        return self.unknown_call_policy


@dataclass(frozen=True)
class TaintFinding:
    """A sink reached by tainted data."""

    sink: CFGNode
    sink_name: str
    rule: TaintRule
    source_kind: str
    sink_kind: str
    severity: str
    cwe: str | None
    suggestion: str | None
    tainted_arguments: tuple[py_ast.Local, ...]
    tainted_argument_labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class TaintFact:
    """Taint on a canonical storage location.

    *access_path* refines the fact to a specific field chain.
    ``()`` means the location itself; ``("f",)`` means ``location.f``;
    ``("f", "g")`` means ``location.f.g``.  Facts with shorter paths
    are matched as prefixes: ``access_path=("f",)`` is considered
    tainted when checking if ``location.f.g`` may be tainted.
    """

    location: object
    kind: str
    access_path: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExpressionTaintFact:
    """Taint on the intermediate result of a specific expression."""

    procedure: cfg_graph.Code
    expression: py_ast.PythonASTNode
    kind: str
    result_index: int = 0
    access_path: tuple[str, ...] = ()


class TaintAnalysisResult:
    """Result wrapper with taint queries and sink findings."""

    def __init__(self, ifds_result, findings: Sequence[TaintFinding], problem) -> None:
        self._ifds_result = ifds_result
        self.findings = tuple(findings)
        self._problem = problem
        self.diagnostics = tuple(problem.semantic_diagnostics())

    def is_tainted(self, node: CFGNode, local: py_ast.Local) -> bool:
        locations = set(self._problem.local_locations(node.procedure, local))
        return any(
            isinstance(fact, TaintFact) and fact.location in locations
            for fact in self._ifds_result.facts_at(node)
        )

    def tainted_locals_at(self, node: CFGNode):
        return frozenset(
            self._problem.describe_fact(fact)
            for fact in self._ifds_result.facts_at(node)
            if isinstance(fact, TaintFact)
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

    def fact_for_local(self, node: CFGNode, local: py_ast.Local) -> TaintFact | None:
        storage_candidate: TaintFact | None = None
        locations = set(self._problem.local_locations(node.procedure, local))
        for fact in self._ifds_result.facts_at(node):
            if isinstance(fact, TaintFact) and fact.location in locations:
                location = fact.location
                if (
                    isinstance(location, HeapLocation)
                    and location.root.kind is not HeapObjectKind.STORAGE
                ):
                    return fact
                if storage_candidate is None:
                    storage_candidate = fact
        return storage_candidate


class InterproceduralTaintProblem(
    AnnotatedFactProblemBase[object],
    IFDSProblem[cfg_graph.Code, CFGNode, object],
):
    """IFDS taint problem over CFG nodes."""

    analysis_name = "IFDS taint"

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        configuration: TaintConfiguration,
        entry_nodes: Sequence[CFGNode] | None = None,
    ) -> None:
        self.configuration = configuration
        self._semantic_diagnostics: set[IFDSDiagnostic] = set()
        super().__init__(
            adapter,
            call_models=configuration.call_models,
        )
        if entry_nodes is None:
            raise ValueError(
                "IFDS taint requires explicit entry_nodes; "
                "use program-backed IFDS APIs to derive roots automatically."
            )
        self.entry_nodes = tuple(entry_nodes)

    def semantic_diagnostics(self) -> tuple[IFDSDiagnostic, ...]:
        return tuple(
            sorted(
                self._semantic_diagnostics,
                key=lambda item: (item.code, item.subject or "", item.message),
            )
        )

    def _call_model_for_node(self, node: CFGNode):
        model = super()._call_model_for_node(node)
        if model is not None:
            return model
        call_name = self._call_name(node)
        model = _PYTHON_SEMANTIC_CALL_MODELS.model_for_name(call_name)
        if model is not None:
            return model
        if (
            call_name is not None
            and call_name.rsplit(".", 1)[-1] in _RECEIVER_PRESERVING_METHODS
        ):
            return CallModel(
                name=call_name,
                taint_propagations=frozenset(
                    {
                        TaintPropagation(
                            TaintModelPort("receiver"),
                            TaintModelPort("return"),
                        )
                    }
                ),
            )
        return None

    def _call_model_for_expression(self, expr: object):
        model = super()._call_model_for_expression(expr)
        if model is not None:
            return model
        call_name = self._call_name_from_expression(expr)
        model = _PYTHON_SEMANTIC_CALL_MODELS.model_for_name(call_name)
        if model is not None:
            return model
        if (
            call_name is not None
            and call_name.rsplit(".", 1)[-1] in _RECEIVER_PRESERVING_METHODS
        ):
            return CallModel(
                name=call_name,
                taint_propagations=frozenset(
                    {
                        TaintPropagation(
                            TaintModelPort("receiver"),
                            TaintModelPort("return"),
                        )
                    }
                ),
            )
        return None

    def _record_semantic_diagnostic(
        self,
        *,
        code: str,
        message: str,
        subject: str | None = None,
        affects_completeness: bool = False,
    ) -> None:
        self._semantic_diagnostics.add(
            IFDSDiagnostic(
                severity="warning",
                phase="solver",
                message=message,
                subject=subject,
                code=code,
                recoverable=True,
                affects_completeness=affects_completeness,
            )
        )

    @property
    def supergraph(self):
        return self.adapter.supergraph

    @property
    def zero_fact(self):
        return ZERO_TAINT

    def local_locations(
        self, procedure: cfg_graph.Code, local: py_ast.Local
    ) -> tuple[object, ...]:
        return self._locations_for_local(procedure, local)

    def initial_seeds(self) -> Mapping[CFGNode, frozenset[object]]:
        seeds = {
            node: set(facts)
            for node, facts in build_entry_seeds(self.entry_nodes, ZERO_TAINT).items()
        }
        if not self.configuration.entry_point_options.taint_parameters:
            return {node: frozenset(facts) for node, facts in seeds.items()}

        source_kinds = _entry_parameter_source_kinds(self.configuration.rules)
        for node in self.entry_nodes:
            parameters = formal_parameters(node.procedure.code.codeparameters)
            for parameter in parameters:
                # Public instance methods receive externally initialized object
                # state through ``self``.  Treat the receiver as a boundary
                # input just like explicit parameters; ``cls`` denotes class
                # metadata rather than per-request/per-object state.
                if parameter.name == "cls":
                    continue
                for location in self._locations_for_local(node.procedure, parameter):
                    seeds[node].update(
                        TaintFact(location, kind) for kind in source_kinds
                    )
        return {node: frozenset(facts) for node, facts in seeds.items()}

    def normal_flow(self, node: CFGNode, successor: CFGNode, fact: object):
        if node.kind == "call" and self.adapter.is_exceptional_successor(
            node, successor
        ):
            outputs = set(self._identity_outputs(fact, ()))
            if fact != ZERO_TAINT:
                self._add_modeled_propagation_outputs(
                    node, fact, outputs, target_kinds=frozenset({"raise"})
                )
            return tuple(outputs)
        unresolved_call_outputs = self._unresolved_call_outputs(node, fact)
        if unresolved_call_outputs is not None:
            return unresolved_call_outputs

        if node.kind == "call" and not self.supergraph.call_to_return_successors(node):
            outputs = set(
                self._identity_outputs(fact, self._killed_locations_for_node(node))
            )
            modeled = False
            if fact == ZERO_TAINT:
                modeled = self._add_modeled_source_outputs(node, outputs)
            else:
                modeled = self._add_modeled_sanitizer_outputs(node, fact, outputs)
                modeled = (
                    self._add_modeled_propagation_outputs(node, fact, outputs)
                    or modeled
                )
            if modeled:
                return tuple(outputs)

        effect = self.adapter.effect_of(node)
        operation = getattr(effect, "operation", self.adapter.operation_of(node))
        if operation is None:
            return self._identity_outputs(fact, ())

        if node.kind == "foriter" and isinstance(node.block, cfg_graph.ForIter):
            outputs = set(self._identity_outputs(fact, ()))
            for template in self._templates_for_expression(
                node.procedure, node.block.iterator, fact
            ):
                outputs.update(
                    self._facts_for_locals(
                        node.procedure, (node.block.index,), template
                    )
                )
            return tuple(outputs)

        killed = self._killed_locations_for_node(node)
        dynamic_setattr_locations = self._dynamic_setattr_locations(
            node.procedure, operation
        )
        if dynamic_setattr_locations:
            outputs = set(self._identity_outputs(fact, killed))
            value = self._dynamic_setattr_value(node.procedure, operation)
            if value is not None:
                for template in self._templates_for_expression(
                    node.procedure, value, fact
                ):
                    outputs.update(
                        self._make_location_fact(location, template)
                        for location in dynamic_setattr_locations
                    )
            return tuple(outputs)

        dynamic_subscript_locations = self._dynamic_subscript_write_locations(
            node.procedure, operation
        )
        if dynamic_subscript_locations:
            outputs = set(self._identity_outputs(fact, killed))
            value = self._dynamic_subscript_value(operation)
            if value is not None:
                for template in self._templates_for_expression(
                    node.procedure, value, fact
                ):
                    outputs.update(
                        self._facts_for_modified_operation(
                            operation,
                            procedure=node.procedure,
                            template_fact=template,
                        )
                    )
                    outputs.update(
                        self._make_location_fact(location, template)
                        for location in dynamic_subscript_locations
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
            templates = {
                template
                for value in collection_values
                for template in self._templates_for_expression(
                    node.procedure, value, fact
                )
            }
            if fact_location is not None and fact_location in copy_source_locations:
                templates.add(fact)
            for template in templates:
                outputs.update(
                    self._make_location_fact(location, template)
                    for location in collection_locations
                )
                outputs.update(
                    self._make_location_fact(location, template)
                    for location in copy_locations
                )
            return tuple(outputs)

        if isinstance(
            operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)
        ):
            outputs = set(self._identity_outputs(fact, killed))
            expr = getattr(operation, "expr", None)
            if isinstance(operation, py_ast.AnnAssign):
                expr = operation.value
            targets = assigned_locals(operation)
            self._update_aliases_for_assignment(node.procedure, targets, expr)

            direct_fact = self._direct_expression_fact(expr, fact)
            if direct_fact is not None:
                _procedure, _expr, result_index = direct_fact
                access_path = self._access_path_from_fact(fact)
                if result_index < len(targets):
                    if access_path:
                        outputs.update(
                            self._facts_for_locals_with_path(
                                node.procedure,
                                (targets[result_index],),
                                access_path,
                                fact,
                            )
                        )
                    else:
                        outputs.update(
                            self._facts_for_assigned_locals(
                                node.procedure,
                                targets,
                                result_index,
                                fact,
                            )
                        )
                return tuple(outputs)
            if expr is not None:
                path = self._access_path_for_expression(expr)
                for template in self._templates_for_expression(
                    node.procedure, expr, fact
                ):
                    if path:
                        outputs.update(
                            self._facts_for_locals_with_path(
                                node.procedure,
                                targets,
                                path,
                                template,
                            )
                        )
                    else:
                        outputs.update(
                            self._facts_for_locals(node.procedure, targets, template)
                        )
            if fact != ZERO_TAINT:
                outputs.update(
                    self._make_location_fact(location, fact)
                    for location in self._aliased_dynamic_locations_for_assignment(
                        node.procedure,
                        operation,
                        fact,
                    )
                )
            for locations, value in self._collection_constructor_writes(
                node.procedure,
                operation,
            ):
                for template in self._templates_for_expression(
                    node.procedure, value, fact
                ):
                    outputs.update(
                        self._make_location_fact(location, template)
                        for location in locations
                    )
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
                            template_fact=fact,
                        )
                    )
                    return tuple(outputs)
            for index, expr in enumerate(operation.exprs):
                for template in self._templates_for_expression(
                    node.procedure, expr, fact
                ):
                    path = self._access_path_for_expression(expr)
                    outputs.update(
                        self._facts_for_return_location(
                            node.procedure,
                            index,
                            access_path=path,
                            template_fact=template,
                        )
                    )
            return tuple(outputs)

        if isinstance(operation, (py_ast.Yield, py_ast.YieldFrom, py_ast.AsyncYield)):
            outputs = set(self._identity_outputs(fact, ()))
            expr = operation.expr
            direct_fact = self._direct_expression_fact(expr, fact)
            if direct_fact is not None:
                path = self._access_path_from_fact(fact)
                outputs.update(
                    self._facts_for_return_location(
                        node.procedure,
                        0,
                        access_path=path,
                        template_fact=fact,
                    )
                )
                return tuple(outputs)
            for template in self._templates_for_expression(
                node.procedure, expr, fact
            ):
                outputs.update(
                    self._facts_for_return_location(
                        node.procedure,
                        0,
                        access_path=self._access_path_for_expression(expr),
                        template_fact=template,
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
            for template in self._templates_for_expression(node.procedure, value, fact):
                path = self._access_path_for_expression(value)
                outputs.update(
                    self._facts_for_modified_operation(
                        operation,
                        access_path=path,
                        procedure=node.procedure,
                        template_fact=template,
                    )
                )
            return tuple(outputs)

        return self._identity_outputs(fact, killed)

    def call_flow(self, call_node: CFGNode, callee: cfg_graph.Code, fact: object):
        outputs = set()
        if fact == ZERO_TAINT:
            outputs.add(ZERO_TAINT)

        model = self._call_model_for_node(call_node)
        if model is not None and (
            model.source_kinds
            or model.sanitizer_kinds
            or model.sanitizer_contracts
        ):
            return tuple(outputs)

        call_effect = self._call_effect(call_node)
        call = call_effect.call_expression if call_effect is not None else None
        if call is None:
            return tuple(outputs)

        self._bind_callee_formals(call_node, callee)
        for actual, formal in self._bind_call_arguments_for_callee(call_node, callee):
            for template in self._templates_for_expression(
                call_node.procedure, actual, fact
            ):
                path = self._access_path_for_expression(actual)
                if path:
                    outputs.update(
                        self._facts_for_locals_with_path(
                            callee, (formal,), path, template
                        )
                    )
                else:
                    outputs.update(self._facts_for_locals(callee, (formal,), template))

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
        del exit_node, return_site
        outputs = set()
        if call_fact == ZERO_TAINT and exit_fact == ZERO_TAINT:
            outputs.add(ZERO_TAINT)

        model = self._call_model_for_node(call_node)
        if (
            model is not None
            and isinstance(exit_fact, (TaintFact, ExpressionTaintFact))
            and (
                "*" in model.sanitizer_kinds or exit_fact.kind in model.sanitizer_kinds
            )
        ):
            return tuple(outputs)

        return_index = self._return_fact_index(callee, exit_fact)
        call_effect = self._call_effect(call_node)
        if return_index is not None and call_effect is not None:
            outputs.update(
                self._facts_for_nested_call_result(
                    call_node.procedure,
                    call_effect.operation,
                    call_effect.call_expression,
                    return_index,
                    nested=False,
                    template_fact=exit_fact,
                )
            )
        projected = self._project_constructor_heap_fact_to_caller(call_node, exit_fact)
        if projected is not None:
            outputs.add(projected)

        return tuple(outputs)

    def call_to_return_flow(
        self, call_node: CFGNode, return_site: CFGNode, fact: object
    ):
        del return_site
        call_effect = self._call_effect(call_node)
        call_expression = (
            call_effect.call_expression if call_effect is not None else None
        )
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
        outputs = set(self._identity_outputs(fact, killed))
        model = self._call_model_for_node(call_node)
        if fact == ZERO_TAINT and model is not None and call_effect is not None:
            self._add_modeled_source_outputs(call_node, outputs)
        elif (
            model is not None
            and model.sanitizer_kinds
            and not model.sanitizer_contracts
            and isinstance(fact, (TaintFact, ExpressionTaintFact))
            and "*" not in model.sanitizer_kinds
            and fact.kind not in model.sanitizer_kinds
            and call_effect is not None
            and any(
                self._expr_is_tainted(call_node.procedure, actual, fact)
                for actual in call_effect.actual_arguments
            )
        ):
            outputs.update(
                self._facts_for_nested_call_result(
                    call_node.procedure,
                    call_effect.operation,
                    call_effect.call_expression,
                    0,
                    nested=False,
                    template_fact=fact,
                )
            )
        if fact != ZERO_TAINT:
            self._add_modeled_sanitizer_outputs(call_node, fact, outputs)
            self._add_modeled_propagation_outputs(call_node, fact, outputs)
        return tuple(outputs)

    def _add_modeled_source_outputs(
        self, call_node: CFGNode, outputs: set[object]
    ) -> bool:
        call_effect = self._call_effect(call_node)
        model = self._call_model_for_node(call_node)
        if call_effect is None or model is None or not model.source_kinds:
            return False

        for kind in model.source_kinds:
            template = TaintFact(object(), kind)
            outputs.update(
                self._facts_for_nested_call_result(
                    call_node.procedure,
                    call_effect.operation,
                    call_effect.call_expression,
                    0,
                    nested=False,
                    template_fact=template,
                )
            )
            operation = call_effect.operation
            if (
                isinstance(operation, py_ast.For)
                and call_effect.call_name
                == self.adapter.call_name(operation.iterator, call_node.procedure)
                and isinstance(operation.index, py_ast.Local)
            ):
                outputs.update(
                    self._facts_for_locals(
                        call_node.procedure,
                        (operation.index,),
                        template,
                    )
                )
        return True

    def _add_modeled_propagation_outputs(
        self,
        call_node: CFGNode,
        fact: object,
        outputs: set[object],
        *,
        target_kinds: FrozenSet[str] | None = None,
    ) -> bool:
        call_effect = self._call_effect(call_node)
        model = self._call_model_for_node(call_node)
        if call_effect is None or model is None or not model.taint_propagations:
            return False
        if not isinstance(fact, (TaintFact, ExpressionTaintFact)):
            return True

        receiver = self._call_receiver_expression(call_effect.call_expression)
        arguments = self._explicit_call_arguments(call_effect.call_expression)
        for propagation in model.taint_propagations:
            if target_kinds is not None and propagation.target.kind not in target_kinds:
                continue
            source_expressions = self._expressions_for_model_port(
                propagation.source, receiver, arguments
            )
            if not self._model_port_is_tainted(
                call_node.procedure, propagation.source, source_expressions, fact
            ):
                continue
            for output_kind in propagation.transform_kind(fact.kind):
                transformed = self._fact_with_kind(fact, output_kind)
                outputs.update(
                    self._facts_for_model_target(
                        call_node,
                        propagation.target,
                        receiver,
                        arguments,
                        transformed,
                    )
                )
            if propagation.guard:
                self._record_semantic_diagnostic(
                    code="IFDS-TAINT-CONDITIONAL-PROPAGATION",
                    message=(
                        f"Joined guarded propagation {propagation.guard!r} for "
                        f"{call_effect.call_name or '<dynamic>'}"
                    ),
                    subject=call_effect.call_name,
                )
        return True

    def _add_modeled_sanitizer_outputs(
        self, call_node: CFGNode, fact: object, outputs: set[object]
    ) -> bool:
        call_effect = self._call_effect(call_node)
        model = self._call_model_for_node(call_node)
        if (
            call_effect is None
            or model is None
            or not model.sanitizer_contracts
            or not isinstance(fact, (TaintFact, ExpressionTaintFact))
        ):
            return False
        receiver = self._call_receiver_expression(call_effect.call_expression)
        arguments = self._explicit_call_arguments(call_effect.call_expression)
        for contract in model.sanitizer_contracts:
            source_expressions = self._expressions_for_model_port(
                contract.input, receiver, arguments
            )
            if not self._model_port_is_tainted(
                call_node.procedure, contract.input, source_expressions, fact
            ):
                continue
            if contract.mutates_input:
                outputs.discard(fact)
            for output_kind in contract.transform_kind(fact.kind):
                transformed = self._fact_with_kind(fact, output_kind)
                outputs.update(
                    self._facts_for_model_target(
                        call_node,
                        contract.output,
                        receiver,
                        arguments,
                        transformed,
                    )
                )
                if contract.mutates_input:
                    for expression in source_expressions:
                        outputs.update(
                            self._facts_for_expression_node(
                                call_node.procedure,
                                expression,
                                extend_paths=True,
                                template_fact=transformed,
                            )
                        )
            for assumption in contract.assumptions:
                self._record_semantic_diagnostic(
                    code="IFDS-TAINT-MODEL-ASSUMPTION",
                    message=assumption,
                    subject=call_effect.call_name,
                )
            if contract.guard:
                self._record_semantic_diagnostic(
                    code="IFDS-TAINT-CONDITIONAL-SANITIZER",
                    message=(
                        f"Joined sanitized and unsanitized outcomes because guard "
                        f"{contract.guard!r} was not proven"
                    ),
                    subject=call_effect.call_name,
                )
        return True

    @staticmethod
    def _expressions_for_model_port(port, receiver, arguments) -> tuple[object, ...]:
        if port.kind == "receiver":
            return (receiver,) if receiver is not None else ()
        if port.kind == "all":
            return arguments
        if port.kind == "parameter":
            position = port.parameter
            if position is not None and position < len(arguments):
                return (arguments[position],)
        return ()

    def _model_port_is_tainted(
        self, procedure, port, expressions, fact: object
    ) -> bool:
        if not port.path:
            return any(
                self._expr_is_tainted(procedure, expr, fact)
                for expr in expressions
            )
        for expression in expressions:
            for candidate in self._facts_for_expression_node(
                procedure, expression, extend_paths=True, template_fact=fact
            ):
                query = self._fact_with_path(candidate, port.path)
                if self._model_path_matches(fact, query):
                    return True
        return False

    @staticmethod
    def _model_path_matches(stored: object, query: object) -> bool:
        if isinstance(stored, ExpressionTaintFact) and isinstance(
            query, ExpressionTaintFact
        ):
            if (
                stored.procedure != query.procedure
                or stored.expression is not query.expression
                or stored.result_index != query.result_index
            ):
                return False
        elif getattr(stored, "location", None) != getattr(query, "location", None):
            return False
        stored_path = getattr(stored, "access_path", ())
        query_path = getattr(query, "access_path", ())
        if len(stored_path) > len(query_path):
            return False
        return all(
            left == right or left in {"*", "[*]"} or right in {"*", "[*]"}
            for left, right in zip(stored_path, query_path)
        )

    @staticmethod
    def _fact_with_kind(fact: object, kind: str) -> object:
        if isinstance(fact, (TaintFact, ExpressionTaintFact)):
            return replace(fact, kind=kind)
        return fact

    @staticmethod
    def _fact_with_path(fact: object, path: tuple[str, ...]) -> object:
        if isinstance(fact, (TaintFact, ExpressionTaintFact)):
            return replace(fact, access_path=(*fact.access_path, *path))
        return fact

    def _facts_for_model_target(
        self, call_node, port, receiver, arguments, template_fact
    ) -> set[object]:
        call_effect = self._call_effect(call_node)
        if call_effect is None:
            return set()
        target_path = port.path
        if port.kind == "raise":
            facts = {
                self._make_expression_fact(
                    call_node.procedure,
                    call_effect.call_expression,
                    template_fact=template_fact,
                )
            }
        elif port.kind in {"return", "yield"}:
            facts = self._facts_for_nested_call_result(
                call_node.procedure,
                call_effect.operation,
                call_effect.call_expression,
                0,
                nested=False,
                template_fact=template_fact,
            )
        elif port.kind in {"receiver", "parameter"}:
            facts = {
                candidate
                for expression in self._expressions_for_model_port(
                    port, receiver, arguments
                )
                for candidate in self._facts_for_expression_node(
                    call_node.procedure,
                    expression,
                    extend_paths=True,
                    template_fact=template_fact,
                )
            }
        else:
            return set()
        if port.kind == "yield":
            element_path = ("[*]", *target_path)
            return set(facts) | {
                self._fact_with_path(candidate, element_path) for candidate in facts
            }
        if not target_path:
            return set(facts)
        return {self._fact_with_path(candidate, target_path) for candidate in facts}

    @staticmethod
    def _call_receiver_expression(call: object) -> object | None:
        if isinstance(call, py_ast.Call) and isinstance(call.expr, py_ast.GetAttr):
            return call.expr.expr
        if isinstance(call, py_ast.MethodCall):
            return call.expr
        if isinstance(call, py_ast.DirectCall):
            return call.selfarg
        return None

    @staticmethod
    def _explicit_call_arguments(call: object) -> tuple[object, ...]:
        arguments = actual_argument_expressions(call)
        selfarg = getattr(call, "selfarg", None)
        if selfarg is not None and arguments and arguments[0] is selfarg:
            return arguments[1:]
        return arguments

    def _unresolved_call_outputs(self, node: CFGNode, fact: object):
        call_effect = self._call_effect(node)
        policy = self.configuration.effective_unknown_call_policy
        model = self._call_model_for_node(node)
        if (
            call_effect is None
            or call_effect.callees
            or policy == "drop"
            or (
                model is not None
                and (
                    model.source_kinds
                    or model.sink_kinds
                    or model.sanitizer_kinds
                    or model.sanitizer_contracts
                    or model.taint_propagations
                )
            )
        ):
            return None

        call_name = call_effect.call_name or "<dynamic>"
        leaf_name = call_name.rsplit(".", 1)[-1]
        if (
            call_name in _PYTHON_MUTATION_INTRINSICS
            or leaf_name in self.configuration.collection_mutator_names
        ):
            # These calls return no useful value.  Let the normal-flow transfer
            # apply the existing heap/container mutation semantics instead of
            # short-circuiting them with unknown-call return propagation.
            return None

        self._record_semantic_diagnostic(
            code="IFDS-TAINT-UNKNOWN-CALL",
            message=(
                f"Applied {policy!r} taint semantics to unresolved call "
                f"{call_name}"
            ),
            subject=call_name,
            affects_completeness=False,
        )

        outputs = set(
            self._identity_outputs(fact, self._killed_locations_for_node(node))
        )
        if fact == ZERO_TAINT:
            if model is not None:
                for kind in model.source_kinds:
                    outputs.update(
                        self._facts_for_nested_call_result(
                            node.procedure,
                            call_effect.operation,
                            call_effect.call_expression,
                            0,
                            nested=False,
                            template_fact=TaintFact(object(), kind),
                        )
                    )
            return tuple(outputs)

        if (
            model is not None
            and not model.sanitizer_contracts
            and isinstance(fact, (TaintFact, ExpressionTaintFact))
            and ("*" in model.sanitizer_kinds or fact.kind in model.sanitizer_kinds)
        ):
            return tuple(outputs)

        if model is not None and model.sanitizer_contracts:
            self._add_modeled_sanitizer_outputs(node, fact, outputs)
            return tuple(outputs)

        if not any(
            self._expr_is_tainted(node.procedure, actual, fact)
            for actual in call_effect.actual_arguments
        ):
            return tuple(outputs)

        if policy == "havoc":
            for actual in call_effect.actual_arguments:
                outputs.update(
                    self._facts_for_expression_node(
                        node.procedure, actual, template_fact=fact
                    )
                )
        outputs.update(
            self._facts_for_nested_call_result(
                node.procedure,
                call_effect.operation,
                call_effect.call_expression,
                0,
                nested=False,
                template_fact=fact,
            )
        )
        return tuple(outputs)

    def describe_fact(self, fact: object) -> str:
        if isinstance(fact, TaintFact):
            return self.describe_location(fact.location)
        if isinstance(fact, ExpressionTaintFact):
            return self.describe_expression(fact.expression)
        return "<expr>"

    @staticmethod
    def _kind_from_template(template_fact: object | None) -> str:
        if isinstance(template_fact, (TaintFact, ExpressionTaintFact)):
            return template_fact.kind
        return QUERY_TAINT_KIND

    def _make_location_fact(
        self, location: object, template_fact: object | None = None
    ) -> object:
        return TaintFact(location, self._kind_from_template(template_fact))

    def _make_location_fact_with_path(
        self,
        location: object,
        access_path: tuple[str, ...],
        template_fact: object | None = None,
    ) -> object:
        return TaintFact(
            location,
            self._kind_from_template(template_fact),
            access_path=access_path,
        )

    def _make_expression_fact(
        self,
        procedure: cfg_graph.Code,
        expression: py_ast.PythonASTNode,
        result_index: int = 0,
        template_fact: object | None = None,
    ) -> object:
        return ExpressionTaintFact(
            procedure,
            expression,
            self._kind_from_template(template_fact),
            result_index,
        )

    def _location_from_fact(self, fact: object) -> object | None:
        if isinstance(fact, TaintFact):
            return fact.location
        return None

    def _expression_fact_result(
        self, fact: object
    ) -> tuple[cfg_graph.Code, py_ast.PythonASTNode, int] | None:
        if isinstance(fact, ExpressionTaintFact):
            return (fact.procedure, fact.expression, fact.result_index)
        return None

    def _identity_outputs(self, fact: object, killed: Sequence[object]):
        if fact == ZERO_TAINT:
            return (ZERO_TAINT,)
        if isinstance(fact, TaintFact) and any(
            fact.location == target for target in killed
        ):
            return ()
        return (fact,)

    def _expr_is_tainted(
        self, procedure: cfg_graph.Code, expr: object, fact: object
    ) -> bool:
        if fact == ZERO_TAINT:
            return bool(self._source_kinds_in_expression(expr))
        return self._expression_matches(
            expr,
            lambda current: any(
                self._fact_prefix_matches(fact, candidate)
                for candidate in self._facts_for_expression_node(
                    procedure, current, template_fact=fact
                )
            ),
            source_kind=(
                fact.kind
                if isinstance(fact, (TaintFact, ExpressionTaintFact))
                else None
            ),
        )

    def _source_kinds_in_expression(self, expr: object) -> FrozenSet[str]:
        def collect(current) -> set[str]:
            if current is None or isinstance(current, py_ast.leafTypes):
                return set()
            model = self._call_model_for_expression(current)
            own_kinds = set(model.source_kinds) if model is not None else set()
            child_kinds: set[str] = set()
            if isinstance(current, (list, tuple)):
                for child in current:
                    child_kinds.update(collect(child))
                return child_kinds
            if isinstance(current, py_ast.Code):
                return own_kinds
            current.visitChildren(lambda child: child_kinds.update(collect(child)))
            if model is not None and not model.taint_propagations:
                if "*" in model.sanitizer_kinds:
                    child_kinds.clear()
                else:
                    child_kinds.difference_update(model.sanitizer_kinds)
            return own_kinds | child_kinds

        return frozenset(collect(expr))

    def _expr_contains_source(self, expr: object) -> bool:
        return bool(self._source_kinds_in_expression(expr))

    def _templates_for_expression(
        self, procedure: cfg_graph.Code, expr: object, fact: object
    ) -> tuple[object, ...]:
        if fact == ZERO_TAINT:
            return tuple(
                TaintFact(object(), kind)
                for kind in self._source_kinds_in_expression(expr)
            )
        if self._expr_is_tainted(procedure, expr, fact):
            return (fact,)
        return ()

    def _expr_sanitizes_kind(self, expr: object, kind: str) -> bool:
        model = self._call_model_for_expression(expr)
        return model is not None and not model.taint_propagations and (
            "*" in model.sanitizer_kinds or kind in model.sanitizer_kinds
        )

    def findings(self, result) -> tuple[TaintFinding, ...]:
        findings: list[TaintFinding] = []
        for node in self.adapter.supergraph.ordered_nodes():
            call_effect = self._call_effect(node)
            sink_name: str | None = None
            sink_expressions: tuple[object, ...] = ()
            sink_receiver_position: int | None = None
            model = None
            if call_effect is not None:
                sink_name = call_effect.call_name or "<sink>"
                sink_expressions = actual_argument_expressions(
                    call_effect.call_expression
                )
                model = self._call_model_for_node(node)
                if model is not None and model.sink_receiver:
                    receiver = self._call_receiver_expression(
                        call_effect.call_expression
                    )
                    if receiver is not None:
                        sink_receiver_position = next(
                            (
                                index
                                for index, expression in enumerate(sink_expressions)
                                if expression is receiver
                            ),
                            None,
                        )
                        if sink_receiver_position is None:
                            sink_receiver_position = len(sink_expressions)
                            sink_expressions = (*sink_expressions, receiver)
            else:
                operation = self.adapter.operation_of(node)
                if isinstance(operation, py_ast.SetAttr):
                    base = self._symbolic_expression_name(operation.expr)
                    component = self._path_component(operation.name)
                    if base and component != "*":
                        sink_name = f"{base}.{component}"
                        sink_expressions = (operation.value,)
                        model = self.call_models.model_for_name(sink_name)
            if model is None or not model.sink_kinds:
                continue
            if call_effect is not None and not self._shell_sink_is_active(
                call_effect.call_expression, sink_name or "", model
            ):
                continue
            if call_effect is not None and not self._sink_behavior_is_active(
                call_effect.call_expression, model
            ):
                continue
            if not result.is_reached(node, ZERO_TAINT):
                continue
            source_kinds = sorted(
                {
                    fact.kind
                    for fact in result.facts_at(node)
                    if isinstance(fact, (TaintFact, ExpressionTaintFact))
                }
                | frozenset(
                    kind
                    for expression in sink_expressions
                    for kind in self._source_kinds_in_expression(expression)
                )
            )
            for source_kind in source_kinds:
                tainted_args, tainted_labels = self._tainted_values_for_expressions(
                    node,
                    sink_expressions,
                    result,
                    source_kind=source_kind,
                    positions=self._sink_positions_for_call(
                        sink_name or "",
                        model,
                        len(sink_expressions),
                        receiver_position=sink_receiver_position,
                    ),
                )
                if not (tainted_args or tainted_labels):
                    continue
                for sink_kind in sorted(model.sink_kinds):
                    for rule in self.configuration.rules:
                        if not rule.matches(source_kind, sink_kind):
                            continue
                        findings.append(
                            TaintFinding(
                                sink=node,
                                sink_name=sink_name or "<sink>",
                                rule=rule,
                                source_kind=source_kind,
                                sink_kind=sink_kind,
                                severity=model.severity or rule.severity,
                                cwe=model.cwe or rule.cwe,
                                suggestion=model.suggestion or rule.suggestion,
                                tainted_arguments=tainted_args,
                                tainted_argument_labels=tainted_labels,
                            )
                        )
        return tuple(findings)

    def _shell_sink_is_active(self, call, sink_name: str, model) -> bool:
        """Return whether a CWE-78 subprocess call actually enables a shell."""
        if model.cwe != "CWE-78":
            return True
        configured = (model.name or sink_name).lower()
        if not configured.startswith("subprocess."):
            return True
        if configured.rsplit(".", 1)[-1] not in _SHELL_OPTION_SUBPROCESS_CALLS:
            return True
        for keyword, value in getattr(call, "kwds", ()) or ():
            if keyword != "shell":
                continue
            if isinstance(value, py_ast.Existing):
                try:
                    return value.constantValue() is not False
                except Exception:
                    return True
            return True
        return False

    def _sink_behavior_is_active(self, call, model) -> bool:
        """Evaluate the context-dependent behavior declared by the sink model."""
        constants = tuple(
            self._constant_string(argument)
            for argument in getattr(call, "args", ()) or ()
        )
        return sink_behavior_is_active(model.sink_behavior, constants)

    def _sink_positions_for_call(
        self,
        sink_name: str,
        model,
        argument_count: int,
        *,
        receiver_position: int | None = None,
    ) -> frozenset[int]:
        """Normalize model ports to explicit arguments in source-level calls."""
        if (
            model.cwe == "CWE-89"
            and sink_name.rsplit(".", 1)[-1].lower()
            in _SQL_QUERY_ARGUMENT_CALLS
        ):
            return frozenset({0})
        if model.sink_all_arguments:
            return frozenset(range(argument_count))
        positions = set(model.sink_arg_positions)
        if model.sink_receiver and receiver_position is not None:
            positions.add(receiver_position)
        for propagation in model.taint_propagations:
            if propagation.target.kind != "sink":
                continue
            if propagation.source.kind == "all":
                positions.update(range(argument_count))
            elif (
                propagation.source.kind == "parameter"
                and propagation.source.parameter is not None
            ):
                positions.add(propagation.source.parameter)
        return frozenset(positions)

    def _tainted_arguments_for_call(
        self,
        node: CFGNode,
        call,
        result,
        *,
        source_kind: str,
        positions: FrozenSet[int],
    ):
        return self._tainted_values_for_expressions(
            node,
            actual_argument_expressions(call),
            result,
            source_kind=source_kind,
            positions=positions,
        )

    def _tainted_values_for_expressions(
        self,
        node: CFGNode,
        expressions: Sequence[object],
        result,
        *,
        source_kind: str,
        positions: FrozenSet[int],
    ):
        tainted_locals: list[py_ast.Local] = []
        tainted_labels: list[str] = []
        seen_local_names: set[str] = set()
        seen_labels: set[str] = set()

        for index, actual in enumerate(expressions):
            if index not in positions:
                continue
            locals_in_expr = sorted(
                self._matching_locals_in_expression(
                    node.procedure,
                    actual,
                    lambda location: any(
                        isinstance(fact, TaintFact)
                        and fact.kind == source_kind
                        and fact.location == location
                        for fact in result.facts_at(node)
                    ),
                    source_kind=source_kind,
                ),
                key=lambda local: local.name or "",
            )
            for local in locals_in_expr:
                if local.name not in seen_local_names:
                    seen_local_names.add(local.name)
                    tainted_locals.append(local)

            labels_in_expr = sorted(
                self._matching_labels_in_expression(
                    node.procedure,
                    actual,
                    lambda candidate_fact: (
                        isinstance(candidate_fact, (TaintFact, ExpressionTaintFact))
                        and candidate_fact.kind == source_kind
                        and result.is_reached(node, candidate_fact)
                    ),
                    source_kind=source_kind,
                )
            )
            for label in labels_in_expr:
                if label not in seen_labels:
                    seen_labels.add(label)
                    tainted_labels.append(label)

            if (
                not locals_in_expr
                and not labels_in_expr
                and source_kind in self._source_kinds_in_expression(actual)
            ):
                label = self.describe_expression(actual)
                if label not in seen_labels:
                    seen_labels.add(label)
                    tainted_labels.append(label)

        return tuple(tainted_locals), tuple(tainted_labels)

    def _matching_labels_in_expression(
        self,
        procedure: cfg_graph.Code,
        expr: object,
        predicate,
        *,
        source_kind: str,
    ) -> frozenset[str]:
        found: set[str] = set()

        def visit(current) -> None:
            if current is None or isinstance(current, py_ast.leafTypes):
                return
            if self._expr_sanitizes_kind(current, source_kind):
                return
            if not isinstance(
                current, py_ast.Local
            ) and not self._expression_has_nested_sanitizer(current, source_kind):
                template = TaintFact(object(), source_kind)
                facts = self._facts_for_expression_node(
                    procedure, current, template_fact=template
                )
                if facts and any(predicate(candidate_fact) for candidate_fact in facts):
                    found.add(self.describe_expression(current))
            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if isinstance(current, py_ast.Code):
                return
            current.visitChildren(visit)

        visit(expr)
        return frozenset(found)

    def _expression_matches(
        self, expr: object, predicate, *, source_kind: str | None = None
    ) -> bool:
        found = False

        def visit(current) -> None:
            nonlocal found
            if found or current is None or isinstance(current, py_ast.leafTypes):
                return
            if source_kind is not None and self._expr_sanitizes_kind(
                current, source_kind
            ):
                return
            if not (
                source_kind is not None
                and self._expression_has_nested_sanitizer(current, source_kind)
            ) and predicate(current):
                found = True
                return
            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if isinstance(current, py_ast.Code):
                return
            current.visitChildren(visit)

        visit(expr)
        return found

    def _expression_has_nested_sanitizer(
        self, expr: object, source_kind: str
    ) -> bool:
        """Return whether a proper descendant sanitizes ``source_kind``.

        Composite IR nodes expose all locals read below them.  Treating such a
        node as tainted before visiting its children would therefore bypass a
        nested sanitizer, for example ``Wrapper(f"{escape_like(value)}")``.
        """
        found = False

        def visit(current) -> None:
            nonlocal found
            if found or current is None or isinstance(current, py_ast.leafTypes):
                return
            if self._expr_sanitizes_kind(current, source_kind):
                found = True
                return
            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if isinstance(current, py_ast.Code):
                return
            current.visitChildren(visit)

        if isinstance(expr, (list, tuple)):
            for child in expr:
                visit(child)
        elif not isinstance(expr, py_ast.Code) and not isinstance(
            expr, py_ast.leafTypes
        ):
            expr.visitChildren(visit)
        return found

    def _matching_locals_in_expression(
        self,
        procedure: cfg_graph.Code,
        expr: object,
        predicate,
        *,
        source_kind: str | None = None,
    ) -> frozenset[py_ast.Local]:
        found: set[py_ast.Local] = set()

        def visit(current) -> None:
            if current is None or isinstance(current, py_ast.leafTypes):
                return
            if source_kind is not None and self._expr_sanitizes_kind(
                current, source_kind
            ):
                return
            if isinstance(current, py_ast.Local):
                if current.name is not None and any(
                    predicate(location)
                    for location in self._locations_for_local(procedure, current)
                ):
                    found.add(current)
                return
            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if isinstance(current, py_ast.Code):
                return
            current.visitChildren(visit)

        visit(expr)
        return frozenset(found)


class InterproceduralTaintAnalysis:
    """Concrete taint analysis backed by the IFDS engine."""

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        configuration: TaintConfiguration,
        *,
        entry_nodes: Sequence[CFGNode] | None = None,
        record_traces: bool = False,
        solver_options: SolverOptions | None = None,
    ) -> None:
        self.problem = InterproceduralTaintProblem(
            adapter, configuration, entry_nodes=entry_nodes
        )
        self.record_traces = record_traces
        self.solver_options = solver_options

    def solve(self) -> TaintAnalysisResult:
        solver = (
            IFDSSolver(options=self.solver_options)
            if self.solver_options is not None
            else IFDSSolver(record_traces=self.record_traces)
        )
        result = solver.solve(self.problem)
        return TaintAnalysisResult(result, self.problem.findings(result), self.problem)


def analyze_taint(
    adapter: CFGSupergraphAdapter,
    configuration: TaintConfiguration,
    *,
    entry_nodes: Sequence[CFGNode] | None = None,
    record_traces: bool = False,
    solver_options: SolverOptions | None = None,
) -> TaintAnalysisResult:
    """Convenience entry point for interprocedural taint analysis."""
    return InterproceduralTaintAnalysis(
        adapter,
        configuration,
        entry_nodes=entry_nodes,
        record_traces=record_traces,
        solver_options=solver_options,
    ).solve()
