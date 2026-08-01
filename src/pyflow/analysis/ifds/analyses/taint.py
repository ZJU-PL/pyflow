"""Concrete interprocedural taint analysis over CFG-backed supergraphs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Mapping, Sequence

from pyflow.analysis.entrypoints import EntryPointOptions
from pyflow.analysis.taint import TaintRule
from pyflow.ir.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast

from ..modeling.calls import CallModelRegistry
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


@dataclass(frozen=True)
class TaintConfiguration:
    """Strict typed call models and rules for IFDS taint analysis."""

    call_models: CallModelRegistry = field(default_factory=CallModelRegistry)
    rules: tuple[TaintRule, ...] = ()
    collection_mutator_names: FrozenSet[str] = frozenset(
        {"append", "add", "extend", "update"}
    )
    collection_accessor_names: FrozenSet[str] = frozenset({"get"})
    conservative_unresolved_call_side_effects: bool = False
    entry_point_options: EntryPointOptions = EntryPointOptions()


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

        source_kinds = frozenset(
            kind for rule in self.configuration.rules for kind in rule.source_kinds
        )
        for node in self.entry_nodes:
            parameters = formal_parameters(node.procedure.code.codeparameters)
            for parameter in parameters:
                if parameter.name in {"self", "cls"}:
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
            return self._identity_outputs(fact, ())
        unresolved_call_outputs = self._unresolved_call_outputs(node, fact)
        if unresolved_call_outputs is not None:
            return unresolved_call_outputs

        effect = self.adapter.effect_of(node)
        operation = getattr(effect, "operation", self.adapter.operation_of(node))
        if operation is None:
            return self._identity_outputs(fact, ())

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
        if model is not None and (model.source_kinds or model.sanitizer_kinds):
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
        elif (
            model is not None
            and model.sanitizer_kinds
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
        return tuple(outputs)

    def _unresolved_call_outputs(self, node: CFGNode, fact: object):
        call_effect = self._call_effect(node)
        if (
            call_effect is None
            or call_effect.callees
            or not self.configuration.conservative_unresolved_call_side_effects
        ):
            return None

        outputs = set(
            self._identity_outputs(fact, self._killed_locations_for_node(node))
        )
        model = self._call_model_for_node(node)
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
            and isinstance(fact, (TaintFact, ExpressionTaintFact))
            and ("*" in model.sanitizer_kinds or fact.kind in model.sanitizer_kinds)
        ):
            return tuple(outputs)

        if not any(
            self._expr_is_tainted(node.procedure, actual, fact)
            for actual in call_effect.actual_arguments
        ):
            return tuple(outputs)

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
            if model is not None:
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
        return model is not None and (
            "*" in model.sanitizer_kinds or kind in model.sanitizer_kinds
        )

    def findings(self, result) -> tuple[TaintFinding, ...]:
        findings: list[TaintFinding] = []
        for node in self.adapter.supergraph.ordered_nodes():
            call_effect = self._call_effect(node)
            sink_name: str | None = None
            sink_expressions: tuple[object, ...] = ()
            model = None
            if call_effect is not None:
                sink_name = call_effect.call_name or "<sink>"
                sink_expressions = actual_argument_expressions(
                    call_effect.call_expression
                )
                model = self._call_model_for_node(node)
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
                        sink_name or "", model, len(sink_expressions)
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

    @staticmethod
    def _sink_positions_for_call(
        sink_name: str, model, argument_count: int
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
        return model.sink_arg_positions

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
            if not isinstance(current, py_ast.Local):
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
            if predicate(current):
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
