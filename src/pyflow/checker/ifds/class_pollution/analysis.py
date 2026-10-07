"""Dedicated relational IFDS analysis for Python class pollution.

This is not a taint configuration.  It defines its own facts, transfer
functions, source semantics, object-path transitions, correlation rules, and
findings.  Only the generic CFG/heap adapter and IFDS solver are reused.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import FrozenSet, Literal, Mapping, Sequence

from pyflow.analysis.entrypoints import EntryPointOptions
from pyflow.analysis.ifds.analyses.base import (
    AnnotatedFactProblemBase,
    build_entry_seeds,
)
from pyflow.analysis.ifds.core.problem import IFDSProblem
from pyflow.analysis.ifds.core.solver import IFDSSolver, SolverOptions
from pyflow.analysis.ifds.core.transfers import formal_parameters
from pyflow.analysis.ifds.frontend.cfg_adapter import (
    CFGNode,
    CFGSupergraphAdapter,
    assigned_locals,
)
from pyflow.ir.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast
from pyflow.language.python.ir_metadata import actual_argument_expressions

from .domain import (
    ExpressionPollutionFact,
    GADGET_PATH_COMPONENTS,
    KeyLanguage,
    MAGIC_PATH_COMPONENTS,
    ObjectPathStep,
    PollutionFact,
    PollutionOrigin,
    PollutionRole,
)


ZERO_CLASS_POLLUTION = "ZERO_CLASS_POLLUTION"
_INTERNAL_ORIGIN = PollutionOrigin("<internal>", "<internal>")
MutationKind = Literal["attribute", "item", "namespace"]
ProofLevel = Literal["pollutable-object", "gadget-reachable"]


@dataclass(frozen=True)
class ReflectiveOperationModel:
    name: str
    kind: Literal["get", "set", "namespace"]
    object_position: int
    key_position: int | None
    value_position: int | None = None
    mutation_kind: MutationKind = "attribute"


@dataclass(frozen=True)
class GetterSummary:
    name: str
    object_position: int
    key_position: int
    mutation_kind: Literal["attribute", "item"] = "attribute"


DEFAULT_OPERATIONS = (
    ReflectiveOperationModel("getattr", "get", 0, 1),
    ReflectiveOperationModel("builtins.getattr", "get", 0, 1),
    ReflectiveOperationModel("object.__getattribute__", "get", 0, 1),
    ReflectiveOperationModel("inspect.getattr_static", "get", 0, 1),
    ReflectiveOperationModel("getattr_static", "get", 0, 1),
    ReflectiveOperationModel("operator.getitem", "get", 0, 1, mutation_kind="item"),
    ReflectiveOperationModel("getitem", "get", 0, 1, mutation_kind="item"),
    ReflectiveOperationModel("interpreter_getattr", "get", 0, 1),
    ReflectiveOperationModel("interpreter_getitem", "get", 0, 1, mutation_kind="item"),
    ReflectiveOperationModel("setattr", "set", 0, 1, 2),
    ReflectiveOperationModel("builtins.setattr", "set", 0, 1, 2),
    ReflectiveOperationModel("object.__setattr__", "set", 0, 1, 2),
    ReflectiveOperationModel("type.__setattr__", "set", 0, 1, 2),
    ReflectiveOperationModel("operator.setitem", "set", 0, 1, 2, "item"),
    ReflectiveOperationModel("setitem", "set", 0, 1, 2, "item"),
    ReflectiveOperationModel("interpreter_setattr", "set", 0, 1, 2),
    ReflectiveOperationModel("interpreter_setitem", "set", 0, 1, 2, "item"),
    ReflectiveOperationModel("vars", "namespace", 0, None, mutation_kind="namespace"),
)


@dataclass(frozen=True)
class ClassPollutionConfiguration:
    source_names: FrozenSet[str] = frozenset({"input"})
    sanitizer_names: FrozenSet[str] = frozenset()
    key_allowlists: Mapping[str, FrozenSet[str]] = field(default_factory=dict)
    operations: tuple[ReflectiveOperationModel, ...] = DEFAULT_OPERATIONS
    namespace_update_names: FrozenSet[str] = frozenset(
        {"update", "dict.update", "collections.UserDict.update"}
    )
    bound_attribute_get_names: FrozenSet[str] = frozenset({"__getattribute__"})
    bound_item_get_names: FrozenSet[str] = frozenset({"get", "pop", "__getitem__"})
    bound_attribute_set_names: FrozenSet[str] = frozenset({"__setattr__"})
    bound_item_set_names: FrozenSet[str] = frozenset(
        {"__setitem__", "setdefault"}
    )
    preserving_call_names: FrozenSet[str] = frozenset(
        {
            "items",
            "keys",
            "values",
            "iter",
            "enumerate",
            "zip",
            "split",
            "rsplit",
            "partition",
            "rpartition",
            "strip",
        }
    )
    seed_entrypoint_parameters: bool = True
    infer_controlled_parameters: bool = True
    infer_root_parameters: bool = True
    preserve_unknown_call_results: bool = True
    summarize_recursive_paths: bool = True
    max_object_path: int = 4
    entry_point_options: EntryPointOptions = EntryPointOptions()

    def __post_init__(self) -> None:
        names = [model.name for model in self.operations]
        if len(names) != len(set(names)):
            raise ValueError("class-pollution operation names must be unique")
        if self.max_object_path < 1:
            raise ValueError("max_object_path must be positive")
        object.__setattr__(
            self,
            "key_allowlists",
            {name: frozenset(values) for name, values in self.key_allowlists.items()},
        )


@dataclass(frozen=True)
class ClassPollutionFinding:
    sink: CFGNode
    sink_name: str
    mutation_kind: MutationKind
    proof_level: ProofLevel
    key_origin: PollutionOrigin
    target_origin: PollutionOrigin
    key_language: KeyLanguage
    object_path: tuple[ObjectPathStep, ...]
    value_controlled: bool
    severity: str
    confidence: str
    cwe: str = "CWE-915"

    @property
    def dangerous_components(self) -> tuple[str, ...]:
        return tuple(
            step.static_name or step.key_language.describe()
            for step in self.object_path
            if step.may_reach_magic()
        )


class ClassPollutionAnalysisResult:
    def __init__(self, ifds_result, findings, problem) -> None:
        self._ifds_result = ifds_result
        self.findings = tuple(findings)
        self._problem = problem
        self.diagnostics = ()

    @property
    def statistics(self):
        return self._ifds_result.statistics

    @property
    def status(self):
        return self._ifds_result.status

    @property
    def termination_reason(self):
        return self._ifds_result.termination_reason

    @property
    def is_complete(self) -> bool:
        return self._ifds_result.is_complete

    def explain(self, finding: ClassPollutionFinding):
        for fact in self._ifds_result.facts_at(finding.sink):
            if (
                isinstance(fact, (PollutionFact, ExpressionPollutionFact))
                and fact.role is PollutionRole.TARGET_OBJECT
                and fact.origin == finding.target_origin
                and fact.object_path == finding.object_path
            ):
                return self._ifds_result.explain_path(finding.sink, fact)
        return ()


class ClassPollutionProblem(
    AnnotatedFactProblemBase[object],
    IFDSProblem[cfg_graph.Code, CFGNode, object],
):
    analysis_name = "class pollution"

    def __init__(self, adapter, configuration, *, entry_nodes) -> None:
        self.configuration = configuration
        self.entry_nodes = tuple(entry_nodes)
        self._operations = {model.name: model for model in configuration.operations}
        self._controlled_parameter_cache = {}
        self._root_parameter_cache = {}
        super().__init__(adapter)
        self._getter_summaries = self._discover_getter_summaries()

    @property
    def supergraph(self):
        return self.adapter.supergraph

    @property
    def zero_fact(self):
        return ZERO_CLASS_POLLUTION

    def _make_location_fact(self, location, template_fact=None):
        if not isinstance(template_fact, (PollutionFact, ExpressionPollutionFact)):
            template_fact = PollutionFact(
                location=location,
                origin=_INTERNAL_ORIGIN,
                role=PollutionRole.INPUT,
            )
        return PollutionFact(
            location=location,
            origin=template_fact.origin,
            role=template_fact.role,
            key_language=template_fact.key_language,
            object_path=template_fact.object_path,
            controller=template_fact.controller,
            access_path=template_fact.access_path,
            recursive_summary=template_fact.recursive_summary,
        )

    def _make_location_fact_with_path(self, location, access_path, template_fact=None):
        return replace(
            self._make_location_fact(location, template_fact),
            access_path=access_path,
        )

    def _make_expression_fact(
        self, procedure, expression, result_index=0, template_fact=None
    ):
        if not isinstance(template_fact, (PollutionFact, ExpressionPollutionFact)):
            raise ValueError("class-pollution facts require a typed template")
        return ExpressionPollutionFact(
            procedure=procedure,
            expression=expression,
            origin=template_fact.origin,
            role=template_fact.role,
            key_language=template_fact.key_language,
            object_path=template_fact.object_path,
            controller=template_fact.controller,
            result_index=result_index,
            access_path=template_fact.access_path,
            recursive_summary=template_fact.recursive_summary,
        )

    @staticmethod
    def _location_from_fact(fact):
        return fact.location if isinstance(fact, PollutionFact) else None

    @staticmethod
    def _expression_fact_result(fact):
        if isinstance(fact, ExpressionPollutionFact):
            return fact.procedure, fact.expression, fact.result_index
        return None

    @staticmethod
    def _local_names(expression) -> set[str]:
        names = set()

        def visit(current):
            if current is None or isinstance(current, py_ast.leafTypes):
                return
            if isinstance(current, py_ast.Code):
                return
            if isinstance(current, py_ast.Local):
                if current.name:
                    names.add(current.name)
                return
            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if hasattr(current, "visitChildren"):
                current.visitChildren(visit)

        visit(expression)
        return names

    def _getter_object_expression(self, node):
        effect = self._call_effect(node)
        if effect is None:
            return None
        higher_order = self._higher_order_getter(effect.call_expression)
        if higher_order is not None:
            return higher_order[0]
        summary = self._summary_getter(effect)
        if summary is not None:
            return summary[0]
        model = self._operation_model(effect.call_name)
        actuals = actual_argument_expressions(effect.call_expression)
        leaf_name = (effect.call_name or "").rsplit(".", 1)[-1]
        receiver = self._call_receiver(effect.call_expression)
        if receiver is not None and (
            (
                leaf_name in self.configuration.bound_attribute_get_names
                and len(actuals) == 1
            )
            or (
                leaf_name in self.configuration.bound_item_get_names
                and 1 <= len(actuals) <= 2
            )
        ):
            return receiver
        if model is not None and model.kind in {"get", "namespace"}:
            if model.object_position < len(actuals):
                return actuals[model.object_position]
            return None
        if (
            effect.call_name
            and effect.call_name.rsplit(".", 1)[-1] == "get"
        ):
            return self._call_receiver(effect.call_expression)
        return None

    def _call_leaf_name(self, expression):
        if isinstance(expression, py_ast.Local):
            return expression.name
        if isinstance(expression, py_ast.Existing):
            return self._constant_string(expression)
        if isinstance(expression, py_ast.GetAttr):
            return self._constant_string(expression.name)
        return None

    def _higher_order_getter(self, call_expression):
        """Recognize access combinators that return or fold getter operations."""

        if not isinstance(call_expression, py_ast.Call):
            return None
        outer_actuals = actual_argument_expressions(call_expression)
        if isinstance(call_expression.expr, py_ast.Call):
            builder = call_expression.expr
            name = self._call_leaf_name(builder.expr)
            builder_actuals = actual_argument_expressions(builder)
            if name in {"attrgetter", "itemgetter"} and builder_actuals and outer_actuals:
                return (
                    outer_actuals[0],
                    builder_actuals[0],
                    "attribute" if name == "attrgetter" else "item",
                )
        name = self._call_leaf_name(call_expression.expr)
        if name == "reduce" and len(outer_actuals) >= 2:
            reducer_name = self._call_leaf_name(outer_actuals[0])
            mutation_kind = "item" if reducer_name == "getitem" else "attribute"
            iterable = outer_actuals[1]
            if (
                isinstance(iterable, py_ast.Call)
                and self._call_leaf_name(iterable.expr) == "interpreter__add__"
            ):
                parts = actual_argument_expressions(iterable)
                if (
                    len(parts) == 2
                    and isinstance(parts[0], py_ast.BuildList)
                    and parts[0].args
                ):
                    return parts[0].args[0], parts[1], mutation_kind
            # Conservative fallback for non-canonical reduce-based getters.
            return outer_actuals[1], outer_actuals[1], mutation_kind
        return None

    def _discover_getter_summaries(self):
        summaries = {}
        for procedure in self.supergraph.ordered_procedures():
            formals = formal_parameters(procedure.code.codeparameters)
            positions = {
                formal.name: index
                for index, formal in enumerate(formals)
                if formal.name
            }
            for node in self.supergraph.ordered_nodes_of(procedure):
                operation = self.adapter.operation_of(node)
                if not isinstance(operation, py_ast.Return):
                    continue
                for expression in operation.exprs:
                    access = self._higher_order_getter(expression)
                    if access is None:
                        continue
                    object_names = self._local_names(access[0]).intersection(positions)
                    key_names = self._local_names(access[1]).intersection(positions)
                    if len(object_names) != 1 or len(key_names) != 1:
                        continue
                    object_name = next(iter(object_names))
                    key_name = next(iter(key_names))
                    summaries[procedure.code.codeName()] = GetterSummary(
                        procedure.code.codeName(),
                        positions[object_name],
                        positions[key_name],
                        access[2],
                    )
        return summaries

    def _summary_getter(self, effect):
        if not effect.call_name:
            return None
        summary = self._getter_summaries.get(effect.call_name.rsplit(".", 1)[-1])
        if summary is None:
            return None
        actuals = actual_argument_expressions(effect.call_expression)
        if max(summary.object_position, summary.key_position) >= len(actuals):
            return None
        return (
            actuals[summary.object_position],
            actuals[summary.key_position],
            summary.mutation_kind,
        )

    def _eval_root_parameter_names(self, procedure):
        eval_key_names = set()
        assignments = []
        for node in self.supergraph.ordered_nodes_of(procedure):
            effect = self._call_effect(node)
            if effect is not None and effect.call_name in {"eval", "builtins.eval"}:
                actuals = actual_argument_expressions(effect.call_expression)
                if actuals:
                    eval_key_names.update(self._local_names(actuals[0]))
            operation = self.adapter.operation_of(node)
            if isinstance(operation, (py_ast.Assign, py_ast.AnnAssign)):
                expression = (
                    operation.value
                    if isinstance(operation, py_ast.AnnAssign)
                    else operation.expr
                )
                targets = {
                    local.name for local in assigned_locals(operation) if local.name
                }
                assignments.append((targets, expression))
        roots = set()
        for targets, expression in assignments:
            if not targets.intersection(eval_key_names):
                continue
            literal = self._constant_string(expression)
            if literal:
                root = literal.split(".", 1)[0]
                if root.isidentifier():
                    roots.add(root)
        return roots

    def _root_parameter_names(self, procedure):
        cached = self._root_parameter_cache.get(procedure)
        if cached is not None:
            return cached
        formals = formal_parameters(procedure.code.codeparameters)
        if not self.configuration.infer_root_parameters:
            result = frozenset(formal.name for formal in formals if formal.name)
            self._root_parameter_cache[procedure] = result
            return result

        candidates = set()
        assignments = []
        for node in self.supergraph.ordered_nodes_of(procedure):
            getter_object = self._getter_object_expression(node)
            if getter_object is not None:
                candidates.update(self._local_names(getter_object))
            site = self._write_site(node)
            if site is not None:
                candidates.update(self._local_names(site[2]))
            operation = self.adapter.operation_of(node)
            if isinstance(
                operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)
            ):
                expression = (
                    operation.value
                    if isinstance(operation, py_ast.AnnAssign)
                    else operation.expr
                )
                targets = {
                    local.name for local in assigned_locals(operation) if local.name
                }
                assignments.append((targets, self._local_names(expression)))

        changed = True
        while changed:
            changed = False
            for targets, sources in assignments:
                if candidates.intersection(targets) and not sources.issubset(candidates):
                    candidates.update(sources)
                    changed = True
        candidates.update(self._eval_root_parameter_names(procedure))
        result = frozenset(
            formal.name for formal in formals if formal.name in candidates
        )
        self._root_parameter_cache[procedure] = result
        return result

    def _controlled_parameter_names(self, procedure):
        cached = self._controlled_parameter_cache.get(procedure)
        if cached is not None:
            return cached
        formals = formal_parameters(procedure.code.codeparameters)
        if not self.configuration.infer_controlled_parameters:
            result = frozenset(formal.name for formal in formals if formal.name)
            self._controlled_parameter_cache[procedure] = result
            return result

        candidates = set()
        assignments = []
        iterations = []
        for node in self.supergraph.ordered_nodes_of(procedure):
            site = self._write_site(node)
            if site is not None:
                candidates.update(self._local_names(site[3]))
                if site[4] is not None:
                    candidates.update(self._local_names(site[4]))
            effect = self._call_effect(node)
            if effect is not None:
                higher_order = self._higher_order_getter(effect.call_expression)
                summary = self._summary_getter(effect)
                model = self._operation_model(effect.call_name)
                actuals = actual_argument_expressions(effect.call_expression)
                leaf_name = (effect.call_name or "").rsplit(".", 1)[-1]
                receiver = self._call_receiver(effect.call_expression)
                if higher_order is not None:
                    candidates.update(self._local_names(higher_order[1]))
                elif summary is not None:
                    candidates.update(self._local_names(summary[1]))
                elif effect.call_name in {"eval", "builtins.eval"} and actuals:
                    candidates.update(self._local_names(actuals[0]))
                elif receiver is not None and actuals and (
                    (
                        leaf_name in self.configuration.bound_attribute_get_names
                        and len(actuals) == 1
                    )
                    or (
                        leaf_name in self.configuration.bound_item_get_names
                        and len(actuals) <= 2
                    )
                ):
                    candidates.update(self._local_names(actuals[0]))
                elif (
                    model is not None
                    and model.kind == "get"
                    and model.key_position is not None
                    and model.key_position < len(actuals)
                ):
                    candidates.update(
                        self._local_names(actuals[model.key_position])
                    )
                elif (
                    model is None
                    and effect.call_name
                    and effect.call_name.rsplit(".", 1)[-1] == "get"
                    and actuals
                ):
                    candidates.update(self._local_names(actuals[0]))
            operation = self.adapter.operation_of(node)
            if isinstance(
                operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)
            ):
                expression = (
                    operation.value
                    if isinstance(operation, py_ast.AnnAssign)
                    else operation.expr
                )
                targets = {
                    local.name for local in assigned_locals(operation) if local.name
                }
                assignments.append((targets, self._local_names(expression)))
            if node.kind == "foriter" and isinstance(node.block, cfg_graph.ForIter):
                iterations.append(
                    (
                        self._local_names(node.block.index),
                        self._local_names(node.block.iterator),
                    )
                )

        changed = True
        while changed:
            changed = False
            for targets, sources in (*assignments, *iterations):
                if candidates.intersection(targets) and not sources.issubset(candidates):
                    candidates.update(sources)
                    changed = True
        result = frozenset(
            formal.name for formal in formals if formal.name in candidates
        )
        self._controlled_parameter_cache[procedure] = result
        return result

    def initial_seeds(self):
        seeds = {
            node: set(facts)
            for node, facts in build_entry_seeds(
                self.entry_nodes, ZERO_CLASS_POLLUTION
            ).items()
        }
        if not self.configuration.seed_entrypoint_parameters:
            return {node: frozenset(facts) for node, facts in seeds.items()}
        for entry in self.entry_nodes:
            parameters = formal_parameters(entry.procedure.code.codeparameters)
            controlled_parameters = self._controlled_parameter_names(entry.procedure)
            root_parameters = self._root_parameter_names(entry.procedure)
            for index, parameter in enumerate(parameters):
                origin = PollutionOrigin(
                    entry.procedure, parameter.name or "<parameter>", index
                )
                for location in self._locations_for_local(entry.procedure, parameter):
                    if parameter.name in controlled_parameters:
                        seeds[entry].add(
                            PollutionFact(location, origin, PollutionRole.INPUT)
                        )
                    if parameter.name in root_parameters:
                        seeds[entry].add(
                            PollutionFact(
                                location, origin, PollutionRole.ROOT_OBJECT
                            )
                        )
        return {node: frozenset(facts) for node, facts in seeds.items()}

    @staticmethod
    def _identity(fact, killed=()):
        if fact == ZERO_CLASS_POLLUTION:
            return (fact,)
        if isinstance(fact, PollutionFact) and fact.location in killed:
            return ()
        return (fact,)

    def _same_storage(self, left, right) -> bool:
        if isinstance(left, PollutionFact) and isinstance(right, PollutionFact):
            return self._fact_prefix_matches(left, right) or self._fact_prefix_matches(
                right, left
            )
        if isinstance(left, ExpressionPollutionFact) and isinstance(
            right, ExpressionPollutionFact
        ):
            return (
                left.procedure is right.procedure
                and left.expression is right.expression
                and left.result_index == right.result_index
            )
        return False

    def _expr_has_fact(self, procedure, expression, fact) -> bool:
        if not isinstance(fact, (PollutionFact, ExpressionPollutionFact)):
            return False
        return any(
            self._same_storage(fact, candidate)
            for candidate in self._facts_for_expression_node(
                procedure,
                expression,
                extend_paths=True,
                template_fact=fact,
            )
        )

    def _semantic_expr_has_fact(self, procedure, expression, fact) -> bool:
        if self._expr_has_fact(procedure, expression, fact):
            return True
        if isinstance(expression, py_ast.ConditionalExpr):
            return self._semantic_expr_has_fact(
                procedure, expression.body, fact
            ) or self._semantic_expr_has_fact(procedure, expression.orelse, fact)
        if isinstance(expression, py_ast.NamedExpr):
            return self._semantic_expr_has_fact(procedure, expression.value, fact)
        return False

    def _operation_model(self, call_name):
        if not call_name:
            return None
        exact = self._operations.get(call_name)
        if exact is not None:
            return exact
        candidates = [
            model
            for name, model in self._operations.items()
            if call_name.endswith(f".{name}")
            or call_name.rsplit(".", 1)[-1] == name.rsplit(".", 1)[-1]
        ]
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            first = candidates[0]
            signature = (
                first.kind,
                first.object_position,
                first.key_position,
                first.value_position,
                first.mutation_kind,
            )
            if all(
                (
                    item.kind,
                    item.object_position,
                    item.key_position,
                    item.value_position,
                    item.mutation_kind,
                )
                == signature
                for item in candidates[1:]
            ):
                return first
        return None

    def _call_result_facts(self, node, template):
        effect = self._call_effect(node)
        if effect is None:
            return set()
        return self._facts_for_nested_call_result(
            node.procedure,
            effect.operation,
            effect.call_expression,
            0,
            nested=False,
            template_fact=template,
        )

    def _extend_object_path(self, fact, step):
        path = fact.object_path
        if (
            self.configuration.summarize_recursive_paths
            and step.static_name is None
            and step.key_language == KeyLanguage.top()
            and any(
                candidate.kind == step.kind
                and candidate.static_name is None
                and candidate.key_language == KeyLanguage.top()
                for candidate in path
            )
        ):
            # A repeated unknown access of the same kind is a regular-language
            # cycle, not a new proof obligation.  Keeping one representative
            # prevents CFG loops from enumerating paths such as item^1..item^N.
            return path
        if fact.recursive_summary:
            return self._canonical_recursive_path((*path, step))
        if len(path) < self.configuration.max_object_path:
            return (*path, step)
        widened = ObjectPathStep(step.kind, KeyLanguage.top())
        if path[-1] == widened:
            return path
        return (*path[: self.configuration.max_object_path - 1], widened)

    @staticmethod
    def _canonical_recursive_path(path):
        """Keep recursive traversal evidence finite without losing magic steps.

        Once a fact has crossed a summarized recursive call, additional
        dynamic attribute/item reads denote further iterations of the same
        unknown traversal language.  Retaining every attribute/item ordering
        creates exponentially many equivalent paths.  One dynamic wildcard
        plus the distinct magic components is sufficient for pollution and
        gadget-reachability proofs.
        """

        canonical = []
        dynamic_seen = False
        magic_seen = set()
        for candidate in path:
            if candidate.static_name in MAGIC_PATH_COMPONENTS:
                identity = (candidate.kind, candidate.static_name)
                if identity not in magic_seen:
                    canonical.append(candidate)
                    magic_seen.add(identity)
                continue
            if candidate.static_name is None and not dynamic_seen:
                canonical.append(
                    ObjectPathStep(candidate.kind, KeyLanguage.top())
                )
                dynamic_seen = True
        return tuple(canonical)

    def _static_access_template(self, procedure, expression, fact):
        """Refine an object fact with static access syntax around its base.

        Heap matching deliberately answers whether a fact may denote an entire
        expression.  Class-pollution reasoning additionally needs to retain the
        semantic path used to obtain that expression, especially for patterns
        such as ``obj.__dict__.get(key)``.
        """

        if fact.role not in {PollutionRole.ROOT_OBJECT, PollutionRole.TARGET_OBJECT}:
            return fact
        if isinstance(expression, py_ast.GetAttr) and self._expr_has_fact(
            procedure, expression.expr, fact
        ):
            name = self._constant_string(expression.name)
            if name is not None:
                return replace(
                    fact,
                    role=PollutionRole.TARGET_OBJECT,
                    object_path=self._extend_object_path(
                        fact,
                        ObjectPathStep(
                            "attribute", KeyLanguage.finite({name}), name
                        ),
                    ),
                    access_path=(),
                )
        if isinstance(expression, py_ast.GetSubscript) and self._expr_has_fact(
            procedure, expression.expr, fact
        ):
            name = self._constant_string(expression.subscript)
            language = KeyLanguage.finite({name}) if name is not None else KeyLanguage.top()
            return replace(
                fact,
                role=PollutionRole.TARGET_OBJECT,
                object_path=self._extend_object_path(
                    fact, ObjectPathStep("item", language, name)
                ),
                access_path=(),
            )
        return fact

    def _source_outputs(self, node):
        effect = self._call_effect(node)
        if effect is None or effect.call_name not in self.configuration.source_names:
            return set()
        origin = PollutionOrigin(
            node.procedure, effect.call_name or "<source>", node.call_index or 0
        )
        template = PollutionFact(object(), origin, PollutionRole.INPUT)
        return self._call_result_facts(node, template)

    def _getter_outputs(self, node, fact):
        effect = self._call_effect(node)
        if effect is None:
            return set()
        higher_order = self._higher_order_getter(effect.call_expression)
        summary = self._summary_getter(effect)
        model = self._operation_model(effect.call_name)
        leaf_name = (effect.call_name or "").rsplit(".", 1)[-1]
        receiver = self._call_receiver(effect.call_expression)
        bound_attribute_get = (
            receiver is not None
            and leaf_name in self.configuration.bound_attribute_get_names
            and len(actual_argument_expressions(effect.call_expression)) == 1
        )
        bound_item_get = (
            receiver is not None
            and leaf_name in self.configuration.bound_item_get_names
            and 1
            <= len(actual_argument_expressions(effect.call_expression))
            <= 2
        )
        method_get = bound_attribute_get or bound_item_get
        eval_get = effect.call_name in {"eval", "builtins.eval"}
        if (
            model is None
            and not method_get
            and higher_order is None
            and summary is None
            and not eval_get
        ) or (
            model is not None and model.kind not in {"get", "namespace"}
        ):
            return set()
        actuals = actual_argument_expressions(effect.call_expression)
        if higher_order is not None:
            object_expr, key_expr, mutation_kind = higher_order
        elif summary is not None:
            object_expr, key_expr, mutation_kind = summary
        elif eval_get:
            object_expr = None
            key_expr = actuals[0] if actuals else None
            mutation_kind = "attribute"
        elif method_get:
            object_expr = receiver
            if object_expr is None or not actuals:
                return set()
            key_expr = actuals[0]
            mutation_kind = "attribute" if bound_attribute_get else "item"
        else:
            assert model is not None
            if model.object_position >= len(actuals):
                return set()
            object_expr = actuals[model.object_position]
            key_expr = (
                actuals[model.key_position]
                if model.key_position is not None
                and model.key_position < len(actuals)
                else None
            )
            mutation_kind = model.mutation_kind

        if model is not None and model.kind == "namespace":
            if fact.role not in {PollutionRole.ROOT_OBJECT, PollutionRole.TARGET_OBJECT}:
                return set()
            if not self._expr_has_fact(node.procedure, actuals[model.object_position], fact):
                return set()
            step = ObjectPathStep(
                "attribute", KeyLanguage.finite({"__dict__"}), "__dict__"
            )
            target = replace(
                fact,
                role=PollutionRole.TARGET_OBJECT,
                object_path=self._extend_object_path(fact, step),
            )
            return self._call_result_facts(node, target)

        if key_expr is None:
            return set()
        outputs = set()

        if eval_get:
            if fact.role is PollutionRole.INPUT and self._expr_has_fact(
                node.procedure, key_expr, fact
            ):
                outputs.update(self._call_result_facts(node, fact))
            if fact.role in {
                PollutionRole.ROOT_OBJECT,
                PollutionRole.TARGET_OBJECT,
            }:
                step = ObjectPathStep("attribute", KeyLanguage.top())
                target = replace(
                    fact,
                    role=PollutionRole.TARGET_OBJECT,
                    object_path=self._extend_object_path(fact, step),
                    access_path=(),
                )
                outputs.update(self._call_result_facts(node, target))
            return outputs

        # Reading from attacker-controlled structured input yields another
        # controlled value.  It does not by itself prove that the result is a
        # pollutable object.  This distinction is essential for recursive
        # ``for key, value in source.items()`` merge functions.
        if fact.role is PollutionRole.INPUT and self._expr_has_fact(
            node.procedure, object_expr, fact
        ):
            outputs.update(self._call_result_facts(node, fact))

        if fact.role in {
            PollutionRole.ROOT_OBJECT,
            PollutionRole.TARGET_OBJECT,
        } and self._expr_has_fact(node.procedure, object_expr, fact):
            base = self._static_access_template(node.procedure, object_expr, fact)
            literal = self._constant_string(key_expr)
            if (
                base.role is PollutionRole.TARGET_OBJECT
                and literal is not None
                and literal not in MAGIC_PATH_COMPONENTS
            ):
                return outputs
            language = (
                KeyLanguage.finite({literal})
                if literal is not None
                else KeyLanguage.top()
            )
            step = ObjectPathStep(mutation_kind, language, literal)
            target = replace(
                base,
                role=PollutionRole.TARGET_OBJECT,
                object_path=self._extend_object_path(base, step),
                access_path=(),
            )
            outputs.update(self._call_result_facts(node, target))
        return outputs

    def _sanitizer_outputs(self, node, fact):
        effect = self._call_effect(node)
        if effect is None or fact.role is not PollutionRole.INPUT:
            return None
        call_name = effect.call_name
        if (
            call_name not in self.configuration.sanitizer_names
            and call_name not in self.configuration.key_allowlists
        ):
            return None
        if not any(
            self._expr_has_fact(node.procedure, actual, fact)
            for actual in actual_argument_expressions(effect.call_expression)
        ):
            return set()
        if call_name in self.configuration.key_allowlists:
            allowed = self.configuration.key_allowlists[call_name]
            transformed = replace(fact, key_language=KeyLanguage.finite(allowed))
            return self._call_result_facts(node, transformed)
        return set()

    def _unknown_call_outputs(self, node, fact):
        effect = self._call_effect(node)
        if (
            effect is None
            or effect.callees
            or not self.configuration.preserve_unknown_call_results
            or not isinstance(fact, (PollutionFact, ExpressionPollutionFact))
        ):
            return set()
        call_name = effect.call_name or ""
        if (
            call_name not in self.configuration.preserving_call_names
            and call_name.rsplit(".", 1)[-1]
            not in self.configuration.preserving_call_names
        ):
            return set()
        inputs = list(actual_argument_expressions(effect.call_expression))
        receiver = self._call_receiver(effect.call_expression)
        if receiver is not None:
            inputs.append(receiver)
        if not any(
            self._expr_has_fact(node.procedure, expression, fact)
            for expression in inputs
        ):
            return set()
        return self._call_result_facts(node, fact)

    def _recursive_call_outputs(self, node, fact):
        """Apply a bounded self-recursion summary when the call graph misses it.

        Python frontends commonly fail to resolve a function's reference to
        itself while its defining scope is still being constructed.  Recursive
        merge helpers are central to class pollution, so dropping that edge is
        not acceptable.  Mapping actuals back to the current procedure's formal
        heap locations lets the surrounding loop compute the same monotone
        fixpoint, with object-path widening providing the bound.
        """

        effect = self._call_effect(node)
        if (
            effect is None
            or effect.callees
            or not effect.call_name
            or not isinstance(fact, (PollutionFact, ExpressionPollutionFact))
        ):
            return set()
        procedure_name = node.procedure.code.codeName()
        if effect.call_name.rsplit(".", 1)[-1] != procedure_name:
            return set()
        actuals = actual_argument_expressions(effect.call_expression)
        formals = formal_parameters(node.procedure.code.codeparameters)
        outputs = set()
        for actual, formal in zip(actuals, formals):
            if self._expr_has_fact(node.procedure, actual, fact):
                template = fact
                if (
                    self.configuration.summarize_recursive_paths
                    and fact.role is PollutionRole.TARGET_OBJECT
                    and fact.object_path
                ):
                    template = replace(
                        fact,
                        object_path=self._canonical_recursive_path(
                            fact.object_path
                        ),
                        recursive_summary=True,
                    )
                outputs.update(
                    self._facts_for_locals(node.procedure, (formal,), template)
                )
        return outputs

    def _synthetic_getter_updates(self, node, fact):
        """Summarize walrus-based getter updates hidden in comprehensions."""

        effect = self._call_effect(node)
        call = effect.call_expression if effect is not None else None
        if (
            not isinstance(call, py_ast.DirectCall)
            or call.code is None
            or not isinstance(fact, (PollutionFact, ExpressionPollutionFact))
            or fact.role
            not in {PollutionRole.ROOT_OBJECT, PollutionRole.TARGET_OBJECT}
        ):
            return set()
        ast_root = getattr(call.code, "ast", None)
        if ast_root is None:
            return set()
        updates = []

        def visit(current):
            if current is None or isinstance(current, py_ast.leafTypes):
                return
            if isinstance(current, py_ast.Code):
                return
            if isinstance(current, py_ast.NamedExpr) and isinstance(
                current.value, py_ast.Call
            ):
                nested = current.value
                name = self._call_leaf_name(nested.expr)
                actuals = actual_argument_expressions(nested)
                model = self._operation_model(name)
                if (
                    model is not None
                    and model.kind == "get"
                    and model.key_position is not None
                    and max(model.object_position, model.key_position) < len(actuals)
                ):
                    updates.append(
                        (
                            current.target,
                            actuals[model.object_position],
                            actuals[model.key_position],
                            model.mutation_kind,
                        )
                    )
            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if hasattr(current, "visitChildren"):
                current.visitChildren(visit)

        visit(ast_root)
        outputs = set()
        for target, object_expr, key_expr, mutation_kind in updates:
            if not self._expr_has_fact(node.procedure, object_expr, fact):
                continue
            literal = self._constant_string(key_expr)
            language = (
                KeyLanguage.finite({literal})
                if literal is not None
                else KeyLanguage.top()
            )
            target_fact = replace(
                fact,
                role=PollutionRole.TARGET_OBJECT,
                object_path=self._extend_object_path(
                    fact, ObjectPathStep(mutation_kind, language, literal)
                ),
                access_path=(),
            )
            outputs.update(
                self._facts_for_locals(node.procedure, (target,), target_fact)
            )
        return outputs

    def _guard_refined_fact(self, node, successor, fact):
        if not isinstance(fact, (PollutionFact, ExpressionPollutionFact)):
            return fact
        if fact.role is not PollutionRole.INPUT:
            return fact
        guard = self._guard_effect(node)
        if guard is None or successor not in {
            *guard.true_successors,
            *guard.false_successors,
        }:
            return fact
        condition = guard.condition
        negated = False
        if isinstance(condition, py_ast.Not):
            condition = condition.expr
            negated = True
        elif isinstance(condition, py_ast.Call) and self._call_leaf_name(
            condition.expr
        ) == "interpreter__not__":
            actuals = actual_argument_expressions(condition)
            if actuals and isinstance(actuals[0], py_ast.Call):
                condition = actuals[0]
                negated = True
        true_branch = successor in guard.true_successors
        predicate_holds = not true_branch if negated else true_branch
        if isinstance(condition, py_ast.Call) and self._call_leaf_name(
            condition.expr
        ) == "interpreter__contains__":
            actuals = actual_argument_expressions(condition)
            if len(actuals) >= 2 and self._expr_has_fact(
                node.procedure, actuals[1], fact
            ):
                values = self._constant_string_collection(actuals[0])
                if predicate_holds and values is not None:
                    return replace(fact, key_language=KeyLanguage.finite(values))
            return fact
        if not isinstance(condition, py_ast.Call) or not isinstance(
            condition.expr, py_ast.GetAttr
        ):
            return fact
        method = self._constant_string(condition.expr.name)
        if method not in {"startswith", "endswith"}:
            return fact
        actuals = actual_argument_expressions(condition)
        if not actuals or self._constant_string(actuals[0]) != "__":
            return fact
        if not self._expr_has_fact(node.procedure, condition.expr.expr, fact):
            return fact
        if predicate_holds:
            return fact
        return replace(fact, key_language=KeyLanguage.safe())

    def _constant_string_collection(self, expression):
        if isinstance(expression, py_ast.Existing):
            value = getattr(expression.object, "pyobj", None)
            if isinstance(value, (set, frozenset, tuple, list)) and all(
                isinstance(item, str) for item in value
            ):
                return frozenset(value)
            return None
        if isinstance(expression, (py_ast.BuildSet, py_ast.BuildTuple, py_ast.BuildList)):
            values = []
            for item in expression.args:
                value = self._constant_string(item)
                if value is None:
                    return None
                values.append(value)
            return frozenset(values)
        return None

    def normal_flow(self, node, successor, fact):
        fact = self._guard_refined_fact(node, successor, fact)
        if node.kind == "call":
            outputs = set(self._identity(fact, self._killed_locations_for_node(node)))
            if fact == ZERO_CLASS_POLLUTION:
                outputs.update(self._source_outputs(node))
                return tuple(outputs)
            sanitized = self._sanitizer_outputs(node, fact)
            if sanitized is not None:
                outputs.update(sanitized)
                return tuple(outputs)
            outputs.update(self._getter_outputs(node, fact))
            outputs.update(self._unknown_call_outputs(node, fact))
            outputs.update(self._recursive_call_outputs(node, fact))
            outputs.update(self._synthetic_getter_updates(node, fact))
            return tuple(outputs)

        operation = self.adapter.operation_of(node)
        if operation is None:
            return self._identity(fact)
        if node.kind == "foriter" and isinstance(node.block, cfg_graph.ForIter):
            outputs = set(self._identity(fact))
            if isinstance(fact, (PollutionFact, ExpressionPollutionFact)) and self._expr_has_fact(
                node.procedure, node.block.iterator, fact
            ):
                outputs.update(
                    self._facts_for_locals(node.procedure, (node.block.index,), fact)
                )
            return tuple(outputs)

        killed = self._killed_locations_for_node(node)
        if isinstance(
            operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)
        ):
            outputs = set(self._identity(fact, killed))
            expr = (
                operation.value
                if isinstance(operation, py_ast.AnnAssign)
                else operation.expr
            )
            targets = assigned_locals(operation)
            self._update_aliases_for_assignment(node.procedure, targets, expr)
            if isinstance(
                fact, (PollutionFact, ExpressionPollutionFact)
            ) and self._semantic_expr_has_fact(node.procedure, expr, fact):
                template = fact
                if isinstance(expr, py_ast.GetSubscript):
                    if fact.role is PollutionRole.INPUT and self._expr_has_fact(
                        node.procedure, expr.expr, fact
                    ):
                        template = fact
                    elif fact.role in {
                        PollutionRole.ROOT_OBJECT,
                        PollutionRole.TARGET_OBJECT,
                    } and self._expr_has_fact(node.procedure, expr.expr, fact):
                        literal = self._constant_string(expr.subscript)
                        if (
                            fact.role is PollutionRole.TARGET_OBJECT
                            and literal is not None
                            and literal not in MAGIC_PATH_COMPONENTS
                        ):
                            return tuple(outputs)
                        language = (
                            KeyLanguage.finite({literal})
                            if literal is not None
                            else KeyLanguage.top()
                        )
                        template = replace(
                            fact,
                            role=PollutionRole.TARGET_OBJECT,
                            object_path=self._extend_object_path(
                                fact, ObjectPathStep("item", language, literal)
                            ),
                            access_path=(),
                        )
                if fact.role in {
                    PollutionRole.ROOT_OBJECT,
                    PollutionRole.TARGET_OBJECT,
                } and isinstance(expr, py_ast.GetAttr):
                    name = self._constant_string(expr.name)
                    if name is not None:
                        step = ObjectPathStep(
                            "attribute", KeyLanguage.finite({name}), name
                        )
                        template = replace(
                            fact,
                            role=PollutionRole.TARGET_OBJECT,
                            object_path=self._extend_object_path(fact, step),
                            access_path=(),
                        )
                outputs.update(
                    self._facts_for_locals(node.procedure, targets, template)
                )
            return tuple(outputs)

        if isinstance(operation, py_ast.Return):
            outputs = set(self._identity(fact))
            if isinstance(fact, (PollutionFact, ExpressionPollutionFact)):
                for index, expression in enumerate(operation.exprs):
                    if self._semantic_expr_has_fact(
                        node.procedure, expression, fact
                    ):
                        outputs.update(
                            self._facts_for_return_location(
                                node.procedure, index, template_fact=fact
                            )
                        )
            return tuple(outputs)
        return self._identity(fact, killed)

    def call_flow(self, call_node, callee, fact):
        outputs = {ZERO_CLASS_POLLUTION} if fact == ZERO_CLASS_POLLUTION else set()
        if not isinstance(fact, (PollutionFact, ExpressionPollutionFact)):
            return tuple(outputs)
        effect = self._call_effect(call_node)
        if effect is None or self._operation_model(effect.call_name) is not None:
            return tuple(outputs)
        if effect.call_name in self.configuration.source_names:
            return tuple(outputs)
        self._bind_callee_formals(call_node, callee)
        for actual, formal in self._bind_call_arguments_for_callee(call_node, callee):
            if self._expr_has_fact(call_node.procedure, actual, fact):
                outputs.update(self._facts_for_locals(callee, (formal,), fact))
        return tuple(outputs)

    def return_flow(
        self, call_node, callee, exit_node, return_site, call_fact, exit_fact
    ):
        del exit_node, return_site
        outputs = set()
        if call_fact == ZERO_CLASS_POLLUTION and exit_fact == ZERO_CLASS_POLLUTION:
            outputs.add(ZERO_CLASS_POLLUTION)
        if not isinstance(exit_fact, (PollutionFact, ExpressionPollutionFact)):
            return tuple(outputs)
        returnparams = tuple(callee.code.codeparameters.returnparams)
        for index, parameter in enumerate(returnparams):
            if any(
                isinstance(exit_fact, PollutionFact)
                and exit_fact.location == location
                for location in self._locations_for_local(callee, parameter)
            ):
                effect = self._call_effect(call_node)
                if effect is not None:
                    outputs.update(
                        self._facts_for_nested_call_result(
                            call_node.procedure,
                            effect.operation,
                            effect.call_expression,
                            index,
                            nested=False,
                            template_fact=exit_fact,
                        )
                    )
        return tuple(outputs)

    def call_to_return_flow(self, call_node, return_site, fact):
        del return_site
        outputs = set(self._identity(fact, self._killed_locations_for_node(call_node)))
        if fact == ZERO_CLASS_POLLUTION:
            outputs.update(self._source_outputs(call_node))
            return tuple(outputs)
        if not isinstance(fact, (PollutionFact, ExpressionPollutionFact)):
            return tuple(outputs)
        sanitized = self._sanitizer_outputs(call_node, fact)
        if sanitized is not None:
            outputs.update(sanitized)
            return tuple(outputs)
        outputs.update(self._getter_outputs(call_node, fact))
        outputs.update(self._unknown_call_outputs(call_node, fact))
        outputs.update(self._recursive_call_outputs(call_node, fact))
        outputs.update(self._synthetic_getter_updates(call_node, fact))
        return tuple(outputs)

    def _facts_matching(self, node, expression, facts, roles):
        return tuple(
            fact
            for fact in facts
            if isinstance(fact, (PollutionFact, ExpressionPollutionFact))
            and fact.role in roles
            and self._expr_has_fact(node.procedure, expression, fact)
        )

    def _call_write_site(self, node):
        effect = self._call_effect(node)
        if effect is None:
            return None
        model = self._operation_model(effect.call_name)
        actuals = actual_argument_expressions(effect.call_expression)
        leaf_name = (effect.call_name or "").rsplit(".", 1)[-1]
        receiver = self._call_receiver(effect.call_expression)
        if receiver is not None and len(actuals) == 2:
            if leaf_name in self.configuration.bound_attribute_set_names:
                return (
                    effect.call_name or leaf_name,
                    "attribute",
                    receiver,
                    actuals[0],
                    actuals[1],
                )
            if leaf_name in self.configuration.bound_item_set_names:
                return (
                    effect.call_name or leaf_name,
                    "item",
                    receiver,
                    actuals[0],
                    actuals[1],
                )
        if (
            model is None
            and effect.call_name is not None
            and (
                effect.call_name in self.configuration.namespace_update_names
                or effect.call_name.rsplit(".", 1)[-1] == "update"
            )
        ):
            receiver = self._call_receiver(effect.call_expression)
            if receiver is None or not actuals:
                return None
            mapping = actuals[0]
            return (
                effect.call_name,
                "namespace",
                receiver,
                mapping,
                mapping,
            )
        if model is None or model.kind != "set" or model.key_position is None:
            return None
        positions = (model.object_position, model.key_position, model.value_position)
        if any(position is not None and position >= len(actuals) for position in positions):
            return None
        return (
            (
                "subscript-assignment"
                if (effect.call_name or model.name) == "interpreter_setitem"
                else effect.call_name or model.name
            ),
            model.mutation_kind,
            actuals[model.object_position],
            actuals[model.key_position],
            actuals[model.value_position] if model.value_position is not None else None,
        )

    @staticmethod
    def _call_receiver(call):
        if isinstance(call, py_ast.MethodCall):
            return call.expr
        if isinstance(call, py_ast.Call) and isinstance(call.expr, py_ast.GetAttr):
            return call.expr.expr
        return getattr(call, "selfarg", None)

    def _target_facts(self, node, expression, facts):
        if self._is_static_safe_projection(node.procedure, expression):
            return ()
        targets = list(
            self._facts_matching(
                node,
                expression,
                facts,
                {PollutionRole.TARGET_OBJECT},
            )
        )
        if isinstance(expression, py_ast.ConditionalExpr):
            targets.extend(
                self._target_facts(node, expression.body, facts)
            )
            targets.extend(
                self._target_facts(node, expression.orelse, facts)
            )
        if isinstance(expression, py_ast.GetAttr):
            name = self._constant_string(expression.name)
            if name is not None:
                for fact in facts:
                    if not isinstance(
                        fact, (PollutionFact, ExpressionPollutionFact)
                    ) or fact.role not in {
                        PollutionRole.ROOT_OBJECT,
                        PollutionRole.TARGET_OBJECT,
                    }:
                        continue
                    if not self._expr_has_fact(
                        node.procedure, expression.expr, fact
                    ):
                        continue
                    targets.append(
                        self._static_access_template(
                            node.procedure, expression, fact
                        )
                    )
        return tuple(dict.fromkeys(targets))

    def _is_static_safe_projection(self, procedure, expression):
        if not isinstance(expression, py_ast.Local) or not expression.name:
            return False
        for candidate in self.supergraph.ordered_nodes_of(procedure):
            operation = self.adapter.operation_of(candidate)
            if not isinstance(operation, (py_ast.Assign, py_ast.AnnAssign)):
                continue
            targets = assigned_locals(operation)
            if not any(target.name == expression.name for target in targets):
                continue
            value = (
                operation.value
                if isinstance(operation, py_ast.AnnAssign)
                else operation.expr
            )
            if not isinstance(value, py_ast.Call):
                continue
            if self._call_leaf_name(value.expr) != "interpreter_getitem":
                continue
            actuals = actual_argument_expressions(value)
            if len(actuals) < 2:
                continue
            literal = self._constant_string(actuals[1])
            if literal is not None and literal not in MAGIC_PATH_COMPONENTS:
                return True
        return False

    def _write_site(self, node):
        call_site = self._call_write_site(node)
        if call_site is not None:
            return call_site
        operation = self.adapter.operation_of(node)
        target = self._dynamic_subscript_write_target(operation)
        if target is None:
            return None
        object_expr, key_expr, value_expr = target
        return (
            "subscript-assignment",
            "item",
            object_expr,
            key_expr,
            value_expr,
        )

    def findings(self, result):
        reports = []
        seen = set()
        for procedure in self.supergraph.ordered_procedures():
            for node in self.supergraph.ordered_nodes_of(procedure):
                site = self._write_site(node)
                if site is None:
                    continue
                sink_name, mutation_kind, target_expr, key_expr, value_expr = site
                facts = result.facts_at(node)
                keys = self._facts_matching(
                    node, key_expr, facts, {PollutionRole.INPUT}
                )
                targets = sorted(
                    self._target_facts(node, target_expr, facts),
                    key=lambda fact: (
                        not any(
                            step.static_name in MAGIC_PATH_COMPONENTS
                            for step in fact.object_path
                        ),
                        len(fact.object_path),
                        repr(fact.object_path),
                    ),
                )
                values = (
                    self._facts_matching(
                        node, value_expr, facts, {PollutionRole.INPUT}
                    )
                    if value_expr is not None
                    else ()
                )
                for key in keys:
                    if not key.key_language.may_contain_magic():
                        continue
                    for target in targets:
                        controlled_path = target.controller == key.origin
                        same_boundary = (
                            target.origin.procedure == key.origin.procedure
                        )
                        explicit_magic_path = any(
                            step.static_name in MAGIC_PATH_COMPONENTS
                            for step in target.object_path
                        )
                        if (
                            not controlled_path
                            and not same_boundary
                            and not explicit_magic_path
                        ):
                            continue
                        if (
                            key.origin == target.origin
                            and not controlled_path
                            and not explicit_magic_path
                        ):
                            continue
                        identity = (
                            self.adapter.operation_of(node),
                            key.origin,
                            target.origin,
                            mutation_kind,
                        )
                        if identity in seen:
                            continue
                        seen.add(identity)
                        value_controlled = bool(values)
                        gadget_reachable = any(
                            step.static_name in GADGET_PATH_COMPONENTS
                            for step in target.object_path
                        ) or bool(
                            set(key.key_language.literals).intersection(
                                GADGET_PATH_COMPONENTS
                            )
                        )
                        reports.append(
                            ClassPollutionFinding(
                                sink=node,
                                sink_name=sink_name,
                                mutation_kind=mutation_kind,
                                proof_level=(
                                    "gadget-reachable"
                                    if gadget_reachable
                                    else "pollutable-object"
                                ),
                                key_origin=key.origin,
                                target_origin=target.origin,
                                key_language=key.key_language,
                                object_path=target.object_path,
                                value_controlled=value_controlled,
                                severity=(
                                    "critical"
                                    if value_controlled or gadget_reachable
                                    else "high"
                                ),
                                confidence=(
                                    "high"
                                    if explicit_magic_path or gadget_reachable
                                    else "medium"
                                ),
                            )
                        )
        return tuple(reports)


def analyze_class_pollution(
    adapter: CFGSupergraphAdapter,
    configuration: ClassPollutionConfiguration | None = None,
    *,
    entry_nodes: Sequence[CFGNode],
    record_traces: bool = True,
    solver_options: SolverOptions | None = None,
) -> ClassPollutionAnalysisResult:
    config = configuration or ClassPollutionConfiguration()
    problem = ClassPollutionProblem(adapter, config, entry_nodes=entry_nodes)
    solver = (
        IFDSSolver(options=solver_options)
        if solver_options is not None
        else IFDSSolver(record_traces=record_traces)
    )
    result = solver.solve(problem)
    return ClassPollutionAnalysisResult(result, problem.findings(result), problem)


__all__ = [
    "ClassPollutionAnalysisResult",
    "ClassPollutionConfiguration",
    "ClassPollutionFinding",
    "ClassPollutionProblem",
    "DEFAULT_OPERATIONS",
    "ReflectiveOperationModel",
    "ZERO_CLASS_POLLUTION",
    "analyze_class_pollution",
]
