"""Formal CPG taint analysis over CFG, dependence, call, and return edges.

The original CPG engine enumerated mutable path snapshots.  This module uses
an immutable product lattice and a monotone worklist keyed by a bounded call
string.  Control-flow edges establish executable order, DATA edges provide
def-use acceleration, and CALL/RETURN edges are matched against the active
call stack.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping, Protocol, Sequence, cast

from pyflow.analysis.taint import TaintRule
from pyflow.analysis.entrypoints import ProcedureDescriptor, select_entry_points
from pyflow.checker.ast_dataflow.domain import (
    AccessSelector,
    AnalysisUncertainty,
    PrecisionLevel,
    ProvenanceOperation,
    TaintFact,
    TaintLocation,
    TaintOrigin,
    TaintState as FormalTaintState,
)
from pyflow.checker.ast_dataflow.semantics import RefinementProvider
from pyflow.ir.cpg.graph import CPGEdgeKind, CodePropertyGraph
from pyflow.ir.pdg.graph import PDGNode
from pyflow.language.python import ast as py_ast

from .model import CPGTaintDiagnostic, CPGTaintResult, TaintFinding

CFG_KINDS = frozenset(
    {
        CPGEdgeKind.CFG_NEXT,
        CPGEdgeKind.CFG_BRANCH_TRUE,
        CPGEdgeKind.CFG_BRANCH_FALSE,
        CPGEdgeKind.CFG_EXCEPT,
    }
)

_NODE_AST = object()

_TAINT_PRESERVING_PURE_CALLS = frozenset(
    {
        "capitalize",
        "casefold",
        "decode",
        "encode",
        "abspath",
        "basename",
        "commonpath",
        "commonprefix",
        "dirname",
        "expanduser",
        "expandvars",
        "format",
        "format_map",
        "join",
        "lower",
        "lstrip",
        "normpath",
        "realpath",
        "relpath",
        "replace",
        "rstrip",
        "split",
        "splitlines",
        "splitext",
        "str",
        "strip",
        "swapcase",
        "title",
        "upper",
    }
)
_TAINT_DROPPING_PURE_CALLS = frozenset(
    {
        "all",
        "any",
        "bool",
        "endswith",
        "exists",
        "float",
        "hasattr",
        "int",
        "isdir",
        "isfile",
        "islink",
        "ismount",
        "isinstance",
        "issubclass",
        "len",
        "lexists",
        "startswith",
    }
)
_SHELL_OPTION_SUBPROCESS_CALLS = frozenset(
    {"call", "check_call", "check_output", "popen", "run"}
)
_SQL_QUERY_ARGUMENT_CALLS = frozenset({"execute", "executemany", "executescript"})


class EngineView(Protocol):
    _cpg: CodePropertyGraph
    _sources: set[str]
    _source_kinds: Mapping[str, frozenset[str]]
    _sinks: Mapping[str, str]
    _sink_kinds: Mapping[str, frozenset[str]]
    _sink_positions: Mapping[str, frozenset[int]]
    _sink_severity: Mapping[str, str]
    _sanitizers: Mapping[str, frozenset[str]]
    _rules: Sequence[TaintRule]
    _max_call_depth: int
    _max_loop_iterations: int
    _max_states: int | None
    _max_seconds: float | None
    _refinement: RefinementProvider
    _node_taint: dict[int, Any]
    _entry_point_options: Any

    def _extract_call_name(self, ast_node: Any) -> str | None: ...

    def _call_expr(self, ast_node: Any) -> Any | None: ...

    def _iter_ast_children(self, node: Any) -> list[Any]: ...

    def _resolve_call_expr(self, expr: Any) -> str | None: ...

    def _matching_rules(
        self, source_kinds: frozenset[str], sink_name: str
    ) -> tuple[TaintRule, ...]: ...

    def _match_sink_name(self, name: str) -> str: ...

    def _matches_source(self, name: str) -> bool: ...

    def _source_kinds_for_name(self, source_name: str) -> frozenset[str]: ...


@dataclass(frozen=True, order=True)
class CPGConfiguration:
    node_id: int
    call_context: tuple[int, ...] = ()


def _ordered_alias(
    left: TaintLocation, right: TaintLocation
) -> tuple[TaintLocation, TaintLocation]:
    return (left, right) if repr(left) <= repr(right) else (right, left)


@dataclass(frozen=True)
class CPGAbstractState:
    """Product of the shared taint lattice and a finite may-alias relation."""

    taint: FormalTaintState = FormalTaintState()
    may_aliases: frozenset[tuple[TaintLocation, TaintLocation]] = frozenset()

    @classmethod
    def bottom(cls) -> "CPGAbstractState":
        return cls(FormalTaintState.bottom())

    @property
    def reachable(self) -> bool:
        return bool(self.taint.reachable)

    def leq(self, other: "CPGAbstractState") -> bool:
        return self.taint.leq(other.taint) and self.may_aliases <= other.may_aliases

    def join(self, other: "CPGAbstractState") -> "CPGAbstractState":
        if not self.reachable:
            return other
        if not other.reachable:
            return self
        return CPGAbstractState(
            self.taint.join(other.taint), self.may_aliases | other.may_aliases
        )

    def with_taint(self, taint: FormalTaintState) -> "CPGAbstractState":
        return replace(self, taint=taint)

    def with_uncertainty(self, uncertainty: AnalysisUncertainty) -> "CPGAbstractState":
        return self.with_taint(self.taint.with_uncertainty(uncertainty))

    def aliases_of(self, location: TaintLocation) -> frozenset[TaintLocation]:
        """Return the finite transitive may-alias class of a root location."""

        result = {location}
        changed = True
        while changed:
            changed = False
            for left, right in self.may_aliases:
                if left in result and right not in result:
                    result.add(right)
                    changed = True
                if right in result and left not in result:
                    result.add(left)
                    changed = True
        return frozenset(result)

    def bind_alias(
        self, destination: TaintLocation, source: TaintLocation
    ) -> "CPGAbstractState":
        cleared = self.clear_binding(destination)
        copied = cleared.taint.copy(
            source,
            destination,
            strong=True,
            operation=ProvenanceOperation.ASSIGN,
        )
        aliases = set(cleared.may_aliases)
        aliases.add(_ordered_alias(destination, source))
        return CPGAbstractState(copied, frozenset(aliases))

    def clear_binding(self, location: TaintLocation) -> "CPGAbstractState":
        aliases = frozenset(pair for pair in self.may_aliases if location not in pair)
        return CPGAbstractState(self.taint.write(location, (), strong=True), aliases)

    def write(
        self,
        location: TaintLocation,
        facts: Iterable[TaintFact],
        *,
        strong: bool,
        source_base: TaintLocation | None = None,
        operation: ProvenanceOperation = ProvenanceOperation.WRITE,
        filename: str | None = None,
        line: int | None = None,
        detail: str | None = None,
    ) -> "CPGAbstractState":
        roots = self.aliases_of(TaintLocation(location.root))
        targets = tuple(TaintLocation(root.root, location.selectors) for root in roots)
        effective_strong = strong and len(targets) == 1
        taint = self.taint
        for target in targets:
            taint = taint.write(
                target,
                facts,
                strong=effective_strong,
                source_base=source_base,
                operation=operation,
                filename=filename,
                line=line,
                detail=detail,
            )
        return self.with_taint(taint)


@dataclass(frozen=True)
class CPGValue:
    state: CPGAbstractState
    facts: frozenset[TaintFact] = frozenset()
    location: TaintLocation | None = None


@dataclass(frozen=True)
class CPGSummarySink:
    sink_name: str
    parameter_indices: frozenset[int]
    source_kinds: frozenset[str]
    line: int | None
    source_occurrences: frozenset[tuple[str, int, str]] = frozenset()
    sink_node_id: int = -1


@dataclass(frozen=True)
class CPGProcedureSummary:
    procedure: str
    parameters: tuple[str, ...]
    return_parameters: frozenset[int] = frozenset()
    return_source_kinds: frozenset[str] = frozenset()
    sinks: frozenset[CPGSummarySink] = frozenset()
    return_sources: frozenset[tuple[str, int, str]] = frozenset()


@dataclass(frozen=True, order=True)
class _SummaryToken:
    """Finite symbolic dependency used to derive relational summaries."""

    kind: str
    parameter_index: int = -1
    source_kind: str = ""
    source_node_id: int = -1
    source_name: str = ""

    @classmethod
    def parameter(cls, index: int) -> "_SummaryToken":
        return cls("parameter", parameter_index=index)

    @classmethod
    def source(cls, kind: str, node_id: int, name: str) -> "_SummaryToken":
        return cls(
            "source",
            source_kind=kind,
            source_node_id=node_id,
            source_name=name,
        )


@dataclass(frozen=True)
class _Transition:
    target: CPGConfiguration
    state: CPGAbstractState
    edge_kind: str


class FormalCPGTaintAnalysis:
    def __init__(self, engine: EngineView) -> None:
        self.engine = engine
        self.cpg = engine._cpg
        self.cpg._ensure_built()
        self._module_function = next(
            (name for name in self.cpg._pdgs if name.endswith(".<module>")),
            "<module>",
        )
        self._global_declarations = self._collect_scope_declarations(py_ast.GlobalDecl)
        self._nonlocal_declarations = self._collect_scope_declarations(
            py_ast.NonlocalDecl
        )
        self._all_nonlocal_names = frozenset(
            name for names in self._nonlocal_declarations.values() for name in names
        )
        self._local_bindings = {
            function: self._defined_local_names(function) for function in self.cpg._pdgs
        }
        self._module_globals = self._local_bindings.get(
            self._module_function, frozenset()
        )
        self._local_class_names = frozenset(
            ast_node.name
            for node in self.cpg.nodes()
            for ast_node in (node.ast_node,)
            if isinstance(ast_node, py_ast.ClassDef) and ast_node.name
        )
        self._import_aliases = self._collect_import_aliases()
        self._diagnostics: set[CPGTaintDiagnostic] = set()
        self._events: list[tuple[PDGNode, str, frozenset[TaintFact]]] = []
        self._states: dict[CPGConfiguration, CPGAbstractState] = {}
        self._predecessors: dict[
            tuple[CPGConfiguration, str], tuple[CPGConfiguration, str]
        ] = {}
        self._summaries = self._build_summaries()
        self._processed_states = 0
        self._data_transitions = 0
        self._summary_applications = 0
        self._loop_nodes = self._compute_loop_nodes()
        self._configuration_updates: dict[CPGConfiguration, int] = {}
        self._loop_threshold_crossings = 0
        self._loop_threshold_reported: set[CPGConfiguration] = set()

    def analyze(self) -> CPGTaintResult:
        from time import monotonic

        started_at = monotonic()
        worklist: deque[CPGConfiguration] = deque()
        queued: set[CPGConfiguration] = set()
        module_seed = self._module_initializer_state()
        for entry in self._root_entries():
            config = CPGConfiguration(entry.node_id)
            initial = (
                CPGAbstractState()
                if self.cpg.node_func_name(entry) == self._module_function
                else module_seed
            )
            self._states[config] = self._seed_entry_parameters(entry, initial)
            worklist.append(config)
            queued.add(config)

        while worklist:
            if (
                self.engine._max_states is not None
                and self._processed_states >= self.engine._max_states
            ):
                self._diagnostics.add(
                    CPGTaintDiagnostic(
                        f"CPG fixed point exceeded {self.engine._max_states} states",
                        "cpg-state-budget",
                        True,
                        level=PrecisionLevel.UNSUPPORTED.value,
                    )
                )
                break
            if (
                self.engine._max_seconds is not None
                and monotonic() - started_at >= self.engine._max_seconds
            ):
                self._diagnostics.add(
                    CPGTaintDiagnostic(
                        "CPG fixed point exceeded its time budget",
                        "cpg-time-budget",
                        True,
                        level=PrecisionLevel.UNSUPPORTED.value,
                    )
                )
                break

            config = worklist.popleft()
            queued.discard(config)
            node = self.cpg.node_by_id(config.node_id)
            if node is None:
                continue
            self._processed_states += 1
            incoming = self._states[config]
            outgoing, events = self._transfer_node(node, incoming)
            self._events.extend((node, name, facts) for name, facts in events)

            for transition in self._successors(config, node, outgoing):
                previous = self._states.get(
                    transition.target, CPGAbstractState.bottom()
                )
                joined = previous.join(transition.state)
                if joined == previous:
                    continue
                updates = self._configuration_updates.get(transition.target, 0) + 1
                self._configuration_updates[transition.target] = updates
                if (
                    transition.target.node_id in self._loop_nodes
                    and updates > self.engine._max_loop_iterations
                    and transition.target not in self._loop_threshold_reported
                ):
                    self._loop_threshold_reported.add(transition.target)
                    self._loop_threshold_crossings += 1
                    loop_node = self.cpg.node_by_id(transition.target.node_id)
                    joined = joined.with_uncertainty(
                        AnalysisUncertainty(
                            "cpg-loop-convergence-threshold",
                            "Loop required more fixed-point updates than the "
                            "configured reporting threshold; analysis continued "
                            "to convergence",
                            PrecisionLevel.CONSERVATIVE,
                            (
                                self.cpg.node_func_name(loop_node)
                                if loop_node is not None
                                else None
                            ),
                            (
                                self._filename(loop_node)
                                if loop_node is not None
                                else None
                            ),
                            (
                                self.cpg.node_lineno(loop_node)
                                if loop_node is not None
                                else None
                            ),
                            "loop",
                        )
                    )
                self._states[transition.target] = joined
                self._record_predecessors(
                    config,
                    transition.target,
                    transition.state,
                    transition.edge_kind,
                )
                if transition.target not in queued:
                    queued.add(transition.target)
                    worklist.append(transition.target)

        self._collect_state_diagnostics()
        self._collect_graph_diagnostics()
        self._publish_node_taint()
        findings = self._build_findings()
        diagnostics = tuple(sorted(self._diagnostics, key=repr))
        status = (
            "partial"
            if any(item.affects_completeness for item in diagnostics)
            else "complete"
        )
        if status == "partial":
            reasons = tuple(
                sorted(item.code for item in diagnostics if item.affects_completeness)
            )
            for finding in findings:
                finding.precision_reasons = tuple(
                    sorted(set(finding.precision_reasons) | set(reasons))
                )
        return CPGTaintResult(
            tuple(findings),
            status=status,
            diagnostics=diagnostics,
            statistics={
                "functions": len(self.cpg.functions),
                "seeds": len(self._source_nodes()),
                "processed_states": self._processed_states,
                "data_dependencies_consulted": self._data_transitions,
                # Historical key retained for consumers of the first CPG
                # result schema. DATA edges are evidence, not state transitions.
                "data_transitions": self._data_transitions,
                "summary_applications": self._summary_applications,
                "loop_threshold_crossings": self._loop_threshold_crossings,
                "findings": len(findings),
            },
        )

    # ---------------------------------------------------------------- state
    def _root_entries(self) -> tuple[PDGNode, ...]:
        calls: dict[str, set[str]] = {function: set() for function in self.cpg._pdgs}
        for edges in self.cpg._cpg_edges_out.values():
            for edge in edges:
                if edge.kind is not CPGEdgeKind.CALL:
                    continue
                caller = self.cpg.node_func_name(edge.source)
                callee = self.cpg.node_func_name(edge.target)
                if caller in calls and callee in calls and caller != callee:
                    calls[caller].add(callee)
        descriptors = []
        for function, pdg in self.cpg._pdgs.items():
            if pdg.entry is None:
                continue
            descriptors.append(
                ProcedureDescriptor(
                    identity=function,
                    qualified_name=function,
                    filename=self._filename(pdg.entry),
                    callees=frozenset(calls[function]),
                    synthetic_module=function == self._module_function,
                )
            )
        selected = select_entry_points(descriptors, self.engine._entry_point_options)
        return tuple(
            self.cpg._pdgs[item.identity].entry
            for item in selected
            if self.cpg._pdgs[item.identity].entry is not None
        )

    def _seed_entry_parameters(
        self, entry: PDGNode, state: CPGAbstractState
    ) -> CPGAbstractState:
        if not self.engine._entry_point_options.taint_parameters:
            return state
        function = self.cpg.node_func_name(entry)
        parameters, _keywords = self._callee_parameters(function)
        parameters = [name for name in parameters if name not in {"self", "cls"}]
        if not parameters:
            return state
        kinds = (
            {kind for values in self.engine._source_kinds.values() for kind in values}
            or {kind for rule in self.engine._rules for kind in rule.source_kinds}
            or {"untrusted"}
        )
        taint = state.taint
        for parameter in parameters:
            for kind in kinds:
                taint = taint.introduce(
                    self._local(function, parameter),
                    {kind},
                    TaintOrigin(
                        kind,
                        self._filename(entry),
                        self.cpg.node_lineno(entry),
                        symbol=f"entry-parameter:{function}:{parameter}",
                    ),
                )
        return state.with_taint(taint)

    def _compute_loop_nodes(self) -> frozenset[int]:
        """Return nodes in non-trivial SCCs of the intraprocedural CFG."""

        adjacency: dict[int, tuple[int, ...]] = {}
        for node in self.cpg.nodes():
            function = self.cpg.node_func_name(node)
            adjacency[node.node_id] = tuple(
                edge.target.node_id
                for edge in self.cpg._cpg_edges_out.get(node.node_id, ())
                if edge.kind in CFG_KINDS
                and self.cpg.node_func_name(edge.target) == function
            )
        index = 0
        indices: dict[int, int] = {}
        lowlinks: dict[int, int] = {}
        stack: list[int] = []
        on_stack: set[int] = set()
        loop_nodes: set[int] = set()

        def visit(node_id: int) -> None:
            nonlocal index
            indices[node_id] = index
            lowlinks[node_id] = index
            index += 1
            stack.append(node_id)
            on_stack.add(node_id)
            for successor in adjacency.get(node_id, ()):
                if successor not in indices:
                    visit(successor)
                    lowlinks[node_id] = min(lowlinks[node_id], lowlinks[successor])
                elif successor in on_stack:
                    lowlinks[node_id] = min(lowlinks[node_id], indices[successor])
            if lowlinks[node_id] != indices[node_id]:
                return
            component: list[int] = []
            while stack:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node_id:
                    break
            if len(component) > 1 or any(
                member in adjacency.get(member, ()) for member in component
            ):
                loop_nodes.update(component)

        for node_id in adjacency:
            if node_id not in indices:
                visit(node_id)
        return frozenset(loop_nodes)

    def _module_initializer_state(self) -> CPGAbstractState:
        """Compute import-time globals used to seed public procedure entries."""

        pdg = self.cpg._pdgs.get(self._module_function)
        if pdg is None or pdg.entry is None:
            return CPGAbstractState()
        states: dict[int, CPGAbstractState] = {pdg.entry.node_id: CPGAbstractState()}
        pending = deque([pdg.entry])
        exits = {node.node_id for node in pdg.exit_nodes}
        exit_state = CPGAbstractState.bottom()
        while pending:
            node = pending.popleft()
            outgoing, events = self._transfer_node(node, states[node.node_id])
            self._events.extend((node, name, facts) for name, facts in events)
            if node.node_id in exits:
                exit_state = exit_state.join(outgoing)
            for edge in self.cpg._cpg_edges_out.get(node.node_id, ()):
                if edge.kind not in CFG_KINDS:
                    continue
                if self.cpg.node_func_name(edge.target) != self._module_function:
                    continue
                target_seen = edge.target.node_id in states
                previous = states.get(edge.target.node_id, CPGAbstractState.bottom())
                joined = previous.join(outgoing)
                if target_seen and joined == previous:
                    continue
                states[edge.target.node_id] = joined
                pending.append(edge.target)
        result = exit_state if exit_state.reachable else CPGAbstractState()
        if not self._module_has_local_calls():
            return result

        source_kinds = {
            kind for kinds in self.engine._source_kinds.values() for kind in kinds
        } or {"unknown"}
        taint = result.taint
        for name in self._module_globals:
            location = self._local(self._module_function, name)
            for kind in source_kinds:
                taint = taint.introduce(
                    location,
                    {kind},
                    TaintOrigin(
                        kind,
                        self._filename(pdg.entry),
                        self.cpg.node_lineno(pdg.entry),
                        symbol=f"module-initializer:{name}",
                    ),
                )
        return result.with_taint(taint)

    def _module_has_local_calls(self) -> bool:
        return any(
            edge.kind is CPGEdgeKind.CALL
            and self.cpg.node_func_name(edge.source) == self._module_function
            for edges in self.cpg._cpg_edges_out.values()
            for edge in edges
        )

    def _local(self, function: str, name: str) -> TaintLocation:
        if name in self._global_declarations.get(function, frozenset()) or (
            function != self._module_function
            and name in self._module_globals
            and name not in self._local_bindings.get(function, frozenset())
        ):
            return TaintLocation((self._module_function, name))
        if name in self._all_nonlocal_names:
            return TaintLocation(("<closure>", name))
        return TaintLocation((function, name))

    def _collect_scope_declarations(
        self, declaration_type: type[Any]
    ) -> dict[str, frozenset[str]]:
        result: dict[str, frozenset[str]] = {}
        for function, pdg in self.cpg._pdgs.items():
            names = {
                declaration.name.name
                for node in pdg.nodes
                for declaration in self._walk_ast(node.ast_node)
                if isinstance(declaration, declaration_type)
                and isinstance(declaration.name, py_ast.Local)
                and declaration.name.name
            }
            result[function] = frozenset(names)
        return result

    def _defined_local_names(self, function: str) -> frozenset[str]:
        pdg = self.cpg._pdgs[function]
        parameters, _keywords = self._callee_parameters(function)
        names = set(parameters)
        for node in pdg.nodes:
            ast_node = node.ast_node
            if isinstance(ast_node, py_ast.Assign):
                names.update(
                    target.name
                    for target in ast_node.lcls or ()
                    if isinstance(target, py_ast.Local) and target.name
                )
            elif isinstance(ast_node, py_ast.AnnAssign):
                target = ast_node.target
                if isinstance(target, py_ast.Local) and target.name:
                    names.add(target.name)
            elif isinstance(ast_node, py_ast.SetGlobal):
                name = self._constant_value(ast_node.name)
                if isinstance(name, str):
                    names.add(name)
        names.difference_update(self._global_declarations.get(function, frozenset()))
        names.difference_update(self._nonlocal_declarations.get(function, frozenset()))
        return frozenset(names)

    def _return_location(self, function: str) -> TaintLocation:
        return TaintLocation((function, "<return>"))

    def _call_location(
        self, node: PDGNode, call: py_ast.Call | None = None
    ) -> TaintLocation:
        marker = id(call) if call is not None else node.node_id
        return TaintLocation((self.cpg.node_func_name(node), "<call>", marker))

    def _expression_location(self, node: PDGNode, expression: Any) -> TaintLocation:
        return TaintLocation(
            (self.cpg.node_func_name(node), "<expression>", id(expression))
        )

    def _filename(self, node: PDGNode) -> str | None:
        code = getattr(
            getattr(self.cpg._pdgs.get(self.cpg.node_func_name(node)), "cfg", None),
            "code",
            None,
        )
        value = getattr(code, "filename", None)
        return value if isinstance(value, str) else None

    # -------------------------------------------------------------- transfer
    def _transfer_node(
        self,
        node: PDGNode,
        state: CPGAbstractState,
        ast_override: Any = _NODE_AST,
    ) -> tuple[CPGAbstractState, tuple[tuple[str, frozenset[TaintFact]], ...]]:
        ast_node = node.ast_node if ast_override is _NODE_AST else ast_override
        if ast_node is None:
            return state, ()
        function = self.cpg.node_func_name(node)
        events: list[tuple[str, frozenset[TaintFact]]] = []

        if isinstance(ast_node, py_ast.Suite):
            current = state
            for statement in ast_node.blocks or ():
                current, statement_events = self._transfer_node(
                    node, current, statement
                )
                events.extend(statement_events)
            return current, tuple(events)

        if isinstance(ast_node, py_ast.For):
            return self._transfer_structured_for(node, ast_node, state)

        if isinstance(ast_node, py_ast.Switch):
            return self._transfer_structured_switch(node, ast_node, state)

        if isinstance(ast_node, py_ast.While):
            return self._transfer_structured_while(node, ast_node, state)

        # A resolved local call is interpreted by the matched CALL/RETURN
        # transitions below.  Evaluating the enclosing assignment here would
        # apply its summary as well and therefore execute the call twice.
        # We still evaluate actual arguments because they can contain source,
        # sanitizer, or unknown external calls with state effects.
        top_call = self._top_level_call(ast_node)
        if (
            top_call is not None
            and self._local_call_edges(node)
            and not self._is_modeled_call(top_call)
        ):
            current, _arguments = self._evaluate_arguments(top_call, state, node)
            return current, ()

        if isinstance(ast_node, py_ast.Assign):
            value = self._evaluate(ast_node.expr, state, node)
            current = value.state
            for target in ast_node.lcls or ():
                if not isinstance(target, py_ast.Local) or not target.name:
                    continue
                destination = self._local(function, target.name)
                if value.location is not None and isinstance(
                    ast_node.expr, py_ast.Local
                ):
                    current = current.bind_alias(destination, value.location)
                else:
                    current = current.clear_binding(destination).write(
                        destination,
                        value.facts,
                        strong=True,
                        source_base=value.location,
                        operation=ProvenanceOperation.ASSIGN,
                        filename=self._filename(node),
                        line=self.cpg.node_lineno(node),
                    )
            events.extend(self._sink_events(ast_node.expr, value, node))
            return current, tuple(events)

        if isinstance(ast_node, py_ast.AnnAssign):
            value = self._evaluate(ast_node.value, state, node)
            target = ast_node.target
            current = value.state
            if isinstance(target, py_ast.Local) and target.name:
                destination = self._local(function, target.name)
                current = current.clear_binding(destination).write(
                    destination,
                    value.facts,
                    strong=True,
                    source_base=value.location,
                    operation=ProvenanceOperation.ASSIGN,
                    filename=self._filename(node),
                    line=self.cpg.node_lineno(node),
                )
            events.extend(self._sink_events(ast_node.value, value, node))
            return current, tuple(events)

        if isinstance(ast_node, py_ast.SetAttr):
            value = self._evaluate(ast_node.value, state, node)
            location = self._location_of_setattr(ast_node, function)
            if location is None:
                return self._unsupported(state, node, "unresolved-attribute-write"), ()
            location = value.state.taint.abstract_location(location)
            decision = self.engine._refinement.update_decision(location, node)
            current = value.state
            for uncertainty in decision.uncertainties:
                current = current.with_uncertainty(uncertainty)
            current = current.write(
                location,
                value.facts,
                strong=decision.strong,
                source_base=value.location,
                operation=ProvenanceOperation.WRITE,
                filename=self._filename(node),
                line=self.cpg.node_lineno(node),
                detail=",".join(decision.reasons) or None,
            )
            base_name = self.engine._resolve_call_expr(ast_node.expr)
            attribute = self.engine._resolve_call_expr(ast_node.name)
            symbolic_name = (
                f"{base_name}.{attribute}"
                if base_name and attribute
                else attribute or base_name or ""
            )
            sink_name = self.engine._match_sink_name(
                self._qualify_import_alias(symbolic_name)
            )
            if sink_name and value.facts:
                events.append((sink_name, value.facts))
            return current, tuple(events)

        if isinstance(ast_node, py_ast.SetSubscript):
            value = self._evaluate(ast_node.value, state, node)
            location = self._location_of_subscript(
                ast_node.expr, ast_node.subscript, function
            )
            if location is None:
                return self._unsupported(state, node, "unresolved-subscript-write"), ()
            decision = self.engine._refinement.update_decision(location, node)
            current = value.state
            for uncertainty in decision.uncertainties:
                current = current.with_uncertainty(uncertainty)
            current = current.write(
                location,
                value.facts,
                strong=decision.strong,
                source_base=value.location,
                operation=ProvenanceOperation.WRITE,
                filename=self._filename(node),
                line=self.cpg.node_lineno(node),
                detail=",".join(decision.reasons) or None,
            )
            return current, ()

        if isinstance(ast_node, py_ast.SetGlobal):
            value = self._evaluate(ast_node.value, state, node)
            name = self._constant_value(ast_node.name)
            if not isinstance(name, str):
                return self._unsupported(state, node, "unresolved-global-write"), ()
            location = TaintLocation((self._module_function, name))
            return (
                value.state.clear_binding(location).write(
                    location,
                    value.facts,
                    strong=True,
                    source_base=value.location,
                    operation=ProvenanceOperation.WRITE,
                    filename=self._filename(node),
                    line=self.cpg.node_lineno(node),
                    detail="global",
                ),
                (),
            )

        if isinstance(ast_node, py_ast.SetCellDeref):
            value = self._evaluate(ast_node.value, state, node)
            cell_name = getattr(ast_node.cell, "name", None)
            if not isinstance(cell_name, str):
                cell_name = str(ast_node.cell)
            location = TaintLocation(("<closure>", cell_name))
            return (
                value.state.clear_binding(location).write(
                    location,
                    value.facts,
                    strong=True,
                    source_base=value.location,
                    operation=ProvenanceOperation.WRITE,
                    filename=self._filename(node),
                    line=self.cpg.node_lineno(node),
                    detail="cell",
                ),
                (),
            )

        if isinstance(ast_node, py_ast.Discard):
            value = self._evaluate(ast_node.expr, state, node)
            events.extend(self._sink_events(ast_node.expr, value, node))
            return value.state, tuple(events)

        if isinstance(ast_node, py_ast.Return):
            current = state
            facts: set[TaintFact] = set()
            values: list[CPGValue] = []
            for expression in ast_node.exprs or ():
                value = self._evaluate(expression, current, node)
                current = value.state
                values.append(value)
                facts.update(value.facts)
                events.extend(self._sink_events(expression, value, node))
            target = self._return_location(function)
            current = current.with_taint(
                current.taint.write(
                    target,
                    facts,
                    strong=True,
                    source_base=(
                        values[0].location
                        if len(values) == 1 and values[0].location is not None
                        else None
                    ),
                    operation=ProvenanceOperation.RETURN,
                    filename=self._filename(node),
                    line=self.cpg.node_lineno(node),
                )
            )
            if len(values) == 1 and values[0].location is not None:
                current = replace(
                    current,
                    may_aliases=current.may_aliases
                    | {_ordered_alias(target, values[0].location)},
                )
            return current, tuple(events)

        if isinstance(ast_node, py_ast.Delete):
            target = ast_node.lcl
            if isinstance(target, py_ast.Local) and target.name:
                return state.clear_binding(self._local(function, target.name)), ()
            return state, ()

        if isinstance(ast_node, py_ast.DeleteGlobal):
            name = self._constant_value(ast_node.name)
            if isinstance(name, str):
                return (
                    state.clear_binding(TaintLocation((self._module_function, name))),
                    (),
                )
            return self._unsupported(state, node, "unresolved-global-delete"), ()

        if isinstance(
            ast_node,
            (
                py_ast.FunctionDef,
                py_ast.ClassDef,
                py_ast.GlobalDecl,
                py_ast.NonlocalDecl,
            ),
        ):
            return state, ()

        if isinstance(ast_node, py_ast.TryExceptFinally):
            return self._transfer_structured_try(node, ast_node, state)

        if isinstance(
            ast_node,
            (
                py_ast.Break,
                py_ast.Continue,
                py_ast.Assert,
                py_ast.Raise,
                py_ast.Yield,
                py_ast.YieldFrom,
                py_ast.AsyncYield,
            ),
        ):
            value = self._evaluate(ast_node, state, node)
            return value.state, ()

        if isinstance(ast_node, py_ast.Expression):
            value = self._evaluate(ast_node, state, node)
            events.extend(self._sink_events(ast_node, value, node))
            return value.state, tuple(events)

        return (
            self._unsupported(
                state, node, f"unsupported-{type(ast_node).__name__.lower()}"
            ),
            (),
        )

    def _transfer_structured_for(
        self, node: PDGNode, loop: py_ast.For, state: CPGAbstractState
    ) -> tuple[CPGAbstractState, tuple[tuple[str, frozenset[TaintFact]], ...]]:
        """Conservatively summarize a source-level ``for`` in one PDG node.

        The CFG deliberately preserves ``For`` until iterator-aware lowering is
        available.  This transfer computes a finite loop fixed point so nested
        assignments and calls remain visible to formal taint analysis.  The
        zero-iteration path and possible ``break`` path are retained by joins.
        """
        events: set[tuple[str, frozenset[TaintFact]]] = set()
        current, preamble_events = self._transfer_node(node, state, loop.loopPreamble)
        events.update(preamble_events)
        iterator = self._evaluate(loop.iterator, current, node)
        current = iterator.state
        events.update(self._sink_events(loop.iterator, iterator, node))

        if isinstance(loop.index, py_ast.Local) and loop.index.name:
            destination = self._local(self.cpg.node_func_name(node), loop.index.name)
            current = current.clear_binding(destination).write(
                destination,
                iterator.facts,
                strong=True,
                source_base=iterator.location,
                operation=ProvenanceOperation.ASSIGN,
                filename=self._filename(node),
                line=self.cpg.node_lineno(node),
                detail="for-index",
            )

        entry = current
        head = entry
        converged = False
        for _ in range(32):
            body_state, body_preamble_events = self._transfer_node(
                node, head, loop.bodyPreamble
            )
            events.update(body_preamble_events)
            body_state, body_events = self._transfer_node(node, body_state, loop.body)
            events.update(body_events)
            next_head = entry.join(body_state)
            if next_head == head:
                head = next_head
                converged = True
                break
            head = next_head

        if not converged:
            head = head.with_uncertainty(
                AnalysisUncertainty(
                    "cpg-loop-fixed-point-limit",
                    "Structured loop summary reached its iteration limit",
                    PrecisionLevel.CONSERVATIVE,
                    self.cpg.node_func_name(node),
                    self._filename(node),
                    self.cpg.node_lineno(node),
                    "for",
                )
            )

        else_state, else_events = self._transfer_node(node, head, loop.else_)
        events.update(else_events)
        result = head.join(else_state).with_uncertainty(
            AnalysisUncertainty(
                "cpg-structured-loop-overapproximation",
                "Structured loop exits are conservatively joined",
                PrecisionLevel.CONSERVATIVE,
                self.cpg.node_func_name(node),
                self._filename(node),
                self.cpg.node_lineno(node),
                "for",
            )
        )
        return result, tuple(sorted(events, key=lambda item: item[0]))

    def _transfer_structured_switch(
        self, node: PDGNode, statement: py_ast.Switch, state: CPGAbstractState
    ) -> tuple[CPGAbstractState, tuple[tuple[str, frozenset[TaintFact]], ...]]:
        """Evaluate the condition and conservatively join both branches."""
        current, preamble_events = self._transfer_node(
            node, state, statement.condition.preamble
        )
        condition = self._evaluate(statement.condition.conditional, current, node)
        true_state, true_events = self._transfer_node(
            node, condition.state, statement.t
        )
        false_state, false_events = self._transfer_node(
            node, condition.state, statement.f
        )
        result = true_state.join(false_state).with_uncertainty(
            AnalysisUncertainty(
                "cpg-structured-branch-overapproximation",
                "Structured branch feasibility is conservatively joined",
                PrecisionLevel.CONSERVATIVE,
                self.cpg.node_func_name(node),
                self._filename(node),
                self.cpg.node_lineno(node),
                "switch",
            )
        )
        events = set(preamble_events) | set(true_events) | set(false_events)
        events.update(
            self._sink_events(statement.condition.conditional, condition, node)
        )
        return result, tuple(sorted(events, key=lambda item: item[0]))

    def _transfer_structured_while(
        self, node: PDGNode, loop: py_ast.While, state: CPGAbstractState
    ) -> tuple[CPGAbstractState, tuple[tuple[str, frozenset[TaintFact]], ...]]:
        """Compute a fixed point that includes the zero-iteration path."""
        events: set[tuple[str, frozenset[TaintFact]]] = set()
        current, preamble_events = self._transfer_node(
            node, state, loop.condition.preamble
        )
        events.update(preamble_events)
        entry = current
        head = entry
        converged = False
        for _ in range(32):
            condition = self._evaluate(loop.condition.conditional, head, node)
            events.update(
                self._sink_events(loop.condition.conditional, condition, node)
            )
            body_state, body_events = self._transfer_node(
                node, condition.state, loop.body
            )
            events.update(body_events)
            next_head = entry.join(body_state)
            if next_head == head:
                head = next_head
                converged = True
                break
            head = next_head
        if not converged:
            head = head.with_uncertainty(
                AnalysisUncertainty(
                    "cpg-loop-fixed-point-limit",
                    "Structured loop summary reached its iteration limit",
                    PrecisionLevel.CONSERVATIVE,
                    self.cpg.node_func_name(node),
                    self._filename(node),
                    self.cpg.node_lineno(node),
                    "while",
                )
            )
        else_state, else_events = self._transfer_node(node, head, loop.else_)
        events.update(else_events)
        result = head.join(else_state).with_uncertainty(
            AnalysisUncertainty(
                "cpg-structured-loop-overapproximation",
                "Structured loop exits are conservatively joined",
                PrecisionLevel.CONSERVATIVE,
                self.cpg.node_func_name(node),
                self._filename(node),
                self.cpg.node_lineno(node),
                "while",
            )
        )
        return result, tuple(sorted(events, key=lambda item: item[0]))

    def _transfer_structured_try(
        self,
        node: PDGNode,
        statement: py_ast.TryExceptFinally,
        state: CPGAbstractState,
    ) -> tuple[CPGAbstractState, tuple[tuple[str, frozenset[TaintFact]], ...]]:
        """Conservatively join normal and exceptional structured branches."""
        events: set[tuple[str, frozenset[TaintFact]]] = set()
        body_state, body_events = self._transfer_node(node, state, statement.body)
        events.update(body_events)

        else_state, else_events = self._transfer_node(node, body_state, statement.else_)
        events.update(else_events)
        branches = [else_state]

        # An exception can arise after any prefix of the body.  Joining the
        # entry and completed-body states safely over-approximates that prefix.
        handler_entry = state.join(body_state)
        for handler in statement.handlers or ():
            handler_state, preamble_events = self._transfer_node(
                node, handler_entry, handler.preamble
            )
            events.update(preamble_events)
            if handler.type is not None:
                handler_type = self._evaluate(handler.type, handler_state, node)
                handler_state = handler_type.state
                events.update(self._sink_events(handler.type, handler_type, node))
            if isinstance(handler.value, py_ast.Local) and handler.value.name:
                exception_location = self._local(
                    self.cpg.node_func_name(node), handler.value.name
                )
                handler_state = handler_state.clear_binding(exception_location).write(
                    exception_location,
                    handler_entry.taint.facts,
                    strong=True,
                    operation=ProvenanceOperation.ASSIGN,
                    filename=self._filename(node),
                    line=self.cpg.node_lineno(node),
                    detail="caught-exception",
                )
            handler_state, handler_events = self._transfer_node(
                node, handler_state, handler.body
            )
            events.update(handler_events)
            branches.append(handler_state)

        # The frontend represents a bare ``except:`` as a Suite rather than
        # an ExceptionHandler.  It has no preamble, exception type, or bound
        # exception value, so it must be transferred directly as a branch.
        if statement.defaultHandler is not None:
            default_state, default_events = self._transfer_node(
                node, handler_entry, statement.defaultHandler
            )
            events.update(default_events)
            branches.append(default_state)

        joined = branches[0]
        for branch in branches[1:]:
            joined = joined.join(branch)
        final_state, finally_events = self._transfer_node(
            node, joined, statement.finally_
        )
        events.update(finally_events)
        final_state = final_state.with_uncertainty(
            AnalysisUncertainty(
                "cpg-exception-overapproximation",
                "Exception handler feasibility is conservatively joined",
                PrecisionLevel.CONSERVATIVE,
                self.cpg.node_func_name(node),
                self._filename(node),
                self.cpg.node_lineno(node),
                "try",
            )
        )
        return final_state, tuple(sorted(events, key=lambda item: item[0]))

    def _evaluate(
        self, expression: Any, state: CPGAbstractState, node: PDGNode
    ) -> CPGValue:
        if expression is None:
            return CPGValue(state)
        function = self.cpg.node_func_name(node)
        location = self._location_of(expression, function)
        if isinstance(expression, py_ast.Local):
            if location is None:
                return CPGValue(state)
            return CPGValue(state, state.taint.facts_at(location), location)
        if isinstance(expression, py_ast.GetGlobal):
            name = self._constant_value(expression.name)
            if not isinstance(name, str):
                return self._conservative_unresolved_read(
                    state, node, "unresolved-global-read"
                )
            global_location = TaintLocation((self._module_function, name))
            return CPGValue(
                state, state.taint.facts_at(global_location), global_location
            )
        if isinstance(expression, py_ast.Existing):
            return CPGValue(state)
        if isinstance(expression, (py_ast.GetAttr, py_ast.GetSubscript)):
            if location is None:
                return self._conservative_unresolved_read(
                    state, node, "unresolved-read"
                )
            current = state
            if isinstance(expression, py_ast.GetAttr):
                symbolic_name = self.engine._resolve_call_expr(expression) or ""
                symbolic_name = self._qualify_import_alias(symbolic_name)
                source_name = self._configured_source(symbolic_name)
                if source_name is not None:
                    taint = current.taint
                    for kind in self.engine._source_kinds_for_name(source_name):
                        taint = taint.introduce(
                            location,
                            {kind},
                            TaintOrigin(
                                kind,
                                self._filename(node),
                                self.cpg.node_lineno(node),
                                symbol=f"cpg:{node.node_id}:{source_name}",
                            ),
                        )
                    current = current.with_taint(taint)
            return CPGValue(current, current.taint.facts_at(location), location)
        if isinstance(expression, py_ast.BuildMap):
            return self._evaluate_map(expression, state, node)
        if isinstance(expression, (py_ast.BuildList, py_ast.BuildTuple)):
            return self._evaluate_sequence(expression, state, node)
        if isinstance(expression, py_ast.Call):
            return self._evaluate_call(expression, state, node)

        current = state
        facts: set[TaintFact] = set()
        for child in self.engine._iter_ast_children(expression):
            value = self._evaluate(child, current, node)
            current = value.state
            facts.update(value.facts)
        return CPGValue(current, frozenset(facts))

    def _evaluate_map(
        self, expression: py_ast.BuildMap, state: CPGAbstractState, node: PDGNode
    ) -> CPGValue:
        base = self._expression_location(node, expression)
        current = state.clear_binding(base)
        items = tuple(expression.args or ())
        for index in range(0, len(items), 2):
            if index + 1 >= len(items):
                break
            key = self._constant_value(items[index])
            value = self._evaluate(items[index + 1], current, node)
            current = value.state
            selector = (
                AccessSelector.key(key)
                if isinstance(key, str)
                else (
                    AccessSelector.index(key)
                    if isinstance(key, int)
                    else AccessSelector.wildcard()
                )
            )
            current = current.write(
                base.select(selector),
                value.facts,
                strong=selector.kind.value != "wildcard",
                source_base=value.location,
                operation=ProvenanceOperation.WRITE,
                filename=self._filename(node),
                line=self.cpg.node_lineno(node),
                detail="map-literal",
            )
        return CPGValue(current, current.taint.facts_at(base), base)

    def _evaluate_sequence(
        self,
        expression: py_ast.BuildList | py_ast.BuildTuple,
        state: CPGAbstractState,
        node: PDGNode,
    ) -> CPGValue:
        base = self._expression_location(node, expression)
        current = state.clear_binding(base)
        for index, item in enumerate(expression.args or ()):
            value_expression = item[0] if isinstance(item, tuple) else item
            value = self._evaluate(value_expression, current, node)
            current = value.state.write(
                base.index(index),
                value.facts,
                strong=True,
                source_base=value.location,
                operation=ProvenanceOperation.WRITE,
                filename=self._filename(node),
                line=self.cpg.node_lineno(node),
                detail="sequence-literal",
            )
        return CPGValue(current, current.taint.facts_at(base), base)

    def _evaluate_call(
        self, call: py_ast.Call, state: CPGAbstractState, node: PDGNode
    ) -> CPGValue:
        current, arguments = self._evaluate_arguments(call, state, node)

        name = self.engine._extract_call_name(call) or "<dynamic>"
        model_name = self._qualify_import_alias(name)
        call_location = self._call_location(node, call)
        argument_facts = frozenset(
            fact for argument in arguments for fact in argument.facts
        )
        source_name = self._configured_source(model_name)
        sanitizer_name = self._configured_sanitizer(model_name)
        sink_name = self.engine._match_sink_name(model_name)
        if sink_name and not self._shell_sink_is_active(call, sink_name):
            sink_name = ""

        if source_name is not None:
            taint = current.taint.write(call_location, (), strong=True)
            for kind in self.engine._source_kinds_for_name(source_name):
                taint = taint.introduce(
                    call_location,
                    {kind},
                    TaintOrigin(
                        kind,
                        self._filename(node),
                        self.cpg.node_lineno(node),
                        symbol=f"cpg:{node.node_id}:{source_name}",
                    ),
                )
            current = current.with_taint(taint)
            return CPGValue(current, taint.facts_at(call_location), call_location)

        if sanitizer_name is not None:
            removed = self.engine._sanitizers[sanitizer_name]
            taint = current.taint.write(
                call_location,
                argument_facts,
                strong=True,
                operation=ProvenanceOperation.CALL,
                filename=self._filename(node),
                line=self.cpg.node_lineno(node),
            )
            taint = taint.sanitize(
                call_location,
                call_location,
                removed,
                filename=self._filename(node),
                line=self.cpg.node_lineno(node),
                sanitizer=sanitizer_name,
            )
            current = current.with_taint(taint)
            return CPGValue(current, taint.facts_at(call_location), call_location)

        if sink_name:
            positions = self._sink_positions_for_call(sink_name)
            sink_facts = {
                fact
                for index, argument in enumerate(arguments[: len(call.args or ())])
                if index in positions
                for fact in argument.facts
            }
            for argument in arguments[len(call.args or ()) :]:
                sink_facts.update(argument.facts)
            if sink_facts:
                self._events.append((node, sink_name, frozenset(sink_facts)))
            taint = current.taint.write(call_location, (), strong=True)
            return CPGValue(current.with_taint(taint), frozenset(), call_location)

        if (
            name in {"interpreter_getitem", "operator.getitem"}
            and len(call.args or ()) >= 2
        ):
            base_location = arguments[0].location if arguments else None
            if base_location is None:
                base_location = self._location_of(
                    call.args[0], self.cpg.node_func_name(node)
                )
            key = self._constant_value(call.args[1])
            location = (
                base_location.index(key)
                if base_location is not None and isinstance(key, int)
                else (
                    base_location.key(key)
                    if base_location is not None and isinstance(key, str)
                    else (
                        base_location.select(AccessSelector.wildcard())
                        if base_location is not None
                        else None
                    )
                )
            )
            if location is None:
                return self._conservative_unresolved_read(
                    current, node, "unresolved-subscript-read"
                )
            return CPGValue(current, current.taint.facts_at(location), location)

        if name.startswith("interpreter_") or name.startswith("operator."):
            taint = current.taint.write(
                call_location,
                argument_facts,
                strong=True,
                operation=ProvenanceOperation.CALL,
                filename=self._filename(node),
                line=self.cpg.node_lineno(node),
                detail=name,
            )
            current = current.with_taint(taint)
            return CPGValue(current, taint.facts_at(call_location), call_location)

        leaf_name = name.rsplit(".", 1)[-1]
        if leaf_name in _TAINT_PRESERVING_PURE_CALLS:
            receiver = self._call_receiver(call)
            receiver_value = (
                self._evaluate(receiver, current, node)
                if receiver is not None
                else CPGValue(current)
            )
            current = receiver_value.state
            pure_facts = argument_facts | receiver_value.facts
            taint = current.taint.write(
                call_location,
                pure_facts,
                strong=True,
                operation=ProvenanceOperation.CALL,
                filename=self._filename(node),
                line=self.cpg.node_lineno(node),
                detail=name,
            )
            return CPGValue(
                current.with_taint(taint), taint.facts_at(call_location), call_location
            )
        if leaf_name in _TAINT_DROPPING_PURE_CALLS:
            taint = current.taint.write(call_location, (), strong=True)
            return CPGValue(current.with_taint(taint), frozenset(), call_location)

        if leaf_name in self._local_class_names:
            taint = current.taint.write(
                call_location,
                argument_facts,
                strong=True,
                operation=ProvenanceOperation.CALL,
                filename=self._filename(node),
                line=self.cpg.node_lineno(node),
                detail=f"constructor:{name}",
            )
            return CPGValue(
                current.with_taint(taint), taint.facts_at(call_location), call_location
            )

        summary = self._summary_for_call(node, name)
        if summary is not None:
            facts = self._instantiate_summary(summary, arguments, node, call)
            taint = current.taint.write(
                call_location,
                facts,
                strong=True,
                operation=ProvenanceOperation.CALL,
                filename=self._filename(node),
                line=self.cpg.node_lineno(node),
                detail=f"summary:{summary.procedure}",
            )
            taint = self._havoc_possible_call_side_effects(
                taint, call, arguments, node, name
            )
            taint = taint.with_uncertainty(
                AnalysisUncertainty(
                    "cpg-expression-call-summary",
                    "Nested local call used a relational summary and "
                    "conservatively havoced mutable arguments, receiver, and "
                    "module globals",
                    PrecisionLevel.CONSERVATIVE,
                    self.cpg.node_func_name(node),
                    self._filename(node),
                    self.cpg.node_lineno(node),
                    name,
                )
            )
            return CPGValue(
                current.with_taint(taint), taint.facts_at(call_location), call_location
            )

        # Unknown external calls conservatively taint their return. Existing
        # argument taint has already been propagated to that return above, but
        # do not invent new source facts on clean arguments or the receiver:
        # doing so makes an unrelated observer/lifecycle call contaminate the
        # caller's entire reachable state.
        source_kinds = {
            kind for kinds in self.engine._source_kinds.values() for kind in kinds
        } or {"unknown"}
        uncertainty = AnalysisUncertainty(
            "cpg-unknown-call-effect",
            f"Unknown call effects for {name}",
            PrecisionLevel.CONSERVATIVE,
            self.cpg.node_func_name(node),
            self._filename(node),
            self.cpg.node_lineno(node),
            name,
        )
        taint = current.taint.write(
            call_location,
            argument_facts,
            strong=True,
            operation=ProvenanceOperation.HAVOC,
            filename=self._filename(node),
            line=self.cpg.node_lineno(node),
            detail=name,
        )
        for kind in source_kinds:
            taint = taint.introduce(
                call_location,
                {kind},
                TaintOrigin(
                    kind,
                    self._filename(node),
                    self.cpg.node_lineno(node),
                    symbol=f"cpg:{node.node_id}:{name}",
                ),
            )
        taint = taint.with_uncertainty(uncertainty)
        current = current.with_taint(taint)
        return CPGValue(current, taint.facts_at(call_location), call_location)

    def _havoc_possible_call_side_effects(
        self,
        taint: FormalTaintState,
        call: py_ast.Call,
        arguments: Sequence[CPGValue],
        node: PDGNode,
        name: str,
    ) -> FormalTaintState:
        """Over-approximate side effects omitted by relational summaries."""
        source_kinds = {
            kind for kinds in self.engine._source_kinds.values() for kind in kinds
        } or {"unknown"}
        locations = {argument.location for argument in arguments if argument.location}
        receiver = self._call_receiver(call)
        receiver_location = (
            self._location_of(receiver, self.cpg.node_func_name(node))
            if receiver is not None
            else None
        )
        if receiver_location is not None:
            locations.add(receiver_location)
        locations.update(
            self._local(self._module_function, global_name)
            for global_name in self._module_globals
        )
        for location in locations:
            for kind in source_kinds:
                taint = taint.introduce(
                    location,
                    {kind},
                    TaintOrigin(
                        kind,
                        self._filename(node),
                        self.cpg.node_lineno(node),
                        symbol=f"cpg:{node.node_id}:{name}:summary-side-effect",
                    ),
                )
        return taint

    def _conservative_unresolved_read(
        self, state: CPGAbstractState, node: PDGNode, code: str
    ) -> CPGValue:
        """Represent an unresolvable read by a tainted synthetic value."""
        location = self._expression_location(node, node.ast_node)
        source_kinds = {
            kind for kinds in self.engine._source_kinds.values() for kind in kinds
        } or {"unknown"}
        taint = state.taint.write(location, (), strong=True)
        for kind in source_kinds:
            taint = taint.introduce(
                location,
                {kind},
                TaintOrigin(
                    kind,
                    self._filename(node),
                    self.cpg.node_lineno(node),
                    symbol=f"cpg:{node.node_id}:{code}",
                ),
            )
        taint = taint.with_uncertainty(
            AnalysisUncertainty(
                code,
                "Unresolvable read was conservatively treated as tainted",
                PrecisionLevel.CONSERVATIVE,
                self.cpg.node_func_name(node),
                self._filename(node),
                self.cpg.node_lineno(node),
                type(node.ast_node).__name__,
            )
        )
        result = state.with_taint(taint)
        return CPGValue(result, taint.facts_at(location), location)

    # ----------------------------------------------------------- graph flow
    def _successors(
        self,
        config: CPGConfiguration,
        node: PDGNode,
        state: CPGAbstractState,
    ) -> tuple[_Transition, ...]:
        call_edges = self._local_call_edges(node)
        top_call = self._top_level_call(node.ast_node)
        if call_edges and top_call is not None and not self._is_modeled_call(top_call):
            if len(
                config.call_context
            ) >= self.engine._max_call_depth or self._would_recurse(
                config, node, call_edges
            ):
                return self._summary_resume_transitions(config, node, state, call_edges)
            transitions = []
            for edge in call_edges:
                callee = self.cpg.node_func_name(edge.target)
                entered = self._enter_call(node, top_call, callee, state)
                transitions.append(
                    _Transition(
                        CPGConfiguration(
                            edge.target.node_id,
                            (*config.call_context, node.node_id),
                        ),
                        entered,
                        CPGEdgeKind.CALL.value,
                    )
                )
            return tuple(transitions)

        return_edges = tuple(
            edge
            for edge in self.cpg._cpg_edges_out.get(node.node_id, ())
            if edge.kind is CPGEdgeKind.RETURN_EDGE
        )
        if return_edges and config.call_context:
            call_site_id = config.call_context[-1]
            matched = tuple(
                edge for edge in return_edges if edge.target.node_id == call_site_id
            )
            if not matched:
                self._diagnostics.add(
                    CPGTaintDiagnostic(
                        "No RETURN_EDGE matches the active call site",
                        "cpg-unmatched-return-edge",
                        True,
                        self.cpg.node_func_name(node),
                        PrecisionLevel.UNSUPPORTED.value,
                        self._filename(node),
                        self.cpg.node_lineno(node),
                        "return",
                    )
                )
                return ()
            call_site = matched[0].target
            resumed = self._resume_call(node, call_site, state)
            return self._normal_transitions(
                CPGConfiguration(call_site.node_id, config.call_context[:-1]),
                call_site,
                resumed,
                skip_call_edges=True,
            )

        return self._normal_transitions(config, node, state)

    def _normal_transitions(
        self,
        config: CPGConfiguration,
        node: PDGNode,
        state: CPGAbstractState,
        *,
        skip_call_edges: bool = False,
    ) -> tuple[_Transition, ...]:
        transitions: list[_Transition] = []
        for edge in self.cpg._cpg_edges_out.get(node.node_id, ()):
            if edge.kind in CFG_KINDS:
                transitions.append(
                    _Transition(
                        CPGConfiguration(edge.target.node_id, config.call_context),
                        state,
                        edge.kind.value,
                    )
                )
            elif edge.kind is CPGEdgeKind.DATA:
                # DATA edges are dependence evidence, not executable control
                # flow.  Jumping across the CFG can bypass a strong overwrite
                # (and produced false positives in the original traversal).
                # Count every consulted edge, including evidence rejected by
                # the current abstract state; summaries and witnesses consume
                # the same relation without transporting the whole state.
                self._data_transitions += 1
            elif edge.kind is CPGEdgeKind.CALL and not skip_call_edges:
                # CALL edges are handled as a group before normal traversal.
                continue
        return tuple(transitions)

    def _enter_call(
        self,
        call_site: PDGNode,
        call: py_ast.Call,
        callee: str,
        state: CPGAbstractState,
    ) -> CPGAbstractState:
        current = state
        caller = self.cpg.node_func_name(call_site)
        parameters, keyword_parameters = self._callee_parameters(callee)
        current, values = self._evaluate_positional_arguments(call, current, call_site)
        keyword_values: dict[str, CPGValue] = {}
        for name, argument in call.kwds or ():
            value = self._evaluate(argument, current, call_site)
            current = value.state
            keyword_values[name] = value

        for local_name in self._function_local_names(callee):
            current = current.clear_binding(self._local(callee, local_name))
        for parameter, value in zip(parameters, values):
            location = self._local(callee, parameter)
            current = current.write(location, value.facts, strong=True)
            if value.location is not None:
                current = replace(
                    current,
                    may_aliases=current.may_aliases
                    | {_ordered_alias(location, value.location)},
                )
        for public_name, value in keyword_values.items():
            keyword_parameter = keyword_parameters.get(public_name)
            if keyword_parameter is None:
                continue
            location = self._local(callee, keyword_parameter)
            current = current.write(location, value.facts, strong=True)
            if value.location is not None:
                current = replace(
                    current,
                    may_aliases=current.may_aliases
                    | {_ordered_alias(location, value.location)},
                )
        # Keep caller locals in the state; scoped roots prevent collisions and
        # allow exact restoration after the matched return.
        _ = caller
        return current

    def _resume_call(
        self, exit_node: PDGNode, call_site: PDGNode, state: CPGAbstractState
    ) -> CPGAbstractState:
        callee = self.cpg.node_func_name(exit_node)
        caller = self.cpg.node_func_name(call_site)
        return_location = self._return_location(callee)
        returned = state.taint.facts_at(return_location)
        escaped_aliases = frozenset(
            alias
            for alias in state.aliases_of(return_location)
            if alias != return_location and not self._is_function_local(alias, callee)
        )
        ast_node = call_site.ast_node
        current = state
        if isinstance(ast_node, py_ast.Assign):
            for target in ast_node.lcls or ():
                if isinstance(target, py_ast.Local) and target.name:
                    location = self._local(caller, target.name)
                    current = current.clear_binding(location).write(
                        location,
                        returned,
                        strong=True,
                        source_base=return_location,
                        operation=ProvenanceOperation.RETURN,
                        filename=self._filename(call_site),
                        line=self.cpg.node_lineno(call_site),
                        detail=callee,
                    )
                    current = self._attach_aliases(current, location, escaped_aliases)
        elif isinstance(ast_node, py_ast.AnnAssign):
            target = ast_node.target
            if isinstance(target, py_ast.Local) and target.name:
                location = self._local(caller, target.name)
                current = current.clear_binding(location).write(
                    location,
                    returned,
                    strong=True,
                    source_base=return_location,
                    operation=ProvenanceOperation.RETURN,
                )
                current = self._attach_aliases(current, location, escaped_aliases)
        elif isinstance(ast_node, py_ast.Return):
            location = self._return_location(caller)
            current = current.write(
                location,
                returned,
                strong=True,
                source_base=return_location,
                operation=ProvenanceOperation.RETURN,
            )
            current = self._attach_aliases(current, location, escaped_aliases)

        for local_name in self._function_local_names(callee):
            current = current.clear_binding(self._local(callee, local_name))
        current = current.clear_binding(self._return_location(callee))
        return current

    @staticmethod
    def _is_function_local(location: TaintLocation, function: str) -> bool:
        root = location.root
        return isinstance(root, tuple) and bool(root) and root[0] == function

    @staticmethod
    def _attach_aliases(
        state: CPGAbstractState,
        destination: TaintLocation,
        aliases: Iterable[TaintLocation],
    ) -> CPGAbstractState:
        pairs = {_ordered_alias(destination, alias) for alias in aliases}
        return replace(state, may_aliases=state.may_aliases | pairs)

    def _summary_resume_transitions(
        self,
        config: CPGConfiguration,
        node: PDGNode,
        state: CPGAbstractState,
        call_edges: Sequence[Any],
    ) -> tuple[_Transition, ...]:
        call = self._top_level_call(node.ast_node)
        if call is None:
            return self._normal_transitions(config, node, state)
        joined = CPGAbstractState.bottom()
        for edge in call_edges:
            summary = self._summaries.get(self.cpg.node_func_name(edge.target))
            if summary is None:
                continue
            evaluated_state, arguments = self._evaluate_arguments(call, state, node)
            facts = self._instantiate_summary(summary, arguments, node, call)
            resumed = self._apply_call_result(node, evaluated_state, facts)
            resumed = resumed.with_taint(
                self._havoc_possible_call_side_effects(
                    resumed.taint,
                    call,
                    arguments,
                    node,
                    summary.procedure,
                )
            )
            joined = joined.join(resumed)
            self._summary_applications += 1
        joined = joined.with_uncertainty(
            AnalysisUncertainty(
                "cpg-call-depth-summary",
                "Call depth bound reached; applied a conservative relational summary",
                PrecisionLevel.CONSERVATIVE,
                self.cpg.node_func_name(node),
                self._filename(node),
                self.cpg.node_lineno(node),
                "call",
            )
        )
        return self._normal_transitions(config, node, joined, skip_call_edges=True)

    def _apply_call_result(
        self, node: PDGNode, state: CPGAbstractState, facts: Iterable[TaintFact]
    ) -> CPGAbstractState:
        function = self.cpg.node_func_name(node)
        ast_node = node.ast_node
        current = state
        if isinstance(ast_node, py_ast.Assign):
            for target in ast_node.lcls or ():
                if isinstance(target, py_ast.Local) and target.name:
                    location = self._local(function, target.name)
                    current = current.clear_binding(location).write(
                        location, facts, strong=True, operation=ProvenanceOperation.CALL
                    )
        elif isinstance(ast_node, py_ast.Return):
            current = current.write(
                self._return_location(function),
                facts,
                strong=True,
                operation=ProvenanceOperation.CALL,
            )
        return current

    # --------------------------------------------------------------- summary
    def _build_summaries(self) -> dict[str, CPGProcedureSummary]:
        summaries = {
            function: CPGProcedureSummary(
                function, tuple(self._callee_parameters(function)[0])
            )
            for function in self.cpg._pdgs
        }
        # The summary domain is finite: parameter tokens and concrete modeled
        # source occurrences.  Iteration therefore computes a least fixed point
        # even for mutually recursive procedures.
        token_bound = (
            1
            + sum(len(summary.parameters) for summary in summaries.values())
            + sum(1 for _node in self.cpg.nodes())
            * max(1, len(self.engine._source_kinds))
        )
        for _iteration in range(token_bound):
            changed = False
            updated: dict[str, CPGProcedureSummary] = {}
            for function in summaries:
                summary = self._derive_summary(function, summaries)
                updated[function] = summary
                changed = changed or summary != summaries[function]
            summaries = updated
            if not changed:
                break
        return summaries

    def _derive_summary(
        self,
        function: str,
        summaries: Mapping[str, CPGProcedureSummary],
    ) -> CPGProcedureSummary:
        pdg = self.cpg._pdgs[function]
        parameters, _keywords = self._callee_parameters(function)
        if pdg.entry is None:
            return CPGProcedureSummary(function, tuple(parameters))
        initial = {
            parameter: frozenset({_SummaryToken.parameter(index)})
            for index, parameter in enumerate(parameters)
        }
        states: dict[int, dict[str, frozenset[_SummaryToken]]] = {
            pdg.entry.node_id: initial
        }
        pending = deque([pdg.entry])
        returns: set[_SummaryToken] = set()
        sinks: dict[tuple[str, int | None, int], set[_SummaryToken]] = {}
        while pending:
            node = pending.popleft()
            incoming = states[node.node_id]
            outgoing, returned, emitted = self._summary_transfer(
                node, incoming, summaries
            )
            returns.update(returned)
            for sink_name, line, sink_node_id, tokens in emitted:
                sinks.setdefault((sink_name, line, sink_node_id), set()).update(tokens)
            for edge in self.cpg._cpg_edges_out.get(node.node_id, ()):
                if edge.kind not in CFG_KINDS:
                    continue
                if self.cpg.node_func_name(edge.target) != function:
                    continue
                target_seen = edge.target.node_id in states
                previous = states.get(edge.target.node_id, {})
                joined = self._join_summary_environments(previous, outgoing)
                if target_seen and joined == previous:
                    continue
                states[edge.target.node_id] = joined
                pending.append(edge.target)

        source_occurrences = frozenset(
            (token.source_kind, token.source_node_id, token.source_name)
            for token in returns
            if token.kind == "source"
        )
        summary_sinks = frozenset(
            CPGSummarySink(
                sink_name,
                frozenset(
                    token.parameter_index
                    for token in tokens
                    if token.kind == "parameter"
                ),
                frozenset(
                    token.source_kind for token in tokens if token.kind == "source"
                ),
                line,
                frozenset(
                    (token.source_kind, token.source_node_id, token.source_name)
                    for token in tokens
                    if token.kind == "source"
                ),
                sink_node_id,
            )
            for (sink_name, line, sink_node_id), tokens in sinks.items()
        )
        return CPGProcedureSummary(
            function,
            tuple(parameters),
            frozenset(
                token.parameter_index for token in returns if token.kind == "parameter"
            ),
            frozenset(kind for kind, _node_id, _name in source_occurrences),
            summary_sinks,
            source_occurrences,
        )

    def _summary_transfer(
        self,
        node: PDGNode,
        incoming: Mapping[str, frozenset[_SummaryToken]],
        summaries: Mapping[str, CPGProcedureSummary],
    ) -> tuple[
        dict[str, frozenset[_SummaryToken]],
        frozenset[_SummaryToken],
        tuple[tuple[str, int | None, int, frozenset[_SummaryToken]], ...],
    ]:
        environment = dict(incoming)
        ast_node = node.ast_node
        returned: frozenset[_SummaryToken] = frozenset()
        if isinstance(ast_node, py_ast.Assign):
            value = self._summary_expression(
                ast_node.expr, environment, node, summaries
            )
            for target in ast_node.lcls or ():
                if isinstance(target, py_ast.Local) and target.name:
                    environment[target.name] = value
        elif isinstance(ast_node, py_ast.AnnAssign):
            value = self._summary_expression(
                ast_node.value, environment, node, summaries
            )
            if isinstance(ast_node.target, py_ast.Local) and ast_node.target.name:
                environment[ast_node.target.name] = value
        elif isinstance(ast_node, (py_ast.SetAttr, py_ast.SetSubscript)):
            base = self._first_local(ast_node.expr)
            if base:
                value = self._summary_expression(
                    ast_node.value, environment, node, summaries
                )
                environment[base] = environment.get(base, frozenset()) | value
        elif isinstance(ast_node, py_ast.Delete):
            if isinstance(ast_node.lcl, py_ast.Local) and ast_node.lcl.name:
                environment[ast_node.lcl.name] = frozenset()
        elif isinstance(ast_node, py_ast.Return):
            returned = frozenset(
                token
                for expression in ast_node.exprs or ()
                for token in self._summary_expression(
                    expression, environment, node, summaries
                )
            )

        emitted = []
        for call in self._calls_in_statement(ast_node):
            raw_name = self.engine._extract_call_name(call) or ""
            sink_name = self.engine._match_sink_name(
                self._qualify_import_alias(raw_name)
            )
            if not sink_name or not self._shell_sink_is_active(call, sink_name):
                continue
            positions = self._sink_positions_for_call(sink_name)
            tokens = frozenset(
                token
                for index, argument in enumerate(call.args or ())
                if index in positions
                for token in self._summary_expression(
                    argument, environment, node, summaries
                )
            )
            if tokens:
                emitted.append(
                    (sink_name, self.cpg.node_lineno(node), node.node_id, tokens)
                )
        return environment, returned, tuple(emitted)

    def _summary_expression(
        self,
        expression: Any,
        environment: Mapping[str, frozenset[_SummaryToken]],
        node: PDGNode,
        summaries: Mapping[str, CPGProcedureSummary],
    ) -> frozenset[_SummaryToken]:
        if expression is None or isinstance(expression, py_ast.Existing):
            return frozenset()
        if isinstance(expression, py_ast.Local):
            return environment.get(expression.name or "", frozenset())
        if isinstance(expression, (py_ast.GetAttr, py_ast.GetSubscript)):
            base = self._first_local(expression)
            return environment.get(base or "", frozenset())
        if isinstance(expression, py_ast.Call):
            name = self.engine._extract_call_name(expression) or "<dynamic>"
            model_name = self._qualify_import_alias(name)
            arguments = [
                self._summary_expression(argument, environment, node, summaries)
                for argument in expression.args or ()
            ]
            arguments.extend(
                self._summary_expression(argument, environment, node, summaries)
                for _name, argument in expression.kwds or ()
            )
            receiver = self._call_receiver(expression)
            receiver_tokens = (
                self._summary_expression(receiver, environment, node, summaries)
                if receiver is not None
                else frozenset()
            )
            source_name = self._configured_source(model_name)
            if source_name is not None:
                return frozenset(
                    _SummaryToken.source(kind, node.node_id, source_name)
                    for kind in self.engine._source_kinds_for_name(source_name)
                )
            sanitizer_name = self._configured_sanitizer(model_name)
            if sanitizer_name is not None:
                removed = self.engine._sanitizers[sanitizer_name]
                values = frozenset(token for value in arguments for token in value)
                if "*" in removed:
                    return frozenset()
                return frozenset(
                    token
                    for token in values
                    if token.kind != "source" or token.source_kind not in removed
                )
            if self.engine._match_sink_name(model_name):
                return frozenset()
            leaf_name = name.rsplit(".", 1)[-1]
            if leaf_name in _TAINT_PRESERVING_PURE_CALLS:
                return receiver_tokens | frozenset(
                    token for value in arguments for token in value
                )
            if leaf_name in _TAINT_DROPPING_PURE_CALLS:
                return frozenset()
            summary = self._summary_for_name(name, summaries)
            if summary is not None:
                bound_arguments = self._bind_summary_arguments(
                    summary.parameters, arguments, expression
                )
                result: set[_SummaryToken] = set()
                for index in summary.return_parameters:
                    if index >= len(bound_arguments):
                        continue
                    argument = bound_arguments[index]
                    if argument is not None:
                        result.update(argument)
                result.update(
                    _SummaryToken.source(kind, source_node_id, source_name)
                    for kind, source_node_id, source_name in summary.return_sources
                )
                # A recursive summary starts at bottom.  Passing through all
                # arguments is the conservative seed that lets identity-style
                # recursion converge instead of unsoundly returning clean.
                if not result and summary.procedure == self.cpg.node_func_name(node):
                    result.update(token for value in arguments for token in value)
                return frozenset(result)
            unknown_tokens: set[_SummaryToken] = {
                token for value in arguments for token in value
            }
            unknown_tokens.update(
                _SummaryToken.source(kind, node.node_id, name)
                for kinds in self.engine._source_kinds.values()
                for kind in kinds
            )
            return frozenset(unknown_tokens)
        return frozenset(
            token
            for child in self.engine._iter_ast_children(expression)
            for token in self._summary_expression(child, environment, node, summaries)
        )

    @staticmethod
    def _join_summary_environments(
        left: Mapping[str, frozenset[_SummaryToken]],
        right: Mapping[str, frozenset[_SummaryToken]],
    ) -> dict[str, frozenset[_SummaryToken]]:
        return {
            name: left.get(name, frozenset()) | right.get(name, frozenset())
            for name in left.keys() | right.keys()
        }

    def _summary_for_name(
        self,
        name: str,
        summaries: Mapping[str, CPGProcedureSummary],
    ) -> CPGProcedureSummary | None:
        candidates = [
            summary
            for procedure, summary in summaries.items()
            if procedure == name
            or procedure.rsplit(".", 1)[-1] == name.rsplit(".", 1)[-1]
        ]
        return candidates[0] if len(candidates) == 1 else None

    def _calls_in_statement(self, node: Any) -> tuple[py_ast.Call, ...]:
        if isinstance(node, (py_ast.FunctionDef, py_ast.ClassDef)):
            return ()
        return tuple(
            item for item in self._walk_ast(node) if isinstance(item, py_ast.Call)
        )

    def _first_local(self, node: Any) -> str | None:
        return next(
            (
                item.name
                for item in self._walk_ast(node)
                if isinstance(item, py_ast.Local) and item.name
            ),
            None,
        )

    @staticmethod
    def _call_receiver(call: py_ast.Call) -> Any | None:
        expression = getattr(call, "expr", None)
        if isinstance(expression, (py_ast.GetAttr, py_ast.MethodCall)):
            return getattr(expression, "expr", None)
        return None

    def _instantiate_summary(
        self,
        summary: CPGProcedureSummary,
        arguments: Sequence[CPGValue],
        node: PDGNode,
        call: py_ast.Call,
    ) -> frozenset[TaintFact]:
        bound_arguments = self._bind_summary_arguments(
            summary.parameters, arguments, call
        )
        result: set[TaintFact] = set()
        for index in summary.return_parameters:
            if index >= len(bound_arguments):
                continue
            argument = bound_arguments[index]
            if argument is not None:
                result.update(argument.facts)
        location = self._call_location(node)
        occurrences = summary.return_sources or frozenset(
            (kind, -1, summary.procedure) for kind in summary.return_source_kinds
        )
        for kind, source_node_id, source_name in occurrences:
            result.add(
                TaintFact(
                    location,
                    kind,
                    TaintOrigin(
                        kind,
                        self._filename(node),
                        self.cpg.node_lineno(node),
                        symbol=(
                            f"cpg:{source_node_id}:{source_name}"
                            if source_node_id >= 0
                            else f"cpg-summary:{summary.procedure}"
                        ),
                    ),
                )
            )
        self._emit_summary_sinks(summary, bound_arguments, node)
        return frozenset(result)

    def _emit_summary_sinks(
        self,
        summary: CPGProcedureSummary,
        arguments: Sequence[CPGValue | None],
        node: PDGNode,
    ) -> None:
        for sink in summary.sinks:
            facts: set[TaintFact] = set()
            for index in sink.parameter_indices:
                if index >= len(arguments):
                    continue
                argument = arguments[index]
                if argument is not None:
                    facts.update(argument.facts)
            occurrences = sink.source_occurrences or frozenset(
                (kind, -1, summary.procedure) for kind in sink.source_kinds
            )
            for kind, source_node_id, source_name in occurrences:
                facts.add(
                    TaintFact(
                        self._call_location(node),
                        kind,
                        TaintOrigin(
                            kind,
                            self._filename(node),
                            sink.line or self.cpg.node_lineno(node),
                            symbol=(
                                f"cpg:{source_node_id}:{source_name}"
                                if source_node_id >= 0
                                else f"cpg-summary:{summary.procedure}"
                            ),
                        ),
                    )
                )
            if facts:
                sink_node = self.cpg.node_by_id(sink.sink_node_id) or node
                self._events.append((sink_node, sink.sink_name, frozenset(facts)))

    @staticmethod
    def _bind_summary_arguments(
        parameters: Sequence[str],
        arguments: Sequence[Any],
        call: py_ast.Call,
    ) -> list[Any | None]:
        """Bind positional/keyword actuals to relational summary parameters."""

        bound: list[Any | None] = [None] * len(parameters)
        positional_count = len(call.args or ())
        for index, value in enumerate(arguments[:positional_count]):
            if index < len(bound):
                bound[index] = value
        keyword_values = arguments[positional_count:]
        for (public_name, _expression), value in zip(call.kwds or (), keyword_values):
            try:
                index = parameters.index(public_name)
            except ValueError:
                continue
            bound[index] = value
        return bound

    # -------------------------------------------------------------- findings
    def _sink_events(
        self, expression: Any, value: CPGValue, node: PDGNode
    ) -> tuple[tuple[str, frozenset[TaintFact]], ...]:
        call = expression if isinstance(expression, py_ast.Call) else None
        if call is None:
            return ()
        raw_name = self.engine._extract_call_name(call) or ""
        sink_name = self.engine._match_sink_name(
            self._qualify_import_alias(raw_name)
        )
        if not sink_name or not self._shell_sink_is_active(call, sink_name):
            return ()
        positions = self._sink_positions_for_call(sink_name)
        facts: set[TaintFact] = set()
        current = value.state
        for index, argument in enumerate(call.args or ()):
            if index not in positions:
                continue
            evaluated = self._evaluate(argument, current, node)
            current = evaluated.state
            facts.update(evaluated.facts)
        for _name, argument in call.kwds or ():
            evaluated = self._evaluate(argument, current, node)
            current = evaluated.state
            facts.update(evaluated.facts)
        return ((sink_name, frozenset(facts)),) if facts else ()

    def _build_findings(self) -> list[TaintFinding]:
        findings: list[TaintFinding] = []
        seen: set[tuple[Any, ...]] = set()
        for sink_node, sink_name, facts in self._events:
            by_origin: dict[TaintOrigin, set[str]] = {}
            for fact in facts:
                by_origin.setdefault(fact.origin, set()).add(fact.kind)
            sink_kinds = self.engine._sink_kinds.get(sink_name, frozenset())
            for origin, kinds in by_origin.items():
                source_kinds = frozenset(kinds)
                source_node = self._source_node(origin) or sink_node
                for rule in self.engine._matching_rules(source_kinds, sink_name):
                    matched = frozenset(source_kinds & rule.source_kinds)
                    if not matched or not (sink_kinds & rule.sink_kinds):
                        continue
                    key = (
                        source_node.node_id,
                        sink_node.node_id,
                        sink_name,
                        rule.rule_id,
                        matched,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    path = self._witness_path(source_node, sink_node, origin)
                    findings.append(
                        TaintFinding(
                            cwe=self.engine._sinks.get(sink_name, "") or rule.cwe or "",
                            severity=self.engine._sink_severity.get(
                                sink_name, rule.severity
                            ),
                            source_label=f"from:{origin.symbol or origin.kind}",
                            sink_label=sink_name,
                            source_node=source_node,
                            sink_node=sink_node,
                            path_nodes=path,
                            tags=matched,
                            sanitizers=self._sanitizers_for_origin(origin, matched),
                            rule_id=rule.rule_id,
                            rule_title=rule.title,
                            suggestion=rule.suggestion or "",
                        )
                    )
        return sorted(findings, key=lambda finding: finding.dedup_key)

    def _sanitizers_for_origin(
        self, origin: TaintOrigin, kinds: frozenset[str]
    ) -> frozenset[str]:
        return frozenset(
            edge.detail
            for state in self._states.values()
            for edge in state.taint.provenance
            if edge.operation is ProvenanceOperation.SANITIZE
            and edge.detail
            and edge.target.origin == origin
            and edge.target.kind in kinds
        )

    def _witness_path(
        self, source: PDGNode, sink: PDGNode, origin: TaintOrigin
    ) -> list[PDGNode]:
        symbol = origin.symbol or ""
        candidates = [
            config for config in self._states if config.node_id == sink.node_id
        ]
        if not candidates:
            return [source, sink] if source is not sink else [sink]
        current = min(candidates, key=lambda item: len(item.call_context))
        path = [sink]
        visited: set[CPGConfiguration] = set()
        while current not in visited:
            visited.add(current)
            predecessor = self._predecessors.get((current, symbol))
            if predecessor is None:
                break
            current, _edge_kind = predecessor
            node = self.cpg.node_by_id(current.node_id)
            if node is not None and (not path or path[-1] is not node):
                path.append(node)
            if current.node_id == source.node_id:
                break
        path.reverse()
        if not path or path[0] is not source:
            path.insert(0, source)
        if path[-1] is not sink:
            path.append(sink)
        if not self._is_graph_path(path):
            graph_path = self._shortest_graph_witness(source, sink)
            if graph_path:
                return graph_path
        return path

    def _is_graph_path(self, path: Sequence[PDGNode]) -> bool:
        return all(
            any(edge.target is target for edge in source.edges_out)
            or any(
                edge.target is target
                for edge in self.cpg._cpg_edges_out.get(source.node_id, ())
            )
            for source, target in zip(path, path[1:])
        )

    def _shortest_graph_witness(self, source: PDGNode, sink: PDGNode) -> list[PDGNode]:
        allowed = CFG_KINDS | {
            CPGEdgeKind.DATA,
            CPGEdgeKind.CALL,
            CPGEdgeKind.RETURN_EDGE,
        }
        pending: deque[tuple[PDGNode, list[PDGNode]]] = deque([(source, [source])])
        visited = {source.node_id}
        while pending:
            current, path = pending.popleft()
            if current is sink:
                return path
            for edge in self.cpg._cpg_edges_out.get(current.node_id, ()):
                if edge.kind not in allowed or edge.target.node_id in visited:
                    continue
                visited.add(edge.target.node_id)
                pending.append((edge.target, [*path, edge.target]))
        return []

    def _record_predecessors(
        self,
        source: CPGConfiguration,
        target: CPGConfiguration,
        state: CPGAbstractState,
        edge_kind: str,
    ) -> None:
        for fact in state.taint.facts:
            symbol = fact.origin.symbol or ""
            self._predecessors.setdefault((target, symbol), (source, edge_kind))

    # --------------------------------------------------------------- helpers
    def _location_of(self, expression: Any, function: str) -> TaintLocation | None:
        if isinstance(expression, py_ast.Local) and expression.name:
            return self._local(function, expression.name)
        if isinstance(expression, py_ast.GetAttr):
            base = self._location_of(expression.expr, function)
            name = self.engine._resolve_call_expr(expression.name)
            return base.attribute(name) if base is not None and name else None
        if isinstance(expression, py_ast.GetSubscript):
            return self._location_of_subscript(
                expression.expr, expression.subscript, function
            )
        return None

    def _location_of_setattr(
        self, statement: py_ast.SetAttr, function: str
    ) -> TaintLocation | None:
        base = self._location_of(statement.expr, function)
        name = self.engine._resolve_call_expr(statement.name)
        return base.attribute(name) if base is not None and name else None

    def _location_of_subscript(
        self, base_expr: Any, key_expr: Any, function: str
    ) -> TaintLocation | None:
        base = self._location_of(base_expr, function)
        if base is None:
            return None
        key = self._constant_value(key_expr)
        if isinstance(key, int):
            return base.index(key)
        if isinstance(key, str):
            return base.key(key)
        return base.select(AccessSelector.wildcard())

    @staticmethod
    def _constant_value(expression: Any) -> object | None:
        if isinstance(expression, py_ast.Existing):
            try:
                value = expression.constantValue()
                return cast(object, value)
            except Exception:
                return None
        return None

    def _configured_source(self, name: str) -> str | None:
        exact = [
            source
            for source in self.engine._sources
            if source.lower() == name.lower()
        ]
        if len(exact) == 1:
            return exact[0]
        matches = {
            source
            for source in self.engine._sources
            if source.lower().endswith(f".{name.lower()}")
            or self._name_matches(name, source)
        }
        return next(iter(matches)) if len(matches) == 1 else None

    def _collect_import_aliases(self) -> dict[str, str]:
        """Recover module and from-import aliases from the lowered CPG AST."""
        aliases: dict[str, str] = {}
        assignments: list[py_ast.Assign] = []
        for node in self.cpg.nodes():
            ast_node = node.ast_node
            if not isinstance(ast_node, py_ast.Assign):
                continue
            assignments.append(ast_node)
            destinations = tuple(ast_node.lcls or ())
            if len(destinations) != 1 or not isinstance(
                destinations[0], py_ast.Local
            ):
                continue
            if isinstance(ast_node.expr, py_ast.Import):
                local_name = destinations[0].name or ""
                imported_name = ast_node.expr.name or ""
                if local_name and imported_name:
                    aliases[local_name] = imported_name

        changed = True
        while changed:
            changed = False
            for assignment in assignments:
                destinations = tuple(assignment.lcls or ())
                if len(destinations) != 1 or not isinstance(
                    destinations[0], py_ast.Local
                ):
                    continue
                expression = assignment.expr
                if not isinstance(expression, py_ast.GetAttr):
                    continue
                base = self.engine._resolve_call_expr(expression.expr) or ""
                attribute = self.engine._resolve_call_expr(expression.name) or ""
                qualified_base = aliases.get(base)
                local_name = destinations[0].name or ""
                if not qualified_base or not attribute or not local_name:
                    continue
                qualified = f"{qualified_base}.{attribute}"
                if aliases.get(local_name) != qualified:
                    aliases[local_name] = qualified
                    changed = True
        return aliases

    def _qualify_import_alias(self, name: str) -> str:
        if not name:
            return name
        head, separator, tail = name.partition(".")
        qualified = self._import_aliases.get(head)
        if not qualified:
            return name
        return f"{qualified}.{tail}" if separator else qualified

    def _shell_sink_is_active(self, call: py_ast.Call, sink_name: str) -> bool:
        """Treat argv-based subprocess execution separately from shell sinks."""
        if self.engine._sinks.get(sink_name) != "CWE-78":
            return True
        configured = sink_name.lower()
        if not configured.startswith("subprocess."):
            return True
        if configured.rsplit(".", 1)[-1] not in _SHELL_OPTION_SUBPROCESS_CALLS:
            return True
        for keyword, value in call.kwds or ():
            if keyword != "shell":
                continue
            constant = self._constant_value(value)
            return constant is not False
        return False

    def _sink_positions_for_call(self, sink_name: str) -> frozenset[int]:
        """Normalize model ports to explicit arguments in source-level calls."""
        if (
            self.engine._sinks.get(sink_name) == "CWE-89"
            and sink_name.rsplit(".", 1)[-1].lower()
            in _SQL_QUERY_ARGUMENT_CALLS
        ):
            return frozenset({0})
        return self.engine._sink_positions.get(sink_name, frozenset({0}))

    def _configured_sanitizer(self, name: str) -> str | None:
        exact = [
            sanitizer
            for sanitizer in self.engine._sanitizers
            if sanitizer.lower() == name.lower()
        ]
        if len(exact) == 1:
            return exact[0]
        matches = {
            sanitizer
            for sanitizer in self.engine._sanitizers
            if sanitizer.lower().endswith(f".{name.lower()}")
            or self._name_matches(name, sanitizer)
        }
        return next(iter(matches)) if len(matches) == 1 else None

    @staticmethod
    def _name_matches(actual: str, configured: str) -> bool:
        return actual.lower() == configured.lower() or (
            "." not in configured
            and actual.rsplit(".", 1)[-1].lower() == configured.lower()
        )

    def _top_level_call(self, ast_node: Any) -> py_ast.Call | None:
        call = self.engine._call_expr(ast_node)
        return call if isinstance(call, py_ast.Call) else None

    def _local_call_edges(self, node: PDGNode) -> tuple[Any, ...]:
        call = self._top_level_call(node.ast_node)
        name = self.engine._extract_call_name(call) if call is not None else None
        if not name:
            return ()
        return tuple(
            edge
            for edge in self.cpg._cpg_edges_out.get(node.node_id, ())
            if edge.kind is CPGEdgeKind.CALL
            and self._function_name_matches(name, self.cpg.node_func_name(edge.target))
        )

    def _is_modeled_call(self, call: py_ast.Call) -> bool:
        name = self.engine._extract_call_name(call) or ""
        model_name = self._qualify_import_alias(name)
        return bool(
            self._configured_source(model_name)
            or self._configured_sanitizer(model_name)
            or self.engine._match_sink_name(model_name)
        )

    @staticmethod
    def _function_name_matches(call_name: str, function: str) -> bool:
        return call_name == function or (
            call_name.rsplit(".", 1)[-1] == function.rsplit(".", 1)[-1]
        )

    def _evaluate_positional_arguments(
        self, call: py_ast.Call, state: CPGAbstractState, node: PDGNode
    ) -> tuple[CPGAbstractState, list[CPGValue]]:
        current = state
        values: list[CPGValue] = []
        for argument in call.args or ():
            value = self._evaluate(argument, current, node)
            current = value.state
            values.append(value)
        return current, values

    def _evaluate_arguments(
        self, call: py_ast.Call, state: CPGAbstractState, node: PDGNode
    ) -> tuple[CPGAbstractState, list[CPGValue]]:
        current, values = self._evaluate_positional_arguments(call, state, node)
        for _name, argument in call.kwds or ():
            value = self._evaluate(argument, current, node)
            current = value.state
            values.append(value)
        for argument in (call.vargs, call.kargs):
            if argument is None:
                continue
            value = self._evaluate(argument, current, node)
            current = value.state
            values.append(value)
        return current, values

    def _would_recurse(
        self,
        config: CPGConfiguration,
        node: PDGNode,
        call_edges: Sequence[Any],
    ) -> bool:
        active_functions = {self.cpg.node_func_name(node)}
        for call_site_id in config.call_context:
            call_site = self.cpg.node_by_id(call_site_id)
            if call_site is not None:
                active_functions.add(self.cpg.node_func_name(call_site))
        return any(
            self.cpg.node_func_name(edge.target) in active_functions
            for edge in call_edges
        )

    def _callee_parameters(self, function: str) -> tuple[list[str], dict[str, str]]:
        pdg = self.cpg._pdgs.get(function)
        code = getattr(getattr(pdg, "cfg", None), "code", None)
        parameters = getattr(code, "codeparameters", None)
        if parameters is None:
            return [], {}
        locals_ = list(getattr(parameters, "posonlyparams", None) or ()) + list(
            getattr(parameters, "params", None) or ()
        )
        names = [
            item.name
            for item in locals_
            if isinstance(item, py_ast.Local) and item.name
        ]
        public = list(getattr(parameters, "posonlynames", None) or ()) + list(
            getattr(parameters, "paramnames", None) or ()
        )
        return names, {
            public_name: local_name
            for public_name, local_name in zip(public, names)
            if public_name and local_name
        }

    def _function_local_names(self, function: str) -> frozenset[str]:
        return self._local_bindings.get(function, frozenset())

    def _walk_ast(self, node: Any) -> Iterable[Any]:
        if node is None:
            return ()
        result = [node]
        if isinstance(node, (py_ast.FunctionDef, py_ast.ClassDef)):
            return result
        for child in self.engine._iter_ast_children(node):
            result.extend(self._walk_ast(child))
        return result

    def _source_calls(self, node: Any) -> frozenset[str]:
        return frozenset(
            name
            for item in self._walk_ast(node)
            if isinstance(item, py_ast.Call)
            for name in [self.engine._extract_call_name(item)]
            if name and self.engine._matches_source(name)
        )

    def _summary_for_call(self, node: PDGNode, name: str) -> CPGProcedureSummary | None:
        call_edges = [
            edge
            for edge in self.cpg._cpg_edges_out.get(node.node_id, ())
            if edge.kind is CPGEdgeKind.CALL
            and self._function_name_matches(name, self.cpg.node_func_name(edge.target))
        ]
        if len(call_edges) == 1:
            return self._summaries.get(self.cpg.node_func_name(call_edges[0].target))
        candidates = [
            summary
            for procedure, summary in self._summaries.items()
            if procedure == name
            or procedure.rsplit(".", 1)[-1] == name.rsplit(".", 1)[-1]
        ]
        return candidates[0] if len(candidates) == 1 else None

    @staticmethod
    def _state_has_taint(state: CPGAbstractState) -> bool:
        return bool(state.taint.facts)

    def _unsupported(
        self, state: CPGAbstractState, node: PDGNode, code: str
    ) -> CPGAbstractState:
        return state.with_uncertainty(
            AnalysisUncertainty(
                code,
                f"No precise CPG taint transfer for {type(node.ast_node).__name__}",
                PrecisionLevel.UNSUPPORTED,
                self.cpg.node_func_name(node),
                self._filename(node),
                self.cpg.node_lineno(node),
                type(node.ast_node).__name__,
            )
        )

    def _collect_state_diagnostics(self) -> None:
        for state in self._states.values():
            for uncertainty in state.taint.uncertainties:
                self._diagnostics.add(
                    CPGTaintDiagnostic(
                        uncertainty.message,
                        uncertainty.code,
                        uncertainty.affects_completeness,
                        uncertainty.function,
                        uncertainty.level.value,
                        uncertainty.filename,
                        uncertainty.line,
                        uncertainty.operation,
                    )
                )

    def _publish_node_taint(self) -> None:
        from .model import TaintState

        self.engine._node_taint.clear()
        for config, state in self._states.items():
            kinds = frozenset(fact.kind for fact in state.taint.facts)
            existing = self.engine._node_taint.get(config.node_id, TaintState.clean())
            self.engine._node_taint[config.node_id] = existing.join(TaintState(kinds))

    def _collect_graph_diagnostics(self) -> None:
        for diagnostic in self.cpg.construction_diagnostics:
            self._diagnostics.add(
                CPGTaintDiagnostic(
                    str(diagnostic.get("message") or "CPG construction failed"),
                    str(diagnostic.get("code") or "cpg-construction-failed"),
                    True,
                    (
                        str(diagnostic["function"])
                        if diagnostic.get("function") is not None
                        else None
                    ),
                    PrecisionLevel.UNSUPPORTED.value,
                    operation=(
                        str(diagnostic["stage"])
                        if diagnostic.get("stage") is not None
                        else None
                    ),
                )
            )
        if not self.cpg._pdgs:
            self._diagnostics.add(
                CPGTaintDiagnostic(
                    "CPG contains no analyzable procedures",
                    "cpg-empty-graph",
                    True,
                    level=PrecisionLevel.UNSUPPORTED.value,
                )
            )
        if self._module_globals and self._module_has_local_calls():
            self._diagnostics.add(
                CPGTaintDiagnostic(
                    "Import-time local calls may mutate module globals; public "
                    "entries conservatively havoc those globals",
                    "cpg-module-initializer-call-effects",
                    False,
                    self._module_function,
                    PrecisionLevel.CONSERVATIVE.value,
                    operation="module-initializer",
                )
            )
        for function, pdg in self.cpg._pdgs.items():
            if pdg.entry is None or not pdg.exit_nodes:
                self._diagnostics.add(
                    CPGTaintDiagnostic(
                        f"Function {function!r} has no complete entry/exit pair",
                        "cpg-missing-entry-exit",
                        True,
                        function,
                        PrecisionLevel.UNSUPPORTED.value,
                    )
                )
            if pdg.data_dependence_mode == "ast-fallback":
                self._diagnostics.add(
                    CPGTaintDiagnostic(
                        pdg.data_dependence_reason
                        or f"Function {function!r} uses AST-local data dependence",
                        "cpg-ast-data-fallback",
                        True,
                        function,
                        PrecisionLevel.UNSUPPORTED.value,
                    )
                )

    def _source_nodes(self) -> tuple[PDGNode, ...]:
        return tuple(
            node for node in self.cpg.nodes() if self._source_calls(node.ast_node)
        )

    def _source_node(self, origin: TaintOrigin) -> PDGNode | None:
        symbol = origin.symbol or ""
        if symbol.startswith("cpg:"):
            parts = symbol.split(":", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                return self.cpg.node_by_id(int(parts[1]))
        return None
