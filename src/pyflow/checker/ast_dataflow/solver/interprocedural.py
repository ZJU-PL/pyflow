"""Relational summary construction over source-AST function CFGs."""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass
from typing import Mapping

from pyflow.analysis.entrypoints import (
    EntryPointMode,
    EntryPointOptions,
    ProcedureDescriptor,
    select_entry_points,
)
from pyflow.analysis.taint import TaintPolicy

from ..domain import AnalysisUncertainty, PrecisionLevel, TaintFact
from ..frontend import find_function
from ..modeling import CallShapeContractRegistry, SanitizerContractRegistry
from ..semantics.events import TaintSinkEvent
from ..semantics.refinement import RefinementProvider
from ..semantics.transfer import ASTFunctionAnalysisResult, analyze_ast_function
from .cfg import SolverOptions
from .summaries import (
    ProcedureTaintSummary,
    SummaryPort,
    SummaryPortKind,
    SummaryRelation,
    SummaryKillEffect,
    SummarySinkEvent,
)


@dataclass(frozen=True)
class ASTInterproceduralResult:
    summaries: Mapping[str, ProcedureTaintSummary]
    analyses: Mapping[str, ASTFunctionAnalysisResult]
    diagnostics: tuple[AnalysisUncertainty, ...]
    status: str
    rounds: int
    reachable: frozenset[str]
    entries: frozenset[str]
    entry_point_options: EntryPointOptions


class ASTInterproceduralAnalyzer:
    """Compute context-insensitive relational summaries to a fixed point."""

    def __init__(
        self,
        policy: TaintPolicy,
        *,
        contracts: SanitizerContractRegistry | None = None,
        shape_contracts: CallShapeContractRegistry | None = None,
        refinement: RefinementProvider | None = None,
        solver_options: SolverOptions | None = None,
        max_rounds: int = 100,
    ) -> None:
        self.policy = policy
        self.contracts = contracts or SanitizerContractRegistry()
        self.shape_contracts = shape_contracts or CallShapeContractRegistry()
        self.refinement = refinement
        self.solver_options = solver_options
        self.max_rounds = max_rounds

    def analyze(
        self,
        sources_by_name: Mapping[str, str],
        filenames: Mapping[str, str] | None = None,
        entry_functions: tuple[str, ...] = (),
        *,
        entry_point_options: EntryPointOptions = EntryPointOptions(
            mode=EntryPointMode.INFERRED_ROOTS
        ),
    ) -> ASTInterproceduralResult:
        functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        diagnostics: set[AnalysisUncertainty] = set()
        for name, source in sources_by_name.items():
            try:
                tree = ast.parse(textwrap.dedent(source))
            except SyntaxError as error:
                diagnostics.add(
                    AnalysisUncertainty(
                        code="ast-dataflow-syntax-error",
                        message=str(error),
                        level=PrecisionLevel.UNSUPPORTED,
                        function=name,
                        filename=(filenames or {}).get(name),
                        line=error.lineno,
                        operation="parse",
                    )
                )
                continue
            function = find_function(tree, name)
            if function is not None:
                functions[name] = function

        summaries = {
            name: ProcedureTaintSummary(
                name, parameters=self._parameter_names(function)
            )
            for name, function in functions.items()
        }
        analyses: dict[str, ASTFunctionAnalysisResult] = {}
        universe = self._taint_kind_universe()
        rounds = 0
        changed = True
        while changed and rounds < self.max_rounds:
            rounds += 1
            changed = False
            next_analyses: dict[str, ASTFunctionAnalysisResult] = {}
            for name, function in functions.items():
                parameters = self._parameter_names(function)
                entry = {parameter: universe for parameter in parameters}
                analysis = analyze_ast_function(
                    function,
                    procedure=name,
                    filename=(filenames or {}).get(name),
                    policy=self.policy,
                    entry_taint=entry,
                    summaries=summaries,
                    contracts=self.contracts,
                    shape_contracts=self.shape_contracts,
                    refinement=self.refinement,
                    solver_options=self.solver_options,
                    known_functions=functions,
                )
                next_analyses[name] = analysis
                diagnostics.update(analysis.diagnostics)
                candidate = self._summarize(name, parameters, analysis)
                joined = summaries[name].join(candidate)
                if joined != summaries[name]:
                    summaries[name] = joined
                    changed = True
            analyses = next_analyses

        if changed:
            diagnostics.add(
                AnalysisUncertainty(
                    code="ast-dataflow-summary-round-limit",
                    message=(
                        "Interprocedural summaries did not converge within "
                        f"{self.max_rounds} rounds"
                    ),
                    level=PrecisionLevel.UNSUPPORTED,
                )
            )
        ordered_diagnostics = tuple(sorted(diagnostics, key=repr))
        entries, reachable = self._entry_and_reachable_functions(
            functions,
            entry_functions,
            filenames=filenames or {},
            entry_point_options=entry_point_options,
        )
        status = (
            "partial"
            if any(item.affects_completeness for item in ordered_diagnostics)
            else "complete"
        )
        return ASTInterproceduralResult(
            summaries=summaries,
            analyses=analyses,
            diagnostics=ordered_diagnostics,
            status=status,
            rounds=rounds,
            reachable=reachable,
            entries=entries,
            entry_point_options=entry_point_options,
        )

    def _summarize(
        self,
        name: str,
        parameters: tuple[str, ...],
        analysis: ASTFunctionAnalysisResult,
    ) -> ProcedureTaintSummary:
        relations: set[SummaryRelation] = set()
        seeds: set[tuple[SummaryPort, str]] = set()
        sinks: set[SummarySinkEvent] = set()
        writes: set[SummaryPort] = set()
        kills: set[SummaryKillEffect] = set()

        if analysis.cfg_result.returned is not None:
            self._add_facts(
                analysis.cfg_result.returned.values,
                SummaryPort(SummaryPortKind.RETURN),
                parameters,
                relations,
                seeds,
            )
        if analysis.cfg_result.raised is not None:
            self._add_facts(
                analysis.cfg_result.raised.values,
                SummaryPort(SummaryPortKind.RAISE),
                parameters,
                relations,
                seeds,
            )
        if analysis.cfg_result.yielded is not None:
            self._add_facts(
                analysis.cfg_result.yielded.values,
                SummaryPort(SummaryPortKind.YIELD),
                parameters,
                relations,
                seeds,
            )

        normal_state = self._normal_exit_state(analysis)
        if normal_state is not None:
            for index, parameter in enumerate(parameters):
                root = (name, parameter)
                for fact in normal_state.facts:
                    if fact.location.root != root or not fact.location.selectors:
                        continue
                    target = SummaryPort(
                        SummaryPortKind.PARAMETER,
                        index=index,
                        path=fact.location.selectors,
                    )
                    writes.add(target)
                    self._add_facts(
                        frozenset({fact}),
                        target,
                        parameters,
                        relations,
                        seeds,
                    )
            parameter_indices = {
                parameter: index for index, parameter in enumerate(parameters)
            }
            for location, kind in normal_state.guarantees:
                root = location.root
                if not (
                    isinstance(root, tuple)
                    and len(root) == 2
                    and root[0] == name
                    and root[1] in parameter_indices
                    and location.selectors
                ):
                    continue
                port = SummaryPort(
                    SummaryPortKind.PARAMETER,
                    index=parameter_indices[root[1]],
                    path=location.selectors,
                )
                kills.add(SummaryKillEffect(port, frozenset({kind})))

        for event in analysis.events:
            if not isinstance(event, TaintSinkEvent):
                continue
            sink_port = SummaryPort(
                SummaryPortKind.SINK,
                name=event.sink_name,
                index=event.argument_index,
            )
            sinks.add(
                SummarySinkEvent(
                    event.sink_name,
                    event.argument_index,
                    sink_port,
                    event.line,
                    event.procedure,
                    event.filename,
                )
            )
            self._add_facts(
                event.facts,
                sink_port,
                parameters,
                relations,
                seeds,
            )

        return ProcedureTaintSummary(
            procedure=name,
            parameters=parameters,
            seeds=frozenset(seeds),
            relations=frozenset(relations),
            writes=frozenset(writes),
            kills=frozenset(kills),
            sinks=frozenset(sinks),
            uncertainties=frozenset(analysis.diagnostics),
        )

    @staticmethod
    def _normal_exit_state(analysis: ASTFunctionAnalysisResult):
        for node, state in analysis.cfg_result.in_states.items():
            kind = getattr(node, "kind", None)
            if getattr(kind, "value", None) == "exit":
                return state
        return None

    @staticmethod
    def _add_facts(
        facts: frozenset[TaintFact],
        target: SummaryPort,
        parameters: tuple[str, ...],
        relations: set[SummaryRelation],
        seeds: set[tuple[SummaryPort, str]],
    ) -> None:
        indices = {parameter: index for index, parameter in enumerate(parameters)}
        for fact in facts:
            symbol = fact.origin.symbol or ""
            prefix = "parameter:"
            if symbol.startswith(prefix) and symbol[len(prefix) :] in indices:
                parameter = symbol[len(prefix) :]
                source = SummaryPort(
                    SummaryPortKind.PARAMETER, index=indices[parameter]
                )
                mapped = (
                    ((fact.origin.kind, fact.kind),)
                    if fact.origin.kind != fact.kind
                    else ()
                )
                relations.add(
                    SummaryRelation(
                        source,
                        target,
                        kinds=frozenset({fact.origin.kind}),
                        mapped_kinds=mapped,
                    )
                )
            else:
                seeds.add((target, fact.kind))

    def _taint_kind_universe(self) -> frozenset[str]:
        kinds = {
            kind
            for values in self.policy.source_kinds_by_call.values()
            for kind in values
        }
        for rule in self.policy.rules:
            kinds.update(rule.source_kinds)
        return frozenset(kinds or {"untrusted"})

    @staticmethod
    def _parameter_names(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[str, ...]:
        arguments = function.args
        return tuple(
            argument.arg
            for argument in (
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
                *((arguments.vararg,) if arguments.vararg is not None else ()),
                *((arguments.kwarg,) if arguments.kwarg is not None else ()),
            )
        )

    @staticmethod
    def _entry_and_reachable_functions(
        functions: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef],
        entries: tuple[str, ...],
        *,
        filenames: Mapping[str, str],
        entry_point_options: EntryPointOptions,
    ) -> tuple[frozenset[str], frozenset[str]]:
        by_short: dict[str, list[str]] = {}
        for name in functions:
            by_short.setdefault(name.rsplit(".", 1)[-1], []).append(name)
        calls: dict[str, set[str]] = {name: set() for name in functions}
        for caller, function in functions.items():
            for node in ast.walk(function):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Name):
                    raw = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    raw = node.func.attr
                else:
                    continue
                candidates = by_short.get(raw.rsplit(".", 1)[-1], ())
                if len(candidates) != 1:
                    continue
                callee = candidates[0]
                calls[caller].add(callee)

        declared = {
            candidate
            for entry in entries
            for candidate in functions
            if candidate == entry or candidate.rsplit(".", 1)[-1] == entry
        }
        descriptors = (
            ProcedureDescriptor(
                identity=name,
                qualified_name=name,
                filename=filenames.get(name),
                callees=frozenset(calls[name]),
                declared=name in declared,
            )
            for name in functions
        )
        roots = {
            selected.identity
            for selected in select_entry_points(descriptors, entry_point_options)
        }
        reachable = set(roots)
        pending = list(roots)
        while pending:
            caller = pending.pop()
            for callee in calls.get(caller, ()):
                if callee not in reachable:
                    reachable.add(callee)
                    pending.append(callee)
        return frozenset(roots), frozenset(reachable)
