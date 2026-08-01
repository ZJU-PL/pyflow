"""Interprocedural orchestration for AST dataflow taint analysis."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from pyflow.analysis.taint import TaintPolicy, TaintRule

from ..core.base import Detector
from ..core.context import AnalysisSession
from ..core.issue import Issue
from ..domain import ProvenanceEdge, ProvenanceNode, TaintFact
from ._taint_local import _LocalTaintAnalyzer
from ._taint_models import (
    FunctionSummary,
    ASTDataflowTaintDiagnostic,
    ASTDataflowTaintFinding,
    ASTDataflowTaintResult,
    ASTDataflowTraceStep,
)
from ..semantics import TaintSinkEvent
from ..solver.interprocedural import ASTInterproceduralAnalyzer


class ASTDataflowTaintDetector(Detector):
    """
    AST dataflow taint detector leveraging PyFlow's analysis infrastructure.

    This detector uses:
    - IPA function summaries for interprocedural return-param dependencies
    - StoreGraph for alias analysis (when available)
    - Local AST-based taint tracking with full state
    - Fixed-point iteration for interprocedural propagation
    """

    name = "ast_dataflow_taint"
    description = "Advanced taint detection using PyFlow's analysis infrastructure."

    def __init__(
        self,
        sources: Optional[Set[str]] = None,
        sinks: Optional[Set[str]] = None,
        sanitizers: Optional[Set[str]] = None,
        *,
        policy: TaintPolicy | None = None,
        frameworks: Sequence[str] | None = None,
        registry_paths: Sequence[str | Path] = (),
        formal_semantics: bool = True,
        shape_contracts=None,
    ):
        self._manual_sources = set(sources or ())
        self._manual_sinks = set(sinks or ())
        self._manual_sanitizers = set(sanitizers or ())
        self._configured_policy = policy
        self.policy = policy
        self.frameworks = None if frameworks is None else tuple(frameworks)
        self.registry_paths = tuple(registry_paths)
        self.formal_semantics = formal_semantics
        self.shape_contracts = shape_contracts
        self.sources: Set[str] = set()
        self.sinks: Set[str] = set()
        self.sanitizers: Set[str] = set()
        self.sink_positions: Dict[str, Set[int]] = {}

    def run(self, session: AnalysisSession) -> List[Issue]:
        """
        Run taint analysis using PyFlow's infrastructure.

        Args:
            session: Analysis session with queries and program

        Returns:
            List of issues for each detected taint flow
        """
        return self.issues_from_result(self.analyze(session))

    def issues_from_result(self, result: ASTDataflowTaintResult) -> List[Issue]:
        """Adapt typed findings to the common checker ``Issue`` interface."""
        reports: List[Issue] = []
        for finding in result.findings:
            issue = Issue(
                severity=finding.severity.upper(),
                confidence=finding.confidence,
                cwe=self._cwe_number(finding.cwe),
                text=f"Untrusted data can reach sink '{finding.sink_name}'.",
                ident=finding.sink_name,
                lineno=finding.sink_line,
                test_id=finding.rule_id,
            )
            issue.fname = finding.filename
            issue.test = self.name
            setattr(issue, "taint_kinds", tuple(sorted(finding.source_kinds)))
            setattr(issue, "precision_reasons", finding.precision_reasons)
            setattr(issue, "trace", finding.trace)
            setattr(issue, "suggestion", finding.suggestion)
            reports.append(issue)
        return reports

    def analyze(self, session: AnalysisSession) -> ASTDataflowTaintResult:
        """Run typed AST dataflow analysis and retain completion metadata."""
        if self._configured_policy is None:
            self.policy = self._policy_for_session(session)
        else:
            self.policy = self._configured_policy
            if self._manual_sources or self._manual_sinks or self._manual_sanitizers:
                self.policy = self._merge_policies(
                    self.policy, self._manual_policy(self.policy)
                )
        self.sources = set(self.policy.source_names) | self._manual_sources
        self.sinks = set(self.policy.sink_names) | self._manual_sinks
        self.sanitizers = {
            name
            for name, kinds in self.policy.sanitizer_kinds_by_call.items()
            if "*" in kinds
        } | self._manual_sanitizers
        self.sink_positions = {
            name: set(positions)
            for name, positions in self.policy.sink_positions_by_call.items()
        }

        if self.formal_semantics:
            return self._analyze_formal(session)

        diagnostics: list[ASTDataflowTaintDiagnostic] = []
        findings: dict[tuple, ASTDataflowTaintFinding] = {}
        summary_updates = 0

        source_kinds = sorted(
            {
                kind
                for kinds in self.policy.source_kinds_by_call.values()
                for kind in kinds
            }
        )
        if self._manual_sources and "untrusted" not in source_kinds:
            source_kinds.append("untrusted")

        for source_kind in source_kinds:
            active_sources = {
                name
                for name, kinds in self.policy.source_kinds_by_call.items()
                if source_kind in kinds
            }
            if source_kind == "untrusted":
                active_sources.update(self._manual_sources)
            active_sanitizers = {
                name
                for name, kinds in self.policy.sanitizer_kinds_by_call.items()
                if "*" in kinds or source_kind in kinds
            } | self._manual_sanitizers
            summaries, pass_diagnostics, updates = self._build_summaries(
                session,
                sources=active_sources,
                sanitizers=active_sanitizers,
            )
            diagnostics.extend(pass_diagnostics)
            summary_updates += updates
            for name, summary in summaries.items():
                for sink in summary.tainted_sinks:
                    sink_kinds = self.policy.sink_kinds_for(sink) or frozenset(
                        {"dangerous"}
                    )
                    rules = tuple(
                        rule
                        for rule in self.policy.rules
                        if source_kind in rule.source_kinds
                        and rule.sink_kinds & sink_kinds
                    )
                    for rule in rules:
                        lines = summary.tainted_sink_lines.get(sink) or {None}
                        for line in lines:
                            finding = ASTDataflowTaintFinding(
                                function=name,
                                filename=getattr(session, "func_to_file", {}).get(
                                    name, name
                                ),
                                sink_name=sink,
                                sink_line=line,
                                source_kinds=frozenset({source_kind}),
                                rule_id=rule.rule_id,
                                rule_title=rule.title,
                                severity=self.policy.sink_severity_for(sink)
                                or rule.severity,
                                cwe=self.policy.sink_cwe_for(sink) or rule.cwe,
                                suggestion=self.policy.sink_suggestion_for(sink)
                                or rule.suggestion,
                            )
                            findings[(name, sink, line, rule.rule_id, source_kind)] = (
                                finding
                            )

        unique_diagnostics = tuple(dict.fromkeys(diagnostics))
        status = (
            "partial"
            if any(d.affects_completeness for d in unique_diagnostics)
            else "complete"
        )
        return ASTDataflowTaintResult(
            findings=tuple(findings.values()),
            status=status,
            diagnostics=unique_diagnostics,
            statistics={
                "source_kinds": len(source_kinds),
                "summary_updates": summary_updates,
                "findings": len(findings),
            },
        )

    def _analyze_formal(self, session: AnalysisSession) -> ASTDataflowTaintResult:
        """Run the CFG/lattice-based engine and adapt its relational summaries."""

        policy = self.policy
        if policy is None:
            raise RuntimeError("taint policy must be configured before analysis")
        refinement = None
        analysis_facts = getattr(session, "analysis_facts", None)
        if analysis_facts is not None:
            from pyflow.ir.core import Capabilities

            has_alias_facts = analysis_facts.catalog.facts.has(
                Capabilities.ALIAS_POINTS_TO
            )
        else:
            has_alias_facts = False
        if has_alias_facts:
            from ..semantics import (
                AdaptiveRefinementProvider,
                HeapGraphRefinementProvider,
                heap_location_adapter,
            )

            refinement = AdaptiveRefinementProvider(
                (
                    HeapGraphRefinementProvider(
                        analysis_facts, heap_location_adapter(analysis_facts)
                    ),
                )
            )
        from pyflow.analysis.entrypoints import EntryPointMode, EntryPointOptions

        interprocedural = ASTInterproceduralAnalyzer(
            policy,
            refinement=refinement,
            shape_contracts=self.shape_contracts,
        ).analyze(
            session.sources_by_name,
            getattr(session, "func_to_file", {}),
            self._entry_functions(session),
            entry_point_options=policy.entry_point_defaults.resolve(
                EntryPointOptions(
                    mode=EntryPointMode.DECLARED_PLUS_ROOTS,
                    taint_parameters=True,
                )
            ),
        )
        findings: dict[tuple, ASTDataflowTaintFinding] = {}
        for name, analysis in interprocedural.analyses.items():
            if name not in interprocedural.reachable:
                continue
            provenance = self._analysis_provenance(analysis)
            for event in analysis.events:
                if not isinstance(event, TaintSinkEvent):
                    continue
                # Parameter facts are symbolic while summaries are built. At
                # externally reachable roots, however, those parameters are
                # the program boundary (HTTP/CLI/RPC inputs) and therefore
                # represent real untrusted sources. Keep filtering symbolic
                # parameters for non-entry helpers so they only report when a
                # concrete caller instantiates their summary.
                actual_facts = frozenset(
                    fact
                    for fact in event.facts
                    if (
                        interprocedural.entry_point_options.taint_parameters
                        and name in interprocedural.entries
                    )
                    or not (fact.origin.symbol or "").startswith("parameter:")
                )
                source_kinds = frozenset(fact.kind for fact in actual_facts)
                if not source_kinds:
                    continue
                sink_kinds = (
                    policy.sink_kinds_for(event.sink_name)
                    or event.sink_kinds
                    or frozenset({"dangerous"})
                )
                for rule in policy.matching_rules(source_kinds, sink_kinds):
                    matched_source_kinds = frozenset(source_kinds & rule.source_kinds)
                    if not matched_source_kinds:
                        continue
                    finding = ASTDataflowTaintFinding(
                        function=event.procedure or name,
                        filename=(
                            event.filename
                            or getattr(session, "func_to_file", {}).get(name, name)
                        ),
                        sink_name=event.sink_name,
                        sink_line=event.line,
                        source_kinds=matched_source_kinds,
                        rule_id=rule.rule_id,
                        rule_title=rule.title,
                        severity=policy.sink_severity_for(event.sink_name)
                        or rule.severity,
                        cwe=(policy.sink_cwe_for(event.sink_name) or rule.cwe),
                        suggestion=(
                            policy.sink_suggestion_for(event.sink_name)
                            or rule.suggestion
                        ),
                        precision_reasons=tuple(
                            sorted(
                                {
                                    diagnostic.code
                                    for diagnostic in interprocedural.diagnostics
                                    if diagnostic.function
                                    in {None, name, event.procedure}
                                }
                            )
                        ),
                        trace=self._build_trace(
                            actual_facts,
                            provenance,
                            event.sink_name,
                            event.filename,
                            event.line,
                        ),
                    )
                    key = (
                        finding.function,
                        finding.filename,
                        finding.sink_name,
                        finding.sink_line,
                        finding.rule_id,
                        finding.source_kinds,
                    )
                    findings[key] = finding

        diagnostics = tuple(
            ASTDataflowTaintDiagnostic(
                message=diagnostic.message,
                code=diagnostic.code,
                affects_completeness=diagnostic.affects_completeness,
                function=diagnostic.function,
                level=diagnostic.level.value,
                filename=diagnostic.filename,
                line=diagnostic.line,
                operation=diagnostic.operation,
            )
            for diagnostic in interprocedural.diagnostics
        )
        return ASTDataflowTaintResult(
            findings=tuple(findings.values()),
            status=interprocedural.status,
            diagnostics=diagnostics,
            statistics={
                "source_kinds": len(
                    {
                        kind
                        for kinds in policy.source_kinds_by_call.values()
                        for kind in kinds
                    }
                ),
                "summary_updates": interprocedural.rounds,
                "summaries": len(interprocedural.summaries),
                "refinement_requests": getattr(refinement, "refinement_requests", 0),
                "successful_refinements": getattr(
                    refinement, "successful_refinements", 0
                ),
                "findings": len(findings),
            },
        )

    @staticmethod
    def _entry_functions(session: AnalysisSession) -> tuple[str, ...]:
        program = getattr(session, "program", None)
        queries = getattr(session, "queries", None)
        context = getattr(queries, "context", None)
        names: list[str] = []
        for entry in getattr(program, "entryPoints", ()) if program is not None else ():
            code = getattr(entry, "code", None)
            if code is None or context is None:
                continue
            try:
                aliases = context.code_aliases(code)
            except Exception:
                aliases = ()
            names.extend(alias for alias in aliases if isinstance(alias, str))
        return tuple(dict.fromkeys(names))

    @staticmethod
    def _analysis_provenance(analysis) -> frozenset[ProvenanceEdge]:
        edges: set[ProvenanceEdge] = set()
        for state in analysis.cfg_result.in_states.values():
            edges.update(state.provenance)
        for state in analysis.cfg_result.edge_states.values():
            edges.update(state.provenance)
        for outcome in (
            analysis.cfg_result.returned,
            analysis.cfg_result.raised,
            analysis.cfg_result.yielded,
        ):
            if outcome is not None:
                edges.update(outcome.state.provenance)
        return frozenset(edges)

    @staticmethod
    def _build_trace(
        facts: Iterable[TaintFact],
        provenance: Iterable[ProvenanceEdge],
        sink: str,
        filename: str | None,
        line: int | None,
    ) -> tuple[ASTDataflowTraceStep, ...]:
        steps: list[ASTDataflowTraceStep] = []
        seen_steps = set()
        incoming: dict[ProvenanceNode, list[ProvenanceEdge]] = {}
        for edge in provenance:
            incoming.setdefault(edge.target, []).append(edge)
        for fact in sorted(facts, key=repr):
            chain = []
            current = fact.provenance_node
            seen_nodes = set()
            while current not in seen_nodes and incoming.get(current):
                seen_nodes.add(current)
                edge = sorted(incoming[current], key=repr)[0]
                chain.append(edge)
                current = edge.source
            origin = fact.origin
            source_step = ASTDataflowTraceStep(
                "source",
                current.location.render(),
                origin.filename,
                origin.line,
                origin.symbol or origin.kind,
            )
            if source_step not in seen_steps:
                seen_steps.add(source_step)
                steps.append(source_step)
            for edge in reversed(chain):
                step = ASTDataflowTraceStep(
                    edge.operation.value,
                    edge.target.location.render(),
                    edge.filename,
                    edge.line,
                    edge.detail,
                )
                if step not in seen_steps:
                    seen_steps.add(step)
                    steps.append(step)
        sink_step = ASTDataflowTraceStep("sink", sink, filename, line, sink)
        if sink_step not in seen_steps:
            steps.append(sink_step)
        return tuple(steps)

    def _policy_for_session(self, session: AnalysisSession) -> TaintPolicy:
        from pyflow.analysis.ifds.modeling.registry import load_registry

        registry = load_registry()
        if self.frameworks is None:
            registry.activate("stdlib", type="taint")
        elif self.frameworks:
            registry.activate("stdlib", *self.frameworks, type="taint")
        else:
            registry.activate("stdlib", type="taint")
            for source in getattr(session, "all_source_code", {}).values():
                registry.detect(source.splitlines(), type="taint")
        if self.registry_paths:
            registry.load_custom(*self.registry_paths)
        base = registry.as_taint_policy()

        manual = self._manual_policy(base)
        if not (
            manual.source_kinds_by_call
            or manual.sink_kinds_by_call
            or manual.sanitizer_kinds_by_call
        ):
            return base
        return self._merge_policies(base, manual)

    def _manual_policy(self, base: TaintPolicy) -> TaintPolicy:
        from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry

        manual_models = [
            *(
                CallModel(name, source_kinds=frozenset({"untrusted"}))
                for name in self._manual_sources
            ),
            *(
                CallModel(name, sink_kinds=frozenset({"dangerous"}))
                for name in self._manual_sinks
            ),
            *(
                CallModel(name, sanitizer_kinds=frozenset({"*"}))
                for name in self._manual_sanitizers
            ),
        ]
        manual_rules: tuple[TaintRule, ...] = ()
        if self._manual_sinks:
            manual_rules = (
                TaintRule(
                    "PYFLOW-SEMANTIC-MANUAL",
                    "Untrusted data reaches configured AST dataflow sink",
                    frozenset(
                        {
                            "untrusted",
                            *(
                                kind
                                for kinds in base.source_kinds_by_call.values()
                                for kind in kinds
                            ),
                        }
                    ),
                    frozenset({"dangerous"}),
                    severity="high",
                ),
            )
        return TaintPolicy.from_call_models(
            CallModelRegistry(manual_models), manual_rules
        )

    @staticmethod
    def _merge_policies(left: TaintPolicy, right: TaintPolicy) -> TaintPolicy:
        def merge_maps(first, second):
            result = dict(first)
            for name, values in second.items():
                result[name] = result.get(name, frozenset()) | values
            return result

        return TaintPolicy(
            source_kinds_by_call=merge_maps(
                left.source_kinds_by_call, right.source_kinds_by_call
            ),
            sink_kinds_by_call=merge_maps(
                left.sink_kinds_by_call, right.sink_kinds_by_call
            ),
            sink_positions_by_call=merge_maps(
                left.sink_positions_by_call, right.sink_positions_by_call
            ),
            sink_cwe_by_call={**left.sink_cwe_by_call, **right.sink_cwe_by_call},
            sink_severity_by_call={
                **left.sink_severity_by_call,
                **right.sink_severity_by_call,
            },
            sink_suggestion_by_call={
                **left.sink_suggestion_by_call,
                **right.sink_suggestion_by_call,
            },
            sink_behavior_by_call={
                **left.sink_behavior_by_call,
                **right.sink_behavior_by_call,
            },
            sanitizer_kinds_by_call=merge_maps(
                left.sanitizer_kinds_by_call,
                right.sanitizer_kinds_by_call,
            ),
            rules=left.rules + right.rules,
            entry_point_defaults=left.entry_point_defaults.overlay(
                right.entry_point_defaults
            ),
        )

    def _rule_for_sink(self, sink: str) -> TaintRule | None:
        policy = self.policy
        if policy is None:
            return None
        sink_kinds = policy.sink_kinds_for(sink)
        if not sink_kinds and sink in self._manual_sinks:
            sink_kinds = frozenset({"dangerous"})
        source_kinds = frozenset(
            kind for kinds in policy.source_kinds_by_call.values() for kind in kinds
        ) | ({"untrusted"} if self._manual_sources else set())
        matches = policy.matching_rules(source_kinds, sink_kinds)
        return matches[0] if matches else None

    @staticmethod
    def _cwe_number(cwe: str | None) -> int:
        if cwe and cwe.startswith("CWE-") and cwe[4:].isdigit():
            return int(cwe[4:])
        return 0

    def _build_summaries(
        self,
        session: AnalysisSession,
        *,
        sources: Set[str] | None = None,
        sanitizers: Set[str] | None = None,
    ) -> Tuple[
        Dict[str, FunctionSummary],
        List[ASTDataflowTaintDiagnostic],
        int,
    ]:
        """Build function summaries using PyFlow infrastructure and local analysis."""
        # Get IPA return-param dependencies from PyFlow
        return_param_deps, returns_value = self._collect_ipa_return_metadata(session)

        # Parse source code into ASTs
        function_trees: Dict[str, ast.AST] = {}
        param_names: Dict[str, List[str]] = {}
        vararg_names: Dict[str, Optional[str]] = {}
        kwarg_names: Dict[str, Optional[str]] = {}
        diagnostics: List[ASTDataflowTaintDiagnostic] = []
        for fname, src in session.sources_by_name.items():
            try:
                parsed_tree = ast.parse(textwrap.dedent(src))
                function_trees[fname] = parsed_tree
                param_names[fname] = self._extract_param_names(parsed_tree, fname)
                vararg, kwarg = self._extract_var_kw_names(parsed_tree, fname)
                vararg_names[fname] = vararg
                kwarg_names[fname] = kwarg
            except SyntaxError as error:
                diagnostics.append(
                    ASTDataflowTaintDiagnostic(
                        message=str(error),
                        code="ast-dataflow-syntax-error",
                        affects_completeness=True,
                        function=fname,
                    )
                )
                continue

        known_callees = set(function_trees.keys()) | set(return_param_deps.keys())
        summaries: Dict[str, FunctionSummary] = {}
        tainted_params: Dict[str, Set[str]] = {name: set() for name in known_callees}
        tainted_param_keys: Dict[str, Dict[str, Set[str]]] = {
            name: {} for name in known_callees
        }
        returns_unconditional: Dict[str, bool] = {name: False for name in known_callees}
        for name in known_callees:
            vararg_names.setdefault(name, None)
            kwarg_names.setdefault(name, None)

        # Fixed-point iteration
        summary_updates = 0
        while True:
            changed = False
            callee_returns_tainted = {
                callee: summary.returns_tainted for callee, summary in summaries.items()
            }
            callee_has_source = {
                callee: summary.has_source for callee, summary in summaries.items()
            }
            callee_param_taint_outputs = {
                callee: summary.param_taint_outputs
                for callee, summary in summaries.items()
            }
            callee_param_key_writes = {
                callee: summary.param_key_writes
                for callee, summary in summaries.items()
            }
            callee_param_key_taint_writes = {
                callee: summary.param_key_taint_writes
                for callee, summary in summaries.items()
            }
            next_summaries: Dict[str, FunctionSummary] = {}
            next_unconditional: Dict[str, bool] = {}
            call_param_taints: Dict[str, Dict[str, Set[str]]] = {}
            call_param_key_taints: Dict[str, Dict[str, Dict[str, Set[str]]]] = {}

            for name, function_tree in function_trees.items():
                summary, call_taints, call_key_taints = self._analyze_function(
                    name,
                    function_tree,
                    tainted_params.get(name, set()),
                    tainted_param_keys.get(name, {}),
                    callee_returns_tainted,
                    callee_has_source,
                    callee_param_taint_outputs,
                    callee_param_key_writes,
                    callee_param_key_taint_writes,
                    returns_unconditional,
                    return_param_deps,
                    returns_value,
                    param_names,
                    vararg_names,
                    kwarg_names,
                    known_callees,
                    sources=sources,
                    sanitizers=sanitizers,
                )
                unconditional_summary, _, _ = self._analyze_function(
                    name,
                    function_tree,
                    set(),
                    {},
                    returns_unconditional,
                    callee_has_source,
                    callee_param_taint_outputs,
                    callee_param_key_writes,
                    callee_param_key_taint_writes,
                    returns_unconditional,
                    return_param_deps,
                    returns_value,
                    param_names,
                    vararg_names,
                    kwarg_names,
                    known_callees,
                    sources=sources,
                    sanitizers=sanitizers,
                )
                summary.returns_tainted_unconditional = (
                    unconditional_summary.returns_tainted
                )
                summary.tainted_sink = bool(summary.tainted_sinks)
                next_summaries[name] = summary
                next_unconditional[name] = summary.returns_tainted_unconditional
                call_param_taints[name] = call_taints
                call_param_key_taints[name] = call_key_taints

            for name, summary in next_summaries.items():
                if self._summary_changed(summaries.get(name), summary):
                    changed = True
                    summary_updates += 1

            summaries = next_summaries
            returns_unconditional = next_unconditional

            for parameter_callee_map in call_param_taints.values():
                for callee, params in parameter_callee_map.items():
                    if not params:
                        continue
                    if callee not in tainted_params:
                        tainted_params[callee] = set()
                    new_params = params - tainted_params[callee]
                    if new_params:
                        tainted_params[callee].update(new_params)
                        changed = True

            for key_callee_map in call_param_key_taints.values():
                for callee, param_map in key_callee_map.items():
                    if not param_map:
                        continue
                    current = tainted_param_keys.setdefault(callee, {})
                    for param, keys in param_map.items():
                        if not keys:
                            continue
                        existing = current.setdefault(param, set())
                        new_keys = keys - existing
                        if new_keys:
                            existing.update(new_keys)
                            changed = True

            if not changed:
                break

        return summaries, diagnostics, summary_updates

    def _analyze_function(
        self,
        name: str,
        tree: ast.AST,
        entry_tainted_params: Set[str],
        entry_tainted_param_keys: Dict[str, Set[str]],
        callee_returns_tainted: Dict[str, bool],
        callee_has_source: Dict[str, bool],
        callee_param_taint_outputs: Dict[str, Set[str]],
        callee_param_key_writes: Dict[str, Dict[str, Set[str]]],
        callee_param_key_taint_writes: Dict[str, Dict[str, Set[str]]],
        callee_returns_unconditional: Dict[str, bool],
        return_param_deps: Dict[str, Set[str]],
        returns_value: Dict[str, bool],
        param_names: Dict[str, List[str]],
        vararg_names: Dict[str, Optional[str]],
        kwarg_names: Dict[str, Optional[str]],
        known_callees: Set[str],
        *,
        sources: Set[str] | None = None,
        sanitizers: Set[str] | None = None,
    ) -> Tuple[FunctionSummary, Dict[str, Set[str]], Dict[str, Dict[str, Set[str]]]]:
        """Analyze a single function for taint flows."""
        analyzer = _LocalTaintAnalyzer(
            sources=self.sources if sources is None else sources,
            sinks=self.sinks,
            sanitizers=self.sanitizers if sanitizers is None else sanitizers,
            sink_positions=self.sink_positions,
            entry_tainted_params=entry_tainted_params,
            entry_tainted_param_keys=entry_tainted_param_keys,
            callee_returns_tainted=callee_returns_tainted,
            callee_returns_unconditional=callee_returns_unconditional,
            callee_has_source=callee_has_source,
            callee_param_taint_outputs=callee_param_taint_outputs,
            callee_param_key_writes=callee_param_key_writes,
            callee_param_key_taint_writes=callee_param_key_taint_writes,
            callee_return_param_deps=return_param_deps,
            callee_param_names=param_names,
            callee_vararg_names=vararg_names,
            callee_kwarg_names=kwarg_names,
            callee_returns_value=returns_value,
            known_callees=known_callees,
        )
        analyzer.visit(tree)
        summary = FunctionSummary(
            name=name,
            has_source=analyzer.has_source,
            returns_tainted=analyzer.returns_tainted,
            params_to_sink=analyzer.params_to_sink,
            param_taint_outputs=analyzer.param_taint_outputs,
            param_key_writes=analyzer.param_key_writes,
            param_key_taint_writes=analyzer.param_key_taint_writes,
            sinks=analyzer.sinks_found,
            tainted_sinks=analyzer.tainted_sinks,
            tainted_sink_lines=analyzer.tainted_sink_lines,
            tainted_sink=bool(analyzer.tainted_sinks),
            returns_value=returns_value.get(name, True),
            return_param_deps=return_param_deps.get(name, set()),
        )
        return summary, analyzer.call_param_taints, analyzer.call_param_key_taints

    def _summary_changed(
        self, old: Optional[FunctionSummary], new: FunctionSummary
    ) -> bool:
        if old is None:
            return True
        return bool(
            old.has_source != new.has_source
            or old.returns_tainted != new.returns_tainted
            or old.returns_tainted_unconditional != new.returns_tainted_unconditional
            or old.params_to_sink != new.params_to_sink
            or old.param_taint_outputs != new.param_taint_outputs
            or old.param_key_writes != new.param_key_writes
            or old.param_key_taint_writes != new.param_key_taint_writes
            or old.sinks != new.sinks
            or old.tainted_sinks != new.tainted_sinks
            or old.tainted_sink_lines != new.tainted_sink_lines
        )

    def _extract_param_names(self, tree: ast.AST, name: str) -> List[str]:
        """Extract parameter names from function AST."""
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == name
            ):
                return self._collect_param_names(node.args)
        return []

    def _extract_var_kw_names(
        self, tree: ast.AST, name: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """Extract *args/**kwargs parameter names (if any) from function AST."""
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == name
            ):
                vararg = node.args.vararg.arg if node.args.vararg else None
                kwarg = node.args.kwarg.arg if node.args.kwarg else None
                return vararg, kwarg
        return None, None

    @staticmethod
    def _collect_param_names(args: ast.arguments) -> List[str]:
        names: List[str] = []
        for arg in getattr(args, "posonlyargs", []):
            names.append(arg.arg)
        for arg in args.args:
            names.append(arg.arg)
        for arg in args.kwonlyargs:
            names.append(arg.arg)
        if args.vararg:
            names.append(args.vararg.arg)
        if args.kwarg:
            names.append(args.kwarg.arg)
        return names

    def _collect_ipa_return_metadata(
        self, session: AnalysisSession
    ) -> Tuple[Dict[str, Set[str]], Dict[str, bool]]:
        """Collect return-param dependencies from IPA analysis."""
        return_param_deps: Dict[str, Set[str]] = {}
        returns_value: Dict[str, bool] = {}
        try:
            summaries = session.queries.get_ipa_function_summaries()
        except Exception:
            return return_param_deps, returns_value

        for summary in summaries:
            if summary.return_dependencies:
                return_param_deps.setdefault(summary.name, set()).update(
                    summary.return_dependencies
                )
            returns_value[summary.name] = (
                returns_value.get(summary.name, False) or summary.returns_value
            )

        return return_param_deps, returns_value
