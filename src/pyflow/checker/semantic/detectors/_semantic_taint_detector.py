"""Interprocedural orchestration for semantic taint analysis."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from pyflow.analysis.taint import TaintPolicy, TaintRule

from ..core.base import Detector
from ..core.context import AnalysisSession
from ..core.issue import Issue
from ._semantic_taint_local import _LocalSemanticTaintAnalyzer
from ._semantic_taint_models import FunctionSummary


class SemanticTaintDetector(Detector):
    """
    Semantic taint detector leveraging PyFlow's analysis infrastructure.

    This detector uses:
    - IPA function summaries for interprocedural return-param dependencies
    - StoreGraph for alias analysis (when available)
    - Local AST-based taint tracking with full state
    - Fixed-point iteration for interprocedural propagation
    """

    name = "semantic_taint"
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
    ):
        self._manual_sources = set(sources or ())
        self._manual_sinks = set(sinks or ())
        self._manual_sanitizers = set(sanitizers or ())
        self.policy = policy
        self.frameworks = None if frameworks is None else tuple(frameworks)
        self.registry_paths = tuple(registry_paths)
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
        self.policy = self.policy or self._policy_for_session(session)
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

        # Build function summaries using hybrid approach
        summaries = self._build_summaries(session)

        reports: List[Issue] = []
        for name, summary in summaries.items():
            for sink in summary.tainted_sinks:
                rule = self._rule_for_sink(sink)
                if rule is None:
                    continue
                cwe = self.policy.sink_cwe_by_call.get(sink) or rule.cwe
                issue = Issue(
                    severity=self.policy.sink_severity_by_call.get(
                        sink, rule.severity
                    ).upper(),
                    confidence="HIGH",
                    cwe=self._cwe_number(cwe),
                    text=f"Untrusted data can reach sink '{sink}'.",
                    ident=sink,
                    lineno=None,
                    test_id=rule.rule_id,
                )
                issue.fname = getattr(session, "func_to_file", {}).get(name, name)
                issue.test = self.name
                reports.append(issue)

        return reports

    def _policy_for_session(self, session: AnalysisSession) -> TaintPolicy:
        from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
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
        if not manual_models:
            return base
        manual_rules: tuple[TaintRule, ...] = ()
        if self._manual_sinks:
            manual_rules = (
                TaintRule(
                    "PYFLOW-SEMANTIC-MANUAL",
                    "Untrusted data reaches configured semantic sink",
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
        manual = TaintPolicy.from_call_models(
            CallModelRegistry(manual_models), manual_rules
        )
        return self._merge_policies(base, manual)

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
            sanitizer_kinds_by_call=merge_maps(
                left.sanitizer_kinds_by_call,
                right.sanitizer_kinds_by_call,
            ),
            rules=left.rules + right.rules,
        )

    def _rule_for_sink(self, sink: str) -> TaintRule | None:
        sink_kinds = self.policy.sink_kinds_by_call.get(sink, frozenset())
        if not sink_kinds and sink in self._manual_sinks:
            sink_kinds = frozenset({"dangerous"})
        source_kinds = frozenset(
            kind
            for kinds in self.policy.source_kinds_by_call.values()
            for kind in kinds
        ) | ({"untrusted"} if self._manual_sources else set())
        matches = self.policy.matching_rules(source_kinds, sink_kinds)
        return matches[0] if matches else None

    @staticmethod
    def _cwe_number(cwe: str | None) -> int:
        if cwe and cwe.startswith("CWE-") and cwe[4:].isdigit():
            return int(cwe[4:])
        return 0

    def _build_summaries(self, session: AnalysisSession) -> Dict[str, FunctionSummary]:
        """Build function summaries using PyFlow infrastructure and local analysis."""
        # Get IPA return-param dependencies from PyFlow
        return_param_deps, returns_value = self._collect_ipa_return_metadata(session)

        # Parse source code into ASTs
        function_trees: Dict[str, ast.AST] = {}
        param_names: Dict[str, List[str]] = {}
        vararg_names: Dict[str, Optional[str]] = {}
        kwarg_names: Dict[str, Optional[str]] = {}
        for fname, src in session.sources_by_name.items():
            try:
                tree = ast.parse(textwrap.dedent(src))
                function_trees[fname] = tree
                param_names[fname] = self._extract_param_names(tree, fname)
                vararg, kwarg = self._extract_var_kw_names(tree, fname)
                vararg_names[fname] = vararg
                kwarg_names[fname] = kwarg
            except SyntaxError:
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
        max_iters = max(3, len(function_trees) * 2)
        for _ in range(max_iters):
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

            for name, tree in function_trees.items():
                summary, call_taints, call_key_taints = self._analyze_function(
                    name,
                    tree,
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
                )
                unconditional_summary, _, _ = self._analyze_function(
                    name,
                    tree,
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

            summaries = next_summaries
            returns_unconditional = next_unconditional

            for callee_map in call_param_taints.values():
                for callee, params in callee_map.items():
                    if not params:
                        continue
                    if callee not in tainted_params:
                        tainted_params[callee] = set()
                    new_params = params - tainted_params[callee]
                    if new_params:
                        tainted_params[callee].update(new_params)
                        changed = True

            for callee_map in call_param_key_taints.values():
                for callee, param_map in callee_map.items():
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

        return summaries

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
    ) -> Tuple[FunctionSummary, Dict[str, Set[str]], Dict[str, Dict[str, Set[str]]]]:
        """Analyze a single function for taint flows."""
        analyzer = _LocalSemanticTaintAnalyzer(
            sources=self.sources,
            sinks=self.sinks,
            sanitizers=self.sanitizers,
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
        return (
            old.has_source != new.has_source
            or old.returns_tainted != new.returns_tainted
            or old.returns_tainted_unconditional != new.returns_tainted_unconditional
            or old.params_to_sink != new.params_to_sink
            or old.param_taint_outputs != new.param_taint_outputs
            or old.param_key_writes != new.param_key_writes
            or old.param_key_taint_writes != new.param_key_taint_writes
            or old.sinks != new.sinks
            or old.tainted_sinks != new.tainted_sinks
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
            ipa = session.queries.get_ipa_analysis()
        except Exception:
            return return_param_deps, returns_value

        context_helper = getattr(session.queries, "context", None)
        if context_helper is None:
            return return_param_deps, returns_value

        for context in ipa.contexts.values():
            name = context_helper.context_name(context)
            if not name:
                continue
            params = self._extract_ipa_param_names(context.params)
            if params:
                deps = self._extract_ipa_return_deps(context.returns, params)
                if deps:
                    return_param_deps.setdefault(name, set()).update(deps)
            returns_value[name] = returns_value.get(name, False) or bool(
                context.returns
            )

        return return_param_deps, returns_value

    @staticmethod
    def _extract_ipa_param_names(params: Any) -> Set[str]:
        """Extract parameter names from IPA context."""
        names: Set[str] = set()
        for param in params:
            raw = getattr(param, "name", None)
            name = getattr(raw, "name", None)
            if isinstance(name, str):
                names.add(name)
            elif isinstance(raw, str):
                names.add(raw)
        return names

    @staticmethod
    def _extract_ipa_return_deps(returns: Any, params: Set[str]) -> Set[str]:
        """Extract which parameters affect return values."""
        deps: Set[str] = set()
        for ret in returns:
            critical = getattr(ret, "critical", None)
            values = getattr(critical, "values", ())
            for value in values:
                name = getattr(value, "name", None)
                if isinstance(name, str) and name in params:
                    deps.add(name)
                elif isinstance(value, str) and value in params:
                    deps.add(value)
        return deps
