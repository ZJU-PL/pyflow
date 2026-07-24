"""Worklist orchestration and public configuration for CPG taint analysis."""

from __future__ import annotations
from collections import deque
from typing import Dict, FrozenSet, List, Set, Tuple
from pyflow.analysis.taint import TaintPolicy, TaintRule
from pyflow.ir.pdg.graph import PDGNode
from pyflow.ir.cpg.graph import CodePropertyGraph, CPGEdgeKind
from .model import MemoryLayout, TaintFinding, TaintState, _CLEAN
from .interprocedural import _TaintInterproceduralMixin
from .matching import _TaintMatchingMixin
from .propagation import _TaintPropagationMixin
from .reporting import _TaintReportingMixin


class CPGTaintEngine(
    _TaintMatchingMixin,
    _TaintPropagationMixin,
    _TaintInterproceduralMixin,
    _TaintReportingMixin,
):
    """Context-sensitive taint analysis over a CodePropertyGraph."""

    def __init__(
        self,
        cpg: CodePropertyGraph,
        *,
        policy: TaintPolicy | None = None,
        max_call_depth: int = 5,
        max_loop_iterations: int = 3,
    ) -> None:
        self._cpg = cpg
        self._sources: Set[str] = set()
        self._source_kinds: Dict[str, FrozenSet[str]] = {}
        self._sinks: Dict[str, str] = {}
        self._sink_kinds: Dict[str, FrozenSet[str]] = {}
        self._sink_positions: Dict[str, FrozenSet[int]] = {}
        self._sink_severity: Dict[str, str] = {}
        self._sanitizers: Dict[str, FrozenSet[str]] = {}
        self._rules: List[TaintRule] = []
        self._max_call_depth: int = max_call_depth
        self._max_loop_iterations: int = max_loop_iterations

        if policy is not None:
            self.apply_policy(policy)

        self._node_taint: Dict[int, TaintState] = {}
        self._summary_cache: Dict[Tuple[str, Tuple[str, ...]], TaintState] = {}
        self._interprocedural_summary_cache: Dict[
            Tuple[str, Tuple[str, ...], Tuple[int, ...]], TaintState
        ] = {}

    def add_source(self, name: str, kind: str = "untrusted") -> None:
        self._sources.add(name)
        self._source_kinds[name] = self._source_kinds.get(name, frozenset()) | {kind}

    def add_sink(
        self,
        name: str,
        cwe: str = "",
        *,
        kind: str = "dangerous",
        positions: FrozenSet[int] = frozenset({0}),
    ) -> None:
        self._sinks[name] = cwe or name
        self._sink_kinds[name] = self._sink_kinds.get(name, frozenset()) | {kind}
        self._sink_positions[name] = (
            self._sink_positions.get(name, frozenset()) | positions
        )
        if not any(kind in rule.sink_kinds for rule in self._rules):
            self._rules.append(
                TaintRule(
                    rule_id=f"CPG-MANUAL-{kind.upper()}",
                    title=f"Untrusted data reaches {kind} sink",
                    source_kinds=frozenset({"untrusted"}),
                    sink_kinds=frozenset({kind}),
                    severity="high",
                    cwe=cwe or None,
                )
            )

    def add_sanitizer(
        self, name: str, kinds: FrozenSet[str] = frozenset({"*"})
    ) -> None:
        self._sanitizers[name] = self._sanitizers.get(name, frozenset()) | kinds

    def apply_policy(self, policy: TaintPolicy) -> None:
        """Merge one strict-v2 typed policy into this engine."""
        for name, kinds in policy.source_kinds_by_call.items():
            self._sources.add(name)
            self._source_kinds[name] = self._source_kinds.get(name, frozenset()) | kinds
        for name, kinds in policy.sink_kinds_by_call.items():
            self._sink_kinds[name] = self._sink_kinds.get(name, frozenset()) | kinds
            self._sink_positions[name] = self._sink_positions.get(
                name, frozenset()
            ) | policy.sink_positions_by_call.get(name, frozenset({0}))
            if name in policy.sink_severity_by_call:
                self._sink_severity[name] = policy.sink_severity_by_call[name]
        for name, kinds in policy.sanitizer_kinds_by_call.items():
            self._sanitizers[name] = self._sanitizers.get(name, frozenset()) | kinds
        known_rule_ids = {rule.rule_id for rule in self._rules}
        self._rules.extend(
            rule for rule in policy.rules if rule.rule_id not in known_rule_ids
        )
        for name, kinds in policy.sink_kinds_by_call.items():
            matching = [rule for rule in self._rules if rule.sink_kinds & kinds]
            cwe = policy.sink_cwe_by_call.get(name) or next(
                (rule.cwe for rule in matching if rule.cwe), ""
            )
            self._sinks[name] = cwe or next(iter(sorted(kinds)), name)

    @property
    def sources(self) -> FrozenSet[str]:
        return frozenset(self._sources)

    @property
    def sinks(self) -> Dict[str, str]:
        return dict(self._sinks)

    @property
    def sanitizers(self) -> Dict[str, FrozenSet[str]]:
        return dict(self._sanitizers)

    @property
    def rules(self) -> tuple[TaintRule, ...]:
        return tuple(self._rules)

    def find_taint_paths(
        self,
    ) -> List[TaintFinding]:
        """Find source-to-sink taint flows under the configured typed policy."""
        self._cpg._ensure_built()
        initial_call_context: Tuple[int, ...] = ()

        seeds = self._collect_seeds()
        if not seeds:
            return []

        findings: List[TaintFinding] = []
        traversal_kinds: Set[CPGEdgeKind] = {
            CPGEdgeKind.CFG_NEXT,
            CPGEdgeKind.CFG_BRANCH_TRUE,
            CPGEdgeKind.CFG_BRANCH_FALSE,
            CPGEdgeKind.CFG_EXCEPT,
            CPGEdgeKind.DATA,
            CPGEdgeKind.CALL,
            CPGEdgeKind.RETURN_EDGE,
        }

        for seed_node, seed_name, source_kinds in seeds:
            # (node_id, tags, call_context) → context-sensitive visited state
            visited: Set[Tuple[int, Tuple[str, ...], Tuple[int, ...]]] = set()
            # Loop re-entry: track how many times each loop header has been
            # entered with a distinct (node_id, call_context) pair.
            loop_entries: Dict[Tuple[int, Tuple[int, ...]], int] = {}
            worklist: deque[
                Tuple[
                    PDGNode,
                    TaintState,
                    List[PDGNode],
                    MemoryLayout,
                    Tuple[int, ...],
                ]
            ] = deque()
            seed_tag = f"from:{seed_name}"
            initial_state = TaintState(tags=source_kinds)
            worklist.append(
                (seed_node, initial_state, [], MemoryLayout(), initial_call_context)
            )

            while worklist:
                node, tstate, path, mem, call_context = worklist.popleft()
                state_key: Tuple[int, Tuple[str, ...], Tuple[int, ...]] = (
                    node.node_id,
                    tuple(sorted(tstate.tags)),
                    call_context,
                )
                if state_key in visited:
                    # Allow re-entering loop headers (fixpoint iteration).
                    if self._is_loop_header(node):
                        lk = (node.node_id, call_context)
                        loop_entries[lk] = loop_entries.get(lk, 0) + 1
                        if loop_entries[lk] > self._max_loop_iterations:
                            continue
                    else:
                        continue
                else:
                    visited.add(state_key)

                existing = self._node_taint.get(node.node_id, _CLEAN)
                self._node_taint[node.node_id] = existing.merge(tstate)

                path = path + [node]

                # For-loop iterator → index taint propagation: when
                # iterating over a tainted container, the loop variable
                # inherits the taint.
                self._propagate_for_loop_index(node, tstate, mem)

                sink_name, cwe = self._check_sink(node)
                if sink_name is not None and tstate.is_tainted():
                    for rule in self._matching_rules(tstate.tags, sink_name):
                        findings.append(
                            TaintFinding(
                                cwe=cwe or rule.cwe or "",
                                severity=self._sink_severity.get(
                                    sink_name, rule.severity
                                ),
                                source_label=seed_tag,
                                sink_label=sink_name,
                                source_node=seed_node,
                                sink_node=node,
                                path_nodes=list(path),
                                tags=tstate.tags,
                                sanitizers=tstate.sanitized_by,
                                rule_id=rule.rule_id,
                                rule_title=rule.title,
                                suggestion=rule.suggestion or "",
                            )
                        )
                    continue

                for succ in self._cpg.successors(node, kinds=traversal_kinds):
                    # DATA edge with label → mark variable tainted in MemoryLayout
                    for e in self._cpg._cpg_edges_out.get(node.node_id, ()):
                        if e.target is succ and e.kind == CPGEdgeKind.DATA and e.label:
                            mem.mark_tainted(e.label, tstate)

                    next_state = self._propagate(tstate, node, succ, mem)
                    if next_state is None or not next_state.is_tainted():
                        continue
                    new_mem = mem
                    new_ctx_path = path
                    new_call_context = call_context
                    if self._is_call_edge(node, succ):
                        next_state, new_mem = self._interprocedural_transfer(
                            next_state, node, succ, mem, call_context
                        )
                        new_ctx_path = path + [succ]
                        new_call_context = call_context + (succ.node_id,)
                        if len(new_call_context) > self._max_call_depth:
                            continue
                    elif self._is_return_edge(node, succ):
                        # Propagate taint from callee's return value to call-site
                        next_state = self._propagate_return(next_state, node, succ, mem)
                        if call_context:
                            new_call_context = call_context[:-1]
                    worklist.append(
                        (succ, next_state, new_ctx_path, new_mem, new_call_context)
                    )

        findings.extend(self._find_local_statement_flows(findings))
        return findings

    def get_node_taint(self, node: PDGNode | int) -> TaintState:
        node_id = node if isinstance(node, int) else node.node_id
        return self._node_taint.get(node_id, _CLEAN)

    def _matching_rules(
        self, source_kinds: FrozenSet[str], sink_name: str
    ) -> tuple[TaintRule, ...]:
        sink_kinds = self._sink_kinds.get(sink_name, frozenset())
        return tuple(
            rule
            for rule in self._rules
            if rule.source_kinds & source_kinds and rule.sink_kinds & sink_kinds
        )

    def _source_kinds_for_name(self, source_name: str) -> FrozenSet[str]:
        for configured, kinds in self._source_kinds.items():
            if (
                source_name == configured
                or source_name.endswith("." + configured)
                or configured.endswith("." + source_name)
            ):
                return kinds
        return frozenset()

    def _collect_seeds(self) -> List[Tuple[PDGNode, str, FrozenSet[str]]]:
        seeds: List[Tuple[PDGNode, str, FrozenSet[str]]] = []
        cpg = self._cpg
        # Strategy 1: Match PDG nodes whose AST contains a call to a source
        for node in cpg.nodes():
            src = self._detect_source(node)
            if src:
                seeds.append((node, src, self._source_kinds_for_name(src)))
        # Strategy 2: Match via DATA edges from source-named definitions
        source_vars: Dict[str, Tuple[str, FrozenSet[str]]] = {}
        for node in cpg.nodes():
            source_name = self._detect_source(node)
            if source_name:
                # Follow DATA edges: which variables does this source define?
                for edge in cpg._cpg_edges_out.get(node.node_id, ()):
                    if edge.kind == CPGEdgeKind.DATA and edge.label:
                        source_vars[edge.label] = (
                            source_name,
                            self._source_kinds_for_name(source_name),
                        )
        if source_vars:
            for var, (source_name, source_kinds) in source_vars.items():
                for seed_node in cpg.defs.get(var, []):
                    if seed_node not in [s[0] for s in seeds]:
                        seeds.append((seed_node, source_name, source_kinds))
        return seeds
