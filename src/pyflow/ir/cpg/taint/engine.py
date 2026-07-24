"""Worklist orchestration and public configuration for CPG taint analysis."""

from __future__ import annotations
from collections import deque
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple
from pyflow.ir.pdg.graph import PDGNode
from pyflow.ir.cpg.graph import CodePropertyGraph, CPGEdgeKind
from .model import MemoryLayout, TaintFinding, TaintState, _CLEAN, _USER_CONTROLLED
from .defaults import _DEFAULT_SANITIZERS, _DEFAULT_SINKS, _DEFAULT_SOURCES
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
        sources: Optional[Set[str]] = None,
        sinks: Optional[Dict[str, str]] = None,
        sanitizers: Optional[Set[str]] = None,
        extra_taint_specs: Optional[Dict[str, Any]] = None,
        max_call_depth: int = 5,
        max_loop_iterations: int = 3,
    ) -> None:
        self._cpg = cpg
        self._sources: Set[str] = set(_DEFAULT_SOURCES)
        self._sinks: Dict[str, str] = dict(_DEFAULT_SINKS)
        self._sanitizers: Dict[str, FrozenSet[str]] = dict(_DEFAULT_SANITIZERS)
        self._max_call_depth: int = max_call_depth
        self._max_loop_iterations: int = max_loop_iterations

        if sources:
            self._sources.update(sources)
        if sinks:
            self._sinks.update(sinks)
        if sanitizers:
            for san in sanitizers:
                self.add_sanitizer(san)
        if extra_taint_specs:
            self.merge_taint_specs(extra_taint_specs)

        self._node_taint: Dict[int, TaintState] = {}
        self._summary_cache: Dict[Tuple[str, Tuple[str, ...]], TaintState] = {}
        self._interprocedural_summary_cache: Dict[
            Tuple[str, Tuple[str, ...], Tuple[int, ...]], TaintState
        ] = {}

    def add_source(self, name: str) -> None:
        self._sources.add(name)

    def add_sink(self, name: str, cwe: str = "") -> None:
        self._sinks[name] = cwe or name

    def add_sanitizer(self, name: str, cwes: Optional[Set[str]] = None) -> None:
        if cwes is not None:
            self._sanitizers[name] = frozenset(cwes)
        else:
            self._sanitizers.setdefault(name, frozenset())

    def merge_taint_specs(
        self, specs: Dict[str, Any], language: str = "python"
    ) -> None:
        """Merge Ansede-style taint specs into this engine.

        Only entries matching *language* (default ``"python"``) are loaded,
        so multi-language spec files are handled correctly.
        """
        for src in specs.get("sources", {}).get(language, []):
            name = src if isinstance(src, str) else src.get("name", "")
            if name:
                self.add_source(name)
        for sink in specs.get("sinks", {}).get(language, []):
            if isinstance(sink, str):
                self.add_sink(sink, cwe="CWE-0")
            else:
                name = sink.get("name", "")
                if name:
                    self.add_sink(name, cwe=sink.get("cwe", "CWE-0"))
        for san in specs.get("sanitizers", {}).get(language, []):
            if isinstance(san, str):
                self.add_sanitizer(san)
            else:
                name = san.get("name", "")
                if name:
                    san_cwes = san.get("cwe", [])
                    if isinstance(san_cwes, str):
                        san_cwes = {san_cwes}
                    self.add_sanitizer(name, cwes=set(san_cwes) if san_cwes else None)

    @property
    def sources(self) -> FrozenSet[str]:
        return frozenset(self._sources)

    @property
    def sinks(self) -> Dict[str, str]:
        return dict(self._sinks)

    @property
    def sanitizers(self) -> Dict[str, FrozenSet[str]]:
        return dict(self._sanitizers)

    def find_taint_paths(
        self,
        call_context: Optional[Tuple[int, ...]] = None,
    ) -> List[TaintFinding]:
        """Find source-to-sink taint flows.

        ``call_context`` is accepted for Ansede API compatibility.  PyFlow's
        traversal manages call context internally, so a supplied tuple is used
        only as the initial context for each seed.
        """
        self._cpg._ensure_built()
        initial_call_context: Tuple[int, ...] = tuple(call_context or ())

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

        for seed_node, seed_tag in seeds:
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
            initial_state = _USER_CONTROLLED.add_tag(seed_tag)
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
                    findings.append(
                        TaintFinding(
                            cwe=cwe,
                            severity="high",
                            source_label=seed_tag,
                            sink_label=sink_name,
                            source_node=seed_node,
                            sink_node=node,
                            path_nodes=list(path),
                            tags=tstate.tags,
                            sanitizers=tstate.sanitized_by,
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

    def _collect_seeds(self) -> List[Tuple[PDGNode, str]]:
        seeds: List[Tuple[PDGNode, str]] = []
        cpg = self._cpg
        # Strategy 1: Match PDG nodes whose AST contains a call to a source
        for node in cpg.nodes():
            src = self._detect_source(node)
            if src:
                seeds.append((node, f"from:{src}"))
        # Strategy 2: Match via DATA edges from source-named definitions
        source_vars = set()
        for node in cpg.nodes():
            if self._detect_source(node):
                # Follow DATA edges: which variables does this source define?
                for edge in cpg._cpg_edges_out.get(node.node_id, ()):
                    if edge.kind == CPGEdgeKind.DATA and edge.label:
                        source_vars.add(edge.label)
        if source_vars:
            for var in source_vars:
                for seed_node in cpg.defs.get(var, []):
                    if seed_node not in [s[0] for s in seeds]:
                        seeds.append((seed_node, f"var:{var}"))
        return seeds
