"""
CPG Taint Engine — context-sensitive taint analysis over the Code Property Graph.

Walks CPG edges (CFG + DATA) from sources to sinks using a worklist-based
forward dataflow traversal with heap-aware alias tracking.  Matching uses
both PDGNode labels and AST structure inspection via pyflow's AST types.

Features:
- AST-based call name resolution for source/sink matching
- Parameterized SQL detection (safe queries with tuple/list/dict args)
- isinstance type-guard stripping on CFG_BRANCH_TRUE edges
- Validating regex heuristic (anchored ^...$ patterns only)
- Assign RHS propagation (alias, subscript, collection, f-string, %-format)
- Per-AST-kind propagation dispatch (Call, Assign, BinaryOp, Return,
  GetSubscript, AugAssign)
- Context-sensitive visited state with call-context tracking and
  configurable max call depth (``max_call_depth``)
- Interprocedural summary cache per (func, context)
- Source tag provenance ("from:request.args")
- Per-node taint state queryable post-analysis
- Lambda call handling via CPG funcs
- getattr dynamic dispatch detection
- Dict unpack (``**kwargs``) taint propagation
- Subscript read propagation (``x = tainted_list[i]``)
- F-string and %-format taint propagation
- Ansede-style taint spec loading (JSON sources / sinks / sanitizers)
- Extended default source/sink/sanitizer registries
- SARIF export for CI/CD integration

Data structures
---------------
* ``TaintState`` — immutable taint tags + sanitizer provenance
* ``MemoryCell`` — abstract heap cell with field-sensitive taint slots
* ``MemoryLayout`` — variable → address → cell alias map
* ``TaintFinding`` — discovered taint flow from source to sink
* ``CPGTaintEngine`` — main engine: ``find_taint_paths()``

Typical usage::

    from pyflow.analysis.cpg import CodePropertyGraph
    from pyflow.analysis.cpg.taint import CPGTaintEngine

    cpg = CodePropertyGraph()
    cpg.add_function("main", pdg)
    cpg.build()

    engine = CPGTaintEngine(cpg)
    engine.add_source("request.args")
    engine.add_sink("subprocess.run", cwe="CWE-78")
    paths = engine.find_taint_paths()
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from pyflow.analysis.pdg.graph import PDGNode
from pyflow.analysis.cpg.graph import CodePropertyGraph, CPGEdgeKind
from pyflow.language.python import ast as py_ast


# ── Taint State ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TaintState:
    """Immutable taint state attached to a value or memory cell field."""

    tags: FrozenSet[str] = field(default_factory=frozenset)
    sanitized_by: FrozenSet[str] = field(default_factory=frozenset)

    def is_tainted(self) -> bool:
        return bool(self.tags)

    def merge(self, other: TaintState) -> TaintState:
        return TaintState(
            tags=self.tags | other.tags,
            sanitized_by=self.sanitized_by & other.sanitized_by,
        )

    def sanitize(self, sanitizer_name: str) -> TaintState:
        return TaintState(
            tags=frozenset(),
            sanitized_by=self.sanitized_by | {sanitizer_name},
        )

    def add_tag(self, tag: str) -> TaintState:
        return TaintState(
            tags=self.tags | {tag},
            sanitized_by=self.sanitized_by,
        )

    @classmethod
    def clean(cls) -> TaintState:
        return _CLEAN

    @classmethod
    def user_controlled(cls) -> TaintState:
        return _USER_CONTROLLED


_CLEAN = TaintState()
_USER_CONTROLLED = TaintState(tags=frozenset({"user_controlled"}))


# ── Memory Model ─────────────────────────────────────────────────────────────


@dataclass
class MemoryCell:
    """Abstract heap cell with field-sensitive taint slots."""

    fields: Dict[str, TaintState] = field(default_factory=dict)

    def taint_field(self, fname: str, state: TaintState) -> None:
        existing = self.fields.get(fname, _CLEAN)
        self.fields[fname] = existing.merge(state)

    def read_field(self, fname: str) -> TaintState:
        return self.fields.get(fname, _CLEAN)

    def is_any_tainted(self) -> bool:
        return any(s.is_tainted() for s in self.fields.values())


class MemoryLayout:
    """Maps variable names to abstract addresses, and addresses to
    ``MemoryCell`` objects.  Supports aliasing through shared addresses.
    """

    def __init__(self) -> None:
        self._var_to_addr: Dict[str, str] = {}
        self._heap: Dict[str, MemoryCell] = {}
        self._counter: int = 0

    def _fresh_addr(self) -> str:
        self._counter += 1
        return f"addr_0x{self._counter:04x}"

    def _cell_for(self, var: str) -> MemoryCell:
        addr = self._var_to_addr.get(var)
        if addr is None:
            addr = self._fresh_addr()
            self._var_to_addr[var] = addr
            self._heap[addr] = MemoryCell()
        return self._heap[addr]

    def alias(self, var_dst: str, var_src: str) -> None:
        src_addr = self._var_to_addr.get(var_src)
        if src_addr:
            self._var_to_addr[var_dst] = src_addr
        else:
            addr = self._fresh_addr()
            self._var_to_addr[var_src] = addr
            self._var_to_addr[var_dst] = addr
            self._heap[addr] = MemoryCell()

    def write(self, var: str, field_name: str, state: TaintState) -> None:
        cell = self._cell_for(var)
        cell.taint_field(field_name, state)

    def read(self, var: str, field_name: str = "__scalar__") -> TaintState:
        addr = self._var_to_addr.get(var)
        if addr is None:
            return _CLEAN
        cell = self._heap.get(addr, MemoryCell())
        return cell.read_field(field_name)

    def mark_tainted(self, var: str, state: TaintState) -> None:
        self.write(var, "__scalar__", state)

    def is_tainted(self, var: str) -> bool:
        return self.read(var, "__scalar__").is_tainted()

    def snapshot(self) -> Dict[str, Any]:
        import copy

        return copy.deepcopy(
            {"vars": self._var_to_addr, "heap": self._heap, "counter": self._counter}
        )

    def restore(self, snap: Dict[str, Any]) -> None:
        import copy

        self._var_to_addr = copy.deepcopy(snap["vars"])
        self._heap = copy.deepcopy(snap["heap"])
        self._counter = snap["counter"]

    def merge_from(self, other: MemoryLayout) -> None:
        for var, addr in other._var_to_addr.items():
            if addr in other._heap:
                other_cell = other._heap[addr]
                for fname, state in other_cell.fields.items():
                    if state.is_tainted():
                        cell = self._cell_for(var)
                        cell.taint_field(fname, state)


# ── Finding ──────────────────────────────────────────────────────────────────


@dataclass
class TaintFinding:
    """A discovered taint flow from source to sink."""

    cwe: str
    severity: str
    source_label: str
    sink_label: str
    source_node: PDGNode
    sink_node: PDGNode
    path_nodes: List[PDGNode] = field(default_factory=list)
    tags: FrozenSet[str] = field(default_factory=frozenset)
    sanitizers: FrozenSet[str] = field(default_factory=frozenset)

    @property
    def source_line(self) -> int:
        if self.source_node is None:
            return 0
        return getattr(self.source_node.ast_node, "lineno", 0) or 0

    @property
    def sink_line(self) -> int:
        if self.sink_node is None:
            return 0
        return getattr(self.sink_node.ast_node, "lineno", 0) or 0

    @property
    def path_length(self) -> int:
        return len(self.path_nodes)

    @property
    def confidence(self) -> float:
        """Confidence score 0.0–1.0 based on path quality signals.

        - Base: 0.50
        - +0.10 per path node (capped at +0.30): longer flow = more certain
        - +0.10 if sanitizers are present (explicit sanitization = stronger flow signal)
        - +0.10 if source_label is a known framework source (e.g., request.*)
        - Capped at 1.0, floored at 0.05
        """
        score = 0.50
        score += min(0.30, len(self.path_nodes) * 0.05)
        if self.sanitizers:
            score += 0.10
        src_lower = self.source_label.lower()
        if any(
            kw in src_lower
            for kw in ("request", "input", "environ", "argv", "get_json", "form.get")
        ):
            score += 0.10
        return max(0.05, min(1.0, score))

    @property
    def dedup_key(self) -> Tuple[str, int, int]:
        """Key for deduplication: (cwe, source_line, sink_line)."""
        return (self.cwe, self.source_line, self.sink_line)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "cwe": self.cwe,
            "severity": self.severity,
            "source_label": self.source_label,
            "sink_label": self.sink_label,
            "source_line": self.source_line,
            "sink_line": self.sink_line,
            "path_length": self.path_length,
            "confidence": round(self.confidence, 2),
            "tags": sorted(self.tags),
            "sanitizers": sorted(self.sanitizers),
            "path_preview": [
                {
                    "kind": n.kind,
                    "line": getattr(n.ast_node, "lineno", 0) or 0,
                    "label": (n.label or "")[:80],
                }
                for n in self.path_nodes[:10]
            ],
        }

    def to_sarif(self, *, rule_index: int = 0) -> Dict[str, Any]:
        """Export as a SARIF result object.

        Parameters
        ----------
        rule_index:
            Zero-based index into the SARIF ``rules`` array.
        """
        return {
            "ruleId": self.cwe,
            "ruleIndex": rule_index,
            "level": _severity_to_sarif_level(self.severity),
            "message": {
                "text": (
                    f"Tainted data from {self.source_label} "
                    f"reaches {self.sink_label} [{self.cwe}]"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": ""},
                        "region": {
                            "startLine": self.source_line,
                        },
                    }
                }
            ],
            "properties": {
                "source_label": self.source_label,
                "sink_label": self.sink_label,
                "sink_line": self.sink_line,
                "path_length": self.path_length,
                "confidence": round(self.confidence, 2),
                "tags": sorted(self.tags),
                "sanitizers": sorted(self.sanitizers),
            },
        }


def _severity_to_sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning"}.get(
        severity.lower(), "note"
    )


# ── Source / Sink / Sanitizer Registries ─────────────────────────────────────


_DEFAULT_SOURCES: Set[str] = {
    "request.args",
    "request.form",
    "request.json",
    "request.data",
    "request.cookies",
    "request.headers",
    "request.files",
    "request.values",
    "request.get_data",
    "os.environ",
    "os.getenv",
    "os.environ.get",
    "input",
    "sys.stdin.read",
    "sys.argv",
    "cursor.fetchone",
    "cursor.fetchall",
    "cursor.fetchmany",
    "get_json",
    "form.get",
    "args.get",
    "pd.read_csv",
    "pd.read_json",
    "pd.read_sql",
    "pd.read_excel",
    "pd.read_parquet",
    "df.query",
    "spark.sql",
    "sc.textFile",
}

_DEFAULT_SINKS: Dict[str, str] = {
    "subprocess.run": "CWE-78",
    "subprocess.call": "CWE-78",
    "subprocess.Popen": "CWE-78",
    "os.system": "CWE-78",
    "os.popen": "CWE-78",
    "eval": "CWE-95",
    "exec": "CWE-95",
    "cursor.execute": "CWE-89",
    "db.execute": "CWE-89",
    "conn.execute": "CWE-89",
    "session.execute": "CWE-89",
    "engine.execute": "CWE-89",
    "spark.sql": "CWE-89",
    "execute": "CWE-89",
    "requests.get": "CWE-918",
    "requests.post": "CWE-918",
    "requests.put": "CWE-918",
    "requests.request": "CWE-918",
    "urllib.request.urlopen": "CWE-918",
    "urllib.urlopen": "CWE-918",
    "open": "CWE-22",
    "os.path.join": "CWE-22",
    "pathlib.Path": "CWE-22",
    "pickle.loads": "CWE-502",
    "yaml.load": "CWE-502",
    "marshal.loads": "CWE-502",
    "render_template_string": "CWE-79",
    "Markup": "CWE-79",
    "jinja2.Template": "CWE-79",
    "df.query": "CWE-89",
}

#: Sanitizer name → set of CWEs it mitigates.
#: An **empty** frozenset means the sanitizer is *universal* — it strips
#: all taint tags regardless of the eventual sink's CWE.
#: A *non-empty* frozenset means the sanitizer only mitigates taint for
#: those specific CWEs; for other CWE sinks, the taint is still live.
_DEFAULT_SANITIZERS: Dict[str, FrozenSet[str]] = {
    "html.escape": frozenset({"CWE-79"}),
    "markupsafe.escape": frozenset({"CWE-79"}),
    "bleach.clean": frozenset({"CWE-79"}),
    "escape": frozenset({"CWE-79"}),
    "urllib.parse.quote": frozenset({"CWE-89", "CWE-918"}),
    "quote": frozenset({"CWE-918"}),
    "quote_plus": frozenset({"CWE-918"}),
    "int": frozenset({"CWE-89", "CWE-78"}),
    "float": frozenset({"CWE-89"}),
    "bool": frozenset({"CWE-89"}),
    "uuid.UUID": frozenset({"CWE-89"}),
    "re.match": frozenset({"CWE-89", "CWE-78", "CWE-22"}),
    "re.fullmatch": frozenset({"CWE-89", "CWE-78", "CWE-22"}),
    "re.search": frozenset({"CWE-89"}),
    "parameterized": frozenset({"CWE-89"}),
    "sqlalchemy.text": frozenset({"CWE-89"}),
    "flask_wtf.csrf": frozenset({"CWE-352"}),
}

# SQL sink methods that support parameterized queries via a second argument
_SQL_SINKS: FrozenSet[str] = frozenset({"execute", "executemany", "executescript"})


# ── Dunder propagation table ─────────────────────────────────────────────────

_DUNDER_PROPAGATE: FrozenSet[str] = frozenset({
    "__str__", "__repr__", "__add__", "__getattr__", "__getitem__", "__iter__",
})


# ── CPG Taint Engine ─────────────────────────────────────────────────────────


class CPGTaintEngine:
    """Context-sensitive taint analysis over a :class:`CodePropertyGraph`.

    Walks ``CFG_NEXT``, ``CFG_BRANCH_*``, ``CFG_EXCEPT``, and ``DATA``
    edges from source-tagged nodes to sinks, maintaining per-path
    ``TaintState`` and an optional ``MemoryLayout`` for alias tracking.
    The worklist uses a **context-sensitive visited state** key that
    includes the call-context tuple (``node_id``, ``tags``, ``call_context``)
    to distinguish analysis states reached via different call paths.

    Parameters
    ----------
    max_call_depth:
        Maximum call-context depth for context-sensitive traversal.
        Calls deeper than this limit are skipped (default 5).

    Features
    --------
    * AST-based call name resolution for precise source/sink matching
    * Parameterized SQL detection (safe parameterized queries skipped)
    * isinstance type-guard stripping on CFG_BRANCH_TRUE edges
    * Validating regex heuristic (anchored ^...$ patterns only)
    * Assign RHS propagation (alias, subscript, collection, f-string)
    * Per-AST-kind propagation dispatch (Call, Assign, BinaryOp,
      GetSubscript, Return)
    * Context-sensitive visited state with call-context tracking
    * Interprocedural summary cache per (func, call context)
    * Source tag provenance (``"from:source_name"``)
    * Per-node taint state queryable post-analysis via :meth:`get_node_taint`
    * getattr dynamic dispatch detection
    * Dict unpack (``**kwargs``) taint propagation
    * Subscript read propagation (``x = tainted_list[i]``)
    * F-string / %-format taint propagation
    * Ansede-style JSON taint spec loading
    """

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

    # ── Configuration ───────────────────────────────────────────────────

    def add_source(self, name: str) -> None:
        self._sources.add(name)

    def add_sink(self, name: str, cwe: str = "") -> None:
        self._sinks[name] = cwe or name

    def add_sanitizer(self, name: str, cwes: Optional[Set[str]] = None) -> None:
        if cwes is not None:
            self._sanitizers[name] = frozenset(cwes)
        else:
            self._sanitizers.setdefault(name, frozenset())

    def merge_taint_specs(self, specs: Dict[str, Any]) -> None:
        """Merge Ansede-style taint specs into this engine."""
        for lang_specs in specs.get("sources", {}).values():
            for src in lang_specs:
                name = src if isinstance(src, str) else src.get("name", "")
                if name:
                    self.add_source(name)
        for lang_specs in specs.get("sinks", {}).values():
            for sink in lang_specs:
                if isinstance(sink, str):
                    self.add_sink(sink, cwe="CWE-0")
                else:
                    name = sink.get("name", "")
                    if name:
                        self.add_sink(name, cwe=sink.get("cwe", "CWE-0"))
        for lang_specs in specs.get("sanitizers", {}).values():
            for san in lang_specs:
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

    # ── Main Finding ────────────────────────────────────────────────────

    def find_taint_paths(self) -> List[TaintFinding]:
        self._cpg._ensure_built()

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
                    PDGNode, TaintState, List[PDGNode],
                    MemoryLayout, Tuple[int, ...],
                ]
            ] = deque()
            initial_state = _USER_CONTROLLED.add_tag(seed_tag)
            worklist.append((seed_node, initial_state, [], MemoryLayout(), ()))

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
                        if (
                            e.target is succ
                            and e.kind == CPGEdgeKind.DATA
                            and e.label
                        ):
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

        return findings

    def get_node_taint(self, node: PDGNode) -> TaintState:
        return self._node_taint.get(node.node_id, _CLEAN)

    # ── Seed Collection ──────────────────────────────────────────────────

    def _detect_source(self, node: PDGNode) -> Optional[str]:
        ast_node = node.ast_node
        if ast_node is not None:
            call_name = self._extract_call_name(ast_node)
            if call_name and self._matches_source(call_name):
                return call_name
        label = node.label or ""
        for src in self._sources:
            if src in label:
                return src
        return None

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

    def _detect_source(self, node: PDGNode) -> Optional[str]:
        ast_node = node.ast_node
        if ast_node is None:
            return None
        call_name = self._extract_call_name(ast_node)
        if call_name and self._matches_source(call_name):
            return call_name
        label = node.label or ""
        for src in self._sources:
            if src in label:
                return src
        return None

    # ── Sink Detection ──────────────────────────────────────────────────

    def _check_sink(self, node: PDGNode) -> Tuple[Optional[str], str]:
        ast_node = node.ast_node
        if ast_node is not None:
            call_name = self._extract_call_name(ast_node)
            if call_name:
                cwe = self._match_sink_cwe(call_name)
                if cwe and not self._is_parameterized_safe(ast_node, call_name):
                    return call_name, cwe
        label = node.label or ""
        for sink_name, cwe in self._sinks.items():
            if sink_name in label:
                return sink_name, cwe
        # Strategy 3: Match via DATA edges — if this node uses a sink-named variable
        cpg = self._cpg
        for edge in cpg._cpg_edges_in.get(node.node_id, ()):
            if edge.kind == CPGEdgeKind.DATA and edge.label:
                cwe = self._match_sink_cwe(edge.label)
                if cwe:
                    return edge.label, cwe
        return None, ""

    def _is_parameterized_safe(self, ast_node: Any, call_name: str) -> bool:
        sink_base = call_name.split(".")[-1]
        if sink_base not in _SQL_SINKS:
            return False
        args = getattr(ast_node, "args", None)
        if args is None or len(args) < 2:
            return False
        second = args[1]
        second_type = type(second).__name__
        return second_type in ("Tuple", "List", "Dict")

    # ── Call Name Resolution ────────────────────────────────────────────

    def _extract_call_name(self, ast_node: Any) -> Optional[str]:
        if not isinstance(ast_node, py_ast.Call):
            return self._extract_call_from_assign(ast_node)
        expr = getattr(ast_node, "expr", None)
        if expr is None:
            return None
        return self._resolve_call_expr(expr)

    def _extract_call_from_assign(self, ast_node: Any) -> Optional[str]:
        if not isinstance(ast_node, py_ast.Assign):
            return None
        rhs = getattr(ast_node, "expr", None)
        if rhs is None:
            return None
        if isinstance(rhs, py_ast.Call):
            return self._extract_call_name(rhs)
        return None

    def _resolve_call_expr(self, expr: Any) -> Optional[str]:
        if isinstance(expr, py_ast.Local):
            n = getattr(expr, "name", None)
            if isinstance(n, str):
                return n
            return str(n) if n is not None else None
        if hasattr(expr, "children"):
            parts: List[str] = []
            for child in expr.children():
                if isinstance(child, (list, tuple)) or child is None:
                    continue
                name = self._resolve_call_expr(child)
                if name:
                    parts.append(name)
            return ".".join(parts) if parts else None
        return None

    # ── Source/Sink Matching ────────────────────────────────────────────

    def _matches_source(self, name: str) -> bool:
        if not name:
            return False
        for src in self._sources:
            if name == src or name.endswith("." + src) or src.endswith("." + name):
                return True
        return False

    def _match_sink_cwe(self, name: str) -> str:
        if not name:
            return ""
        for sink, cwe in self._sinks.items():
            if name == sink or name.endswith("." + sink):
                return cwe
            if "." in name and sink.endswith("." + name):
                return cwe
        return ""

    # ── Propagation ─────────────────────────────────────────────────────

    def _propagate(
        self,
        tstate: TaintState,
        src_node: PDGNode,
        dst_node: PDGNode,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        ast_node = dst_node.ast_node
        if ast_node is None:
            return tstate

        src_label = src_node.label or ""
        if src_label.startswith("isinstance_guard:"):
            guarded_var = src_label.split(":", 1)[1]
            if guarded_var:
                mem.mark_tainted(guarded_var, _CLEAN)
                return None

        if self._isinstance_guard_strip(ast_node, mem):
            return None

        if isinstance(ast_node, py_ast.Call):
            return self._propagate_call(ast_node, tstate, mem)
        if isinstance(ast_node, py_ast.Assign):
            return self._propagate_assign(ast_node, tstate, mem)
        if isinstance(ast_node, py_ast.AnnAssign):
            return self._propagate_annassign(ast_node, tstate, mem)
        if isinstance(ast_node, py_ast.BinaryOp):
            return self._propagate_binary_op(ast_node, tstate, mem)
        if isinstance(ast_node, py_ast.GetSubscript):
            return self._propagate_subscript(ast_node, tstate, mem)
        if isinstance(ast_node, py_ast.Return):
            return tstate

        if isinstance(ast_node, py_ast.TryExceptFinally):
            return self._propagate_try(ast_node, tstate, dst_node, mem)

        label = dst_node.label or ""
        for san, san_cwes in self._sanitizers.items():
            if san in label:
                return self._apply_sanitizer(tstate, san, san_cwes)

        return tstate

    # ── Call Propagation ────────────────────────────────────────────────

    def _propagate_call(
        self,
        call_node: py_ast.Call,
        tstate: TaintState,
        mem: MemoryLayout,
        *,
        pending_sink_cwe: str = "",
    ) -> Optional[TaintState]:
        call_name = self._extract_call_name(call_node)

        if call_name and call_name in self._sanitizers:
            if call_name in ("re.match", "re.fullmatch", "re.search"):
                if self._is_validating_regex(call_node):
                    return self._apply_sanitizer(
                        tstate,
                        call_name,
                        self._sanitizers[call_name],
                        pending_sink_cwe,
                    )
                return tstate
            return self._apply_sanitizer(
                tstate, call_name, self._sanitizers[call_name], pending_sink_cwe
            )

        if call_name in ("int", "float", "bool", "str"):
            return tstate.sanitize(call_name)

        if call_name == "getattr":
            return self._handle_getattr(call_node, tstate, mem)

        if self._has_tainted_dict_unpack(call_node, mem):
            return tstate

        if call_name and call_name.split(".")[-1] in _DUNDER_PROPAGATE:
            return tstate

        if call_name and call_name.startswith("<lambda"):
            return self._handle_lambda_call(call_name, tstate, mem)

        if call_name:
            cache_key = (call_name, tuple(sorted(tstate.tags)))
            cached = self._summary_cache.get(cache_key)
            if cached is not None:
                return cached if cached.is_tainted() else None

        return tstate

    def _apply_sanitizer(
        self,
        tstate: TaintState,
        sanitizer_name: str,
        sanitizer_cwes: FrozenSet[str],
        pending_sink_cwe: str = "",
    ) -> TaintState:
        if not sanitizer_cwes:
            return tstate.sanitize(sanitizer_name)
        if not pending_sink_cwe or pending_sink_cwe in sanitizer_cwes:
            return tstate.sanitize(sanitizer_name)
        return tstate

    def _handle_lambda_call(
        self,
        lambda_name: str,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        lambda_entry = self._find_lambda_entry(lambda_name)
        if lambda_entry is None:
            return tstate
        lambda_meta = self._cpg.node_meta(lambda_entry)
        if not lambda_meta.get("lambda_name"):
            return tstate
        cache_key = (lambda_name, tuple(sorted(tstate.tags)))
        cached = self._summary_cache.get(cache_key)
        if cached is not None:
            return cached if cached.is_tainted() else None
        self._summary_cache[cache_key] = tstate
        return tstate

    def _find_lambda_entry(self, lambda_name: str) -> Optional[PDGNode]:
        for node in self._cpg.nodes():
            meta = self._cpg.node_meta(node)
            if meta.get("lambda_name") == lambda_name:
                return node
        return None

    # ── Assign Propagation ──────────────────────────────────────────────

    def _propagate_assign(
        self,
        assign_node: py_ast.Assign,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        rhs = getattr(assign_node, "expr", None)
        if rhs is None:
            return tstate
        lcls = getattr(assign_node, "lcls", None)
        if lcls is None or len(lcls) != 1:
            return tstate
        target = lcls[0]
        if not isinstance(target, py_ast.Local):
            return tstate
        var_name = getattr(target, "name", "") or ""

        if isinstance(rhs, py_ast.Local):
            rhs_name = getattr(rhs, "name", "") or ""
            if rhs_name:
                mem.alias(var_name, rhs_name)
            return tstate

        if self._looks_like_subscript(rhs):
            base_name = self._first_local_name(rhs)
            if base_name and mem.is_tainted(base_name):
                mem.mark_tainted(var_name, tstate)
                return tstate

        if isinstance(rhs, py_ast.BinaryOp):
            op_type = (
                type(getattr(rhs, "op", None)).__name__
                if hasattr(rhs, "op")
                else ""
            )
            if op_type == "Mod" or self._contains_tainted_local(rhs, mem):
                mem.mark_tainted(var_name, tstate)
                return tstate

        if isinstance(rhs, py_ast.Call):
            if tstate.is_tainted():
                mem.mark_tainted(var_name, tstate)
            return tstate

        rhs_type = type(rhs).__name__
        if rhs_type in ("List", "Tuple", "Set"):
            elts = getattr(rhs, "elts", None) or getattr(rhs, "elements", None)
            if elts:
                for elt in elts:
                    if isinstance(elt, py_ast.Local) and mem.is_tainted(
                        getattr(elt, "name", "")
                    ):
                        mem.mark_tainted(var_name, tstate)
                        return tstate

        if rhs_type == "Dict" and self._contains_tainted_local(rhs, mem):
            mem.mark_tainted(var_name, tstate)
            return tstate

        if self._looks_like_fstring(rhs) and self._contains_tainted_local(rhs, mem):
            mem.mark_tainted(var_name, tstate)
            return tstate

        return tstate

    # ── AnnAssign Propagation ─────────────────────────────────────────

    def _propagate_annassign(
        self,
        ann_node: py_ast.AnnAssign,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        """Propagate taint through an annotated assignment (``x: int = val``).

        If the RHS value is tainted, or if the target is itself a tainted
        expression, taint flows through.  Annotation-only declarations
        (``x: int`` with no value) do not propagate.
        """
        value = getattr(ann_node, "value", None)
        if value is None:
            return tstate
        target = getattr(ann_node, "target", None)
        if not isinstance(target, py_ast.Local):
            return tstate
        var_name = getattr(target, "name", "") or ""

        if isinstance(value, py_ast.Local):
            rhs_name = getattr(value, "name", "") or ""
            if rhs_name and mem.is_tainted(rhs_name):
                mem.mark_tainted(var_name, tstate)
                return tstate

        if self._contains_tainted_local(value, mem):
            mem.mark_tainted(var_name, tstate)
            return tstate

        return tstate

    # ── BinaryOp Propagation ────────────────────────────────────────────

    def _propagate_binary_op(
        self,
        binop_node: py_ast.BinaryOp,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        left = getattr(binop_node, "left", None)
        right = getattr(binop_node, "right", None)
        if (
            left
            and isinstance(left, py_ast.Local)
            and mem.is_tainted(getattr(left, "name", ""))
        ):
            return tstate
        if (
            right
            and isinstance(right, py_ast.Local)
            and mem.is_tainted(getattr(right, "name", ""))
        ):
            return tstate
        return tstate

    def _propagate_subscript(
        self,
        sub_node: py_ast.GetSubscript,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        """Propagate taint through a subscript read (``items[i]``).

        If the subscripted container or the index expression is tainted,
        the read result carries the taint.
        """
        container = getattr(sub_node, "expr", None) or getattr(sub_node, "value", None)
        if isinstance(container, py_ast.Local) and mem.is_tainted(
            getattr(container, "name", "") or ""
        ):
            return tstate
        subscript = getattr(sub_node, "subscript", None)
        if isinstance(subscript, py_ast.Local) and mem.is_tainted(
            getattr(subscript, "name", "") or ""
        ):
            return tstate
        return tstate

    # ── Structural propagation helpers ──────────────────────────────────

    @staticmethod
    def _iter_ast_children(node: Any) -> List[Any]:
        if node is None or isinstance(node, py_ast.leafTypes):
            return []
        children = getattr(node, "children", None)
        if children is None:
            return []
        result: List[Any] = []
        for child in children():
            if isinstance(child, (list, tuple)):
                result.extend(c for c in child if c is not None)
            elif child is not None:
                result.append(child)
        return result

    @classmethod
    def _first_local_name(cls, node: Any) -> str:
        if isinstance(node, py_ast.Local):
            return getattr(node, "name", "") or ""
        for child in cls._iter_ast_children(node):
            name = cls._first_local_name(child)
            if name:
                return name
        return ""

    @classmethod
    def _contains_tainted_local(cls, node: Any, mem: MemoryLayout) -> bool:
        if isinstance(node, py_ast.Local):
            return mem.is_tainted(getattr(node, "name", "") or "")
        return any(
            cls._contains_tainted_local(child, mem)
            for child in cls._iter_ast_children(node)
        )

    @staticmethod
    def _looks_like_subscript(node: Any) -> bool:
        node_type = type(node).__name__.lower()
        return node_type in {"subscript", "getitem"} or "subscript" in node_type

    @classmethod
    def _looks_like_fstring(cls, node: Any) -> bool:
        node_type = type(node).__name__
        if node_type in {"JoinedStr", "FormattedValue"}:
            return True
        text = ""
        if hasattr(node, "toStr"):
            try:
                text = node.toStr()
            except Exception:
                text = ""
        return text.startswith(("f'", 'f"', "F'", 'F"'))

    @staticmethod
    def _literal_string(node: Any) -> Optional[str]:
        value = CPGTaintEngine._extract_constant_value(node)
        if value is not None:
            return value
        if hasattr(node, "toStr"):
            try:
                text = node.toStr()
            except Exception:
                return None
            if len(text) >= 2 and text[0] in "'\"" and text[-1] == text[0]:
                return text[1:-1]
            return text
        return None

    def _handle_getattr(
        self,
        call_node: py_ast.Call,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        args = getattr(call_node, "args", None) or []
        if len(args) >= 2:
            method_name = self._literal_string(args[1])
            if method_name:
                for sink_name in self._sinks:
                    if sink_name == method_name or sink_name.endswith(
                        "." + method_name
                    ):
                        return tstate
            if isinstance(args[1], py_ast.Local) and mem.is_tainted(
                getattr(args[1], "name", "") or ""
            ):
                return tstate
        return tstate

    def _has_tainted_dict_unpack(
        self, call_node: py_ast.Call, mem: MemoryLayout
    ) -> bool:
        kargs = getattr(call_node, "kargs", None)
        if isinstance(kargs, py_ast.Local) and mem.is_tainted(
            getattr(kargs, "name", "") or ""
        ):
            return True
        for keyword in getattr(call_node, "keywords", None) or []:
            key = getattr(keyword, "arg", None)
            value = getattr(keyword, "value", None)
            if key is None and isinstance(value, py_ast.Local):
                if mem.is_tainted(getattr(value, "name", "") or ""):
                    return True
        return False

    # ── Interprocedural Taint ───────────────────────────────────────────

    def _is_loop_header(self, node: PDGNode) -> bool:
        """Check if a PDG node corresponds to a loop header Merge block."""
        meta = self._cpg.node_meta(node)
        return bool(meta.get("loop_header"))

    def _is_call_edge(self, src: PDGNode, dst: PDGNode) -> bool:
        self._cpg._ensure_built()
        for e in self._cpg._cpg_edges_out.get(src.node_id, ()):
            if e.target is dst and e.kind == CPGEdgeKind.CALL:
                return True
        return False

    def _is_return_edge(self, src: PDGNode, dst: PDGNode) -> bool:
        self._cpg._ensure_built()
        for e in self._cpg._cpg_edges_out.get(src.node_id, ()):
            if e.target is dst and e.kind == CPGEdgeKind.RETURN_EDGE:
                return True
        return False

    # ── Parameter extraction ─────────────────────────────────────────

    def _get_callee_param_names(self, func_name: str) -> List[str]:
        """Extract positional parameter names from a callee's ``Code`` object.

        ``ProgramDependenceGraph.cfg.code`` holds the ``py_ast.Code`` AST node,
        giving us direct access to ``Code.codeparameters``.  Returns an empty
        list when the function cannot be found or has no parameters.
        """
        pdg = self._cpg._pdgs.get(func_name)
        if pdg is None:
            return []
        code_ast = getattr(pdg.cfg, "code", None)
        if code_ast is None or not isinstance(code_ast, py_ast.Code):
            return []
        codeparams = getattr(code_ast, "codeparameters", None)
        if codeparams is None:
            return []
        posonly = getattr(codeparams, "posonlyparams", None) or []
        params = getattr(codeparams, "params", None) or []
        result: List[str] = []
        for p in posonly:
            if isinstance(p, py_ast.Local):
                result.append(getattr(p, "name", "") or "")
        for p in params:
            if isinstance(p, py_ast.Local):
                result.append(getattr(p, "name", "") or "")
        return result

    @staticmethod
    def _get_call_arg_exprs(call_node: Any) -> List[Any]:
        """Extract positional argument expressions from a ``Call`` AST node."""
        if not isinstance(call_node, py_ast.Call):
            return []
        return list(getattr(call_node, "args", None) or [])

    def _map_args_to_params(
        self,
        call_site: PDGNode,
        func_name: str,
        mem: MemoryLayout,
        new_mem: MemoryLayout,
    ) -> None:
        """Transfer taint from caller-side actual arguments to callee-side
        formal parameters in *new_mem*."""
        call_ast = call_site.ast_node
        if call_ast is None:
            return
        args = self._get_call_arg_exprs(call_ast)
        if not args:
            return
        param_names = self._get_callee_param_names(func_name)
        if not param_names:
            return
        for arg_expr, pname in zip(args, param_names):
            if isinstance(arg_expr, py_ast.Local):
                aname = getattr(arg_expr, "name", "") or ""
                if aname and mem.is_tainted(aname):
                    new_mem.mark_tainted(pname, mem.read(aname))

    def _propagate_return(
        self,
        tstate: TaintState,
        exit_node: PDGNode,
        call_site: PDGNode,
        mem: MemoryLayout,
    ) -> TaintState:
        """Propagate taint from a callee's ``Return`` value back to the
        caller's call-site result.

        When the callee exit carries a ``Return`` whose value references a
        variable that is tainted in *mem*, the return is marked as tainted.
        """
        exit_ast = exit_node.ast_node
        if not isinstance(exit_ast, py_ast.Return):
            return tstate
        # py_ast.Return uses "exprs" (a list; stdlib ast uses "value").
        ret_exprs = getattr(exit_ast, "exprs", None)
        if not ret_exprs:
            return tstate
        # The return value is either the sole expression or the first one.
        ret_value = ret_exprs[0] if len(ret_exprs) == 1 else ret_exprs[0]
        call_ast = call_site.ast_node
        if call_ast is None:
            return tstate

        # If the return value references a tainted variable, produce a
        # tainted state that flows back to the call site.  The caller's
        # DATA edges will then mark the LHS variable at the call site.
        if isinstance(ret_value, py_ast.Local):
            rname = getattr(ret_value, "name", "") or ""
            if rname and mem.is_tainted(rname):
                ret_taint = mem.read(rname)
                return tstate.merge(ret_taint)
        if self._contains_tainted_local(ret_value, mem):
            return tstate.merge(_USER_CONTROLLED)

        # Also propagate if the tstate at the exit is already tainted
        # (e.g. the return node itself was reached with tainted state).
        if tstate.is_tainted():
            return tstate

        return tstate

    def _propagate_for_loop_index(
        self,
        node: PDGNode,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> None:
        """If *node* is a loop header with for-loop variable metadata,
        mark loop index variables as tainted when their iterators are
        tainted in *mem*.
        """
        if not tstate.is_tainted():
            return
        meta = self._cpg.node_meta(node)
        for_loop_vars = meta.get("for_loop_vars", [])
        for iter_name, index_name in for_loop_vars:
            if mem.is_tainted(iter_name):
                mem.mark_tainted(index_name, tstate)

    def _propagate_try(
        self,
        try_node: py_ast.TryExceptFinally,
        tstate: TaintState,
        pdg_node: PDGNode,
        mem: MemoryLayout,
    ) -> TaintState:
        """Propagate taint through a TryExceptFinally node.

        If ``tstate`` is tainted, any handler with a caught variable
        ``except ... as e`` gets that variable marked as tainted in
        *mem* (modelling exception flow into the handler).
        """
        if not tstate.is_tainted():
            return tstate

        meta = self._cpg.node_meta(pdg_node)
        handlers = meta.get("handlers", [])
        for hinfo in handlers:
            caught_var = hinfo.get("caught_var")
            if caught_var:
                mem.mark_tainted(caught_var, tstate)
        return tstate

    def _interprocedural_transfer(
        self,
        tstate: TaintState,
        src: PDGNode,
        dst: PDGNode,
        mem: MemoryLayout,
        call_context: Tuple[int, ...] = (),
    ) -> Tuple[TaintState, MemoryLayout]:
        dst_meta = self._cpg.node_meta(dst)
        func_name = dst_meta.get("func_name", str(dst.node_id))
        cache_key = (func_name, tuple(sorted(tstate.tags)), call_context)
        cached = self._interprocedural_summary_cache.get(cache_key)
        if cached is not None:
            return cached, mem
        self._interprocedural_summary_cache[cache_key] = tstate
        new_mem = MemoryLayout()
        self._map_args_to_params(src, func_name, mem, new_mem)
        return tstate, new_mem

    # ── isinstance Guard Stripping ──────────────────────────────────────

    def _isinstance_guard_strip(
        self, ast_node: Any, mem: MemoryLayout
    ) -> bool:
        if not isinstance(ast_node, py_ast.Call):
            return False
        call_name = self._extract_call_name(ast_node)
        if call_name == "isinstance":
            args = getattr(ast_node, "args", None)
            if args is not None and len(args) >= 1:
                first_arg = args[0]
                if isinstance(first_arg, py_ast.Local):
                    var_name = getattr(first_arg, "name", "") or ""
                    if var_name:
                        mem.mark_tainted(var_name, _CLEAN)
                        return True
            return False
        return False

    # ── Validating Regex Heuristic ──────────────────────────────────────

    def _is_validating_regex(self, call_node: py_ast.Call) -> bool:
        args = getattr(call_node, "args", None)
        if args is None or len(args) < 1:
            return False
        pattern_arg = args[0]
        pattern_str = self._extract_constant_value(pattern_arg)
        if pattern_str is None:
            return False
        return pattern_str.startswith("^") and pattern_str.endswith("$")

    @staticmethod
    def _extract_constant_value(node: Any) -> Optional[str]:
        node_type = type(node).__name__
        if node_type == "Str":
            return getattr(node, "s", None)
        if node_type == "Constant":
            val = getattr(node, "value", None)
            return str(val) if isinstance(val, str) else None
        if hasattr(node, "children"):
            parts = []
            for child in node.children():
                if isinstance(child, (list, tuple)):
                    continue
                v = CPGTaintEngine._extract_constant_value(child)
                if v is not None:
                    parts.append(v)
            return "".join(parts) if parts else None
        return None

    # ── Deduplication ────────────────────────────────────────────────────

    @staticmethod
    def deduplicate(findings: List[TaintFinding]) -> List[TaintFinding]:
        """Collapse similar findings by ``(cwe, source_line, sink_line)``.

        For each group of duplicates, keeps the finding with the longest
        path (most evidence) and merges tags/sanitizers from all members.
        """
        groups: Dict[Tuple[str, int, int], List[TaintFinding]] = {}
        for f in findings:
            key = f.dedup_key
            groups.setdefault(key, []).append(f)

        result: List[TaintFinding] = []
        for group in groups.values():
            if len(group) == 1:
                result.append(group[0])
                continue
            best = max(group, key=lambda f: f.path_length)
            all_tags: Set[str] = set()
            all_sans: Set[str] = set()
            for f in group:
                all_tags.update(f.tags)
                all_sans.update(f.sanitizers)
            best.tags = frozenset(all_tags)
            best.sanitizers = frozenset(all_sans)
            result.append(best)
        return sorted(result, key=lambda f: f.confidence, reverse=True)

    # ── Export ───────────────────────────────────────────────────────────

    @staticmethod
    def to_json(findings: List[TaintFinding]) -> str:
        """Serialize findings to a JSON string."""
        import json

        return json.dumps([f.to_dict() for f in findings], indent=2)

    @staticmethod
    def to_sarif(
        findings: List[TaintFinding],
        *,
        tool_name: str = "pyflow-cpg",
        artifact_uri: str = "",
    ) -> Dict[str, Any]:
        """Build a SARIF v2.1.0 document from taint findings.

        Returns a JSON-serializable dict.
        """
        rules: List[Dict[str, Any]] = []
        seen_cwes: Set[str] = set()
        for f in findings:
            if f.cwe not in seen_cwes:
                seen_cwes.add(f.cwe)
                rules.append({
                    "id": f.cwe,
                    "shortDescription": {"text": f.cwe},
                    "defaultConfiguration": {
                        "level": _severity_to_sarif_level(f.severity)
                    },
                })
        cwe_to_idx = {cwe: i for i, cwe in enumerate(sorted(seen_cwes))}

        return {
            "version": "2.1.0",
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/"
                "sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
            ),
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "rules": sorted(rules, key=lambda r: r["id"]),
                        }
                    },
                    "artifacts": [
                        {"location": {"uri": artifact_uri}}
                    ] if artifact_uri else [],
                    "results": [
                        f.to_sarif(rule_index=cwe_to_idx.get(f.cwe, 0))
                        for f in findings
                    ],
                }
            ],
        }
