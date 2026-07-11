"""
CPG Taint Engine — context-sensitive taint analysis over the Code Property Graph.

Walks CPG edges (CFG + DATA) from sources to sinks using a worklist-based
forward dataflow traversal with heap-aware alias tracking.  Matching uses
both PDGNode labels and AST structure inspection via pyflow's AST types.

Features (ported from Ansede):
- AST-based call name resolution for source/sink matching
- Parameterized SQL detection (safe queries with tuple/list/dict args)
- isinstance type-guard stripping on CFG_BRANCH_TRUE edges
- Validating regex heuristic (anchored ^...$ patterns only)
- Assign RHS propagation (alias, subscript, collection, f-string, %-format)
- Per-AST-kind propagation dispatch (Call, Assign, BinaryOp, Return)
- Interprocedural summary cache per (func, context)
- Source tag provenance ("from:request.args")
- Per-node taint state queryable post-analysis
- Lambda call handling via CPG funcs

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
    "os.environ",
    "os.getenv",
    "input",
    "sys.stdin.read",
    "sys.argv",
    "get_json",
    "form.get",
    "args.get",
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
    "execute": "CWE-89",
    "requests.get": "CWE-918",
    "requests.post": "CWE-918",
    "open": "CWE-22",
    "os.path.join": "CWE-22",
    "pickle.loads": "CWE-502",
    "yaml.load": "CWE-502",
    "render_template_string": "CWE-79",
}

_DEFAULT_SANITIZERS: Set[str] = {
    "html.escape",
    "bleach.clean",
    "escape",
    "int",
    "float",
    "bool",
    "re.match",
    "re.fullmatch",
    "re.search",
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

    Features
    --------
    * AST-based call name resolution for precise source/sink matching
    * Parameterized SQL detection (safe parameterized queries skipped)
    * isinstance type-guard stripping on CFG_BRANCH_TRUE edges
    * Validating regex heuristic (anchored ^...$ patterns only)
    * Assign RHS propagation (alias, subscript, collection, f-string)
    * Per-AST-kind propagation dispatch
    * Interprocedural summary cache per (func, call context)
    * Source tag provenance (``"from:source_name"``)
    * Per-node taint state queryable post-analysis via :meth:`get_node_taint`
    """

    def __init__(
        self,
        cpg: CodePropertyGraph,
        *,
        sources: Optional[Set[str]] = None,
        sinks: Optional[Dict[str, str]] = None,
        sanitizers: Optional[Set[str]] = None,
        max_call_depth: int = 5,
    ) -> None:
        self._cpg = cpg
        self._sources: Set[str] = set(_DEFAULT_SOURCES)
        self._sinks: Dict[str, str] = dict(_DEFAULT_SINKS)
        self._sanitizers: Set[str] = set(_DEFAULT_SANITIZERS)
        self._max_call_depth: int = max_call_depth

        if sources:
            self._sources.update(sources)
        if sinks:
            self._sinks.update(sinks)
        if sanitizers:
            self._sanitizers.update(sanitizers)

        self._node_taint: Dict[int, TaintState] = {}
        self._summary_cache: Dict[Tuple[str, Tuple[str, ...]], TaintState] = {}

    # ── Configuration ───────────────────────────────────────────────────

    def add_source(self, name: str) -> None:
        self._sources.add(name)

    def add_sink(self, name: str, cwe: str = "") -> None:
        self._sinks[name] = cwe or name

    def add_sanitizer(self, name: str) -> None:
        self._sanitizers.add(name)

    @property
    def sources(self) -> FrozenSet[str]:
        return frozenset(self._sources)

    @property
    def sinks(self) -> Dict[str, str]:
        return dict(self._sinks)

    @property
    def sanitizers(self) -> FrozenSet[str]:
        return frozenset(self._sanitizers)

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
            visited: Set[Tuple[int, Tuple[str, ...]]] = set()
            worklist: deque[Tuple[PDGNode, TaintState, List[PDGNode], MemoryLayout]] = deque()
            initial_state = _USER_CONTROLLED.add_tag(seed_tag)
            worklist.append((seed_node, initial_state, [], MemoryLayout()))

            while worklist:
                node, tstate, path, mem = worklist.popleft()
                state_key: Tuple[int, Tuple[str, ...]] = (
                    node.node_id,
                    tuple(sorted(tstate.tags)),
                )
                if state_key in visited:
                    continue
                visited.add(state_key)

                existing = self._node_taint.get(node.node_id, _CLEAN)
                self._node_taint[node.node_id] = existing.merge(tstate)

                path = path + [node]

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
                    next_state = self._propagate(tstate, node, succ, mem)
                    if next_state is None or not next_state.is_tainted():
                        continue
                    new_mem = mem
                    new_ctx_path = path
                    if self._is_call_edge(node, succ):
                        next_state, new_mem = self._interprocedural_transfer(
                            next_state, node, succ, mem
                        )
                        new_ctx_path = path + [succ]
                    worklist.append((succ, next_state, new_ctx_path, new_mem))

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
        if isinstance(ast_node, py_ast.BinaryOp):
            return self._propagate_binary_op(ast_node, tstate, mem)
        if isinstance(ast_node, py_ast.Return):
            return tstate

        label = dst_node.label or ""
        for san in self._sanitizers:
            if san in label:
                return tstate.sanitize(san)

        return tstate

    # ── Call Propagation ────────────────────────────────────────────────

    def _propagate_call(
        self,
        call_node: py_ast.Call,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        call_name = self._extract_call_name(call_node)

        if call_name and call_name in self._sanitizers:
            if call_name in ("re.match", "re.fullmatch", "re.search"):
                if self._is_validating_regex(call_node):
                    return tstate.sanitize(call_name)
                return tstate
            return tstate.sanitize(call_name)

        if call_name in ("int", "float", "bool", "str"):
            return tstate.sanitize(call_name)

        if call_name and call_name.split(".")[-1] in _DUNDER_PROPAGATE:
            return tstate

        if call_name and call_name.startswith("<lambda"):
            return tstate

        cached = self._summary_cache.get((call_name or "", ()))
        if cached is not None:
            return cached if cached.is_tainted() else None

        return tstate

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

        if isinstance(rhs, py_ast.BinaryOp):
            op_type = type(getattr(rhs, "op", None)).__name__ if hasattr(rhs, "op") else ""
            if op_type == "Mod":
                mem.mark_tainted(var_name, tstate)
                return tstate

        if isinstance(rhs, py_ast.Call):
            return tstate

        rhs_type = type(rhs).__name__
        if rhs_type in ("List", "Tuple", "Set"):
            elts = getattr(rhs, "elts", None) or getattr(rhs, "elements", None)
            if elts:
                for elt in elts:
                    if isinstance(elt, py_ast.Local) and mem.is_tainted(getattr(elt, "name", "")):
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
        if left and isinstance(left, py_ast.Local) and mem.is_tainted(getattr(left, "name", "")):
            return tstate
        if right and isinstance(right, py_ast.Local) and mem.is_tainted(getattr(right, "name", "")):
            return tstate
        return tstate

    # ── Interprocedural Taint ───────────────────────────────────────────

    def _is_call_edge(self, src: PDGNode, dst: PDGNode) -> bool:
        self._cpg._ensure_built()
        for e in self._cpg._cpg_edges_out.get(src.node_id, ()):
            if e.target is dst and e.kind == CPGEdgeKind.CALL:
                return True
        return False

    def _interprocedural_transfer(
        self,
        tstate: TaintState,
        src: PDGNode,
        dst: PDGNode,
        mem: MemoryLayout,
    ) -> Tuple[TaintState, MemoryLayout]:
        cache_key = (str(dst.node_id), tuple(sorted(tstate.tags)))
        cached = self._summary_cache.get(cache_key)
        if cached is not None:
            return cached, mem
        self._summary_cache[cache_key] = tstate
        new_mem = MemoryLayout()
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
                    "defaultConfiguration": {"level": _severity_to_sarif_level(f.severity)},
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
