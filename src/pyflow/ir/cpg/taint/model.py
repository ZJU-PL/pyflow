"""Taint state, memory, finding, and reporting value objects."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Tuple
from pyflow.ir.pdg.graph import PDGNode


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


@dataclass
class RuleMetadata:
    """Rule metadata used to enrich JSON and SARIF exports."""

    rule_id: str
    name: str
    short_description: str
    help_text: str = ""
    help_uri: str = ""
    precision: str = "medium"
    tags: Tuple[str, ...] = field(default_factory=tuple)

    def to_sarif_rule(self, severity: str) -> Dict[str, Any]:
        props: Dict[str, Any] = {
            "precision": self.precision,
            "tags": list(self.tags),
        }
        return {
            "id": self.rule_id,
            "name": self.name[:80],
            "shortDescription": {"text": self.short_description},
            "fullDescription": {"text": self.short_description},
            "helpUri": self.help_uri,
            "help": {"text": self.help_text or self.short_description},
            "defaultConfiguration": {"level": _severity_to_sarif_level(severity)},
            "properties": props,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "short_description": self.short_description,
            "help_text": self.help_text,
            "help_uri": self.help_uri,
            "precision": self.precision,
            "tags": list(self.tags),
        }


_CWE_RULE_METADATA: Dict[str, RuleMetadata] = {
    "CWE-22": RuleMetadata(
        "CWE-22",
        "Path traversal",
        "Tainted input reaches a filesystem path sink.",
        "Validate and canonicalize paths, then enforce an allowlisted root.",
        "https://cwe.mitre.org/data/definitions/22.html",
        "medium",
        ("security", "path-traversal"),
    ),
    "CWE-78": RuleMetadata(
        "CWE-78",
        "OS command injection",
        "Tainted input reaches a command execution sink.",
        "Avoid shell execution or pass validated arguments without shell parsing.",
        "https://cwe.mitre.org/data/definitions/78.html",
        "high",
        ("security", "command-injection"),
    ),
    "CWE-79": RuleMetadata(
        "CWE-79",
        "Cross-site scripting",
        "Tainted input reaches an HTML/template rendering sink.",
        "Escape output for the target context and avoid rendering raw templates.",
        "https://cwe.mitre.org/data/definitions/79.html",
        "medium",
        ("security", "xss"),
    ),
    "CWE-89": RuleMetadata(
        "CWE-89",
        "SQL injection",
        "Tainted input reaches a SQL execution sink.",
        "Use parameterized queries or a query builder that binds parameters.",
        "https://cwe.mitre.org/data/definitions/89.html",
        "high",
        ("security", "sql-injection"),
    ),
    "CWE-95": RuleMetadata(
        "CWE-95",
        "Code injection",
        "Tainted input reaches dynamic code execution.",
        "Remove eval/exec usage or strictly validate inputs before interpretation.",
        "https://cwe.mitre.org/data/definitions/95.html",
        "high",
        ("security", "code-injection"),
    ),
    "CWE-502": RuleMetadata(
        "CWE-502",
        "Unsafe deserialization",
        "Tainted input reaches a deserialization sink.",
        "Use safe formats and never deserialize attacker-controlled payloads.",
        "https://cwe.mitre.org/data/definitions/502.html",
        "medium",
        ("security", "deserialization"),
    ),
    "CWE-918": RuleMetadata(
        "CWE-918",
        "Server-side request forgery",
        "Tainted input reaches an outbound request sink.",
        "Allowlist destinations and block internal network ranges.",
        "https://cwe.mitre.org/data/definitions/918.html",
        "medium",
        ("security", "ssrf"),
    ),
}


def _metadata_for_cwe(cwe: str) -> RuleMetadata:
    if cwe in _CWE_RULE_METADATA:
        return _CWE_RULE_METADATA[cwe]
    return RuleMetadata(
        cwe or "CPG-TAINT",
        cwe or "CPG taint flow",
        f"Tainted data reaches a sink ({cwe or 'unknown rule'}).",
        "Review the source-to-sink flow and add validation or sanitization.",
        (
            f"https://cwe.mitre.org/data/definitions/{cwe.split('-', 1)[1]}.html"
            if cwe.startswith("CWE-") and cwe.split("-", 1)[1].isdigit()
            else ""
        ),
        "medium",
        ("security", "taint"),
    )


@dataclass
class TaintPath:
    """Ansede-compatible source-to-sink path DTO."""

    source_node_id: int
    sink_node_id: int
    source_label: str
    sink_label: str
    source_lineno: int
    sink_lineno: int
    tags: FrozenSet[str]
    sanitizers: FrozenSet[str]
    path: List[Tuple[int, int, str]] = field(default_factory=list)


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
    rule_id: str = ""

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

    @property
    def effective_rule_id(self) -> str:
        return self.rule_id or self.cwe or "CPG-TAINT"

    @property
    def rule_metadata(self) -> RuleMetadata:
        return _metadata_for_cwe(self.effective_rule_id)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        rule = self.rule_metadata
        return {
            "rule_id": self.effective_rule_id,
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
            "rule": rule.to_dict(),
            "path_preview": [
                {
                    "kind": n.kind,
                    "line": getattr(n.ast_node, "lineno", 0) or 0,
                    "label": (n.label or "")[:80],
                }
                for n in self.path_nodes[:10]
            ],
        }

    def to_taint_path(self) -> TaintPath:
        """Return an Ansede-compatible path object."""
        return TaintPath(
            source_node_id=getattr(self.source_node, "node_id", -1),
            sink_node_id=getattr(self.sink_node, "node_id", -1),
            source_label=self.source_label,
            sink_label=self.sink_label,
            source_lineno=self.source_line,
            sink_lineno=self.sink_line,
            tags=self.tags,
            sanitizers=self.sanitizers,
            path=[
                (
                    getattr(n, "node_id", -1),
                    getattr(getattr(n, "ast_node", None), "lineno", 0) or 0,
                    (getattr(n, "label", "") or "")[:120],
                )
                for n in self.path_nodes
            ],
        )

    def to_sarif(
        self,
        *,
        rule_index: int = 0,
        artifact_uri: str = "",
    ) -> Dict[str, Any]:
        """Export as a SARIF result object.

        Parameters
        ----------
        rule_index:
            Zero-based index into the SARIF ``rules`` array.
        """
        physical_location = {
            "artifactLocation": {"uri": artifact_uri},
            "region": {
                "startLine": self.source_line,
            },
        }
        result: Dict[str, Any] = {
            "ruleId": self.effective_rule_id,
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
                    "physicalLocation": physical_location,
                }
            ],
            "properties": {
                "cwe": self.cwe,
                "source_label": self.source_label,
                "sink_label": self.sink_label,
                "sink_line": self.sink_line,
                "path_length": self.path_length,
                "confidence": round(self.confidence, 2),
                "tags": sorted(self.tags),
                "sanitizers": sorted(self.sanitizers),
                "precision": self.rule_metadata.precision,
                "rule": self.rule_metadata.to_dict(),
            },
        }
        if self.path_nodes:
            result["codeFlows"] = [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": artifact_uri},
                                            "region": {
                                                "startLine": getattr(
                                                    n.ast_node, "lineno", 0
                                                )
                                                or 0
                                            },
                                        },
                                        "message": {"text": (n.label or n.kind)[:120]},
                                    }
                                }
                                for n in self.path_nodes
                            ]
                        }
                    ]
                }
            ]
        return result


def _severity_to_sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning"}.get(
        severity.lower(), "note"
    )
