"""
SQLite persistence for Code Property Graphs.

Stores CPG nodes, edges, and taint findings in a relational SQLite
database, enabling incremental re-analysis, delta scans, and
cross-session result persistence.

Usage::

    from pyflow.analysis.cpg.persist import CPGStore

    store = CPGStore("analysis.db")
    store.save_cpg(cpg, file_path="app.py")
    store.save_findings(findings, file_path="app.py")
    cached = store.get_cached_findings("app.py")
"""
from __future__ import annotations

import json
import hashlib
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


_SCHEMA_VERSION = 1
_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\s+|import\s+([A-Za-z_][\w.]*))",
    re.MULTILINE,
)


_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS _meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    path        TEXT UNIQUE NOT NULL,
    sha256      TEXT,
    scanned_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cpg_nodes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id     INTEGER NOT NULL REFERENCES files(id),
    node_id     INTEGER NOT NULL,
    kind        TEXT NOT NULL DEFAULT '',
    label       TEXT NOT NULL DEFAULT '',
    func_name   TEXT NOT NULL DEFAULT '',
    lineno      INTEGER NOT NULL DEFAULT 0,
    meta_json   TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_cpg_nodes_file ON cpg_nodes(file_id);
CREATE INDEX IF NOT EXISTS idx_cpg_nodes_func ON cpg_nodes(func_name);

CREATE TABLE IF NOT EXISTS cpg_edges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id     INTEGER NOT NULL REFERENCES files(id),
    source_id   INTEGER NOT NULL,
    target_id   INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_cpg_edges_source ON cpg_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_cpg_edges_target ON cpg_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_cpg_edges_kind ON cpg_edges(kind);

CREATE TABLE IF NOT EXISTS taint_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         INTEGER NOT NULL REFERENCES files(id),
    cwe             TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT '',
    source_label    TEXT NOT NULL DEFAULT '',
    sink_label      TEXT NOT NULL DEFAULT '',
    source_line     INTEGER NOT NULL DEFAULT 0,
    sink_line       INTEGER NOT NULL DEFAULT 0,
    confidence      REAL NOT NULL DEFAULT 0.0,
    finding_json    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_taint_findings_file ON taint_findings(file_id);
CREATE INDEX IF NOT EXISTS idx_taint_findings_cwe ON taint_findings(cwe);
"""


class CPGStore:
    """SQLite-backed store for CPG nodes, edges, and taint findings."""

    def __init__(self, db_path: str | Path) -> None:
        self._conn: sqlite3.Connection = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(_CREATE_TABLES)
        cur.execute(
            "INSERT OR REPLACE INTO _meta (key, value) VALUES (?, ?)",
            ("schema_version", str(_SCHEMA_VERSION)),
        )
        self._conn.commit()

    def _ensure_file(self, file_path: str, sha256: str = "") -> int:
        cur = self._conn.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO files (path, sha256) VALUES (?, ?)",
            (file_path, sha256),
        )
        if sha256:
            cur.execute(
                "UPDATE files SET sha256 = ?, scanned_at = datetime('now') "
                "WHERE path = ?",
                (sha256, file_path),
            )
        cur.execute("SELECT id FROM files WHERE path = ?", (file_path,))
        row = cur.fetchone()
        return row["id"] if row else 0

    @staticmethod
    def _sha256_file(file_path: str | Path) -> str:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def file_changed(self, file_path: str | Path) -> bool:
        """Return True when *file_path* is new, missing from cache, or changed."""
        path = str(file_path)
        try:
            current = self._sha256_file(path)
        except OSError:
            return True
        cur = self._conn.cursor()
        cur.execute("SELECT sha256 FROM files WHERE path = ?", (path,))
        row = cur.fetchone()
        return row is None or row["sha256"] != current

    def update_hash(self, file_path: str | Path) -> str:
        """Persist the current content hash for *file_path* and return it."""
        path = str(file_path)
        sha256 = self._sha256_file(path)
        self._ensure_file(path, sha256)
        self._conn.commit()
        return sha256

    def invalidate(self, file_path: str | Path) -> None:
        """Remove cached data for *file_path*."""
        path = str(file_path)
        cur = self._conn.cursor()
        cur.execute("SELECT id FROM files WHERE path = ?", (path,))
        row = cur.fetchone()
        if row is None:
            return
        file_id = row["id"]
        cur.execute("DELETE FROM cpg_nodes WHERE file_id = ?", (file_id,))
        cur.execute("DELETE FROM cpg_edges WHERE file_id = ?", (file_id,))
        cur.execute("DELETE FROM taint_findings WHERE file_id = ?", (file_id,))
        cur.execute("UPDATE files SET sha256 = '' WHERE id = ?", (file_id,))
        self._conn.commit()

    @staticmethod
    def _module_names_for_path(path: Path) -> Set[str]:
        names = {path.stem}
        parts = [p for p in path.with_suffix("").parts if p not in {"", "."}]
        if parts:
            names.add(".".join(parts))
        return names

    @staticmethod
    def _imports_module(source: str, module_names: Set[str]) -> bool:
        for match in _IMPORT_RE.finditer(source):
            imported = match.group(1) or match.group(2) or ""
            imported_root = imported.split(".", 1)[0]
            for module in module_names:
                if imported == module or imported_root == module.split(".", 1)[0]:
                    return True
        return False

    def affected_files(
        self,
        changed_paths: List[str | Path],
        *,
        candidate_paths: Optional[List[str | Path]] = None,
    ) -> List[str]:
        """Return changed files plus candidates that import changed modules."""
        changed = {str(Path(p)) for p in changed_paths}
        modules: Set[str] = set()
        for p in changed_paths:
            modules.update(self._module_names_for_path(Path(p)))
        affected = set(changed)
        for candidate in candidate_paths or []:
            cpath = Path(candidate)
            cstr = str(cpath)
            if cstr in affected:
                continue
            try:
                source = cpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if self._imports_module(source, modules):
                affected.add(cstr)
        return sorted(affected)

    def save_cpg(
        self,
        cpg: Any,
        *,
        file_path: str,
        sha256: str = "",
    ) -> int:
        cpg._ensure_built()
        file_id = self._ensure_file(file_path, sha256)
        cur = self._conn.cursor()
        cur.execute("DELETE FROM cpg_nodes WHERE file_id = ?", (file_id,))
        cur.execute("DELETE FROM cpg_edges WHERE file_id = ?", (file_id,))
        for node in cpg.nodes():
            meta = cpg.node_meta(node) if hasattr(cpg, "node_meta") else {}
            cur.execute(
                "INSERT INTO cpg_nodes "
                "(file_id, node_id, kind, label, func_name, lineno, meta_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    file_id,
                    node.node_id,
                    node.kind,
                    node.label or "",
                    meta.get("func_name", ""),
                    meta.get("lineno", getattr(node.ast_node, "lineno", 0)
                     if node.ast_node else 0),
                    json.dumps(meta, default=str),
                ),
            )
        for edge in cpg.all_edges():
            cur.execute(
                "INSERT INTO cpg_edges "
                "(file_id, source_id, target_id, kind, label) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    file_id,
                    edge.source.node_id,
                    edge.target.node_id,
                    edge.kind.value,
                    edge.label,
                ),
            )
        self._conn.commit()
        return file_id

    def save_findings(
        self,
        findings: List[Any],
        *,
        file_path: str,
    ) -> int:
        file_id = self._ensure_file(file_path)
        cur = self._conn.cursor()
        cur.execute("DELETE FROM taint_findings WHERE file_id = ?", (file_id,))
        for f in findings:
            d = f.to_dict() if hasattr(f, "to_dict") else {}
            cur.execute(
                "INSERT INTO taint_findings "
                "(file_id, cwe, severity, source_label, sink_label, "
                "source_line, sink_line, confidence, finding_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    file_id,
                    d.get("cwe", ""),
                    d.get("severity", ""),
                    d.get("source_label", ""),
                    d.get("sink_label", ""),
                    d.get("source_line", 0),
                    d.get("sink_line", 0),
                    d.get("confidence", 0.0),
                    json.dumps(d, default=str),
                ),
            )
        self._conn.commit()
        return file_id

    def get_cached_findings(
        self, file_path: str
    ) -> Optional[List[Dict[str, Any]]]:
        cur = self._conn.cursor()
        cur.execute("SELECT id FROM files WHERE path = ?", (file_path,))
        row = cur.fetchone()
        if row is None:
            return None
        cur.execute(
            "SELECT finding_json FROM taint_findings WHERE file_id = ?",
            (row["id"],),
        )
        rows = cur.fetchall()
        if not rows:
            return None
        return [json.loads(r["finding_json"]) for r in rows]

    def get_cpg_edges(
        self, file_path: str
    ) -> List[Dict[str, Any]]:
        cur = self._conn.cursor()
        cur.execute("SELECT id FROM files WHERE path = ?", (file_path,))
        row = cur.fetchone()
        if row is None:
            return []
        cur.execute(
            "SELECT source_id, target_id, kind, label "
            "FROM cpg_edges WHERE file_id = ?",
            (row["id"],),
        )
        return [dict(r) for r in cur.fetchall()]

    def get_cpg_nodes(
        self, file_path: str
    ) -> List[Dict[str, Any]]:
        cur = self._conn.cursor()
        cur.execute("SELECT id FROM files WHERE path = ?", (file_path,))
        row = cur.fetchone()
        if row is None:
            return []
        cur.execute(
            "SELECT node_id, kind, label, func_name, lineno, meta_json "
            "FROM cpg_nodes WHERE file_id = ?",
            (row["id"],),
        )
        results: List[Dict[str, Any]] = []
        for r in cur.fetchall():
            d = dict(r)
            d["meta"] = json.loads(d.pop("meta_json", "{}"))
            results.append(d)
        return results

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "CPGStore":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
