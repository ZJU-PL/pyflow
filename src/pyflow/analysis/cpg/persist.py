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
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


_SCHEMA_VERSION = 1


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
        cur.execute("SELECT id FROM files WHERE path = ?", (file_path,))
        row = cur.fetchone()
        return row["id"] if row else 0

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