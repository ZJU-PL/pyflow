"""
Incremental analysis cache — file hash tracking with invalidation.

Provides :class:`IncrementalCache` for detecting changed files, caching
analysis findings per file, and tracking import dependencies so that
changing a dependency marks all of its importers as affected.

Uses BLAKE2b hashing for content-addressed file identity and SQLite
for persistent storage.

Typical usage::

    from pyflow.analysis.cache.incremental import IncrementalCache

    with IncrementalCache(".pyflow/cache.db") as cache:
        if cache.file_changed("app.py"):
            findings = analyze("app.py")
            cache.store_findings("app.py", findings)
            cache.update_hash("app.py")
        else:
            findings = cache.get_cached_findings("app.py")

        affected = cache.affected_files(
            changed=["dep.py"],
            candidate_paths=["dep.py", "app.py"],
        )
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class IncrementalCache:
    """File-level incremental cache backed by SQLite.

    Tracks file content hashes, caches analysis findings, and supports
    dependency-aware invalidation.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    # ── Context manager ──────────────────────────────────────────────────

    def __enter__(self) -> IncrementalCache:
        self.open()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def open(self) -> None:
        if self._conn is not None:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        assert self._conn is not None
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS file_hashes ("
            "  path TEXT PRIMARY KEY,"
            "  hash TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL DEFAULT (datetime('now'))"
            ")"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS cached_findings ("
            "  path TEXT PRIMARY KEY,"
            "  findings_json TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL DEFAULT (datetime('now'))"
            ")"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS import_deps ("
            "  importer TEXT NOT NULL,"
            "  imported TEXT NOT NULL,"
            "  PRIMARY KEY (importer, imported)"
            ")"
        )
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ── Hash tracking ────────────────────────────────────────────────────

    @staticmethod
    def _hash_file(path: str) -> str:
        try:
            data = Path(path).read_bytes()
            return hashlib.blake2b(data, digest_size=20).hexdigest()
        except OSError:
            return ""

    @staticmethod
    def _normalize(path: str) -> str:
        try:
            p = Path(path)
            if p.exists():
                return str(p.resolve())
            return str(p.absolute())
        except (OSError, ValueError):
            return path

    def file_changed(self, path: str) -> bool:
        assert self._conn is not None
        norm = self._normalize(path)
        current_hash = self._hash_file(norm)
        if not current_hash:
            return True
        row = self._conn.execute(
            "SELECT hash FROM file_hashes WHERE path = ?", (norm,)
        ).fetchone()
        if row is None:
            return True
        return row[0] != current_hash

    def update_hash(self, path: str) -> None:
        assert self._conn is not None
        norm = self._normalize(path)
        current_hash = self._hash_file(norm)
        if not current_hash:
            return
        self._conn.execute(
            "INSERT OR REPLACE INTO file_hashes (path, hash, updated_at) "
            "VALUES (?, ?, datetime('now'))",
            (norm, current_hash),
        )
        self._conn.commit()

    def invalidate(self, path: str) -> None:
        assert self._conn is not None
        norm = self._normalize(path)
        self._conn.execute("DELETE FROM file_hashes WHERE path = ?", (norm,))
        self._conn.execute(
            "DELETE FROM cached_findings WHERE path = ?", (norm,)
        )
        self._conn.commit()

    # ── Findings cache ───────────────────────────────────────────────────

    def store_findings(self, path: str, findings: List[Any]) -> None:
        assert self._conn is not None
        import json

        norm = self._normalize(path)
        payload = json.dumps(
            [self._finding_to_dict(f) for f in findings]
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO cached_findings (path, findings_json, updated_at) "
            "VALUES (?, ?, datetime('now'))",
            (norm, payload),
        )
        self._conn.commit()

    def get_cached_findings(self, path: str) -> Optional[List[Dict[str, Any]]]:
        assert self._conn is not None
        import json

        norm = self._normalize(path)
        row = self._conn.execute(
            "SELECT findings_json FROM cached_findings WHERE path = ?", (norm,)
        ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    @staticmethod
    def _finding_to_dict(finding: Any) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        for attr in ("cwe", "severity", "source_label", "sink_label",
                      "source_line", "sink_line"):
            val = getattr(finding, attr, None)
            if val is not None:
                d[attr] = val
        return d

    # ── Import dependency tracking ───────────────────────────────────────

    def record_import(self, importer: str, imported: str) -> None:
        assert self._conn is not None
        self._conn.execute(
            "INSERT OR IGNORE INTO import_deps (importer, imported) "
            "VALUES (?, ?)",
            (self._normalize(importer), self._normalize(imported)),
        )
        self._conn.commit()

    def affected_files(
        self,
        changed: List[str],
        candidate_paths: Optional[List[str]] = None,
    ) -> Set[str]:
        assert self._conn is not None
        changed_norm = {self._normalize(p) for p in changed}
        affected: Set[str] = set(changed_norm)

        if candidate_paths is None:
            rows = self._conn.execute(
                "SELECT DISTINCT importer FROM import_deps"
            ).fetchall()
            candidate_paths = [r[0] for r in rows]

        cand_norm = {self._normalize(p) for p in candidate_paths}

        queue: List[str] = list(changed_norm)
        while queue:
            imported = queue.pop()
            rows = self._conn.execute(
                "SELECT importer FROM import_deps WHERE imported = ?",
                (imported,),
            ).fetchall()
            for (importer,) in rows:
                if importer in cand_norm and importer not in affected:
                    affected.add(importer)
                    queue.append(importer)
        return affected