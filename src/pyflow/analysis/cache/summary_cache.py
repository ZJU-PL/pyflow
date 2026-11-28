"""Content-addressed, module-level incremental summary cache.

Stores JSON-serializable analysis summaries (e.g., ``ModuleExportTable``,
per-module type summaries, per-module call-graph summaries) keyed by:

    (namespace, module_name, file_hash, env_fingerprint, dependency_hash, schema_version)

Backed by SQLite (WAL mode) plus an optional in-memory L1 cache so repeated
CLI/LSP/CI runs reuse verified module summaries across processes while
automatically invalidating stale entries whenever source content, transitive
dependencies, target environment, or schema versions change.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pyflow.language.modules.module_graph import ModuleExportTable, ModuleGraph


@dataclass(frozen=True, slots=True)
class SummaryCacheKey:
    """Content-addressed key uniquely identifying one cached module summary."""

    namespace: str
    module_name: str
    file_hash: str
    env_fingerprint: str
    dependency_hash: str
    schema_version: str

    def as_tuple(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.namespace,
            self.module_name,
            self.file_hash,
            self.env_fingerprint,
            self.dependency_hash,
            self.schema_version,
        )


@dataclass(frozen=True)
class SummaryCacheStats:
    """Runtime hit/miss counters and stored entry count."""

    hits: int
    misses: int
    writes: int
    entries: int


class SummaryCache:
    """SQLite-backed content-addressed cache for module-level analysis summaries."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        """Create a summary cache.

        When *db_path* is ``None`` or ``":memory:"``, uses an in-memory SQLite
        database (useful for single-process sessions and unit tests).
        """
        self._db_path = ":memory:" if db_path is None else str(db_path)
        self._conn: sqlite3.Connection | None = None
        self._l1: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
        self.hits = 0
        self.misses = 0
        self.writes = 0

    def __enter__(self) -> "SummaryCache":
        self.open()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def open(self) -> None:
        if self._conn is not None:
            return
        if self._db_path != ":memory:":
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path)
        if self._db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS module_summaries ("
            "  namespace TEXT NOT NULL,"
            "  module_name TEXT NOT NULL,"
            "  file_hash TEXT NOT NULL,"
            "  env_fingerprint TEXT NOT NULL,"
            "  dependency_hash TEXT NOT NULL,"
            "  schema_version TEXT NOT NULL,"
            "  payload_json TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL DEFAULT (datetime('now')),"
            "  PRIMARY KEY (namespace, module_name, env_fingerprint, schema_version)"
            ")"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_module_summaries_mod "
            "ON module_summaries (module_name, namespace)"
        )
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _ensure_open(self) -> sqlite3.Connection:
        if self._conn is None:
            self.open()
        assert self._conn is not None
        return self._conn

    def get(self, key: SummaryCacheKey) -> dict[str, Any] | None:
        """Return the cached JSON payload when all key components match exactly."""
        key_tuple = key.as_tuple()
        cached = self._l1.get(key_tuple)
        if cached is not None:
            self.hits += 1
            return cached

        conn = self._ensure_open()
        row = conn.execute(
            "SELECT file_hash, dependency_hash, payload_json "
            "FROM module_summaries "
            "WHERE namespace = ? AND module_name = ? "
            "AND env_fingerprint = ? AND schema_version = ?",
            (key.namespace, key.module_name, key.env_fingerprint, key.schema_version),
        ).fetchone()
        if row is None:
            self.misses += 1
            return None
        stored_file_hash, stored_dep_hash, payload_json = row
        if stored_file_hash != key.file_hash or stored_dep_hash != key.dependency_hash:
            self.misses += 1
            return None
        try:
            payload = json.loads(payload_json)
        except (ValueError, TypeError):
            self.misses += 1
            return None
        if not isinstance(payload, dict):
            self.misses += 1
            return None
        self._l1[key_tuple] = payload
        self.hits += 1
        return payload

    def put(self, key: SummaryCacheKey, payload: Mapping[str, Any]) -> None:
        """Persist *payload* under *key*, replacing any older version for the same slot."""
        conn = self._ensure_open()
        serialized = json.dumps(dict(payload), sort_keys=True)
        conn.execute(
            "INSERT OR REPLACE INTO module_summaries "
            "(namespace, module_name, file_hash, env_fingerprint, dependency_hash, "
            " schema_version, payload_json, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))",
            (
                key.namespace,
                key.module_name,
                key.file_hash,
                key.env_fingerprint,
                key.dependency_hash,
                key.schema_version,
                serialized,
            ),
        )
        conn.commit()
        # Evict any older file/dep hash entries for this (namespace, module, env, schema) in L1.
        stale_l1 = [
            k
            for k in self._l1
            if k[0] == key.namespace
            and k[1] == key.module_name
            and k[3] == key.env_fingerprint
            and k[5] == key.schema_version
        ]
        for old_k in stale_l1:
            self._l1.pop(old_k, None)
        self._l1[key.as_tuple()] = dict(payload)
        self.writes += 1

    def invalidate_module(
        self,
        module_name: str,
        *,
        namespace: str | None = None,
    ) -> int:
        """Delete cached summaries for *module_name* (optionally scoped to *namespace*)."""
        conn = self._ensure_open()
        if namespace is None:
            cur = conn.execute(
                "DELETE FROM module_summaries WHERE module_name = ?",
                (module_name,),
            )
            stale_l1 = [k for k in self._l1 if k[1] == module_name]
        else:
            cur = conn.execute(
                "DELETE FROM module_summaries WHERE module_name = ? AND namespace = ?",
                (module_name, namespace),
            )
            stale_l1 = [k for k in self._l1 if k[0] == namespace and k[1] == module_name]
        conn.commit()
        for k in stale_l1:
            self._l1.pop(k, None)
        return cur.rowcount

    def invalidate_affected(
        self,
        changed_modules: Iterable[str],
        module_graph: "ModuleGraph",
        *,
        namespace: str | None = None,
    ) -> int:
        """Invalidate *changed_modules* and all their transitive importers."""
        affected: set[str] = set()
        for mod in changed_modules:
            affected.add(mod)
            affected.update(module_graph.transitive_dependents(mod))
        removed = 0
        for mod in sorted(affected):
            removed += self.invalidate_module(mod, namespace=namespace)
        return removed

    def prune_stale_schemas(self, namespace: str, active_schema_version: str) -> int:
        """Delete entries in *namespace* whose schema_version != *active_schema_version*."""
        conn = self._ensure_open()
        cur = conn.execute(
            "DELETE FROM module_summaries WHERE namespace = ? AND schema_version != ?",
            (namespace, active_schema_version),
        )
        conn.commit()
        stale_l1 = [k for k in self._l1 if k[0] == namespace and k[5] != active_schema_version]
        for k in stale_l1:
            self._l1.pop(k, None)
        return cur.rowcount

    def clear(self) -> None:
        conn = self._ensure_open()
        conn.execute("DELETE FROM module_summaries")
        conn.commit()
        self._l1.clear()
        self.hits = 0
        self.misses = 0
        self.writes = 0

    def stats(self) -> SummaryCacheStats:
        conn = self._ensure_open()
        row = conn.execute("SELECT COUNT(*) FROM module_summaries").fetchone()
        count = int(row[0]) if row is not None else 0
        return SummaryCacheStats(
            hits=self.hits,
            misses=self.misses,
            writes=self.writes,
            entries=count,
        )

    # ── High-level typed helpers ─────────────────────────────────────────

    def get_module_export_table(
        self,
        module_name: str,
        *,
        file_hash: str,
        env_fingerprint: str,
    ) -> "ModuleExportTable | None":
        from pyflow.language.modules.module_graph import (
            MODULE_EXPORT_SCHEMA_VERSION,
            ModuleExportTable,
        )

        key = SummaryCacheKey(
            namespace="module_exports",
            module_name=module_name,
            file_hash=file_hash,
            env_fingerprint=env_fingerprint,
            dependency_hash=file_hash,
            schema_version=MODULE_EXPORT_SCHEMA_VERSION,
        )
        payload = self.get(key)
        return None if payload is None else ModuleExportTable.from_dict(payload)

    def put_module_export_table(
        self,
        table: "ModuleExportTable",
        *,
        file_hash: str,
        env_fingerprint: str,
    ) -> None:
        from pyflow.language.modules.module_graph import MODULE_EXPORT_SCHEMA_VERSION

        key = SummaryCacheKey(
            namespace="module_exports",
            module_name=table.module_name,
            file_hash=file_hash,
            env_fingerprint=env_fingerprint,
            dependency_hash=file_hash,
            schema_version=MODULE_EXPORT_SCHEMA_VERSION,
        )
        self.put(key, table.to_dict())


__all__ = [
    "SummaryCache",
    "SummaryCacheKey",
    "SummaryCacheStats",
]
