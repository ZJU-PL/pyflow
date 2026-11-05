"""Persistent cache for parsed ``.pyi`` stubs.

Adapted from the design of mypy's ``fscache``/``metastore`` modules: the cache
key combines the absolute path, ``mtime_ns``, size, target Python version, and
a parser-format version, so editing a stub or changing the parser invalidates
the entry automatically.  SQLite keeps concurrent analyses from rereading and
reparsing the same typeshed files.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import asdict
from pathlib import Path

from pyflow.language.modules.type_stubs import (
    StubAliasInfo,
    StubClassInfo,
    StubFunctionInfo,
    StubImportInfo,
    StubInfo,
    StubTypeVarInfo,
)

CACHE_FORMAT_VERSION = 1


def default_cache_dir() -> Path:
    configured = os.environ.get("PYFLOW_CACHE_DIR")
    if configured:
        return Path(configured)
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base else Path.home() / ".cache") / "pyflow"


def stub_info_to_dict(info: StubInfo) -> dict:
    data = asdict(info)
    data["exports"] = None if info.exports is None else sorted(info.exports)
    return data


def stub_info_from_dict(data: dict) -> StubInfo:
    def function(item: dict) -> StubFunctionInfo:
        return StubFunctionInfo(
            name=item["name"],
            params=[tuple(pair) for pair in item.get("params", ())],
            param_kinds=dict(item.get("param_kinds", {})),
            returns=item.get("returns"),
            decorators=list(item.get("decorators", ())),
        )

    def class_info(item: dict) -> StubClassInfo:
        return StubClassInfo(
            name=item["name"],
            bases=list(item.get("bases", ())),
            methods=[function(method) for method in item.get("methods", ())],
            class_vars=[tuple(pair) for pair in item.get("class_vars", ())],
        )

    return StubInfo(
        functions=[function(item) for item in data.get("functions", ())],
        classes=[class_info(item) for item in data.get("classes", ())],
        variables=[tuple(pair) for pair in data.get("variables", ())],
        imports=[
            StubImportInfo(
                module=item.get("module"),
                names=[tuple(pair) for pair in item.get("names", ())],
                level=int(item.get("level", 0)),
                is_from=bool(item.get("is_from", False)),
            )
            for item in data.get("imports", ())
        ],
        type_vars=[
            StubTypeVarInfo(
                name=item["name"],
                kind=item.get("kind", "typevar"),
                constraints=list(item.get("constraints", ())),
                bound=item.get("bound"),
                default=item.get("default"),
                covariant=bool(item.get("covariant", False)),
                contravariant=bool(item.get("contravariant", False)),
            )
            for item in data.get("type_vars", ())
        ],
        aliases=[
            StubAliasInfo(
                name=item["name"],
                value=item["value"],
                annotation=item.get("annotation"),
            )
            for item in data.get("aliases", ())
        ],
        exports=None if data.get("exports") is None else frozenset(data.get("exports", ())),
    )


class StubCache:
    """SQLite-backed cache of parsed stub declarations."""

    def __init__(self, cache_dir: str | Path | None = None, *, enabled: bool = True) -> None:
        self.enabled = enabled
        self.cache_dir = Path(cache_dir) if cache_dir is not None else default_cache_dir()
        self._connection: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection | None:
        if not self.enabled:
            return None
        if self._connection is None:
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                connection = sqlite3.connect(
                    self.cache_dir / "stubs.sqlite3",
                    timeout=5.0,
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS stub_cache ("
                    "key TEXT PRIMARY KEY, path TEXT NOT NULL, mtime_ns INTEGER NOT NULL, "
                    "size INTEGER NOT NULL, python_version TEXT NOT NULL, payload TEXT NOT NULL)"
                )
                connection.commit()
                self._connection = connection
            except (OSError, sqlite3.Error):
                self.enabled = False
                return None
        return self._connection

    def _key(
        self, path: str | Path, python_version: tuple[int, int] | None
    ) -> tuple[str, os.stat_result] | None:
        try:
            stat = os.stat(path)
        except OSError:
            return None
        version = ".".join(str(part) for part in (python_version or ()))
        key = (
            f"{Path(path).resolve()}:{stat.st_mtime_ns}:{stat.st_size}:"
            f"{version}:{CACHE_FORMAT_VERSION}"
        )
        return key, stat

    def get(self, path: str | Path, python_version: tuple[int, int] | None) -> StubInfo | None:
        keyed = self._key(path, python_version)
        if keyed is None:
            return None
        key, _ = keyed
        connection = self._connect()
        if connection is None:
            return None
        with self._lock:
            try:
                row = connection.execute(
                    "SELECT payload FROM stub_cache WHERE key = ?", (key,)
                ).fetchone()
            except sqlite3.Error:
                return None
        if row is None:
            return None
        try:
            return stub_info_from_dict(json.loads(row[0]))
        except (KeyError, TypeError, ValueError):
            return None

    def put(self, path: str | Path, python_version: tuple[int, int] | None, info: StubInfo) -> None:
        keyed = self._key(path, python_version)
        if keyed is None:
            return
        key, stat = keyed
        connection = self._connect()
        if connection is None:
            return
        version = ".".join(str(part) for part in (python_version or ()))
        try:
            payload = json.dumps(stub_info_to_dict(info), sort_keys=True)
        except (TypeError, ValueError):
            return
        with self._lock:
            try:
                connection.execute(
                    "INSERT OR REPLACE INTO stub_cache "
                    "(key, path, mtime_ns, size, python_version, payload) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (key, str(path), stat.st_mtime_ns, stat.st_size, version, payload),
                )
                connection.commit()
            except sqlite3.Error:
                pass

    def clear(self) -> None:
        connection = self._connect()
        if connection is None:
            return
        with self._lock:
            try:
                connection.execute("DELETE FROM stub_cache")
                connection.commit()
            except sqlite3.Error:
                pass

    def close(self) -> None:
        if self._connection is not None:
            with self._lock:
                try:
                    self._connection.close()
                finally:
                    self._connection = None
