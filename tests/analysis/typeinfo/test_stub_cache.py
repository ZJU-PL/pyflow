"""Persistent stub parse cache tests."""

from __future__ import annotations

import os
from pathlib import Path

from pyflow.analysis.typeinfo.resolution.stub_cache import StubCache
from pyflow.language.modules.project_resolution import ProjectContext
from pyflow.language.modules.type_stubs import StubResolver, parse_stub_source


def test_stub_cache_roundtrip_and_invalidation(tmp_path: Path) -> None:
    stub = tmp_path / "module.pyi"
    stub.write_text("__all__ = ['f']\ndef f(x: int) -> str: ...\n")
    info = parse_stub_source(stub.read_text())
    cache = StubCache(tmp_path / "cache")

    cache.put(stub, (3, 13), info)
    cached = cache.get(stub, (3, 13))
    assert cached is not None
    assert cached.functions[0].name == "f"
    assert cached.functions[0].returns == "str"
    assert cached.exports == frozenset({"f"})

    # A different target version is a different key.
    assert cache.get(stub, (3, 10)) is None

    # Changing the file invalidates the mtime/size key.
    stub.write_text("def g() -> None: ...\n")
    assert cache.get(stub, (3, 13)) is None


def test_stub_resolver_reuses_persisted_parse(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "typeshed"
    (root / "stdlib").mkdir(parents=True)
    stub_path = root / "stdlib" / "vendor.pyi"
    stub_path.write_text("def convert(x: int) -> str: ...\n")
    cache_dir = tmp_path / "cache"

    from pyflow.language.modules import type_stubs

    calls = 0
    original = type_stubs.parse_stub_file

    def counted(path, **kwargs):
        nonlocal calls
        calls += 1
        return original(path, **kwargs)

    monkeypatch.setattr(type_stubs, "parse_stub_file", counted)
    context = ProjectContext(None)
    first = StubResolver(
        context,
        typeshed_roots=[root],
        stub_cache_dir=cache_dir,
    ).resolve("vendor")
    second = StubResolver(
        context,
        typeshed_roots=[root],
        stub_cache_dir=cache_dir,
    ).resolve("vendor")

    assert first is not None and second is not None
    assert second.info.functions[0].returns == "str"
    assert calls == 1
