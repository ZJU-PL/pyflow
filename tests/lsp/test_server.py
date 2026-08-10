"""Tests for snapshot publication by the workspace analysis manager."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from pyflow.application.analysis_snapshot import AnalysisConfig
from pyflow.lsp import server as server_module
from pyflow.lsp.server import AnalysisManager


def test_current_snapshot_requires_a_loaded_workspace():
    manager = AnalysisManager()
    with pytest.raises(RuntimeError, match="not loaded"):
        manager.current_snapshot()


def test_load_publishes_revision_pinned_snapshot(tmp_path: Path):
    source = tmp_path / "sample.py"
    source.write_text("def foo():\n    return 1\n")
    manager = AnalysisManager(
        verbose=False,
        analysis_config=AnalysisConfig(ipa=False, cpa=False, lifetime=False),
    )

    manager.load_files([source], run_pipeline=False)
    first = manager.current_snapshot()
    manager.load_files([source], run_pipeline=False)
    second = manager.current_snapshot()

    assert first.revision == 1
    assert second.revision == 2
    assert first is not second
    assert first.queries is not second.queries
    assert first.features.control_flow
    assert not first.features.call_graph


def test_snapshot_exposes_query_components_not_server_forwarders(tmp_path: Path):
    source = tmp_path / "sample.py"
    source.write_text("def foo():\n    return 1\n")
    manager = AnalysisManager(verbose=False)
    manager.load_files([source], run_pipeline=False)

    assert hasattr(manager.current_snapshot().queries, "call_graph")
    assert not hasattr(manager, "get_callers")


def test_document_edit_publishes_latest_syntax_before_semantic_refresh(tmp_path: Path):
    source = tmp_path / "sample.py"
    source.write_text("def old_name():\n    return 1\n")
    manager = AnalysisManager(verbose=False)
    manager.load_files([source], run_pipeline=False)
    analyzed = manager.current_snapshot()

    assert manager.open_document(source.as_uri(), source.read_text(), 1)
    assert manager.change_document(
        source.as_uri(),
        [{"range": None, "text": "def new_name():\n    return 1\n"}],
        2,
    )
    syntax = manager.current_snapshot()

    assert syntax.revision > analyzed.revision
    assert syntax.semantic_stale
    assert syntax.semantic_revision == analyzed.semantic_revision
    assert syntax.source_revision > analyzed.source_revision
    assert [symbol.name for symbol in syntax.source_index.symbols] == ["new_name"]


def test_document_versions_do_not_allow_stale_edits_to_overwrite_newer_text(tmp_path: Path):
    source = tmp_path / "sample.py"
    source.write_text("value = 1\n")
    manager = AnalysisManager(verbose=False)
    manager.load_files([source], run_pipeline=False)
    manager.open_document(source.as_uri(), "value = 1\n", 3)

    assert manager.change_document(source.as_uri(), [{"text": "value = 2\n"}], 4)
    assert not manager.change_document(source.as_uri(), [{"text": "value = 0\n"}], 3)
    assert manager.current_snapshot().source_index.text_for_uri(source.as_uri()) == "value = 2\n"


def test_multiple_workspace_folders_are_indexed(tmp_path: Path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "one.py").write_text("def one(): pass\n")
    (second / "two.py").write_text("def two(): pass\n")
    manager = AnalysisManager(verbose=False)

    manager.load_workspaces([str(first), str(second)], run_pipeline=False)

    symbols = {symbol.name for symbol in manager.current_snapshot().source_index.symbols}
    assert {"one", "two"} <= symbols


def test_multi_root_source_and_type_info_share_module_identity(tmp_path: Path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_module = first / "pkg" / "one.py"
    second_module = second / "pkg" / "two.py"
    first_module.parent.mkdir(parents=True)
    second_module.parent.mkdir(parents=True)
    first_module.write_text("def one() -> int: return 1\n")
    second_module.write_text("def two() -> int: return 2\n")
    manager = AnalysisManager(verbose=False)

    manager.load_workspaces([str(first), str(second)], run_pipeline=False)
    snapshot = manager.current_snapshot()
    context = snapshot.type_info_service.project_context

    for path in (first_module, second_module):
        uri = path.as_uri()
        assert snapshot.source_index.module_for_uri(uri) == context.module_name_from_path(path)


def test_analysis_finishing_after_close_cannot_republish(tmp_path: Path, monkeypatch):
    source = tmp_path / "sample.py"
    source.write_text("def first(): pass\n")
    manager = AnalysisManager(verbose=False)
    manager.load_files([source], run_pipeline=False)
    entered = threading.Event()
    release = threading.Event()
    original_index = server_module.SourceIndex
    calls = 0

    def slow_index(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            assert release.wait(timeout=5)
        return original_index(*args, **kwargs)

    monkeypatch.setattr(server_module, "SourceIndex", slow_index)
    worker = threading.Thread(target=manager.reload)
    worker.start()
    assert entered.wait(timeout=5)

    manager.close()
    release.set()
    worker.join(timeout=5)

    assert not worker.is_alive()
    with pytest.raises(RuntimeError, match="not loaded"):
        manager.current_snapshot()


def test_old_workspace_analysis_cannot_overwrite_new_generation(
    tmp_path: Path, monkeypatch
):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "first.py").write_text("def first(): pass\n")
    (second / "second.py").write_text("def second(): pass\n")
    manager = AnalysisManager(verbose=False)
    manager.load_workspaces([str(first)], run_pipeline=False)
    entered = threading.Event()
    release = threading.Event()
    original_index = server_module.SourceIndex
    calls = 0

    def slow_index(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            assert release.wait(timeout=5)
        return original_index(*args, **kwargs)

    monkeypatch.setattr(server_module, "SourceIndex", slow_index)
    old_worker = threading.Thread(target=manager.reload)
    old_worker.start()
    assert entered.wait(timeout=5)

    new_worker = threading.Thread(
        target=manager.load_workspaces,
        args=([str(second)],),
        kwargs={"run_pipeline": False},
    )
    new_worker.start()
    for _ in range(100):
        if manager.workspace_roots == (str(second),):
            break
        threading.Event().wait(0.01)
    assert manager.workspace_roots == (str(second),)
    release.set()
    old_worker.join(timeout=5)
    new_worker.join(timeout=5)

    assert not old_worker.is_alive()
    assert not new_worker.is_alive()
    symbols = manager.current_snapshot().source_index.symbols
    assert {symbol.name for symbol in symbols} == {"second"}
