"""The external adapter must not scan or execute unrelated Python environments."""

import importlib.util
import sys

import pytest

from pyflow.analysis.callgraph import pycg_based


@pytest.mark.skipif(not pycg_based.PYCG_AVAILABLE, reason="Optional PyCG package")
def test_external_pycg_resolves_only_local_imports_without_global_finders(tmp_path, monkeypatch, capsys):
    marker = tmp_path / "executed"
    entry = tmp_path / "entry.py"
    entry.write_text("import unavailable_external_package\nfrom helper import leaf\ndef run(): return leaf()\nrun()\n")
    (tmp_path / "helper.py").write_text(f"open({str(marker)!r}, 'w').write('executed')\ndef leaf(): return 1\n")
    (tmp_path / "unrelated.py").write_text("deliberately invalid Python !!!\n")
    def forbid_global_lookup(*args, **kwargs):
        raise AssertionError("global find_spec must not be used")
    monkeypatch.setattr(importlib.util, "find_spec", forbid_global_lookup)
    paths, hooks = list(sys.path), list(sys.path_hooks)
    graph = pycg_based.extract_call_graph_pycg(
        entry.read_text(), source_path=str(entry), use_fixture_fallback=False,
    )
    assert "helper.leaf" in graph.get()["main.run"]
    assert sys.path == paths
    assert sys.path_hooks == hooks
    assert not marker.exists()
    assert "partial" in capsys.readouterr().err


@pytest.mark.skipif(not pycg_based.PYCG_AVAILABLE, reason="Optional PyCG package")
def test_external_import_depth_prevents_deeper_preprocessing(tmp_path, monkeypatch, capsys):
    entry = tmp_path / "entry.py"
    entry.write_text("import first\nfirst.run()\n")
    (tmp_path / "first.py").write_text("import second\ndef run(): return second.leaf()\n")
    # This must only be parsed when the user explicitly raises the limit.
    (tmp_path / "second.py").write_text("invalid source !!!\n")
    graph = pycg_based.extract_call_graph_pycg(
        entry.read_text(), source_path=str(entry), use_fixture_fallback=False, max_import_depth=1,
    )
    assert "first.run" in graph.get()["main"]
    assert "partial" in capsys.readouterr().err
    with pytest.raises(SyntaxError):
        pycg_based.extract_call_graph_pycg(
            entry.read_text(), source_path=str(entry), use_fixture_fallback=False, max_import_depth=2,
        )
