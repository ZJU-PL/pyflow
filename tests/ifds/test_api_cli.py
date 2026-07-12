"""Tests for the IFDS analysis API and CLI entrypoints."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pyflow.analysis.ifds.api as ifds_api
from pyflow.analysis.ifds.api import (
    load_analysis_session,
    run_nullness_analysis,
    run_taint_analysis,
    run_typestate_analysis,
)
from pyflow.cli.security import run_security


PROGRAM = """
def source():
    return 1

def sanitize(x):
    return x

def sink(x):
    return x

def helper(x):
    return x

def main():
    a = source()
    b = helper(a)
    c = sanitize(b)
    sink(b)
    sink(c)
    return c
"""


def test_run_taint_analysis_api_on_source_file(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(PROGRAM)

    session, result, _ = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
        sanitizer_names=["sanitize"],
    )

    assert {code.codeName() for code in session.program.liveCode} >= {
        "main",
        "helper",
        "sanitize",
        "sink",
        "source",
    }
    assert len(result.findings) == 1
    assert result.findings[0].sink_name == "sink"
    assert [local.name for local in result.findings[0].tainted_arguments] == ["b"]


def test_run_taint_analysis_api_models_source_level_subscript_helpers(tmp_path):
    target = tmp_path / "subscript_sample.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def main():
    items = []
    items[0] = source()
    out = items[0]
    sink(out)
"""
    )

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    assert len(result.findings) == 1
    assert result.findings[0].sink_name == "sink"
    assert [local.name for local in result.findings[0].tainted_arguments] == ["out"]


def test_load_analysis_session_uses_constraint_callsite_edges_for_higher_order_calls(
    tmp_path,
):
    target = tmp_path / "higher_order.py"
    target.write_text(
        """
def target():
    return 1

def apply(fn):
    return fn()

def main():
    return apply(target)
"""
    )

    session = load_analysis_session([target], root_function="main")
    apply_cfg = next(
        cfg
        for cfg in session.adapter.cfgs
        if getattr(cfg, "code", None) is not None and cfg.code.codeName() == "apply"
    )
    apply_call_nodes = [
        node
        for node in session.adapter.supergraph.nodes()
        if node.procedure is apply_cfg
        and session.adapter.call_expression_of(node) is not None
    ]

    assert len(apply_call_nodes) == 1
    assert [
        callee.code.codeName()
        for callee in session.adapter.callees_of(apply_call_nodes[0])
    ] == ["target"]


def test_run_nullness_analysis_api_on_source_file(tmp_path):
    target = tmp_path / "nullness_sample.py"
    target.write_text(
        """
def main():
    value = None
    return value
"""
    )

    session, result = run_nullness_analysis(
        [target],
        function="main",
    )

    assert {code.codeName() for code in session.program.liveCode} >= {"main"}
    assert hasattr(result, "findings")
    assert isinstance(result.findings, tuple)


def test_run_typestate_analysis_api_on_source_file(tmp_path):
    target = tmp_path / "typestate_sample.py"
    target.write_text(
        """
def main():
    resource = open()
    close(resource)
    read(resource)
"""
    )

    session, result = run_typestate_analysis(
        [target],
        function="main",
        open_names=["open"],
        close_names=["close"],
        use_names=["read"],
    )

    assert {code.codeName() for code in session.program.liveCode} >= {"main"}
    assert any(f.kind == "use_after_close" for f in result.findings)


def test_run_taint_analysis_forwards_dynamic_model_configuration(monkeypatch):
    captured = {}
    expected_result = object()

    monkeypatch.setattr(
        ifds_api,
        "load_analysis_session",
        lambda *_args, **_kwargs: SimpleNamespace(adapter=object()),
    )
    monkeypatch.setattr(
        ifds_api,
        "_entry_nodes_from_program",
        lambda *_args, **_kwargs: ("entry",),
    )

    def fake_analyze_taint(adapter, configuration, *, entry_nodes):
        captured["configuration"] = configuration
        captured["entry_nodes"] = entry_nodes
        return expected_result

    monkeypatch.setattr(ifds_api, "analyze_taint", fake_analyze_taint)

    _session, result, _ = run_taint_analysis(
        ["sample.py"],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
        sanitizer_names=["clean"],
        collection_mutator_names=["append_safe"],
        collection_accessor_names=["fetch"],
        conservative_unresolved_call_side_effects=True,
    )

    assert result is expected_result
    assert captured["entry_nodes"] == ("entry",)
    configuration = captured["configuration"]
    assert configuration.source_names == frozenset({"source"})
    assert configuration.sink_names == frozenset({"sink"})
    assert configuration.sanitizer_names == frozenset({"clean"})
    assert configuration.collection_mutator_names == frozenset({"append_safe"})
    assert configuration.collection_accessor_names == frozenset({"fetch"})
    assert configuration.conservative_unresolved_call_side_effects is True


def test_run_nullness_analysis_forwards_dynamic_model_configuration(monkeypatch):
    captured = {}
    expected_result = object()

    monkeypatch.setattr(
        ifds_api,
        "load_analysis_session",
        lambda *_args, **_kwargs: SimpleNamespace(adapter=object()),
    )
    monkeypatch.setattr(
        ifds_api,
        "_entry_nodes_from_program",
        lambda *_args, **_kwargs: ("entry",),
    )

    def fake_analyze_nullness(adapter, configuration, *, entry_nodes):
        captured["configuration"] = configuration
        captured["entry_nodes"] = entry_nodes
        return expected_result

    monkeypatch.setattr(ifds_api, "analyze_nullness", fake_analyze_nullness)

    _session, result = run_nullness_analysis(
        ["sample.py"],
        function="main",
        nullable_return_names=["maybe_none"],
        collection_mutator_names=["append_safe"],
        collection_accessor_names=["fetch"],
    )

    assert result is expected_result
    assert captured["entry_nodes"] == ("entry",)
    configuration = captured["configuration"]
    assert configuration.nullable_return_names == frozenset({"maybe_none"})
    assert configuration.collection_mutator_names == frozenset({"append_safe"})
    assert configuration.collection_accessor_names == frozenset({"fetch"})


def test_run_typestate_analysis_forwards_dynamic_model_configuration(monkeypatch):
    captured = {}
    expected_result = object()

    monkeypatch.setattr(
        ifds_api,
        "load_analysis_session",
        lambda *_args, **_kwargs: SimpleNamespace(adapter=object()),
    )
    monkeypatch.setattr(
        ifds_api,
        "_entry_nodes_from_program",
        lambda *_args, **_kwargs: ("entry",),
    )

    def fake_analyze_typestate(adapter, configuration, *, entry_nodes):
        captured["configuration"] = configuration
        captured["entry_nodes"] = entry_nodes
        return expected_result

    monkeypatch.setattr(ifds_api, "analyze_typestate", fake_analyze_typestate)

    _session, result = run_typestate_analysis(
        ["sample.py"],
        function="main",
        open_names=["open_file"],
        close_names=["close_file"],
        use_names=["read_file"],
        enabled_protocols=["resource", "python-builtins"],
        collection_mutator_names=["append_safe"],
        collection_accessor_names=["fetch"],
    )

    assert result is expected_result
    assert captured["entry_nodes"] == ("entry",)
    configuration = captured["configuration"]
    assert configuration.open_names == frozenset({"open_file"})
    assert configuration.close_names == frozenset({"close_file"})
    assert configuration.use_names == frozenset({"read_file"})
    assert configuration.enabled_protocols == frozenset(
        {"resource", "file", "socket", "lock", "transaction"}
    )
    assert configuration.collection_mutator_names == frozenset({"append_safe"})
    assert configuration.collection_accessor_names == frozenset({"fetch"})


def test_run_typestate_analysis_forwards_registry_models(monkeypatch):
    captured = {}
    expected_result = object()

    monkeypatch.setattr(
        ifds_api,
        "load_analysis_session",
        lambda *_args, **_kwargs: SimpleNamespace(adapter=object()),
    )
    monkeypatch.setattr(
        ifds_api,
        "_entry_nodes_from_program",
        lambda *_args, **_kwargs: ("entry",),
    )

    class FakeRegistry:
        detected_frameworks = frozenset({"network"})

        def activate(self, *frameworks):
            captured["frameworks"] = frameworks

        def active_models(self):
            return "registry-models"

    monkeypatch.setattr(
        ifds_api, "load_registry", lambda: FakeRegistry(), raising=False
    )

    def fake_analyze_typestate(adapter, configuration, *, entry_nodes):
        captured["configuration"] = configuration
        captured["entry_nodes"] = entry_nodes
        return expected_result

    monkeypatch.setattr(ifds_api, "analyze_typestate", fake_analyze_typestate)

    _session, result = run_typestate_analysis(
        ["sample.py"],
        function="main",
        enabled_protocols=["socket"],
        registry_frameworks=["network"],
    )

    assert result is expected_result
    assert captured["frameworks"] == ("network",)
    assert captured["configuration"].enabled_protocols == frozenset({"socket"})
    assert captured["configuration"].call_models == "registry-models"


def test_run_taint_analysis_api_on_repo_backed_multi_file_snippet():
    snippet_dir = Path(__file__).parent / "snippets" / "multi_file_taint"
    python_files = sorted(snippet_dir.glob("*.py"))

    session, result, _ = run_taint_analysis(
        python_files,
        function="main",
        source_names=["source"],
        sink_names=["sink"],
        sanitizer_names=["sanitize"],
        search_paths=[str(snippet_dir)],
    )

    assert {code.codeName() for code in session.program.liveCode} >= {
        "main",
        "helper",
        "sanitize",
        "sink",
        "source",
    }
    assert len(result.findings) == 1
    assert result.findings[0].sink_name == "sink"
    assert [local.name for local in result.findings[0].tainted_arguments] == ["b"]


def test_load_analysis_session_with_root_function_drops_unrelated_module_roots(
    tmp_path,
):
    main = tmp_path / "main.py"
    dead = tmp_path / "dead.py"
    main.write_text(
        """
def main():
    return 0
"""
    )
    dead.write_text("x = source()\nsink(x)\n")

    session = load_analysis_session([main, dead], verbose=False, root_function="main")

    assert [ep.code.codeName() for ep, _ in session.program.entryPoints] == [
        "main",
        "main.<module>",
    ]


def test_run_taint_analysis_includes_module_top_level_of_requested_file(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

x = source()
sink(x)

def main():
    return 0
"""
    )

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    assert len(result.findings) == 1


def test_run_taint_analysis_includes_class_definition_time_code(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

class C:
    x = source()
    sink(x)

def main():
    return 0
"""
    )

    session, result, _ = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    assert len(result.findings) == 1
    assert any("best-effort mode" in diagnostic for diagnostic in session.diagnostics)


def test_run_taint_analysis_handles_nested_and_computed_sink_expressions(tmp_path):
    target = tmp_path / "nested.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def helper(x):
    return x

def main():
    sink(source())
    a = source()
    sink(a + 1)
    b = helper(source())
    sink(b)
"""
    )

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    findings = sorted(
        (
            [local.name for local in finding.tainted_arguments],
            finding.tainted_argument_labels,
        )
        for finding in result.findings
    )
    assert findings == [
        ([], ("source()",)),
        (["a"], ()),
        (["b"], ()),
    ]


def test_run_taint_analysis_ignores_sanitized_nested_sink_expressions(tmp_path):
    target = tmp_path / "sanitized.py"
    target.write_text(
        """
def source():
    return 1

def sanitize(x):
    return x

def sink(x):
    return x

def main():
    a = source()
    sink(sanitize(a))
    sink(sanitize(source()))
"""
    )

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
        sanitizer_names=["sanitize"],
    )

    assert result.findings == ()


def test_run_taint_analysis_seeds_program_entry_points_only(tmp_path):
    target = tmp_path / "roots.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def dead_helper():
    sink(source())

def main():
    return 0
"""
    )

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    assert result.findings == ()


def test_run_taint_analysis_tracks_nested_call_results(tmp_path):
    target = tmp_path / "nested_results.py"
    target.write_text(
        """
def source():
    return 1

def wrap(x):
    return x

def wrapper():
    return wrap(source())

def sink(x):
    return x

def main():
    sink(wrapper())
"""
    )

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    assert len(result.findings) == 1
    assert result.findings[0].tainted_arguments == ()
    assert result.findings[0].tainted_argument_labels == ("wrapper()",)


def test_run_taint_analysis_tracks_try_except_sink_flow(tmp_path):
    target = tmp_path / "try_except.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def main():
    try:
        x = source()
        raise ValueError()
    except ValueError:
        sink(x)
"""
    )

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    assert len(result.findings) == 1
    assert result.findings[0].sink_name == "sink"
    assert [local.name for local in result.findings[0].tainted_arguments] == ["x"]


def test_run_taint_analysis_does_not_report_unreachable_except_calls(tmp_path):
    target = tmp_path / "unreachable_except.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def main():
    try:
        x = 0
    except Exception:
        sink(source())
"""
    )

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    assert result.findings == ()


def test_run_taint_analysis_scopes_findings_to_reachable_entry(tmp_path):
    target = tmp_path / "reachability.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def dead():
    sink(source())

def main():
    return 0
"""
    )

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    assert result.findings == ()


def test_load_analysis_session_handles_common_expression_shapes(tmp_path):
    target = tmp_path / "expressions.py"
    target.write_text(
        """
def f(a, b, xs):
    items = [a]
    subset = xs[1:2]
    both = a and b
    either = a or b
    maker = lambda z: z
    if (w := a):
        items = [w]
    return maker(both or either or subset or items)
"""
    )

    session = load_analysis_session([target], verbose=False)

    assert {code.codeName() for code in session.program.liveCode} >= {"f"}
    assert any("best-effort mode" in diagnostic for diagnostic in session.diagnostics)


def test_load_analysis_session_handles_annotated_assignments(tmp_path):
    target = tmp_path / "annassign.py"
    target.write_text(
        """
def f():
    x: int = 1
    y: int
    return x
"""
    )

    session = load_analysis_session([target], verbose=False)

    assert {code.codeName() for code in session.program.liveCode} >= {"f"}


def test_security_cli_emits_json_report(tmp_path, capsys):
    target = tmp_path / "sample.py"
    target.write_text(PROGRAM)

    args = SimpleNamespace(
        function="main",
        analysis="taint",
        engine="ifds",
        targets=[target],
        sources=["source"],
        sinks=["sink"],
        sanitizers=["sanitize"],
        format="json",
        recursive=False,
        dependency_strategy="auto",
        verbose=False,
    )

    exit_code = run_security(args)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["function"] == "main"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["tainted_arguments"] == ["b"]


def test_security_cli_reports_expression_only_taint_findings(tmp_path, capsys):
    target = tmp_path / "nested.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def main():
    sink(source())
"""
    )

    args = SimpleNamespace(
        function="main",
        analysis="taint",
        engine="ifds",
        targets=[target],
        sources=["source"],
        sinks=["sink"],
        sanitizers=[],
        format="json",
        recursive=False,
        dependency_strategy="auto",
        verbose=False,
    )

    exit_code = run_security(args)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["findings"][0]["tainted_arguments"] == ["source()"]
