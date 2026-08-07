"""Tests for the IFDS analysis API and CLI entrypoints."""

from __future__ import annotations

import json
import importlib
import inspect
from pathlib import Path
from types import SimpleNamespace

import pyflow.analysis.ifds.api as ifds_api
import pyflow.analysis.callgraph.publication as callgraph_publication
from pyflow.analysis.ifds.api import (
    load_analysis_session,
    run_nullness_analysis,
    run_taint_analysis,
    run_typestate_analysis,
)
from pyflow.cli.security import run_security
from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
from pyflow.analysis.ifds.modeling.calls import TaintModelPort, TaintPropagation
from pyflow.analysis.taint import TaintRule
from pyflow.ir.core import Capabilities


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


def test_run_taint_analysis_defaults_to_drop_unknown_calls():
    parameter = inspect.signature(run_taint_analysis).parameters[
        "unknown_call_policy"
    ]
    assert parameter.default == "drop"


def _taint_setup(sources, sinks, sanitizers=()):
    return {
        "call_models": CallModelRegistry(
            [
                *(
                    CallModel(name, source_kinds=frozenset({"test.source"}))
                    for name in sources
                ),
                *(
                    CallModel(name, sink_kinds=frozenset({"test.sink"}))
                    for name in sinks
                ),
                *(
                    CallModel(name, sanitizer_kinds=frozenset({"*"}))
                    for name in sanitizers
                ),
            ]
        ),
        "rules": (
            TaintRule(
                "TEST-TAINT",
                "Test taint flow",
                frozenset({"test.source"}),
                frozenset({"test.sink"}),
            ),
        ),
    }


def test_run_taint_analysis_api_on_source_file(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(PROGRAM)

    session, result, _ = run_taint_analysis(
        [target],
        function="main",
        **_taint_setup(["source"], ["sink"], ["sanitize"]),
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
        **_taint_setup(["source"], ["sink"]),
    )

    assert len(result.findings) == 1
    assert result.findings[0].sink_name == "sink"
    assert [local.name for local in result.findings[0].tainted_arguments] == ["out"]


def test_run_taint_analysis_uses_stdlib_getoutput_model(tmp_path):
    target = tmp_path / "command.py"
    target.write_text(
        "import subprocess\n"
        "def main():\n"
        "    command = input()\n"
        "    subprocess.getoutput(command)\n",
        encoding="utf-8",
    )
    registry = ifds_api.load_registry()
    registry.activate("stdlib", type="taint")

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        call_models=registry.active_models(type="taint"),
        rules=registry.as_taint_policy().rules,
    )

    assert any(
        finding.sink_name == "subprocess.getoutput"
        and finding.cwe == "CWE-78"
        for finding in result.findings
    )


def test_odoo_template_context_shape_distinguishes_allowlist_rebuild(tmp_path):
    vulnerable = tmp_path / "vulnerable.py"
    vulnerable.write_text(
        "def main(request):\n"
        "    values = request.params.copy()\n"
        "    request.render('web.login', values)\n",
        encoding="utf-8",
    )
    fixed = tmp_path / "fixed.py"
    fixed.write_text(
        "def main(request):\n"
        "    allowed = {'login', 'redirect'}\n"
        "    values = {k: v for k, v in request.params.items() if k in allowed}\n"
        "    request.render('web.login', values)\n",
        encoding="utf-8",
    )
    registry = ifds_api.load_registry()
    registry.activate("odoo", type="taint")
    configuration = {
        "call_models": registry.active_models(type="taint"),
        "rules": registry.as_taint_policy().rules,
    }

    _session, vulnerable_result, _ = run_taint_analysis(
        [vulnerable], function="main", **configuration
    )
    _session, fixed_result, _ = run_taint_analysis(
        [fixed], function="main", **configuration
    )

    assert any(
        finding.rule.rule_id == "PYFLOW-ODOO-TEMPLATE-CONTEXT"
        for finding in vulnerable_result.findings
    )
    assert not any(
        finding.rule.rule_id == "PYFLOW-ODOO-TEMPLATE-CONTEXT"
        for finding in fixed_result.findings
    )


def test_run_taint_analysis_uses_archive_member_models(tmp_path):
    target = tmp_path / "archive.py"
    target.write_text(
        "import tarfile\n"
        "def main(archive):\n"
        "    names = archive.getnames()\n"
        "    archive.extract(names[0], '/tmp/output')\n",
        encoding="utf-8",
    )
    registry = ifds_api.load_registry()
    registry.activate("stdlib", type="taint")

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        call_models=registry.active_models(type="taint"),
        rules=registry.as_taint_policy().rules,
    )

    assert any(
        finding.sink_name.endswith("extract")
        and finding.cwe == "CWE-22"
        for finding in result.findings
    )


def test_run_taint_analysis_propagates_modeled_source_into_nested_for(tmp_path):
    target = tmp_path / "archive_nested_loop.py"
    target.write_text(
        "import os\n"
        "def main(archive):\n"
        "    try:\n"
        "        for member in archive.getnames():\n"
        "            try:\n"
        "                os.remove(member)\n"
        "            except OSError:\n"
        "                pass\n"
        "    except Exception:\n"
        "        pass\n",
        encoding="utf-8",
    )
    registry = ifds_api.load_registry()
    registry.activate("stdlib", type="taint")

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        call_models=registry.active_models(type="taint"),
        rules=registry.as_taint_policy().rules,
    )

    assert any(
        finding.sink_name == "os.remove" and finding.cwe == "CWE-22"
        for finding in result.findings
    )


def test_run_taint_analysis_models_tortoise_like_and_escape_like(tmp_path):
    vulnerable = tmp_path / "vulnerable.py"
    vulnerable.write_text(
        "from pypika import functions\n"
        "def main(field):\n"
        "    value = input()\n"
        "    return functions.Cast(field, 'CHAR').like(f'%{value}%')\n",
        encoding="utf-8",
    )
    fixed = tmp_path / "fixed.py"
    fixed.write_text(
        "from tortoise.filters import Like\n"
        "class StrWrapper:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n"
        "def escape_like(value):\n"
        "    return value.replace('%', r'\\%').replace('_', r'\\_')\n"
        "def main(field):\n"
        "    value = input()\n"
        "    pattern = StrWrapper(f'%{escape_like(value)}%')\n"
        "    return Like(field, pattern, escape='')\n",
        encoding="utf-8",
    )
    registry = ifds_api.load_registry()
    registry.activate("stdlib", "tortoise", type="taint")
    setup = {
        "call_models": registry.active_models(type="taint"),
        "rules": registry.as_taint_policy().rules,
    }

    _session, vulnerable_result, _ = run_taint_analysis(
        [vulnerable], function="main", **setup
    )
    _session, fixed_result, _ = run_taint_analysis(
        [fixed], function="main", **setup
    )

    assert any(
        finding.sink_name.endswith("like") and finding.cwe == "CWE-89"
        for finding in vulnerable_result.findings
    )
    assert not any(finding.cwe == "CWE-89" for finding in fixed_result.findings)


def test_run_taint_analysis_applies_parameter_to_return_propagation(tmp_path):
    target = tmp_path / "modeled_wrapper.py"
    target.write_text(
        "def source():\n"
        "    return 1\n"
        "def wrapper(value):\n"
        "    return 0\n"
        "def sink(value):\n"
        "    return value\n"
        "def main():\n"
        "    sink(wrapper(source()))\n",
        encoding="utf-8",
    )
    setup = _taint_setup(["source"], ["sink"])
    setup["call_models"] = setup["call_models"].merged(
        CallModelRegistry(
            [
                CallModel(
                    "wrapper",
                    taint_propagations=frozenset(
                        {
                            TaintPropagation(
                                TaintModelPort("parameter", 0),
                                TaintModelPort("return"),
                            )
                        }
                    ),
                )
            ]
        )
    )

    _session, result, _ = run_taint_analysis(
        [target], function="main", **setup
    )

    assert any(finding.sink_name == "sink" for finding in result.findings)


def test_run_taint_analysis_applies_parameter_to_receiver_propagation(tmp_path):
    target = tmp_path / "modeled_mutator.py"
    target.write_text(
        "def source():\n"
        "    return 1\n"
        "def sink(value):\n"
        "    return value\n"
        "def main():\n"
        "    box = []\n"
        "    box.absorb(source())\n"
        "    sink(box)\n",
        encoding="utf-8",
    )
    setup = _taint_setup(["source"], ["sink"])
    setup["call_models"] = setup["call_models"].merged(
        CallModelRegistry(
            [
                CallModel(
                    "library.Box.absorb",
                    taint_propagations=frozenset(
                        {
                            TaintPropagation(
                                TaintModelPort("parameter", 0),
                                TaintModelPort("receiver"),
                            )
                        }
                    ),
                )
            ]
        )
    )

    _session, result, _ = run_taint_analysis(
        [target], function="main", **setup
    )

    assert any(finding.sink_name == "sink" for finding in result.findings)


def test_run_taint_analysis_applies_stdlib_format_propagations(tmp_path):
    target = tmp_path / "format_propagation.py"
    target.write_text(
        "def source():\n"
        "    return 'tainted'\n"
        "def sink(value):\n"
        "    return value\n"
        "def main():\n"
        "    template = source()\n"
        "    sink(template.format())\n"
        "    sink('{}'.format(source()))\n",
        encoding="utf-8",
    )
    registry = ifds_api.load_registry()
    registry.activate("stdlib", type="taint")
    models = registry.active_models(type="taint").merged(
        _taint_setup(["source"], ["sink"])["call_models"]
    )

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        call_models=models,
        rules=_taint_setup(["source"], ["sink"])["rules"],
    )

    assert sum(finding.sink_name == "sink" for finding in result.findings) == 2


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


def test_load_analysis_session_runs_one_entry_rooted_constraint_solve(
    tmp_path, monkeypatch
):
    entry = tmp_path / "entry.py"
    helper = tmp_path / "helper.py"
    entry.write_text("from helper import apply, target\napply(target)\n")
    helper.write_text(
        "def target():\n    return 1\n\ndef apply(fn):\n    return fn()\n"
    )

    calls = []
    original = callgraph_publication.ConstraintCallGraphBuilder.build

    def recording_build(builder):
        calls.append(builder.entry_path)
        return original(builder)

    monkeypatch.setattr(
        callgraph_publication.ConstraintCallGraphBuilder,
        "build",
        recording_build,
    )

    session = load_analysis_session([entry, helper], entry_file=entry)
    apply_cfg = next(
        cfg
        for cfg in session.adapter.cfgs
        if getattr(cfg, "code", None) is not None and cfg.code.codeName() == "apply"
    )
    call_node = next(
        node
        for node in session.adapter.supergraph.nodes_of(apply_cfg)
        if session.adapter.call_expression_of(node) is not None
    )

    assert calls == [str(entry.resolve())]
    assert [
        callee.code.codeName() for callee in session.adapter.callees_of(call_node)
    ] == ["target"]


def test_load_analysis_session_finalizes_semantics_once(tmp_path, monkeypatch):
    target = tmp_path / "main.py"
    target.write_text("def main():\n    return 1\nmain()\n")
    semantics_builder = importlib.import_module("pyflow.ir.core.build_semantics")
    calls = []
    original = semantics_builder.build_semantics

    def recording_build(catalog):
        calls.append(catalog)
        return original(catalog)

    monkeypatch.setattr(semantics_builder, "build_semantics", recording_build)

    session = load_analysis_session([target], entry_file=target)

    assert calls == [session.program.ir]


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
        **_taint_setup(["source"], ["sink"], ["clean"]),
        collection_mutator_names=["append_safe"],
        collection_accessor_names=["fetch"],
        unknown_call_policy="preserve",
        conservative_unresolved_call_side_effects=True,
    )

    assert result is expected_result
    assert captured["entry_nodes"] == ("entry",)
    configuration = captured["configuration"]
    mapping = configuration.call_models.as_mapping()
    assert mapping["source"].source_kinds == frozenset({"test.source"})
    assert mapping["sink"].sink_kinds == frozenset({"test.sink"})
    assert mapping["clean"].sanitizer_kinds == frozenset({"*"})
    assert configuration.rules[0].rule_id == "TEST-TAINT"
    assert configuration.collection_mutator_names == frozenset({"append_safe"})
    assert configuration.collection_accessor_names == frozenset({"fetch"})
    assert configuration.unknown_call_policy == "preserve"
    assert configuration.conservative_unresolved_call_side_effects is True
    assert configuration.entry_point_options.taint_parameters is False


def test_run_taint_analysis_enables_entry_parameter_sources_for_file_scans(
    monkeypatch,
):
    captured = {}
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
        return object()

    monkeypatch.setattr(ifds_api, "analyze_taint", fake_analyze_taint)

    run_taint_analysis(
        ["sample.py"],
        entry_file="sample.py",
        **_taint_setup(["source"], ["sink"]),
    )

    assert captured["configuration"].entry_point_options.taint_parameters is True


def test_run_taint_analysis_forwards_shared_entrypoint_options(monkeypatch):
    from pyflow.analysis.entrypoints import EntryPointMode, EntryPointOptions

    captured = {}
    options = EntryPointOptions(
        mode=EntryPointMode.INFERRED_ROOTS,
        taint_parameters=True,
    )
    monkeypatch.setattr(
        ifds_api,
        "load_analysis_session",
        lambda *_args, **_kwargs: SimpleNamespace(adapter=object()),
    )

    def fake_entries(*_args, **kwargs):
        captured["entry_point_options"] = kwargs["entry_point_options"]
        return ("entry",)

    monkeypatch.setattr(ifds_api, "_entry_nodes_from_program", fake_entries)

    def fake_analyze_taint(adapter, configuration, *, entry_nodes):
        captured["configuration"] = configuration
        return object()

    monkeypatch.setattr(ifds_api, "analyze_taint", fake_analyze_taint)

    run_taint_analysis(
        ["sample.py"],
        entry_point_options=options,
        **_taint_setup(["source"], ["sink"]),
    )

    assert captured["entry_point_options"] is options
    assert captured["configuration"].entry_point_options.taint_parameters is True


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

        def activate(self, *frameworks, type=None):
            captured["frameworks"] = frameworks

        def active_models(self, *, type=None):
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
        **_taint_setup(["source"], ["sink"], ["sanitize"]),
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

    assert [ep.code.codeName() for ep in session.program.entryPoints] == [
        "main",
        "main.<module>",
    ]


def test_load_analysis_session_with_entry_file_keeps_only_that_module_root(tmp_path):
    entry = tmp_path / "entry.py"
    other = tmp_path / "other.py"
    entry.write_text("run()\n", encoding="utf-8")
    other.write_text("unused()\n", encoding="utf-8")

    session = load_analysis_session([entry, other], entry_file=entry)

    assert [ep.code.codeName() for ep in session.program.entryPoints] == [
        "entry.<module>"
    ]


def test_entry_file_ignores_inferred_function_invocation_arguments(tmp_path):
    entry = tmp_path / "entry.py"
    entry.write_text(
        "def helper(*, verbose=True, temperature=0.0):\n"
        "    return temperature if verbose else 0.0\n"
        "helper()\n",
        encoding="utf-8",
    )

    session = load_analysis_session([entry], entry_file=entry)

    assert [ep.code.codeName() for ep in session.program.entryPoints] == [
        "entry.<module>"
    ]


def test_load_analysis_session_uses_constraint_callgraph_without_ipa_cpa(tmp_path):
    entry = tmp_path / "entry.py"
    entry.write_text("def helper():\n    return 1\nhelper()\n", encoding="utf-8")

    session = load_analysis_session([entry], entry_file=entry)

    facts = session.program.ir.facts
    assert facts.has(Capabilities.CALL_TARGET_CODES)
    assert not facts.has(Capabilities.CONTEXTS)


def test_run_taint_analysis_entry_file_does_not_seed_unrelated_modules(tmp_path):
    entry = tmp_path / "entry.py"
    dead = tmp_path / "dead.py"
    entry.write_text("value = 0\n", encoding="utf-8")
    dead.write_text("sink(source())\n", encoding="utf-8")

    _session, result, _ = run_taint_analysis(
        [entry, dead],
        entry_file=entry,
        **_taint_setup(["source"], ["sink"]),
    )

    assert result.findings == ()


def test_run_taint_analysis_entry_file_seeds_file_local_handlers(tmp_path):
    entry = tmp_path / "handler.py"
    entry.write_text(
        "def route_handler():\n" "    value = source()\n" "    sink(value)\n",
        encoding="utf-8",
    )

    _session, result, _ = run_taint_analysis(
        [entry],
        entry_file=entry,
        **_taint_setup(["source"], ["sink"]),
    )

    assert len(result.findings) == 1


def test_run_taint_analysis_entry_file_follows_cross_module_calls(tmp_path):
    entry = tmp_path / "entry.py"
    helper = tmp_path / "helper.py"
    entry.write_text("from helper import flow\nflow()\n", encoding="utf-8")
    helper.write_text(
        "def source():\n"
        "    return 1\n"
        "def sink(value):\n"
        "    return value\n"
        "def flow():\n"
        "    sink(source())\n",
        encoding="utf-8",
    )

    _session, result, _ = run_taint_analysis(
        [entry, helper],
        entry_file=entry,
        **_taint_setup(["source"], ["sink"]),
    )

    assert len(result.findings) == 1


def test_entry_file_public_handler_follows_cross_module_calls(tmp_path):
    entry = tmp_path / "entry.py"
    helper = tmp_path / "helper.py"
    unused = tmp_path / "unused.py"
    entry.write_text(
        "from helper import flow\n"
        "def route_handler():\n"
        "    flow()\n",
        encoding="utf-8",
    )
    helper.write_text(
        "def source():\n"
        "    return 1\n"
        "def sink(value):\n"
        "    return value\n"
        "def flow():\n"
        "    sink(source())\n",
        encoding="utf-8",
    )
    unused.write_text("def dead():\n    return 0\n", encoding="utf-8")

    session, result, _ = run_taint_analysis(
        [entry, helper, unused],
        entry_file=entry,
        **_taint_setup(["source"], ["sink"]),
    )

    assert len(result.findings) == 1
    analyzed_names = {
        procedure.code.codeName()
        for procedure in session.adapter.supergraph.procedures()
    }
    assert "dead" not in analyzed_names


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
        **_taint_setup(["source"], ["sink"]),
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
        **_taint_setup(["source"], ["sink"]),
    )

    assert len(result.findings) == 1
    assert session.diagnostics == ()


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
        **_taint_setup(["source"], ["sink"]),
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
        (["a"], ("interpreter__add__()",)),
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
        **_taint_setup(["source"], ["sink"], ["sanitize"]),
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
        **_taint_setup(["source"], ["sink"]),
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
        **_taint_setup(["source"], ["sink"]),
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
        **_taint_setup(["source"], ["sink"]),
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
        **_taint_setup(["source"], ["sink"]),
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
        **_taint_setup(["source"], ["sink"]),
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
    assert session.diagnostics == ()
    assert session.diagnostic_messages == ()


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
    target.write_text(PROGRAM + "\nmain()\n")

    args = SimpleNamespace(
        entry=None,
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
    assert payload["entry"] == str(target)
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

main()
"""
    )

    args = SimpleNamespace(
        entry=None,
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
