"""CLI regressions distilled from the real-project user evaluation."""

import argparse
import json
from types import SimpleNamespace

import pytest

from pyflow.cli.callgraph import add_callgraph_parser, run_callgraph
from pyflow.cli.security.command import run_security
from pyflow.cli.security.filters import filter_report
from pyflow.cli.security.parser import add_security_parser
from pyflow.analysis.callgraph.constraint_based import extract_call_graph_constraint
from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
from pyflow.analysis.taint_policy import TaintPolicy


def scan(tmp_path, capsys, source, engine, *options):
    path = tmp_path / "sample.py"
    path.write_text(source)
    parser = argparse.ArgumentParser()
    add_security_parser(parser.add_subparsers())
    args = parser.parse_args(
        ["security", str(path), "--engine", engine, "--format", "json", *options]
    )
    assert run_security(args) == 0
    return json.loads(capsys.readouterr().out)


def test_library_methods_have_receivers_without_instantiation(tmp_path):
    path = tmp_path / "library.py"
    source = """
class Base:
    def helper(self): pass
    def run(self): self.helper()
    @classmethod
    def create(cls): cls.helper_class()
    @classmethod
    def helper_class(cls): pass
    @staticmethod
    def static(self): self.helper()
class Child(Base):
    def inherited(self): self.helper()
"""
    path.write_text(source)
    graph = extract_call_graph_constraint(
        source, source_path=str(path), canonical_entry_names=True
    ).get()
    assert "library.Base.helper" in graph["library.Base.run"]
    assert "library.Base.helper_class" in graph["library.Base.create"]
    assert "library.Base.helper" in graph["library.Child.inherited"]
    assert "library.Base.helper" not in graph["library.Base.static"]


def test_recursive_src_layout_keeps_package_identity(tmp_path, capsys):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "conf.py").write_text("pass\n")
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "helpers.py").write_text("def helper(): pass\n")
    (package / "app.py").write_text("from demo.helpers import helper\ndef run(): helper()\n")
    parser = argparse.ArgumentParser()
    add_callgraph_parser(parser.add_subparsers())
    for root in (tmp_path, tmp_path / "src", package):
        args = parser.parse_args(
            ["callgraph", str(root), "-r", "-a", "constraint", "--format", "json"]
        )
        assert run_callgraph(root, args) == 0
        graph = json.loads(capsys.readouterr().out)
        assert "demo.helpers.helper" in graph["demo.app.run"]
        assert "app.run" not in graph


def test_dynamic_entry_names_are_canonical(tmp_path):
    path = tmp_path / "entry.py"
    source = "unknown()\ndef run(): missing.attr()\n"
    path.write_text(source)
    graph = extract_call_graph_constraint(
        source, source_path=str(path), canonical_entry_names=True
    ).get()
    assert not any(name.startswith("<dynamic>.main") for name in graph)
    assert any(name.startswith("<dynamic>.entry@") for name in graph)
    assert any(name.startswith("<dynamic>.entry.run@") for name in graph)


def test_canonical_entry_is_not_loaded_again_via_import(tmp_path):
    from pyflow.analysis.callgraph.constraint_based.engine import ConstraintCallGraphBuilder

    source = "import helper\ndef run(): missing.call()\n"
    entry = tmp_path / "entry.py"
    entry.write_text(source)
    (tmp_path / "helper.py").write_text("import entry\ndef call(): entry.run()\n")
    builder = ConstraintCallGraphBuilder(source, entry_path=str(entry), canonical_entry_names=True)
    graph = builder.build().get()
    assert set(builder.modules) == {"entry", "helper"}
    assert "entry.run" in graph["helper.call"]


def test_native_mir_project_root_recognizes_src_layout(tmp_path):
    from pyflow.ir.mir import lower_file

    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    entry = package / "app.py"
    entry.write_text("def run(): pass\n")
    program = lower_file(entry, project_root=tmp_path)
    assert "demo.app.run" in program.cfgs
    assert "src.demo.app.run" not in program.cfgs


@pytest.mark.parametrize("name", ["__init__", "items", "unknown.items"])
def test_leaf_names_cannot_borrow_library_source_models(name):
    registry = CallModelRegistry(
        [
            CallModel("wsgiref.headers.Headers.items", source_kinds=frozenset({"user_input"})),
            CallModel("email.mime.Message.__init__", sink_kinds=frozenset({"email"})),
        ]
    )
    policy = TaintPolicy.from_call_models(registry, ())
    assert not policy.source_kinds_for(name)
    assert not policy.sink_kinds_for(name)
    assert registry.model_for_name(name) is None
    assert policy.source_kinds_for("Headers.items") == frozenset({"user_input"})


def test_unknown_constructor_is_not_a_sink_even_with_explicit_tainted_parameters(tmp_path, capsys):
    report = scan(
        tmp_path,
        capsys,
        """
class Config:
    def __init__(self, name, data):
        super().__init__(name, data)
""",
        "ast-dataflow",
        "--ast-entry-source-kind",
        "user_input",
    )
    assert report["findings"] == []


def test_library_parameters_are_not_sources_by_default(tmp_path, capsys):
    source = "def helper(value):\n    eval(value)\n"
    assert scan(tmp_path, capsys, source, "ast-dataflow")["findings"] == []
    assert scan(tmp_path, capsys, source, "ast-dataflow", "--ast-entry-source-kind", "user_input")[
        "findings"
    ]


@pytest.mark.parametrize("engine", ["ast-dataflow", "cpg"])
def test_database_receiver_resolution_and_parameterized_negative(tmp_path, capsys, engine):
    report = scan(
        tmp_path,
        capsys,
        """
import sqlite3 as db
def handler():
    query = input()
    connection = db.connect(":memory:")
    cursor = connection.cursor()
    cursor.execute(query)
    connection.execute(query)
    db.connect(":memory:").cursor().execute(query)
    cursor.execute("SELECT ?", (query,))
def unrelated(worker):
    worker.execute(input())
""",
        engine,
        "--framework",
    )
    findings = report["findings"]
    assert {f["sink_line"] for f in findings} == {7, 8, 9}
    assert all(f["cwe"] == "CWE-89" for f in findings)


@pytest.mark.parametrize(
    "path", ["name", "'/srv/' + name", "os.path.join('/srv', name)", "f'/srv/{name}'"]
)
def test_cpg_nested_open_sink_with_framework_source(tmp_path, capsys, path):
    source = f"""
import os
from flask import request
def handler():
    name = request.args.get('file')
    return open({path}).read()
"""
    report = scan(tmp_path, capsys, source, "cpg")
    assert len(report["findings"]) == 1
    assert report["findings"][0]["cwe"] == "CWE-22"
    assert report["findings"][0]["sink_line"] == 6
    raw = scan(tmp_path, capsys, source, "cpg", "--no-deduplicate")
    assert len(raw["findings"]) > 1


@pytest.mark.parametrize("engine", ["ast-dataflow", "cpg", "ifds"])
def test_literal_dictionary_iteration_is_not_an_http_source(tmp_path, capsys, engine):
    report = scan(
        tmp_path,
        capsys,
        """
import os
configs = {'a.json': {'debug': False}, 'b.json': {'debug': True}}
for name, data in configs.items():
    path = os.path.join('/tmp/configs', name)
    with open(path, 'w') as stream:
        stream.write(str(data))
""",
        engine,
    )
    assert report["findings"] == []


@pytest.mark.parametrize("engine", ["ifds", "cpg"])
def test_cross_pack_folding_preserves_severity_and_rule_provenance(engine):
    findings = [
        {
            "filename": "app.py",
            "sink_line": 3,
            "sink_name": "open",
            "cwe": "CWE-22",
            "rule_id": rule,
            "severity": severity,
        }
        for rule, severity in [("PACK-A", "medium"), ("PACK-B", "high")]
    ]
    result = filter_report(engine, {"findings": findings}, SimpleNamespace(), frozenset())
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "high"
    assert {r["rule_id"] for r in result["findings"][0]["related_rules"]} == {"PACK-A", "PACK-B"}
    raw = filter_report(
        engine, {"findings": findings}, SimpleNamespace(no_deduplicate=True), frozenset()
    )
    assert len(raw["findings"]) == 2


@pytest.mark.parametrize("engine", ["ast-dataflow", "cpg", "ifds"])
def test_custom_sinks_extend_default_sources(tmp_path, capsys, engine):
    report = scan(
        tmp_path,
        capsys,
        "def main():\n    custom_sink(input())\nmain()\n",
        engine,
        "--sinks",
        "custom_sink",
    )
    assert report["findings"]


@pytest.mark.parametrize("engine", ["ast-dataflow", "cpg", "ifds"])
def test_pickle_encoded_request_preserves_source_taint(tmp_path, capsys, engine):
    report = scan(
        tmp_path,
        capsys,
        """
import pickle
from flask import request
def main():
    value = request.args.get('payload')
    return pickle.loads(value.encode())
main()
""",
        engine,
    )
    assert any(f["cwe"] == "CWE-502" for f in report["findings"])


def test_ifds_recursive_library_without_detectable_entry(tmp_path, capsys):
    (tmp_path / "library.py").write_text("def helper():\n    eval(input())\n")
    parser = argparse.ArgumentParser()
    add_security_parser(parser.add_subparsers())
    args = parser.parse_args(
        ["security", str(tmp_path), "-r", "--engine", "ifds", "--format", "json"]
    )
    assert run_security(args) == 0
    assert json.loads(capsys.readouterr().out)["findings"]


def test_partial_security_report_can_require_completion(tmp_path, capsys):
    path = tmp_path / "library.py"
    path.write_text("def main():\n    vendor_call()\n")
    parser = argparse.ArgumentParser()
    add_security_parser(parser.add_subparsers())
    args = parser.parse_args(
        ["security", str(path), "--engine", "ast-dataflow", "--require-complete"]
    )
    assert run_security(args) == 3
    assert "Status: partial" in capsys.readouterr().out


def test_callgraph_unified_schema_separates_unresolved_targets(tmp_path, capsys):
    path = tmp_path / "sample.py"
    path.write_text("unknown()\nprint('constant')\n")
    parser = argparse.ArgumentParser()
    add_callgraph_parser(parser.add_subparsers())
    args = parser.parse_args(
        ["callgraph", str(path), "-a", "constraint", "--format", "json", "--json-schema", "unified"]
    )
    assert run_callgraph(path, args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "partial"
    assert report["analysis_complete"] is True
    assert report["termination_reason"] == "converged"
    assert report["unresolved_calls"]
    assert report["external_calls"]
    assert all(not name.startswith("<") for name in report["graph"])


def test_explicit_mir_budget_is_not_capped_by_implicit_process_limit(tmp_path, capsys, monkeypatch):
    import pyflow.cli.callgraph as cli

    def run(request, *, timeout):
        assert request["analysis_seconds"] == 60
        assert timeout == 65
        return "{}"

    monkeypatch.setattr(cli, "run_isolated_callgraph", run)
    path = tmp_path / "sample.py"
    path.write_text("pass\n")
    parser = argparse.ArgumentParser()
    add_callgraph_parser(parser.add_subparsers())
    args = parser.parse_args(["callgraph", str(path), "-a", "pycg-mir", "--mir-max-seconds", "60"])
    assert run_callgraph(path, args) == 0


def test_native_mir_library_receivers_and_no_descriptor_cross_edges():
    from pyflow.ir.mir import lower_source
    from pyflow.analysis.callgraph.pycg_mir import analyze_program

    program = lower_source(
        """
class Base:
    @classmethod
    def cm(cls): return cls.helper()
    @classmethod
    def helper(cls): return 1
    def im(self): return self.helper2()
    def helper2(self): return 2
    @staticmethod
    def sm(): return Base.helper()
""",
        module_name="library",
    )
    result = analyze_program(program, max_iterations=64, raise_on_truncation=True)
    graph = result.call_graph.get()
    assert graph["library.Base.cm"] == {"library.Base.helper"}
    assert graph["library.Base.im"] == {"library.Base.helper2"}
    assert graph["library.Base.sm"] == {"library.Base.helper"}


def test_scanner_constant_shell_sql_yaml_and_hash_contracts(tmp_path, capsys):
    report = scan(
        tmp_path,
        capsys,
        """
import os, hashlib, yaml, sqlite3
os.system('echo hello')
cursor.execute(f'SELECT * FROM records WHERE name = {user_input}')
yaml.load(payload)
hashlib.md5(b'data')
""",
        "ast-scanner",
    )
    findings = report["results"]
    assert any(f["test_id"] == "B605" and f["issue_severity"] == "LOW" for f in findings)
    assert not any(f["test_id"] in {"B604", "B612"} for f in findings)
    assert any(f["test_id"] == "B608" for f in findings)
    assert any(f["test_id"] == "B9022" and f["issue_severity"] == "MEDIUM" for f in findings)
    assert any(f["test_id"] == "B324" and f["issue_severity"] == "HIGH" for f in findings)


def test_declared_http_handler_parameters_remain_sources(tmp_path, capsys):
    report = scan(
        tmp_path,
        capsys,
        """
from flask import Flask
app = Flask(__name__)
@app.get('/<value>')
def handler(value):
    eval(value)
def helper(value):
    eval(value)
""",
        "ast-dataflow",
    )
    assert {finding["function"] for finding in report["findings"]} == {"handler"}


def test_quart_sql_format_source_and_receiver(tmp_path, capsys):
    report = scan(
        tmp_path,
        capsys,
        """
from quart import request
import sqlite3
async def search():
    value = request.args.get('q')
    connection = sqlite3.connect(':memory:')
    cursor = connection.cursor()
    query = "SELECT * FROM records WHERE name = '{value}'".format(value=value)
    cursor.execute(query)
""",
        "ast-dataflow",
    )
    assert any(f["cwe"] == "CWE-89" and f["sink_line"] == 9 for f in report["findings"])


@pytest.mark.parametrize("engine", ["cpg", "ifds"])
def test_lowered_with_sink_retains_location_and_source_owner(tmp_path, capsys, engine):
    report = scan(
        tmp_path,
        capsys,
        """
def load_config():
    name = input()
    with open(name) as stream:
        return stream.read()
load_config()
""",
        engine,
    )
    findings = report["findings"]
    assert findings
    for finding in findings:
        if engine == "ifds":
            assert finding["procedure"] == "load_config"
            assert finding["primary_location"]["start_line"] == 4
        else:
            assert finding["sink_line"] == 4
            assert finding["sink_filename"].endswith("sample.py")
