"""Public security CLI regressions from the 62-case field evaluation."""

import argparse
import json

import pytest

from pyflow.cli.security.command import run_security
from pyflow.cli.security.parser import add_security_parser


def scan(target, capsys, engine, *options):
    parser = argparse.ArgumentParser()
    add_security_parser(parser.add_subparsers())
    args = parser.parse_args(
        [
            "security",
            str(target),
            "--engine",
            engine,
            "--format",
            "json",
            "--json-schema",
            "unified",
            *options,
        ]
    )
    code = run_security(args)
    report = json.loads(capsys.readouterr().out)
    return code, report


@pytest.mark.parametrize(
    "definition", ["def f():\n    BODY\n", "class Worker:\n    def run(self):\n        BODY\n"]
)
@pytest.mark.parametrize("second", ['os.system("ls")', "eval(input())"])
def test_duplicate_definitions_keep_file_identity(tmp_path, capsys, definition, second):
    (tmp_path / "a.py").write_text("import os\n" + definition.replace("BODY", "os.system(input())"))
    (tmp_path / "b.py").write_text("import os\n" + definition.replace("BODY", second))
    code, report = scan(tmp_path, capsys, "ast-dataflow")
    assert code == 0
    assert report["status"] == "complete"
    actual = {(f["location"]["filename"].split("/")[-1], f["cwe"]) for f in report["findings"]}
    expected = {("a.py", "CWE-78")}
    if second == "eval(input())":
        expected.add(("b.py", "CWE-95"))
    assert actual == expected


@pytest.mark.parametrize(
    "imports,tainted,safe",
    [
        ("from a import f as source\nfrom b import f as safe\n", "source()", "safe()"),
        ("import a, b\n", "a.f()", "b.f()"),
    ],
)
def test_colliding_summaries_resolve_local_and_imported_calls(
    tmp_path, capsys, imports, tainted, safe
):
    (tmp_path / "a.py").write_text("def f(): return input()\ndef local(): eval(f())\n")
    (tmp_path / "b.py").write_text("def f(): return 'safe'\ndef local(): eval(f())\n")
    (tmp_path / "main.py").write_text(
        imports + f"def run():\n    eval({tainted})\n    eval({safe})\n"
    )
    code, report = scan(tmp_path, capsys, "ast-dataflow")
    assert code == 0
    assert {
        (f["location"]["filename"].split("/")[-1], f["location"]["line"])
        for f in report["findings"]
    } == {("a.py", 2), ("main.py", len(imports.splitlines()) + 2)}


@pytest.mark.parametrize(
    "body", ["os.system(input())", 'if __name__ == "__main__":\n    os.system(input())']
)
def test_ast_scans_module_execution(tmp_path, capsys, body):
    path = tmp_path / "main.py"
    path.write_text("import os\n" + body + "\n")
    code, report = scan(path, capsys, "ast-dataflow")
    assert code == 0
    assert {f["cwe"] for f in report["findings"]} == {"CWE-78"}


@pytest.mark.parametrize(
    "expression",
    [
        "request.args.get('x').upper()",
        "request.headers.get('X').strip()",
        "request.headers.get('X').split(';')[0]",
        "request.args.get('x').replace('a', 'b').encode()",
    ],
)
def test_ast_preserves_chained_receiver_taint(tmp_path, capsys, expression):
    path = tmp_path / "app.py"
    path.write_text(
        f"import os\nfrom flask import request\ndef handler():\n    os.system({expression})\n    os.system(' x '.strip().upper())\n"
    )
    code, report = scan(path, capsys, "ast-dataflow")
    assert code == 0
    assert {f["location"]["line"] for f in report["findings"]} == {4}


@pytest.mark.parametrize(
    "overwrite",
    [
        'cmd = "ls"',
        'cmd = other = "ls"',
        'cmd: str = "ls"',
        'if True:\n        cmd = "ls"',
        'if flag:\n        cmd = "ls"\n    else:\n        cmd = "pwd"',
        'cmd = "a"\n    cmd += "b"',
    ],
)
def test_ifds_constant_overwrites(tmp_path, capsys, overwrite):
    path = tmp_path / "main.py"
    path.write_text(
        f"import os\ndef run(flag):\n    cmd = input()\n    {overwrite}\n    os.system(cmd)\n"
    )
    code, report = scan(path, capsys, "ifds")
    assert code == 0
    assert report["findings"] == []


@pytest.mark.parametrize(
    "body",
    [
        'cmd = input()\n    if flag:\n        cmd = "ls"\n    os.system(cmd)',
        'cmd = input()\n    saved = cmd\n    cmd = "ls"\n    os.system(saved)',
        'cmd = "ls"\n    if flag:\n        cmd = input()\n    os.system(cmd)',
        'cmd = input()\n    cmd += "suffix"\n    os.system(cmd)',
        'cmd = input()\n    os.system(cmd)\n    cmd = "ls"',
    ],
)
def test_ifds_overwrites_preserve_other_paths_and_aliases(tmp_path, capsys, body):
    path = tmp_path / "main.py"
    path.write_text(f"import os\ndef run(flag):\n    {body}\n")
    code, report = scan(path, capsys, "ifds")
    assert code == 0
    assert any(f["cwe"] == "CWE-78" for f in report["findings"])


@pytest.mark.parametrize("engine", ["ast-dataflow", "ifds"])
@pytest.mark.parametrize("framework", ["flask", "quart"])
@pytest.mark.parametrize(
    "sink,cwe",
    [("pickle.loads", "CWE-502"), ("yaml.load", "CWE-502"), ("ET.fromstring", "CWE-611")],
)
def test_request_body_methods_are_sources(tmp_path, capsys, engine, framework, sink, cwe):
    path = tmp_path / "app.py"
    path.write_text(
        f"import pickle, yaml\nfrom lxml import etree as ET\nfrom {framework} import request\ndef handler():\n    {sink}(request.get_data())\n"
    )
    code, report = scan(path, capsys, engine)
    assert code == 0
    assert any(f["cwe"] == cwe and f["location"]["line"] == 5 for f in report["findings"])


@pytest.mark.parametrize("engine", ["ast-dataflow", "ifds"])
def test_library_parameter_policy_is_explicit(tmp_path, capsys, engine):
    path = tmp_path / "library.py"
    path.write_text("def helper(value):\n    eval(value)\nhelper('1+1')\n")
    code, report = scan(path, capsys, engine)
    assert code == 0
    assert report["findings"] == []
    code, report = scan(path, capsys, engine, "--entry-source-kind", "user_input")
    assert code == 0
    assert report["findings"]


@pytest.mark.parametrize("engine", ["ast-dataflow", "ifds"])
def test_declared_http_handler_parameter_is_a_boundary(tmp_path, capsys, engine):
    path = tmp_path / "app.py"
    path.write_text(
        "from flask import Flask\napp = Flask(__name__)\n@app.get('/<value>')\ndef handler(value):\n    eval(value)\ndef helper(value):\n    eval(value)\n"
    )
    code, report = scan(path, capsys, engine)
    assert code == 0
    assert {f["location"]["line"] for f in report["findings"]} == {5}


def test_ifds_import_aliases_and_unrelated_leaf_names(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text(
        "import ast, pickle\nfrom flask import request, redirect as rd\nfrom yaml import load\ndef handler():\n    rd(request.args.get('next'))\n    load(request.get_data())\n    ast.parse(input())\n    d = {}\n    d.setdefault('k', input())\n    pickle.loads(input())\n"
    )
    code, report = scan(path, capsys, "ifds")
    assert code == 0
    assert {(f["location"]["line"], f["cwe"]) for f in report["findings"]} == {
        (5, "CWE-601"),
        (6, "CWE-502"),
        (10, "CWE-502"),
    }
    assert all(f["rule_title"] for f in report["findings"])
    assert all(f["properties"]["function"] == "handler" for f in report["findings"])


@pytest.mark.parametrize("engine", ["ast-dataflow", "ifds"])
@pytest.mark.parametrize("encoding", ["utf-8-sig", "latin-1"])
def test_source_encodings_produce_json(tmp_path, capsys, engine, encoding):
    path = tmp_path / "app.py"
    path.write_bytes(
        (
            "# coding: "
            + ("latin-1" if encoding == "latin-1" else "utf-8")
            + "\n# café\nimport os\ndef run(): os.system(input())\n"
        ).encode(encoding)
    )
    code, report = scan(path, capsys, engine)
    assert code == 0
    assert any(f["cwe"] == "CWE-78" for f in report["findings"])


@pytest.mark.parametrize("engine", ["ast-dataflow", "ifds"])
@pytest.mark.parametrize("bad_source", [b"def bad(:\n", b"# coding: utf-8\n# \xff\n"])
def test_bad_file_does_not_hide_good_directory_results(tmp_path, capsys, engine, bad_source):
    (tmp_path / "good.py").write_text("import os\ndef run(): os.system(input())\n")
    (tmp_path / "bad.py").write_bytes(bad_source)
    code, report = scan(tmp_path, capsys, engine)
    assert code == 0
    assert report["status"] == "partial"
    assert report["diagnostics"]
    assert any(f["cwe"] == "CWE-78" for f in report["findings"])


@pytest.mark.parametrize("source", ["def bad(:\n", "(" * 1000 + "1" + ")" * 1000])
def test_ast_parse_failures_disclose_incompleteness(tmp_path, capsys, source):
    path = tmp_path / "bad.py"
    path.write_text(source)
    code, report = scan(path, capsys, "ast-dataflow")
    assert code == 0
    assert report["status"] == "partial"
    assert any(d["affects_completeness"] for d in report["diagnostics"])


@pytest.mark.parametrize("engine", ["ast-dataflow", "ifds"])
@pytest.mark.parametrize("module", ["requests", "httpx"])
def test_http_url_arguments_are_ssrf_sinks(tmp_path, capsys, engine, module):
    path = tmp_path / "app.py"
    path.write_text(
        f"import {module}\nfrom flask import request\ndef handler():\n    {module}.get(request.args.get('url'))\n    {module}.get('https://example.com')\n"
    )
    code, report = scan(path, capsys, engine)
    assert code == 0
    assert {(f["location"]["line"], f["cwe"]) for f in report["findings"]} == {(4, "CWE-918")}


def test_ast_invalid_source_encoding_is_a_structured_partial_report(tmp_path, capsys):
    path = tmp_path / "bad.py"
    path.write_bytes(b"# coding: utf-8\n# \xff\n")
    code, report = scan(path, capsys, "ast-dataflow")
    assert code == 0
    assert report["status"] == "partial"
    assert any(d["code"] == "ast-source-read-error" for d in report["diagnostics"])


def test_ifds_assignment_alias_keeps_the_qualified_sink(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("import os\ndef handler():\n    sink = os.system\n    sink(input())\n")
    code, report = scan(path, capsys, "ifds")
    assert code == 0
    assert {(f["location"]["line"], f["cwe"]) for f in report["findings"]} == {(4, "CWE-78")}


@pytest.mark.parametrize("engine", ["ast-dataflow", "ifds"])
def test_unified_reports_use_consistent_absolute_paths(tmp_path, capsys, monkeypatch, engine):
    path = tmp_path / "app.py"
    path.write_text("def handler(): eval(input())\n")
    monkeypatch.chdir(tmp_path)
    code, report = scan("app.py", capsys, engine)
    assert code == 0
    assert {f["location"]["filename"] for f in report["findings"]} == {str(path.resolve())}
