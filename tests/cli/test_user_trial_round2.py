"""End-to-end regressions for the second user trial."""

import json
import subprocess
import sys

import pytest


def cli(*args):
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "from pyflow.cli.main import entrypoint; raise SystemExit(entrypoint())",
            *map(str, args),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )


def successful(*args):
    result = cli(*args)
    assert result.returncode == 0, result.stderr
    return result


@pytest.mark.parametrize("literal", ['"Doc."', "42", "...", '"not a docstring"'])
def test_ddg_constant_expression_statements(tmp_path, literal):
    path = tmp_path / "doc.py"
    path.write_text(f"def f():\n    {literal}\n    x = 1\n    {literal}\n    return x\n")
    result = successful("ir", path, "--dump-ddg", "f")
    assert result.stdout.strip()


def test_directory_mir_preserves_package_identity(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "a.py").write_text("def fa(): return 1\n")
    (pkg / "runner.py").write_text("from .a import fa\ndef run(): return fa()\n")
    result = successful("ir", pkg, "--dump-mir", "--mir-view", "source", "--dump-format", "json")
    report = json.loads(result.stdout)
    assert "pkg.runner" in result.stdout
    assert report


@pytest.mark.parametrize(
    "statement",
    [
        "async def f():\n    return 1\n",
        "def f(x):\n    match x:\n        case 1: return 2\n",
        "def f(x):\n    x[1:2] = [3]\n",
        pytest.param(
            "type X = int\n",
            marks=pytest.mark.skipif(sys.version_info < (3, 12), reason="Python 3.12 syntax"),
        ),
    ],
)
def test_opaque_mir_retains_unsupported_statements(tmp_path, statement):
    path = tmp_path / "modern.py"
    path.write_text(statement)
    report = json.loads(successful("ir", path, "--dump-mir", "--dump-format", "json").stdout)
    assert report["status"] == "partial"
    assert any(d["code"] == "mir-opaque-statement" for d in report["diagnostics"])
    strict = cli("ir", path, "--dump-mir", "--mir-import-policy", "strict")
    assert strict.returncode == 1
    assert "Traceback" not in strict.stderr


@pytest.mark.parametrize("mode", ["basic", "full", "advanced"])
def test_alias_query_runs_heap_and_resolves_source_variables(tmp_path, mode):
    path = tmp_path / "aliases.py"
    path.write_text("def f():\n    a = []\n    b = a\n    return b\n")
    report = json.loads(successful("query", path, "--mode", mode, "--get-aliases", "a").stdout)
    assert "b" in report["aliases"]
    assert report["is_aliased"]


@pytest.mark.parametrize("invoke", ["", "\nmain()\n"])
def test_alias_query_resolves_main_body(tmp_path, invoke):
    """``main`` is not an entry point, so its body is culled before the heap pass."""
    path = tmp_path / "main_aliases.py"
    path.write_text(
        "class Box:\n"
        "    def __init__(self):\n"
        "        self.value = []\n"
        "\n"
        "def main():\n"
        "    a = Box()\n"
        "    b = a\n"
        "    c = a.value\n"
        "    d = c\n"
        "    return d\n" + invoke
    )
    a_report = json.loads(successful("query", path, "--get-aliases", "a").stdout)
    assert {"a", "b"} <= set(a_report["aliases"])
    c_report = json.loads(successful("query", path, "--get-aliases", "c").stdout)
    assert {"c", "d"} <= set(c_report["aliases"])


def test_alias_query_ignores_interpreter_helper_parameters(tmp_path):
    """Lowered ``obj.attr = value`` helpers must not leak ``name``/``value``."""
    path = tmp_path / "attribute_aliases.py"
    path.write_text(
        "class C:\n"
        "    attr = []\n"
        "\n"
        "def f(param):\n"
        "    obj = C()\n"
        "    obj.attr = param\n"
        "    return obj\n"
    )
    report = json.loads(successful("query", path, "--get-aliases", "obj").stdout)
    assert "obj" in report["aliases"]
    assert not {"name", "value"} & set(report["aliases"])


@pytest.mark.parametrize(
    "source",
    [
        "def clear_session_cookies():\n    return str(1)\n",
        "class QueryNotify:\n    def __str__(self): return str(1)\n",
        "def f(db):\n    db.execute('select 1')\n",
    ],
)
def test_a110_requires_fastapi_and_real_database_calls(tmp_path, source):
    path = tmp_path / "sample.py"
    path.write_text(source)
    report = json.loads(successful("security", path, "--format", "json").stdout)
    assert not any(item["test_id"] == "A110" for item in report["results"])


@pytest.mark.parametrize("commit,expected", [(False, True), (True, False)])
def test_a110_checks_the_actual_calls(tmp_path, commit, expected):
    path = tmp_path / "sample.py"
    path.write_text(
        "from fastapi import Depends\ndef save(db):\n    db.add(1)\n"
        + ("    db.commit()\n" if commit else "")
    )
    report = json.loads(successful("security", path, "--format", "json").stdout)
    assert any(item["test_id"] == "A110" for item in report["results"]) is expected


@pytest.mark.parametrize(
    "source",
    [
        "def f():\n    print(input())\n",
        "def f(d):\n    d.get(input())\n",
        "import tomli\ndef f(fh):\n    tomli.load(fh)\n",
    ],
)
def test_ast_dataflow_does_not_guess_unrelated_library_sinks(tmp_path, source):
    path = tmp_path / "sample.py"
    path.write_text(source)
    report = json.loads(
        successful("security", path, "--engine", "ast-dataflow", "--format", "json").stdout
    )
    assert report["findings"] == []


def test_explicit_sink_model_and_import_alias_still_detect_taint(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text("from pickle import loads as decode\ndef f():\n    decode(input())\n")
    report = json.loads(
        successful("security", path, "--engine", "ast-dataflow", "--format", "json").stdout
    )
    assert any(finding["cwe"] == "CWE-502" for finding in report["findings"])


def test_query_names_round_trip_across_listing_graph_and_cfg(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "a.py").write_text("def fa(): return 1\n")
    (pkg / "__main__.py").write_text("from .a import fa\ndef main(): return fa()\nmain()\n")
    names = json.loads(successful("query", pkg, "--list-functions").stdout)
    graph = json.loads(successful("query", pkg, "--get-callgraph").stdout)
    for name in names:
        assert name in graph
        successful("query", pkg, "--get-cfg", name)
        assert json.loads(successful("query", pkg, "--get-callees", name).stdout) == graph[name]
    invalid = cli("query", pkg, "--get-callees", "typo")
    assert invalid.returncode == 1
    assert "not found" in invalid.stderr and "Traceback" not in invalid.stderr


def test_all_scopes_loads_unimported_module(tmp_path):
    (tmp_path / "__main__.py").write_text("def main(): pass\nmain()\n")
    (tmp_path / "unused.py").write_text("def hidden(): pass\n")
    default = successful("callgraph", tmp_path, "--format", "json")
    assert "auto-detected entry" in default.stderr
    graph = json.loads(successful("callgraph", tmp_path, "--all-scopes", "--format", "json").stdout)
    assert "unused.hidden" in graph


def test_mir_callgraph_has_only_real_callback_edge(tmp_path):
    path = tmp_path / "higher.py"
    path.write_text("def leaf(): pass\ndef apply(f): f()\napply(leaf)\n")
    graph = json.loads(
        successful("callgraph", path, "--algorithm", "pycg-mir", "--format", "json").stdout
    )
    assert graph["higher.apply"] == ["higher.leaf"]
    assert "builtins.print" not in graph


def test_ssa_match_uses_fresh_source_symbols(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text(
        "def f(x):\n    match x:\n        case 1: y = 2\n        case _: y = 3\n    return y\n"
    )
    assert successful("ir", path, "--dump-ssa", "f").stdout.strip()


def test_ssa_try_exports_successfully(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text("def f(x):\n    try: return x()\n    except Exception: return None\n")
    result = cli("ir", path, "--dump-ssa", "f")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip()
    assert "Traceback" not in result.stderr


def test_ddg_merge_of_constant_branches(tmp_path):
    path = tmp_path / "branches.py"
    path.write_text(
        "def f(x):\n    y = 0\n    match x:\n        case 1: y = 1\n        case 2: y = 2\n    return y\n"
    )
    assert successful("ir", path, "--dump-ddg", "f").stdout.strip()
