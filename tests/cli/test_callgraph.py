from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pyflow.cli.callgraph as callgraph_cli


def parse_callgraph_args(*arguments):
    parser = argparse.ArgumentParser()
    callgraph_cli.add_callgraph_parser(parser.add_subparsers())
    return parser.parse_args(["callgraph", *map(str, arguments)])


def test_callgraph_rejects_constraint_only_flags_for_simple_algorithm(
    monkeypatch, tmp_path, capsys
):
    sample = tmp_path / "sample.py"
    sample.write_text("def f():\n    return 1\n", encoding="utf-8")

    monkeypatch.setattr(
        callgraph_cli,
        "analyze_file_ast",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("simple analyzer should not run")
        ),
    )

    args = SimpleNamespace(
        algorithm="simple",
        verbose=False,
        context_sensitive=True,
        context_depth=3,
        fixpoint_max_iterations=5,
        no_fixpoint_warning=True,
        allocation_site_sensitive_instances=True,
        as_graph_output=tmp_path / "graph.json",
        output=None,
    )

    exit_code = callgraph_cli.run_callgraph(Path(sample), args)

    assert exit_code == 1
    assert "only supported with --algorithm constraint" in capsys.readouterr().err


def test_callgraph_reports_ambiguous_detected_entries(tmp_path, capsys):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    for name in ("client", "server"):
        (package / f"{name}.py").write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[project]
name = "demo"

[project.scripts]
client = "demo.client:main"
server = "demo.server:main"
""",
        encoding="utf-8",
    )
    args = SimpleNamespace(entry=None, verbose=False, dry_run=True)

    exit_code = callgraph_cli.run_callgraph(tmp_path, args)

    error = capsys.readouterr().err
    assert exit_code == 1
    assert "Multiple entry points detected" in error
    assert "src/demo/client.py [project.scripts] (command: client)" in error
    assert "src/demo/server.py [project.scripts] (command: server)" in error
    assert "Use --entry to select one" in error


def test_constraint_project_entry_defaults_to_reachable_scopes(monkeypatch, tmp_path, capsys):
    sample = tmp_path / "main.py"
    sample.write_text("def main():\n    return 1\n", encoding="utf-8")
    captured = []

    def fake_analyze(_path, **kwargs):
        captured.append(kwargs)
        return "graph"

    monkeypatch.setattr(callgraph_cli, "analyze_file_constraint", fake_analyze)
    args = SimpleNamespace(
        algorithm="constraint",
        verbose=False,
        context_sensitive=False,
        context_depth=1,
        fixpoint_max_iterations=None,
        no_fixpoint_warning=False,
        allocation_site_sensitive_instances=False,
        all_scopes=False,
        skip_stdlib=True,
        as_graph_output=None,
        output=None,
    )

    assert callgraph_cli._analyze_file(sample, args, project_entry=True) == 0
    assert captured[-1]["analyze_reachable_only"] is True
    assert captured[-1]["seed_entry_file_scopes"] is True
    capsys.readouterr()

    args.all_scopes = True
    assert callgraph_cli._analyze_file(sample, args, project_entry=True) == 0
    assert captured[-1]["analyze_reachable_only"] is False
    assert captured[-1]["seed_entry_file_scopes"] is False


def test_native_pycg_mir_cli_resolves_callback_without_external_pycg(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text(
        "def chosen():\n    pass\n" "def use(callback):\n    callback()\n" "use(chosen)\n",
        encoding="utf-8",
    )

    original = callgraph_cli.run_isolated_callgraph

    def native_worker(request, **kwargs):
        assert request["algorithm"] == "pycg-mir"
        return original(request, **kwargs)

    monkeypatch.setattr(callgraph_cli, "run_isolated_callgraph", native_worker)
    args = parse_callgraph_args(sample, "--algorithm", "pycg-mir")

    assert callgraph_cli.run_callgraph(sample, args) == 0
    output = capsys.readouterr().out
    assert "sample.use -> sample.chosen" in output


def test_native_pycg_mir_cli_passes_project_root(tmp_path, monkeypatch, capsys):
    entry = tmp_path / "src" / "app.py"
    entry.parent.mkdir()
    entry.write_text("def run(): pass\nrun()\n", encoding="utf-8")
    captured = {}

    def analyze(request, *, timeout):
        captured.update(
            filepath=request["filepath"],
            verbose=request["verbose"],
            project_root=request["project_root"],
        )
        assert timeout == 35
        return "native graph"

    monkeypatch.setattr(callgraph_cli, "run_isolated_callgraph", analyze)
    args = parse_callgraph_args(tmp_path, "--entry", "src/app.py", "--algorithm", "pycg-mir")
    assert callgraph_cli.run_callgraph(tmp_path, args) == 0
    assert captured == {
        "filepath": str(entry),
        "verbose": False,
        "project_root": str(tmp_path),
    }
    assert "native graph" in capsys.readouterr().out


def test_native_pycg_mir_cli_reports_invalid_source(tmp_path, capsys):
    sample = tmp_path / "broken.py"
    sample.write_text("def broken(: pass\n", encoding="utf-8")
    output = tmp_path / "graph.txt"
    args = parse_callgraph_args(sample, "--algorithm", "pycg-mir", "-o", output)

    assert callgraph_cli.run_callgraph(sample, args) == 1
    assert "Error:" in capsys.readouterr().err
    assert not output.exists()


def test_native_pycg_mir_cli_rejects_context_sensitive_flag(tmp_path, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text("pass\n", encoding="utf-8")
    args = parse_callgraph_args(sample, "--algorithm", "pycg-mir", "--context-sensitive")

    assert callgraph_cli.run_callgraph(sample, args) == 1
    assert "--context-sensitive" in capsys.readouterr().err


def test_native_pycg_mir_handles_unmodeled_stdlib_with_partial_diagnostic(tmp_path, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text("import math\ndef f(): return math.sqrt(4)\nf()\n")
    args = parse_callgraph_args(sample, "--algorithm", "pycg-mir", "--format", "json")
    assert callgraph_cli.run_callgraph(sample, args) == 3
    captured = capsys.readouterr()
    import json

    assert "sample.f" in json.loads(captured.out)["sample"]
    assert "MIR call graph is partial" in captured.err
    args = parse_callgraph_args(sample, "--algorithm", "pycg-mir", "--mir-import-policy", "strict")
    assert callgraph_cli.run_callgraph(sample, args) == 1


def test_mir_import_policy_rejects_other_algorithms(tmp_path, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text("pass\n")
    args = parse_callgraph_args(
        sample, "--algorithm", "constraint", "--mir-import-policy", "strict"
    )
    assert callgraph_cli.run_callgraph(sample, args) == 1
    assert "only supported with --algorithm pycg-mir" in capsys.readouterr().err


def test_constraint_truncation_metadata_in_file_and_recursive_json(tmp_path, capsys):
    import json

    source = tmp_path / "main.py"
    source.write_text("def f(): pass\nf()\n")
    for recursive in (False, True):
        for schema in ("legacy", "unified"):
            input_path = tmp_path if recursive else source
            flags = ["--recursive"] if recursive else []
            args = parse_callgraph_args(
                input_path,
                *flags,
                "--format",
                "json",
                "--json-schema",
                schema,
                "--fixpoint-max-iterations",
                "1",
                "--no-fixpoint-warning",
            )
            assert callgraph_cli.run_callgraph(input_path, args) == 3
            output = json.loads(capsys.readouterr().out)
            if schema == "unified":
                assert output["status"] == "partial"
                assert output["converged"] is False
                assert output["analysis_complete"] is False
                assert output["termination_reason"] == "iteration_limit"
                assert any("budget exhausted" in item for item in output["diagnostics"])
            else:
                assert "main.f" in output
                assert all(isinstance(callees, list) for callees in output.values())


def test_recursive_scan_skips_bad_first_source_and_reports_it(tmp_path, capsys):
    import json

    (tmp_path / "a_bad.py").write_text('print "hello"\n')
    (tmp_path / "b_good.py").write_text("def f(): pass\nf()\n")
    for schema in ("legacy", "unified"):
        args = parse_callgraph_args(
            tmp_path,
            "--recursive",
            "--format",
            "json",
            "--json-schema",
            schema,
        )
        assert callgraph_cli.run_callgraph(tmp_path, args) == 3
        captured = capsys.readouterr()
        assert "a_bad.py" in captured.err
        document = json.loads(captured.out)
        graph = document["graph"] if schema == "unified" else document
        assert "b_good.f" in graph["b_good"]
        if schema == "unified":
            assert document["status"] == "partial"
            assert document["converged"] is True
            assert any("a_bad.py" in item for item in document["diagnostics"])


def test_recursive_scan_with_no_parseable_sources_fails_cleanly(tmp_path, capsys):
    (tmp_path / "bad.py").write_text('print "hello"\n')
    args = parse_callgraph_args(tmp_path, "--recursive", "--format", "json")
    assert callgraph_cli.run_callgraph(tmp_path, args) == 2
    captured = capsys.readouterr()
    assert captured.out.strip() == "{}"
    assert "no parseable" in captured.err
    assert "Traceback" not in captured.err


def test_recursive_scan_preserves_explicit_invalid_entry_error(tmp_path, capsys):
    (tmp_path / "bad.py").write_text('print "hello"\n')
    (tmp_path / "good.py").write_text("def f(): pass\n")
    args = parse_callgraph_args(tmp_path, "--recursive", "--entry", "bad.py")
    assert callgraph_cli.run_callgraph(tmp_path, args) == 2
    captured = capsys.readouterr()
    assert "explicit entry" in captured.err
    assert captured.out == ""


def test_constraint_complete_json_reports_convergence(tmp_path, capsys):
    import json

    source = tmp_path / "sample.py"
    source.write_text("def f(): pass\nf()\n")
    args = parse_callgraph_args(source, "--format", "json", "--json-schema", "unified")
    assert callgraph_cli.run_callgraph(source, args) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == "complete"
    assert document["converged"] is True
    assert document["diagnostics"] == []


def test_constraint_json_retains_direct_recursion(tmp_path, capsys):
    import json

    source = tmp_path / "sample.py"
    source.write_text(
        "def fact(n):\n" "    if n <= 1:\n" "        return 1\n" "    return n * fact(n - 1)\n"
    )
    args = parse_callgraph_args(source, "--format", "json", "--json-schema", "unified")
    assert callgraph_cli.run_callgraph(source, args) == 0
    graph = json.loads(capsys.readouterr().out)["graph"]
    assert "sample.fact" in graph["sample.fact"]


def test_recursive_encoding_errors_and_declared_latin1(tmp_path, capsys):
    import json

    (tmp_path / "a_bad.py").write_bytes(b'label = "caf\xe9"\n')
    (tmp_path / "b_latin.py").write_bytes(
        b'# coding: latin-1\nlabel = "caf\xe9"\ndef f(): pass\nf()\n'
    )
    (tmp_path / "c_good.py").write_text("def g(): pass\ng()\n")
    args = parse_callgraph_args(
        tmp_path, "--recursive", "--format", "json", "--json-schema", "unified"
    )
    assert callgraph_cli.run_callgraph(tmp_path, args) == 3
    document = json.loads(capsys.readouterr().out)
    assert document["converged"] is True
    assert document["analysis_complete"] is False
    assert "b_latin.f" in document["graph"]["b_latin"]
    assert "c_good.g" in document["graph"]["c_good"]
    assert any("a_bad.py" in item for item in document["diagnostics"])


def test_empty_recursive_json_reports_reason_and_writes_output(tmp_path, capsys):
    import json

    output = tmp_path / "result.json"
    for empty in (True, False):
        if not empty:
            (tmp_path / "bad.py").write_text('print "hello"\n')
        args = parse_callgraph_args(
            tmp_path, "--recursive", "--format", "json", "--json-schema", "unified", "-o", output
        )
        assert callgraph_cli.run_callgraph(tmp_path, args) == 2
        assert capsys.readouterr().out == ""
        document = json.loads(output.read_text())
        assert document["graph"] == {}
        assert document["analysis_complete"] is False
        assert document["converged"] is False
        assert document["status"] == "partial"
        assert document["diagnostics"]
        assert document["termination_reason"] == ("no_sources" if empty else "no_parseable_sources")


def test_unresolved_calls_do_not_signal_constraint_truncation(tmp_path, capsys):
    import json

    source = tmp_path / "sample.py"
    source.write_text("def run(): input()()\nrun()\n")
    for recursive in (False, True):
        target = tmp_path if recursive else source
        for schema in ("legacy", "unified"):
            args = parse_callgraph_args(
                target,
                *(["--recursive"] if recursive else []),
                "--format",
                "json",
                "--json-schema",
                schema,
            )
            assert callgraph_cli.run_callgraph(target, args) == 0
            document = json.loads(capsys.readouterr().out)
            if schema == "unified":
                assert document["status"] == "partial"
                assert document["analysis_complete"] is True
                assert document["termination_reason"] == "converged"
                assert document["unresolved_calls"]


def test_constraint_cli_time_budget_reaches_solver(tmp_path, capsys):
    import json

    source = tmp_path / "sample.py"
    source.write_text("def f(): pass\nf()\n")
    for recursive in (False, True):
        target = tmp_path if recursive else source
        args = parse_callgraph_args(
            target,
            *(["--recursive"] if recursive else []),
            "--format",
            "json",
            "--json-schema",
            "unified",
            "--fixpoint-max-seconds",
            "0.000000001",
            "--no-fixpoint-warning",
        )
        assert callgraph_cli.run_callgraph(target, args) == 3
        document = json.loads(capsys.readouterr().out)
        assert document["analysis_complete"] is False
        assert document["termination_reason"] == "time_limit"


def test_constraint_time_limit_zero_disables_deadline(tmp_path, capsys):
    import json

    source = tmp_path / "sample.py"
    source.write_text("def f(): pass\nf()\n")
    args = parse_callgraph_args(
        source, "--format", "json", "--json-schema", "unified", "--fixpoint-max-seconds", "0"
    )
    assert callgraph_cli.run_callgraph(source, args) == 0
    assert json.loads(capsys.readouterr().out)["termination_reason"] == "converged"


def test_recursive_monorepo_json_connects_calls_to_function_bodies(tmp_path, capsys):
    import json

    for layout in ("lib", "libs/core", "packages/core"):
        root = tmp_path / layout.replace("/", "_")
        package = root / layout / "mypkg"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("")
        (package / "mod.py").write_text("def f(): pass\ndef run(): f()\n")
        app = root / "apps" / "app"
        app.mkdir(parents=True)
        (app / "main.py").write_text("from mypkg.mod import run\ndef entry(): run()\n")
        args = parse_callgraph_args(
            root, "--recursive", "--format", "json", "--json-schema", "unified"
        )
        assert callgraph_cli.run_callgraph(root, args) == 0
        document = json.loads(capsys.readouterr().out)
        assert document["converged"] is True
        assert document["analysis_complete"] is True
        assert document["unresolved_calls"] == []
        assert document["graph"]["apps.app.main.entry"] == ["mypkg.mod.run"]
        assert document["graph"]["mypkg.mod.run"] == ["mypkg.mod.f"]
        assert not any(node.endswith(".mypkg.mod.run") for node in document["graph"])
