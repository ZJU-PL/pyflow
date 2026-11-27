"""Tests for the pyflow ir CLI, focused on the GIR dump path."""

import argparse
import ast as python_ast
import json
import os
import tempfile
import unittest

import pytest

from pyflow.cli import ir as ir_cli
from pyflow.frontend.conversion.ast import ASTConverter
from pyflow.language.python import ast as pyflow_ast


def module_code(source: str, name: str = "test.<module>") -> pyflow_ast.Code:
    tree = python_ast.parse(source)
    suite = ASTConverter(verbose=False).convert_python_ast_to_pyflow(tree.body)
    return pyflow_ast.Code(
        name,
        pyflow_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[],
            paramnames=[],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[],
            type_params=None,
        ),
        suite,
    )


class TestIrParser(unittest.TestCase):
    def test_parser_exposes_dump_gir_flag(self):
        parser = argparse.ArgumentParser()
        ir_cli.add_ir_parser(parser.add_subparsers())
        args = parser.parse_args(["ir", "input.py", "--dump-gir", "main"])
        self.assertEqual(args.dump_gir, "main")


class TestDumpGir(unittest.TestCase):
    def test_dump_gir_writes_readable_file(self):
        module = module_code(
            "def main():\n"
            "    s = Stack()\n"
            "    s.push(1)\n"
            "    s.push(2)\n"
            "    return s.pop()\n"
        )
        code = module.ast.blocks[0].code
        with tempfile.TemporaryDirectory() as out_dir:
            ok = ir_cli.dump_gir(None, [code], "main", out_dir)
            self.assertTrue(ok)
            path = os.path.join(out_dir, "main_gir.text")
            with open(path) as f:
                content = f.read()
            self.assertIn("GIR for function: main", content)
            self.assertIn("def main():", content)
            self.assertIn("s.push(1)", content)
            self.assertIn("= s.pop()", content)

    def test_dump_gir_reports_missing_function(self):
        with tempfile.TemporaryDirectory() as out_dir:
            ok = ir_cli.dump_gir(None, [], "missing", out_dir)
            self.assertFalse(ok)
            self.assertEqual(os.listdir(out_dir), [])

    def test_dump_gir_writes_machine_readable_json(self):
        module = module_code("def main(value: int):\n    return value\n")
        code = module.ast.blocks[0].code
        with tempfile.TemporaryDirectory() as out_dir:
            ok = ir_cli.dump_gir(None, [code], "main", out_dir, format="json")
            self.assertTrue(ok)
            path = os.path.join(out_dir, "main_gir.json")
            with open(path) as f:
                rows = json.load(f)
            method = next(row for row in rows if row["operation"] == "method_decl")
            self.assertEqual(method["name"], "main")
            self.assertEqual(method["data_type"], None)


def parse_ir_args(path, *arguments):
    parser = argparse.ArgumentParser()
    ir_cli.add_ir_parser(parser.add_subparsers())
    return parser.parse_args(["ir", str(path), *map(str, arguments)])


@pytest.mark.parametrize("flag", ["--dump-ddg", "--dump-cdg"])
@pytest.mark.parametrize("conservative", [False, True])
def test_dependence_modes_are_explicit_in_json(tmp_path, flag, conservative):
    source = tmp_path / "precision.py"
    source.write_text(
        "def f(a,b):\n    if a:\n        x=a+b\n    else:\n        x=a-b\n    return x\n"
    )
    destination = tmp_path / "out"
    arguments = [flag, "f", "--dump-format", "json", "--dump-output", destination]
    if conservative:
        arguments.append("--conservative-dependencies")
    ir_cli.run_ir_dump(source, parse_ir_args(source, *arguments))
    suffix = flag.removeprefix("--dump-")
    payload = json.loads((destination / f"f_{suffix}.json").read_text())
    if suffix == "ddg":
        assert payload["assumptions"] == {
            "primitive_intrinsics": not conservative,
            "distinct_parameters": not conservative,
        }
        assert any(edge["label"] == "EXTERNAL" for edge in payload["edges"]) == conservative
    else:
        assert payload["include_exceptional"] is conservative
        assert any(edge["label"] == "error" for edge in payload["edges"]) == conservative


def test_unfiltered_ddg_requires_destination_on_a_terminal(tmp_path, monkeypatch, capsys):
    source = tmp_path / "sample.py"
    source.write_text("def f():\n    return 1\n")
    monkeypatch.setattr(ir_cli.sys.stdout, "isatty", lambda: True)
    with pytest.raises(SystemExit) as error:
        ir_cli.run_ir_dump(source, parse_ir_args(source, "--dump-ddg"))
    assert error.value.code == 2
    assert "--dump-ddg FUNCTION" in capsys.readouterr().err


def test_unfiltered_ddg_still_supports_redirected_json(tmp_path, monkeypatch, capsys):
    source = tmp_path / "sample.py"
    source.write_text("def f():\n    return 1\ndef g():\n    return 2\n")
    monkeypatch.setattr(ir_cli.sys.stdout, "isatty", lambda: False)
    ir_cli.run_ir_dump(source, parse_ir_args(source, "--dump-ddg", "--dump-format", "json"))
    result = json.loads(capsys.readouterr().out)
    assert "f_ddg.json" in result
    assert "g_ddg.json" in result


@pytest.mark.parametrize(
    ("flag", "key"),
    [("--dump-ast", "ast"), ("--dump-cfg", "cfg"), ("--dump-ssa", "ssa")],
)
def test_structured_json_dumps_are_machine_readable(tmp_path, flag, key):
    source = tmp_path / "sample.py"
    source.write_text(
        "def f(n):\n"
        "    total = 0\n"
        "    for i in range(n):\n"
        "        total += i\n"
        "    return total\n"
    )
    destination = tmp_path / "out"
    args = parse_ir_args(source, flag, "f", "--dump-format", "json", "--dump-output", destination)
    ir_cli.run_ir_dump(source, args)

    suffix = flag.removeprefix("--dump-")
    payload = json.loads((destination / f"f_{suffix}.json").read_text(encoding="utf-8"))
    assert payload["function"] == "f"
    graph = payload[key]
    if key == "ast":
        assert graph["type"] == "Suite"
    else:
        assert graph["entry"] == "B0"
        assert any(block["successors"] for block in graph["blocks"])


def test_cfg_json_defaults_to_stdout_without_text_header(tmp_path, monkeypatch, capsys):
    source = tmp_path / "sample.py"
    source.write_text("def f(n):\n    return n + 1\n")
    monkeypatch.chdir(tmp_path)
    ir_cli.run_ir_dump(source, parse_ir_args(source, "--dump-cfg", "f", "--dump-format", "json"))
    payload = json.loads(capsys.readouterr().out)
    assert payload["function"] == "f"
    assert payload["cfg"]["entry"] == "B0"


@pytest.mark.parametrize("format", ["text", "json", "dot"])
def test_ssa_dump_handles_deep_expression(tmp_path, format):
    source = tmp_path / "deep.py"
    source.write_text("def f(x):\n    return " + " + ".join(["x"] * 1200) + "\n")
    destination = tmp_path / "out"
    ir_cli.run_ir_dump(
        source,
        parse_ir_args(
            source, "--dump-ssa", "f", "--dump-format", format, "--dump-output", destination
        ),
    )
    output = (destination / f"f_ssa.{format}").read_text()
    assert "Return" in output
    assert "x.v0" in output
    assert "Error processing" not in output


@pytest.mark.parametrize("flag", ["--dump-cfg", "--dump-ssa", "--dump-ddg"])
@pytest.mark.parametrize("context_manager", [False, True])
def test_exception_functions_export_json(tmp_path, flag, context_manager):
    source = tmp_path / "sample.py"
    body = (
        "    with cm as value:\n        return value\n"
        if context_manager
        else "    try:\n        return cm()\n"
        "    except ValueError:\n        return 0\n"
        "    finally:\n        cleanup()\n"
    )
    source.write_text("def f(cm):\n" + body)
    destination = tmp_path / "out"
    ir_cli.run_ir_dump(
        source,
        parse_ir_args(source, flag, "f", "--dump-format", "json", "--dump-output", destination),
    )
    suffix = flag.removeprefix("--dump-")
    payload = json.loads((destination / f"f_{suffix}.json").read_text())
    assert payload


def test_cfg_dot_dump_writes_valid_graphviz(tmp_path, capsys):
    source = tmp_path / "sample.py"
    source.write_text("def add(a, b):\n    if a:\n        return a + b\n    return b\n")
    parser = argparse.ArgumentParser()
    ir_cli.add_ir_parser(parser.add_subparsers())
    destination = tmp_path / "out"
    args = parser.parse_args(
        [
            "ir",
            str(source),
            "--dump-cfg",
            "add",
            "--dump-format",
            "dot",
            "--dump-output",
            str(destination),
        ]
    )

    ir_cli.run_ir_dump(source, args)

    captured = capsys.readouterr()
    assert "DOT generation failed" not in captured.out
    content = (destination / "add_cfg.dot").read_text(encoding="utf-8")
    assert content.startswith("// CFG for function: add")
    assert "digraph" in content
    assert "->" in content


def test_cfg_default_output_does_not_write_into_working_directory(tmp_path, monkeypatch, capsys):
    source = tmp_path / "sample.py"
    source.write_text("def add(a, b):\n    return a + b\n")
    parser = argparse.ArgumentParser()
    ir_cli.add_ir_parser(parser.add_subparsers())
    args = parser.parse_args(["ir", str(source), "--dump-cfg", "add"])
    monkeypatch.chdir(tmp_path)
    ir_cli.run_ir_dump(source, args)
    captured = capsys.readouterr()
    assert "CFG for function" in captured.out
    assert "begin [ extraction ]" not in captured.out
    assert list(tmp_path.iterdir()) == [source]


def test_ir_function_resolution_matches_query_suffixes_and_rejects_ambiguity(capsys):
    left = type("Code", (), {"codeName": lambda self: "app.Left.run"})()
    right = type("Code", (), {"codeName": lambda self: "app.Right.run"})()
    assert ir_cli.find_function_in_live_code([left], "run") is left
    assert ir_cli.find_function_in_live_code([left, right], "run") is None
    error = capsys.readouterr().err
    assert "ambiguous" in error
    assert "app.Left.run" in error and "app.Right.run" in error


if __name__ == "__main__":
    unittest.main()


def test_ir_single_syntax_error_reports_parse_failure(tmp_path, capsys):
    source = tmp_path / "bad.py"
    source.write_text("def broken(:\n    pass\n", encoding="utf-8")
    parser = argparse.ArgumentParser()
    ir_cli.add_ir_parser(parser.add_subparsers())
    args = parser.parse_args(["ir", str(source), "--dump-ast", "f"])

    with pytest.raises(SystemExit) as excinfo:
        ir_cli.run_ir_dump(source, args)

    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Could not parse" in captured.err
    assert "invalid syntax" in captured.err


def test_ir_mixed_directory_still_dumps_good_files(tmp_path, capsys):
    (tmp_path / "good.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
    output = tmp_path / "out"
    parser = argparse.ArgumentParser()
    ir_cli.add_ir_parser(parser.add_subparsers())
    args = parser.parse_args(["ir", str(tmp_path), "--dump-ast", "f", "--dump-output", str(output)])

    ir_cli.run_ir_dump(tmp_path, args)

    captured = capsys.readouterr()
    assert any(output.glob("f_ast.*"))
    assert "Could not parse" in captured.out + captured.err


def test_list_functions_text_and_json(tmp_path, capsys):
    source = tmp_path / "mod.py"
    source.write_text("def alpha(): return 1\ndef beta(): return 2\n")
    parser = argparse.ArgumentParser()
    ir_cli.add_ir_parser(parser.add_subparsers())

    # Text format
    args = parser.parse_args(["ir", str(source), "--list-functions"])
    ir_cli.run_ir_dump(source, args)
    out = capsys.readouterr().out
    assert "Available functions" in out
    assert "alpha" in out and "beta" in out

    # JSON format
    args_json = parser.parse_args(["ir", str(source), "--list-functions", "--dump-format", "json"])
    ir_cli.run_ir_dump(source, args_json)
    data = json.loads(capsys.readouterr().out)
    assert "functions" in data
    assert "alpha" in data["functions"] and "beta" in data["functions"]


def test_dump_cfg_wildcard_dumps_all_functions(tmp_path):
    source = tmp_path / "mod.py"
    source.write_text("def f1(): return 1\ndef f2(): return 2\n")
    output = tmp_path / "out"
    parser = argparse.ArgumentParser()
    ir_cli.add_ir_parser(parser.add_subparsers())
    args = parser.parse_args(["ir", str(source), "--dump-cfg", "*", "--dump-output", str(output)])
    ir_cli.run_ir_dump(source, args)

    dumps = {p.name for p in output.glob("*_cfg.*")}
    assert any("f1" in name for name in dumps)
    assert any("f2" in name for name in dumps)


def test_dump_gir_wildcard_dumps_all_functions(tmp_path):
    source = tmp_path / "mod.py"
    source.write_text("def f1(): return 1\ndef f2(): return 2\n")
    output = tmp_path / "out"
    parser = argparse.ArgumentParser()
    ir_cli.add_ir_parser(parser.add_subparsers())
    args = parser.parse_args(["ir", str(source), "--dump-gir", "--dump-output", str(output)])
    ir_cli.run_ir_dump(source, args)

    dumps = {p.name for p in output.glob("*_gir.*")}
    assert any("f1" in name for name in dumps)
    assert any("f2" in name for name in dumps)


class TestWholeProgramDumpLabels(unittest.TestCase):
    def test_same_named_functions_get_distinct_artifacts(self):
        first = module_code("def f():\n    return 1\n")
        second = module_code("def g():\n    return 2\n")
        # Same artifact stem as repeated ``__getattr__`` definitions in
        # different modules; the later dump used to overwrite the earlier one.
        first.name = "pkg.mod.__getattr__"
        second.name = "pkg.mod.__getattr__"
        with tempfile.TemporaryDirectory() as out_dir:
            ok = ir_cli.dump_ir(None, [first, second], "*", out_dir, "CFG", "text")
            self.assertTrue(ok)
            self.assertEqual(len(os.listdir(out_dir)), 2)

    def test_labels_stay_unique_across_collisions(self):
        first = module_code("")
        second = module_code("")
        third = module_code("")
        for code in (first, second, third):
            code.name = "same"
        labels = [label for _code, label in ir_cli._iter_function_labels([first, second, third])]
        self.assertEqual(len(labels), 3)
        self.assertEqual(len(set(labels)), 3)
