"""Tests for the pyflow ir CLI, focused on the GIR dump path."""

import argparse
import ast as python_ast
import json
import os
import tempfile
import unittest
from pathlib import Path

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

    def test_parser_exposes_whole_program_and_scoped_mir(self):
        parser = argparse.ArgumentParser()
        ir_cli.add_ir_parser(parser.add_subparsers())
        args = parser.parse_args(["ir", "input.py", "--dump-mir"])
        self.assertEqual(args.dump_mir, "*")
        args = parser.parse_args(["ir", "input.py", "--dump-mir", "module.main"])
        self.assertEqual(args.dump_mir, "module.main")


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


def parse_mir_args(path, *arguments):
    parser = argparse.ArgumentParser()
    ir_cli.add_ir_parser(parser.add_subparsers())
    return parser.parse_args(["ir", str(path), "--dump-mir", *map(str, arguments)])


def test_dump_mir_json_does_not_execute_source_or_legacy_frontend(tmp_path, monkeypatch, capsys):
    source = tmp_path / "sample.py"
    marker = tmp_path / "executed.txt"
    source.write_text(
        f"open({str(marker)!r}, 'w').write('executed')\n"
        "def worker(callback):\n    return callback()\n",
        encoding="utf-8",
    )

    def legacy_frontend_must_not_run(*_args, **_kwargs):
        raise AssertionError("MIR dumps must lower source without legacy extraction")

    monkeypatch.setattr(ir_cli, "build_interface_from_paths", legacy_frontend_must_not_run)
    destination = tmp_path / "out"
    args = parse_mir_args(source, "--dump-format", "json", "--dump-output", destination)
    ir_cli.run_ir_dump(source, args)

    data = json.loads((destination / "sample_mir.json").read_text(encoding="utf-8"))
    assert data["entry"] in data["cfgs"]
    assert "sample.worker" in data["cfgs"]
    assert not marker.exists()
    assert "IR dumping complete!" in capsys.readouterr().out


def test_dump_mir_can_select_nested_scope(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        "def outer():\n" "    def inner():\n        return 1\n" "    return inner\n",
        encoding="utf-8",
    )
    destination = tmp_path / "out"
    args = parse_mir_args(source, "inner", "--dump-format", "text", "--dump-output", destination)
    ir_cli.run_ir_dump(source, args)

    dumps = list(destination.glob("*_mir.text"))
    assert len(dumps) == 1
    content = dumps[0].read_text(encoding="utf-8")
    assert "sample.outer.inner" in content


def test_dump_mir_reports_ambiguous_scope_without_writing_artifacts(tmp_path, capsys):
    source = tmp_path / "sample.py"
    source.write_text(
        "class A:\n    def run(self):\n        pass\n"
        "class B:\n    def run(self):\n        pass\n",
        encoding="utf-8",
    )
    destination = tmp_path / "out"
    args = parse_mir_args(source, "run", "--dump-output", destination)

    with pytest.raises(SystemExit) as error:
        ir_cli.run_ir_dump(source, args)
    assert error.value.code == 1
    assert "ambiguous" in capsys.readouterr().err
    assert not destination.exists()


def test_dump_mir_recursive_directories_preserve_source_paths(tmp_path):
    for folder in ("one", "two"):
        path = tmp_path / folder / "sample.py"
        path.parent.mkdir()
        path.write_text("def worker():\n    return 1\n", encoding="utf-8")
    destination = tmp_path / "out"
    args = parse_mir_args(
        tmp_path, "--recursive", "--dump-format", "json", "--dump-output", destination
    )
    ir_cli.run_ir_dump(tmp_path, args)

    assert sorted(path.relative_to(destination) for path in destination.rglob("*.json")) == [
        Path("one/sample_mir.json"),
        Path("two/sample_mir.json"),
    ]


def test_ir_function_resolution_matches_query_suffixes_and_rejects_ambiguity(capsys):
    left = type("Code", (), {"codeName": lambda self: "app.Left.run"})()
    right = type("Code", (), {"codeName": lambda self: "app.Right.run"})()
    assert ir_cli.find_function_in_live_code([left], "run") is left
    assert ir_cli.find_function_in_live_code([left, right], "run") is None
    error = capsys.readouterr().err
    assert "ambiguous" in error
    assert "app.Left.run" in error and "app.Right.run" in error


def test_trivial_mir_dump_stays_small(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("def add(a, b):\n    return a + b\n")
    output = tmp_path / "out"
    args = parse_mir_args(source, "add", "--dump-output", output)
    ir_cli.run_ir_dump(source, args)
    content = next(output.glob("*_mir.text")).read_text()
    assert "sample.add" in content
    assert len(content.splitlines()) < 100


def test_unscoped_mir_text_hides_runtime_and_full_view_is_available(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("def add(a, b):\n    return a + b\n")
    output = tmp_path / "out"
    args = parse_mir_args(source, "--dump-output", output)
    ir_cli.run_ir_dump(source, args)
    path = output / "sample_mir.text"
    compact = path.read_text()
    assert "MIR source view" in compact
    assert "cfg builtins." not in compact
    assert len(compact.splitlines()) < 1000
    args.mir_view = "full"
    ir_cli.run_ir_dump(source, args)
    full = path.read_text()
    assert "cfg builtins." in full
    assert len(full.splitlines()) > 10 * len(compact.splitlines())


if __name__ == "__main__":
    unittest.main()
