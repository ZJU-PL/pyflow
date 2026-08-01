"""Tests for the pyflow ir CLI, focused on the GIR dump path."""

import argparse
import ast as python_ast
import json
import os
import tempfile
import unittest

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
            ok = ir_cli.dump_gir(
                None, [code], "main", out_dir, format="json"
            )
            self.assertTrue(ok)
            path = os.path.join(out_dir, "main_gir.json")
            with open(path) as f:
                rows = json.load(f)
            method = next(row for row in rows if row["operation"] == "method_decl")
            self.assertEqual(method["name"], "main")
            self.assertEqual(method["data_type"], None)


if __name__ == "__main__":
    unittest.main()
