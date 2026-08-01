"""Unit tests for the Lian-compatible GIR emitter and pipeline."""

import ast as python_ast
import unittest

from pyflow.frontend.conversion.ast import ASTConverter
from pyflow.ir.gir.emitter import GirCompatibilityWarning, GirEmitter
from pyflow.ir.gir.flatten import GirFlattener
from pyflow.ir.gir.postprocess import (
    add_main_func,
    add_unit_gir,
    adjust_variable_decls,
    unify_python_self,
)
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


def emit(source: str):
    """Run the full pipeline and return the unflattened tree and flat rows."""
    code = module_code(source)
    tree = GirEmitter().emit_unit(code)
    unify_python_self(tree)
    adjust_variable_decls(tree)
    flattener = GirFlattener()
    _, rows = flattener.flatten(tree)
    rows = add_main_func(rows)
    add_unit_gir(rows, "unit_test")
    return tree, rows


def emit_tree(source: str):
    """Emit the unprocessed GIR tree for exact upstream-schema assertions."""
    return GirEmitter().emit_unit(module_code(source))


def operations(rows):
    return [row["operation"] for row in rows]


def top_level(rows):
    return [row for row in rows if row["parent_stmt_id"] == 0]


class TestGirEmitter(unittest.TestCase):
    def test_assign_constant(self):
        tree, _ = emit("x = 42")
        row = next(r for r in tree if "assign_stmt" in r)["assign_stmt"]
        self.assertEqual(row["target"], "x")
        self.assertEqual(row["operand"], "42")

    def test_binary_operator_form(self):
        tree, _ = emit("x = a + b")
        row = tree[-1]
        self.assertEqual(row["assign_stmt"]["target"], "x")
        self.assertEqual(row["assign_stmt"]["operator"], "+")
        self.assertEqual(row["assign_stmt"]["operand"], "a")
        self.assertEqual(row["assign_stmt"]["operand2"], "b")

    def test_augassign_unwraps_tagged_suite(self):
        tree, _ = emit("x += 1")
        row = tree[-1]
        self.assertEqual(row["assign_stmt"]["target"], "x")
        self.assertEqual(row["assign_stmt"]["operator"], "+")
        self.assertEqual(row["assign_stmt"]["operand"], "x")

    def test_attr_and_subscript(self):
        tree, _ = emit("v = obj.attr\nobj.attr = v\ns[i] = v\ndel s[i]")
        ops = {next(iter(r.keys())) for r in tree}
        self.assertIn("field_read", ops)
        self.assertIn("field_write", ops)
        self.assertIn("array_write", ops)

    def test_collection_literals(self):
        tree, _ = emit("l = [1, 2]\nt = (1, 2)\nd = {\"a\": x}")
        ops = {next(iter(r.keys())) for r in tree}
        self.assertIn("new_array", ops)
        self.assertIn("new_record", ops)
        self.assertIn("record_write", ops)

    def test_if_while_for(self):
        tree, _ = emit(
            "if a:\n    x = 1\nwhile a:\n    a = 0\nfor i in items:\n    x = i"
        )
        ops = {next(iter(r.keys())) for r in tree}
        self.assertIn("if_stmt", ops)
        self.assertIn("while_stmt", ops)
        self.assertIn("forin_stmt", ops)

    def test_lian_control_flow_row_shapes(self):
        tree, _ = emit(
            "while flag:\n"
            "    if stop:\n"
            "        break\n"
            "    continue\n"
            "assert ready\n"
            "raise ValueError\n"
            "def values():\n"
            "    yield item\n"
        )
        while_body = tree[0]["while_stmt"]["body"]
        break_row = while_body[0]["if_stmt"]["then_body"][0]["break_stmt"]
        continue_row = while_body[1]["continue_stmt"]
        self.assertEqual(break_row["name"], "")
        self.assertEqual(continue_row["name"], "")
        self.assertIn("start_row", break_row)
        self.assertIn("start_row", continue_row)
        self.assertEqual(tree[1]["assert_stmt"]["condition"], "ready")
        self.assertEqual(tree[2]["throw_stmt"]["name"], "ValueError")
        yield_row = tree[3]["method_decl"]["body"][0]["yield_stmt"]
        self.assertEqual(yield_row["target"], "item")

    def test_lian_record_slice_and_zero_based_locations(self):
        tree = emit_tree(
            'd = {"key": value, **other}\n'
            "item = values[1:4:2]\n"
            "values[1:4] = replacement\n"
        )
        record = next(row["record_write"] for row in tree if "record_write" in row)
        self.assertEqual(
            set(record) - {"start_row", "start_col", "end_row", "end_col"},
            {"receiver_record", "key", "value"},
        )
        self.assertEqual(record["key"], "'key'")
        self.assertEqual(record["start_row"], 0)
        self.assertTrue(any("record_extend" in row for row in tree))
        read = next(row["slice_read"] for row in tree if "slice_read" in row)
        write = next(row["slice_write"] for row in tree if "slice_write" in row)
        self.assertEqual(read["end"], "4")
        self.assertEqual(write["end"], "4")
        self.assertNotIn("stop", read)
        self.assertNotIn("stop", write)

    def test_lian_source_syntax_rows_survive_frontend_lowering(self):
        tree = emit_tree(
            "from package.module import item as alias\n"
            "with manager() as resource:\n"
            "    pass\n"
            "match value:\n"
            "    case 1:\n"
            "        result = 'one'\n"
            "    case _:\n"
            "        result = 'other'\n"
        )
        imported = tree[0]["from_import_stmt"]
        self.assertEqual(
            (imported["source"], imported["name"], imported["alias"]),
            ("package.module", "item", "alias"),
        )
        with_row = tree[1]["with_stmt"]
        self.assertEqual(with_row["attrs"], [])
        self.assertEqual(with_row["init_body"][0]["call_stmt"]["name"], "manager")
        self.assertIn("pass_stmt", with_row["update_body"][0])
        switch = tree[2]["switch_stmt"]
        self.assertEqual(switch["condition"], "value")
        self.assertEqual(switch["body"][0]["case_stmt"]["condition"], "1")
        self.assertIn("default_stmt", switch["body"][1])

    def test_lian_packed_calls_and_starred_collections(self):
        tree = emit_tree(
            "result = func(a, *items, key=value, **options)\n"
            "values = [a, *items, b]\n"
        )
        call = next(row["call_stmt"] for row in tree if "call_stmt" in row)
        self.assertEqual(call["positional_args"], [])
        self.assertTrue(call["packed_positional_args"].startswith("%vv"))
        self.assertTrue(call["packed_named_args"].startswith("%vv"))
        self.assertIsNone(call["named_args"])
        self.assertTrue(any("array_extend" in row for row in tree))
        self.assertTrue(any("array_append" in row for row in tree))
        self.assertTrue(any("record_extend" in row for row in tree))

    def test_lian_comprehension_and_lambda_rows(self):
        tree = emit_tree(
            "values = [transform(x) for x in items if allowed(x)]\n"
            "callback = lambda value: value + 1\n"
        )
        self.assertIn("new_array", tree[0])
        loop = next(row["forin_stmt"] for row in tree if "forin_stmt" in row)
        self.assertEqual(loop["attr"], [])
        self.assertEqual(loop["name"], "x")
        self.assertTrue(any("if_stmt" in row for row in loop["body"]))
        method = next(row["method_decl"] for row in tree if "method_decl" in row)
        self.assertTrue(method["name"].startswith("%mm"))
        self.assertIn("return_stmt", method["body"][-1])

    def test_lian_literal_folding_boolean_operators_and_set_rows(self):
        tree = emit_tree(
            "folded = 1 + 2\n"
            "combined = left and right\n"
            "negated = not combined\n"
            "items = {left, right}\n"
        )
        folded = next(
            row["assign_stmt"]
            for row in tree
            if "assign_stmt" in row and row["assign_stmt"]["target"] == "folded"
        )
        self.assertEqual(folded["operand"], "3")
        operators = [
            row["assign_stmt"].get("operator")
            for row in tree
            if "assign_stmt" in row
        ]
        self.assertIn("and", operators)
        self.assertIn("not", operators)
        set_allocations = [
            row["new_array"] for row in tree if "new_array" in row
        ]
        self.assertEqual(set_allocations[-2]["attrs"], ["set"])
        self.assertNotIn("attrs", set_allocations[-1])

    def test_lian_function_metadata_and_default_preamble(self):
        tree = emit_tree(
            "@decorator\n"
            "async def function(value: int = make()) -> str:\n"
            "    pass\n"
        )
        method = next(row["method_decl"] for row in tree if "method_decl" in row)
        self.assertEqual(method["attrs"], ["decorator", "async"])
        self.assertEqual(method["data_type"], "str")
        parameter = method["parameters"][0]["parameter_decl"]
        self.assertEqual(parameter["data_type"], "int")
        self.assertTrue(parameter["default_value"].startswith("%dvv"))
        method_index = next(
            index for index, row in enumerate(tree) if "method_decl" in row
        )
        self.assertTrue(any("call_stmt" in row for row in tree[:method_index]))
        self.assertIn("pass_stmt", method["body"][0])

    @unittest.skipUnless(
        hasattr(python_ast, "TypeVar"), "PEP 695 parsing requires Python 3.12+"
    )
    def test_lian_generic_class_and_annotated_fields(self):
        tree = emit_tree("class Box[T](Base[T]):\n    value: T = initial\n")
        class_decl = tree[0]["class_decl"]
        self.assertEqual(class_decl["type_parameters"], "T")
        self.assertEqual(class_decl["supers"], ["Base[T]"])
        field = class_decl["fields"][0]["variable_decl"]
        self.assertEqual((field["name"], field["data_type"]), ("value", "T"))
        static_init = class_decl["methods"][0]["method_decl"]
        self.assertEqual(static_init["name"], "%class_sinit")
        self.assertEqual(
            static_init["body"][0]["field_write"]["field"], "value"
        )

    def test_try_except(self):
        tree, _ = emit(
            "try:\n    risky()\nexcept ValueError as e:\n    x = 1"
        )
        try_row = next(r for r in tree if "try_stmt" in r)
        body = try_row["try_stmt"]
        self.assertEqual(len(body["catch_body"]), 1)
        clause = body["catch_body"][0]["catch_clause"]
        self.assertEqual(clause["as"], "e")
        self.assertEqual(clause["expcetion"], "ValueError")

    def test_parameters_kwonly_and_packed(self):
        tree, _ = emit("def f(a, b=1, *args, c, **kw):\n    return a")
        method = tree[-1]["method_decl"]
        params = [p["parameter_decl"] for p in method["parameters"]]
        by_name = {p["name"]: p for p in params}
        self.assertEqual(by_name["a"]["default_value"], None)
        self.assertEqual(by_name["b"]["default_value"], "1")
        self.assertIn("%keyword_pmt", by_name["c"]["attrs"])
        self.assertIn("%packed_pos_pmt", by_name["args"]["attrs"])
        self.assertIn("%packed_named_pmt", by_name["kw"]["attrs"])

    def test_class_unify_drops_self(self):
        tree, _ = emit(
            "class Foo:\n    def __init__(self, x):\n        self.x = x\n"
        )
        class_decl = tree[0]["class_decl"]
        method = class_decl["methods"][0]["method_decl"]
        self.assertEqual(
            [p["parameter_decl"]["name"] for p in method["parameters"]], ["x"]
        )
        body = method["body"]
        field_write = next(r for r in body if "field_write" in r)
        self.assertEqual(field_write["field_write"]["receiver_object"], "%this")

    def test_class_static_init(self):
        tree, _ = emit("class Foo:\n    cls_attr = 42\n")
        class_decl = tree[0]["class_decl"]
        names = [m["method_decl"]["name"] for m in class_decl["methods"]]
        self.assertIn("%class_sinit", names)
        fields = [f["variable_decl"]["name"] for f in class_decl["fields"]]
        self.assertEqual(fields, ["cls_attr"])

    def test_import_stays_top_level(self):
        _, rows = emit("import os\nx = os.getcwd()")
        top = top_level(rows)
        top_ops = {r["operation"] for r in top}
        self.assertIn("import_stmt", top_ops)
        self.assertIn("method_decl", top_ops)

    def test_unit_init_wraps_module_exec(self):
        _, rows = emit("import os\nx = os.getcwd()")
        init = next(
            r for r in rows
            if r.get("operation") == "method_decl" and r.get("name") == "%unit_init"
        )
        wrapped = [r for r in rows if r["parent_stmt_id"] == init["body"]]
        wrapped_ops = {r["operation"] for r in wrapped}
        self.assertIn("object_call_stmt", wrapped_ops)
        self.assertIn("assign_stmt", wrapped_ops)

    def test_no_unit_init_without_module_exec(self):
        _, rows = emit("def f():\n    return 1")
        names = {r.get("name") for r in rows if r.get("operation") == "method_decl"}
        self.assertNotIn("%unit_init", names)

    def test_flatten_starts_ids_at_one(self):
        _, rows = emit("x = 1")
        ids = {r["stmt_id"] for r in rows}
        self.assertNotIn(0, ids)

    def test_method_call(self):
        tree, _ = emit("r = obj.method(1, k=2)")
        row = next(r for r in tree if "object_call_stmt" in r)
        call = row["object_call_stmt"]
        self.assertEqual(call["receiver_object"], "obj")
        self.assertEqual(call["field"], "method")
        self.assertEqual(call["positional_args"], ["1"])

    def test_discard_expression_statement(self):
        tree, _ = emit("risky()")
        ops = {next(iter(r.keys())) for r in tree}
        self.assertIn("call_stmt", ops)

    def test_build_gir_pipeline_entry(self):
        from pyflow.ir.gir import build_gir
        from pyflow.ir.gir.dump import readable_gir

        source = "def main():\n    s = Stack()\n    s.push(1)\n    return s.pop()\n"
        rows = build_gir(module_code(source), "unit_test")
        names = {r.get("name") for r in rows if r.get("operation") == "method_decl"}
        self.assertIn("main", names)
        text = readable_gir(rows)
        self.assertIn("s.push(1)", text)
        self.assertNotIn("['1']", text)
        self.assertIn("= s.pop()", text)

    def test_build_gir_accepts_external_statement_id_start(self):
        from pyflow.ir.gir import build_gir

        rows = build_gir(module_code("value = 1"), "unit", start_id=100)
        self.assertEqual(min(row["stmt_id"] for row in rows), 100)

    def test_readable_gir_includes_flattened_parameters(self):
        from pyflow.ir.gir import build_gir
        from pyflow.ir.gir.dump import readable_gir

        rows = build_gir(module_code("def f(value=1):\n    return value\n"), "unit")
        self.assertIn("def f(value=1):", readable_gir(rows))

    @unittest.skipUnless(
        hasattr(python_ast, "TypeVar"), "PEP 695 parsing requires Python 3.12+"
    )
    def test_pep695_type_parameters_warn_and_keep_runtime_parameters(self):
        code = module_code(
            "def first[T](xs: list[T]) -> T:\n"
            "    return xs[0]\n"
            "class Box[T]:\n"
            "    pass\n"
        )
        function_statements = []
        with self.assertWarnsRegex(
            GirCompatibilityWarning, "function type parameters"
        ):
            GirEmitter().emit_statement(
                code.ast.blocks[0], function_statements
            )
        class_statements = []
        GirEmitter().emit_statement(code.ast.blocks[1], class_statements)
        method = function_statements[0]["method_decl"]
        self.assertEqual(method["parameters"][0]["parameter_decl"]["name"], "xs")
        self.assertEqual(class_statements[0]["class_decl"]["name"], "Box")
        self.assertEqual(
            class_statements[0]["class_decl"]["type_parameters"], "T"
        )


if __name__ == "__main__":
    unittest.main()
