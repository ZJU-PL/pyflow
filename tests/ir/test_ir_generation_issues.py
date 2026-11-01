"""Regression tests for IR generation issues found during audit."""

import ast as python_ast
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pyflow.frontend.conversion.ast import ASTConverter
from pyflow.frontend.interface_builder import InterfaceBuildOptions, build_interface_from_paths
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.util.application.console import Console
from pyflow.ir.cfg import transform, ssa, ssatransform
from pyflow.ir.mir import lower_source, lower_file, MIRInterpreter
from pyflow.ir.mir.lowering import _default_root


def test_match_guard_linear_scaling_no_exponential_explosion():
    """Pattern matching with many guarded cases must scale linearly, not O(2^n)."""
    lines = ["def f(x):", "    match x:"]
    for i in range(16):
        lines.append(f"        case {i} if x > {i}:")
        lines.append(f"            return {i}")
    lines.append("        case _:")
    lines.append("            return -1")

    source = "\n".join(lines)
    tree = python_ast.parse(source)
    conv = ASTConverter()
    code = conv._convert_function_def(tree.body[0]).code

    t0 = time.time()
    cfg = transform.evaluate(None, code)
    ssa.evaluate(None, cfg)
    elapsed = time.time() - t0

    # 16 cases previously took > 10 minutes; now runs in under 0.25 seconds.
    assert elapsed < 1.0, f"CFG/SSA generation took too long: {elapsed:.2f}s"


def test_match_mapping_missing_key_does_not_abort_to_error_exit():
    """Mapping patterns must check key presence before indexing, avoiding KeyError."""
    source = """
def f(x):
    match x:
        case {"target": 1}:
            return True
        case _:
            return False
"""
    tree = python_ast.parse(source)
    conv = ASTConverter()
    code = conv._convert_function_def(tree.body[0]).code
    cfg = transform.evaluate(None, code)

    # In CFG, the condition should use interpreter__contains__ before interpreter_getitem
    nodes = []
    pending, seen = [cfg.entryTerminal], set()
    while pending:
        b = pending.pop()
        if b is None or b in seen:
            continue
        seen.add(b)
        nodes.append(b)
        pending.extend(b.next.values())

    conditions = [str(getattr(b, "condition", "")) for b in nodes if hasattr(b, "condition")]
    assert any("interpreter__contains__" in cond for cond in conditions)


def test_match_class_missing_attr_does_not_abort_to_error_exit():
    """Class keyword patterns must check attribute existence before getattr."""
    source = """
def f(x):
    match x:
        case Point(x=1):
            return True
        case _:
            return False
"""
    tree = python_ast.parse(source)
    conv = ASTConverter()
    code = conv._convert_function_def(tree.body[0]).code
    cfg = transform.evaluate(None, code)

    nodes = []
    pending, seen = [cfg.entryTerminal], set()
    while pending:
        b = pending.pop()
        if b is None or b in seen:
            continue
        seen.add(b)
        nodes.append(b)
        pending.extend(b.next.values())

    conditions = [str(getattr(b, "condition", "")) for b in nodes if hasattr(b, "condition")]
    assert any("interpreter_hasattr" in cond for cond in conditions)


def test_ssatransform_evaluate_code_handles_exception_regions():
    """evaluateCode must not crash on functions containing try or with statements."""
    source = """
def f(x):
    try:
        return x()
    except Exception:
        return None
"""
    tree = python_ast.parse(source)
    conv = ASTConverter()
    code = conv._convert_function_def(tree.body[0]).code

    compiler = CompilerContext(Console(verbose=False))
    result_code = ssatransform.evaluateCode(compiler, code)
    assert result_code is not None


def test_default_root_finds_package_root_for_namespace_subpackage(tmp_path):
    """_default_root should resolve src-layout package roots even through namespace directories."""
    project_dir = tmp_path / "my_project"
    project_dir.mkdir()
    (project_dir / "pyproject.toml").touch()
    src_dir = project_dir / "src"
    pkg_dir = src_dir / "my_package"
    sub_dir = pkg_dir / "sansio"
    sub_dir.mkdir(parents=True)
    (pkg_dir / "__init__.py").touch()
    module_file = sub_dir / "routes.py"
    module_file.touch()

    resolved = _default_root(module_file)
    assert resolved == src_dir


def test_mir_int_truediv_zero_raises_zero_division():
    """1 / 0 in MIR must raise ZeroDivisionError rather than TypeError."""
    source = """
try:
    x = 1 / 0
except ZeroDivisionError:
    result = 42
"""
    program = lower_source(source, filename="<test>")
    execution = MIRInterpreter(program, max_steps=100_000).run()
    builtins = execution.value("$builtins")
    module = execution.value("$return")
    env = execution.memory[module.fields["$env"]]
    res_val = execution.memory[env.fields["result"]]
    assert execution.memory[res_val.fields["$value"]] == 42


def test_mir_string_comparison_operators():
    """MIR string comparisons (<, <=, >, >=, !=) should work correctly."""
    source = """
result = (
    "apple" < "banana",
    "banana" > "apple",
    "cat" == "cat",
    "cat" != "dog",
    "abc" <= "abc",
    "def" >= "abc",
)
"""
    program = lower_source(source, filename="<test>")
    execution = MIRInterpreter(program, max_steps=100_000).run()
    module = execution.value("$return")
    env = execution.memory[module.fields["$env"]]
    res_val = execution.memory[env.fields["result"]]
    items = [execution.memory[addr] for addr in execution.memory[res_val.fields["$value"]].items]
    bool_values = [execution.memory[item.fields["$value"]] for item in items]
    assert bool_values == [True, True, True, True, True, True]


def test_cli_ir_directory_without_recursive_hints_subdirectories(tmp_path):
    """When a directory has no root files but subdirectories do, give a helpful hint."""
    subdir = tmp_path / "sub"
    subdir.mkdir()
    (subdir / "target.py").write_text("def f(): return 1\n", encoding="utf-8")

    from pyflow.cli.main import main as cli_main
    from unittest.mock import patch
    import io

    stderr_buf = io.StringIO()
    with (
        patch("sys.stderr", stderr_buf),
        patch("sys.argv", ["pyflow", "ir", str(tmp_path), "--dump-cfg"]),
    ):
        try:
            cli_main()
        except SystemExit:
            pass

    output = stderr_buf.getvalue()
    assert "--recursive" in output or "-r" in output


def test_cli_ir_dump_ast_dot_format(tmp_path):
    """--dump-ast with --dump-format dot should dump a valid Graphviz digraph."""
    target = tmp_path / "simple.py"
    target.write_text("def f(x): return x + 1\n", encoding="utf-8")

    from pyflow.cli.main import main as cli_main
    from unittest.mock import patch
    import io

    stdout_buf = io.StringIO()
    with (
        patch("sys.stdout", stdout_buf),
        patch("sys.argv", ["pyflow", "ir", str(target), "--dump-ast", "f", "--dump-format", "dot"]),
    ):
        try:
            cli_main()
        except SystemExit:
            pass

    output = stdout_buf.getvalue()
    assert "digraph G" in output
    assert "ast_" in output


def test_gir_for_loop_attribute_and_subscript_targets():
    """GIR generation must handle for loops with attribute or subscript targets without crashing."""
    from pyflow.ir.gir import build_function_gir

    source = """
def f(opt, weights, data, items):
    for opt.weights in weights:
        pass
    for data['k'] in items:
        pass
"""
    tree = python_ast.parse(source)
    conv = ASTConverter()
    code = conv._convert_function_def(tree.body[0]).code
    rows = build_function_gir(code, "f")

    operations = [row["operation"] for row in rows]
    assert "forin_stmt" in operations
    assert "field_write" in operations
    assert "array_write" in operations


def test_gir_comprehension_tuple_unpacking():
    """GIR generation for comprehensions with tuple targets
    must unpack elements and use valid schema.
    """
    from pyflow.ir.gir import build_function_gir

    source = """
def f(items):
    return [v for k, v in items if k > 0]
"""
    tree = python_ast.parse(source)
    conv = ASTConverter()
    code = conv._convert_function_def(tree.body[0]).code
    rows = build_function_gir(code, "f")

    array_reads = [r for r in rows if r.get("operation") == "array_read"]
    target_names = {r.get("target") for r in array_reads}
    assert "k" in target_names
    assert "v" in target_names

    forin_rows = [r for r in rows if r.get("operation") == "forin_stmt"]
    assert len(forin_rows) == 1
    # Ensure "(k, v)" tuple string was not left as
    # the forin loop variable name
    assert forin_rows[0].get("name") != "(k, v)"


def test_lambda_default_arguments_recorded_in_makefunction_and_defuse():
    """Lambda default arguments must be preserved on MakeFunction and tracked in def-use chains."""
    from pyflow.language.python.defuse import evaluateCode

    source = """
def f(val):
    fn = lambda x=val: x + 1
    return fn()
"""
    tree = python_ast.parse(source)
    conv = ASTConverter()
    code = conv._convert_function_def(tree.body[0]).code

    # Verify MakeFunction defaults
    make_fn = code.ast.blocks[0].expr
    assert len(make_fn.defaults) == 1
    assert getattr(make_fn.defaults[0], "name", None) == "val"

    # Verify def-use visitor tracks the usage of 'val'
    (lcldef, lcluse), _ = evaluateCode(None, code)
    val_local = next(k for k in lcluse if k.name == "val")
    assert len(lcluse[val_local]) >= 1


def test_ast_nodes_traversal_linear_scaling():
    """_ast_nodes must scale linearly with the number of AST nodes without O(N^2) explosion."""
    from pyflow.ir.cfg.revision import _ast_nodes
    from pyflow.language.python import ast as pyflow_ast
    from pyflow.ir.cfg import graph as cfg_graph

    region = object()
    code = object()
    entry = cfg_graph.Entry(region)
    suite = cfg_graph.Suite(region)
    suite.ops = [pyflow_ast.Local(f"var_{i}") for i in range(4000)]
    entry.setExit("entry", suite)
    normal_term = cfg_graph.Exit(region)
    fail_term = cfg_graph.Exit(region)
    error_term = cfg_graph.Exit(region)
    suite.setExit("normal", normal_term)

    class DummyCFG:
        pass

    cfg = DummyCFG()
    cfg.code = code
    cfg.entryTerminal = entry
    cfg.normalTerminal = normal_term
    cfg.failTerminal = fail_term
    cfg.errorTerminal = error_term

    t0 = time.time()
    nodes = _ast_nodes(cfg)
    elapsed = time.time() - t0

    assert len(nodes) >= 4000
    assert elapsed < 0.2, f"_ast_nodes traversal took too long: {elapsed:.3f}s"


def test_ddg_dot_dump_syntax_validity(tmp_path):
    """DDG DOT dump must produce valid Graphviz syntax that passes dot parsing."""
    from pyflow.ir.dataflow import convert
    from pyflow.ir.ddg import construction, dump as ddg_dump
    import shutil

    source = """
def is_even(number):
    if number % 2 == 0:
        return True
    return False
"""
    tree = python_ast.parse(source)
    conv = ASTConverter()
    code = conv._convert_function_def(tree.body[0]).code
    compiler = CompilerContext(Console(verbose=False))
    dfg = convert.evaluateCode(compiler, code)
    ddg = construction.construct_ddg(dfg)

    dot_file = tmp_path / "ddg.dot"
    ddg_dump.dump_ddg(ddg, str(dot_file), fmt="dot", title="is_even")

    dot_content = dot_file.read_text(encoding="utf-8")
    assert "digraph G" in dot_content
    for line in dot_content.splitlines():
        if "label=" in line and ("@" in line or ":" in line) and not line.strip().startswith("//"):
            label_part = line.split("label=", 1)[1]
            assert label_part.startswith('"') or label_part.startswith(
                "<"
            ), f"Unquoted label: {line}"

    dot_bin = shutil.which("dot")
    if dot_bin:
        proc = subprocess.run(
            [dot_bin, "-Tpng", str(dot_file), "-o", "/dev/null"], capture_output=True, text=True
        )
        assert proc.returncode == 0, f"Graphviz dot failed on DDG DOT output: {proc.stderr}"


def test_dataflow_and_ddg_named_expr_def_use():
    """Walrus operator := must create definition edges and def-use chains in DDG."""
    from pyflow.ir.dataflow import convert
    from pyflow.ir.ddg import construction

    source = """
def f(x):
    if (val := x + 10) > 20:
        return val * 2
    return 0
"""
    tree = python_ast.parse(source)
    conv = ASTConverter()
    code = conv._convert_function_def(tree.body[0]).code
    compiler = CompilerContext(Console(verbose=False))
    dfg = convert.evaluateCode(compiler, code)
    ddg = construction.construct_ddg(dfg)

    val_edges = [e for e in ddg.all_edges() if "val" in repr(e.label)]
    assert len(val_edges) >= 2, "Expected at least 2 def-use edges involving walrus target 'val'"

    ret_op = [n for n in ddg.nodes if "interpreter__mul__" in repr(n.ir_node)][0]
    in_edges_null = [
        e for e in ddg.all_edges() if e.target is ret_op and "null" in repr(e.source.ir_node)
    ]
    assert len(in_edges_null) == 0, "Return calculation should not read from null()"


def test_ssa_delete_statement_unbinds_local():
    """del x in a branch must unbind x so merge blocks receive None on the deleted path."""
    from pyflow.ir.cfg.verifier import _all_blocks, verify_cfg

    source = """
def f(flag):
    val = 42
    if flag:
        del val
    return val
"""
    tree = python_ast.parse(source)
    conv = ASTConverter()
    code = conv._convert_function_def(tree.body[0]).code
    compiler = CompilerContext(Console(verbose=False))
    cfg = transform.evaluate(compiler, code)
    ssa.evaluate(compiler, cfg)

    verify_cfg(cfg)

    all_phis = [phi for b in _all_blocks(cfg) for phi in getattr(b, "phi", [])]
    assert len(all_phis) == 1, f"Expected 1 Phi node, found {len(all_phis)}"
    phi = all_phis[0]
    assert (
        None in phi.arguments
    ), f"Expected None in Phi arguments for deleted local: {phi.arguments}"
    assert any(a is not None for a in phi.arguments), "Expected at least one defined argument"


def test_dataflow_dce_preserves_generator_yields():
    """Dataflow DCE must treat yields as live sinks so generator bodies are retained in DDG."""
    from pyflow.ir.dataflow import convert
    from pyflow.ir.ddg import construction

    source = """
def gen():
    x = 1
    yield x
    y = 2
    yield y
"""
    tree = python_ast.parse(source)
    conv = ASTConverter()
    code = conv._convert_function_def(tree.body[0]).code
    compiler = CompilerContext(Console(verbose=False))
    dfg = convert.evaluateCode(compiler, code)
    ddg = construction.construct_ddg(dfg)

    yield_nodes = [n for n in ddg.nodes if "Yield" in repr(n.ir_node)]
    assert (
        len(yield_nodes) >= 2
    ), f"Expected at least 2 yield operations in DDG, found {len(yield_nodes)}"


def test_cfg_dump_foriter_and_typeswitch_content():
    """CFG text and JSON dumps must include ForIter iterator and index information."""
    from pyflow.ir.cfg.dump import generate_clang_style_cfg, generate_json_cfg

    source = """
def f(items):
    for item in items:
        pass
"""
    tree = python_ast.parse(source)
    conv = ASTConverter()
    code = conv._convert_function_def(tree.body[0]).code
    compiler = CompilerContext(Console(verbose=False))
    cfg = transform.evaluate(compiler, code)

    text_cfg = generate_clang_style_cfg(cfg)
    assert "Iterator: Local(%item) <- iter(Local(%items))" in text_cfg

    json_cfg = generate_json_cfg(cfg)
    foriter_blocks = [b for b in json_cfg["blocks"] if b["kind"] == "ForIter"]
    assert len(foriter_blocks) == 1
    assert "item" in foriter_blocks[0]["condition"]
    assert "items" in foriter_blocks[0]["condition"]
    assert foriter_blocks[0].get("index") == "Local(%item)"
    assert foriter_blocks[0].get("iterator") == "Local(%items)"


def test_dataflow_state_deep_parent_chain_no_recursion_error():
    """AbstractState.get must traverse deep State parent chains
    iteratively without RecursionError.
    """
    from pyflow.ir.dataflow import convert, graph as df_graph
    from pyflow.language.python import ast as lang_ast

    hyperblock = df_graph.Hyperblock(0)
    pred = df_graph.PredicateNode(hyperblock, "true")

    base = convert.DeferedEntryPoint(hyperblock, pred, None, None)
    curr = convert.State(hyperblock, pred, base)
    for _ in range(1500):
        curr = convert.State(hyperblock, pred, curr)

    local = lang_ast.Local("x")
    curr.set(local, df_graph.LocalNode(hyperblock, (local,)))

    child = curr
    for _ in range(500):
        child = convert.State(hyperblock, pred, child)

    val = child.get(local)
    assert val is not None
