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
