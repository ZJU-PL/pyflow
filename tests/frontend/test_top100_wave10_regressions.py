"""Regression tests for Wave 10 issues found across the top-100 Python corpus."""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import patch

from pyflow.analysis.numbering.readmodify import FindReadModify, ReadModifyInfo
from pyflow.analysis.typeinfo.core.typesystem import ANY, TypeSystem
from pyflow.application.context import CompilerContext
from pyflow.application.pipeline import Pipeline
from pyflow.application.program import Program
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.interface_builder import (
    InterfaceBuildOptions,
    build_interface_from_paths,
)
from pyflow.ir.cfg import ssa as cfg_ssa
from pyflow.ir.cfg import transform as cfg_transform
from pyflow.ir.cfg import verifier as cfg_verifier
from pyflow.language.python import ast as pyflow_ast
from pyflow.optimization import dce, fold
from pyflow.util.application.console import Console


def _build_program(tmp_path: Path, filename: str, source: str):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    compiler = CompilerContext(Console(out=io.StringIO(), verbose=False))
    program = Program()
    opts = InterfaceBuildOptions(
        verbose=False,
        dependency_strategy="stubs",
        include_main_entry_points=True,
    )
    program.interface, all_src = build_interface_from_paths([path], opts)
    compiler.extractor = Extractor(compiler, verbose=False, source_code=all_src)
    extract_program(compiler, program)
    return compiler, program


def test_fold_and_dce_preserve_live_locals_and_params_on_extracted_code():
    """Distinct ast.Local occurrences of the same variable must share dataflow identity."""
    source = """
def compute(a):
    x = 42
    unused = 99
    y = a + x
    return y
"""
    compiler = CompilerContext(Console(out=io.StringIO(), verbose=False))
    extractor = Extractor(compiler, verbose=False, source_code=source)
    compiler.extractor = extractor
    program = extractor.extract_from_source(source, "sample.py")

    code = next(c for c in program.liveCode if c.name == "compute")
    fold.evaluateCode(compiler, program, code)
    dce.evaluateCode(compiler, code)

    # Parameter `a` must stay live (never replaced by DoNotCare).
    assert len(code.codeparameters.params) == 1
    assert isinstance(code.codeparameters.params[0], pyflow_ast.Local)
    assert code.codeparameters.params[0].name == "a"

    # Constant `42` folds into `a + 42`; dead `x` and `unused` are eliminated;
    # live assignment to `y` and `return y` are preserved.
    assigns = [stmt for stmt in code.ast.blocks if isinstance(stmt, pyflow_ast.Assign)]
    assert len(assigns) == 1
    assert assigns[0].lcls[0].name == "y"
    call_args = assigns[0].expr.args
    assert any(isinstance(arg, pyflow_ast.Existing) and arg.object.pyobj == 42 for arg in call_args)


def test_fold_invalidates_copy_alias_when_source_local_is_reassigned():
    """Copy propagation `y = a` must not propagate a later reassignment `a = 2`."""
    source = """
def copy_then_reassign(a):
    y = a
    a = 2
    return y
"""
    compiler = CompilerContext(Console(out=io.StringIO(), verbose=False))
    extractor = Extractor(compiler, verbose=False, source_code=source)
    compiler.extractor = extractor
    program = extractor.extract_from_source(source, "sample.py")

    code = next(c for c in program.liveCode if c.name == "copy_then_reassign")
    fold.evaluateCode(compiler, program, code)
    dce.evaluateCode(compiler, code)

    # Parameter `a` is still needed for `y = a`, and `return` must not return constant 2.
    assert isinstance(code.codeparameters.params[0], pyflow_ast.Local)
    returns = [stmt for stmt in code.ast.blocks if isinstance(stmt, pyflow_ast.Return)]
    assert len(returns) == 1
    ret_expr = returns[0].exprs[0]
    assert isinstance(ret_expr, pyflow_ast.Local)
    assert ret_expr.name == "y"


def test_fold_binds_cloned_copy_local_in_ir_catalog_and_scopes_semantics(tmp_path):
    """Copy-propagated locals stay indexed and commitFactRemap scopes build_semantics."""
    source = """
def helper(items):
    alias = items
    for x in alias.values():
        y = alias.get(x, default=1)
    return y

def other(v):
    return v + 1
"""
    compiler, program = _build_program(tmp_path, "copy_prop.py", source)
    Pipeline().run_custom_pipeline(compiler, program, ["ipa", "cpa", "methodcall"])

    code = next(c for c in program.liveCode if c.name.endswith("helper"))
    scoped_calls = []
    from pyflow.ir.core import build_semantics as real_build_semantics

    def spy_build_semantics(catalog, *, register_missing_nodes=True, codes=None):
        scoped_calls.append(codes)
        return real_build_semantics(
            catalog,
            register_missing_nodes=register_missing_nodes,
            codes=codes,
        )

    with patch("pyflow.optimization.fold.build_semantics", side_effect=spy_build_semantics):
        fold.evaluateCode(compiler, program, code)

    assert scoped_calls
    assert all(codes == (program.ir.procedure(code).code_id,) for codes in scoped_calls)


def test_fold_handles_unindexed_code_with_real_extractor():
    """fold.evaluateCode must not crash when Code has no ir_catalog."""
    compiler = CompilerContext(Console(out=io.StringIO(), verbose=False))
    compiler.extractor = Extractor(compiler, verbose=False, source_code="def f(): return 1\n")

    ret_local = pyflow_ast.Local("ret")
    code = pyflow_ast.Code(
        "unindexed",
        pyflow_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[],
            paramnames=[],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[ret_local],
            type_params=None,
        ),
        pyflow_ast.Suite(
            [pyflow_ast.Return([pyflow_ast.Existing(compiler.extractor.getObject(1))])]
        ),
    )
    assert getattr(code, "ir_catalog", None) is None

    result = fold.evaluateCode(compiler, None, code)
    assert result is code


def test_clone_pass_handles_splitting_kwargs_and_unresolved_direct_calls(tmp_path):
    """Cloning must rebuild IR before simplify, clone tuple/list children, and keep valid DirectCalls."""
    source = """
class Base:
    def configure(self):
        return self.build(opt=1)

    def get_input(self, batch):
        raise NotImplementedError()

class SubA(Base):
    def build(self, opt=0):
        return self.only_a(opt, flag=True)

    def only_a(self, v, flag=False):
        return self.unresolved_a(v, mode=flag)

class SubB(Base):
    def build(self, opt=0):
        return self.only_b(opt, flag=False)

    def only_b(self, v, flag=False):
        return self.unresolved_b(v, mode=flag)

def driver():
    a = SubA()
    b = SubB()
    return (a.configure(), b.configure())
"""
    compiler, program = _build_program(tmp_path, "clone_case.py", source)
    res = Pipeline().run(program, compiler=compiler, name="clone_case")
    assert all(record.success for record in res.records)
    assert any(record.stage_name == "clone" and record.changed for record in res.records)
    assert any("_clone_" in code.name for code in program.liveCode)


def test_ipa_handles_delete_attr_on_nested_expression(tmp_path):
    """IPA constraint extraction must handle `del obj.a.b` where target expr is a nested call."""
    source = """
class Trainer:
    def cleanup(self):
        del self.model.criterion
        self.model.flag = True

def run(t):
    t.cleanup()
"""
    compiler, program = _build_program(tmp_path, "delattr_case.py", source)
    res = Pipeline().run(program, compiler=compiler, name="delattr_case")
    assert all(record.success for record in res.records)


def test_load_and_store_elimination_pipeline_with_compound_constructs(tmp_path):
    """FindReadModify/ForwardESSA/ForwardDataflow handle try/except, loops, classes, del, AnnAssign."""
    assert isinstance(ReadModifyInfo(), ReadModifyInfo)

    source = """
class Box:
    def __init__(self, v):
        self.v = v

def work(items, flag):
    total: int = 0
    class LocalHelper:
        x = 1
    try:
        for item in items:
            if flag:
                total = total + item
            else:
                tmp = item
                del tmp
    except ValueError as err:
        return err
    finally:
        done = True
    b = Box(total)
    return b.v
"""
    compiler, program = _build_program(tmp_path, "load_elim_case.py", source)
    passes = Pipeline().default_pass_names(dump_reports=True) + [
        "heap",
        "load_elimination",
        "store_elimination",
    ]
    res = Pipeline().run_custom_pipeline(compiler, program, passes)
    assert all(record.success for record in res.records)


def test_ssa_fixed_point_prunes_chained_all_none_phis():
    """Chained merges whose incoming phi placeholders are all unbound must be pruned cleanly."""
    source = """
def chained_undef(flag1, flag2):
    try:
        raise ValueError()
    except ValueError as e:
        return 1
    if flag1:
        z = 1
    if flag2:
        z = 2
    return e
"""
    compiler = CompilerContext(Console(out=io.StringIO(), verbose=False))
    extractor = Extractor(compiler, verbose=False, source_code=source)
    program = extractor.extract_from_source(source, "chained_phi.py")

    code = next(c for c in program.liveCode if c.name == "chained_undef")
    cfg = cfg_transform.evaluate(compiler, code)
    cfg_ssa.evaluate(compiler, cfg)
    cfg_verifier.verify_cfg(cfg, code.ir_catalog)
    cfg_verifier.verify_ssa(cfg, code.ir_catalog)


def test_typesystem_get_members_caches_runtime_inspection_and_reflects_dynamic_members():
    """TypeSystem.get_members caches MRO inspect.signature work while keeping dynamic updates live."""
    ts = TypeSystem()
    desc = ts.to_class_descriptor(str)

    first = ts.get_members(desc)
    assert "upper" in first

    with patch(
        "pyflow.analysis.typeinfo.core.typesystem.inspect.signature",
        side_effect=AssertionError("runtime MRO inspection should be cached"),
    ):
        second = ts.get_members(desc)
        assert "upper" in second

        # Dynamic descriptor member updates must still appear immediately.
        desc.members["__custom_wave10__"] = ANY
        third = ts.get_members(desc)
        assert "__custom_wave10__" in third
