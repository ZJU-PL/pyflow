"""Regression tests for Wave 8 top-100 robustness and performance fixes."""

from __future__ import annotations

import ast
import io
from dataclasses import replace
from pathlib import Path

import pytest


def test_union_find_union_handles_equal_weight_unorderable_objects():
    """UnionFind.union must not compare unorderable elements when weights tie (Python 3)."""
    from pyflow.util.PADS.UnionFind import UnionFind

    class Unorderable:
        pass

    uf = UnionFind()
    assert uf.union() is None

    a, b, c = Unorderable(), Unorderable(), Unorderable()
    root = uf.union(a, b, a)
    assert root in (a, b)
    assert uf[a] == uf[b] == root

    root2 = uf.union(b, c)
    assert uf[a] == uf[b] == uf[c] == root2
    assert uf.weights[root2] == 3


def test_forward_dataflow_for_index_and_exception_handler_not_folded_to_existing(
    tmp_path: Path,
):
    """Pre-loop/pre-try constants must not fold For.index or ExceptionHandler.value to Existing."""
    from pyflow.application.context import CompilerContext
    from pyflow.application.pipeline import Pipeline
    from pyflow.application.program import Program
    from pyflow.frontend.extractor import Extractor, extract_program
    from pyflow.frontend.interface_builder import (
        InterfaceBuildOptions,
        build_interface_from_paths,
    )
    from pyflow.util.application.console import Console

    src = (
        "def run_loop(items):\n"
        "    i = 0\n"
        "    total = 0\n"
        "    for i in items:\n"
        "        total += i\n"
        "    err = 0\n"
        "    try:\n"
        "        total += 1\n"
        "    except ValueError as err:\n"
        "        return err\n"
        "    return total + i\n"
        "\n"
        "def entry():\n"
        "    return run_loop([1, 2, 3])\n"
    )
    path = tmp_path / "loop_and_exc.py"
    path.write_text(src, encoding="utf-8")

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

    # Full optimization pipeline (includes clone, fold/simplify, etc.) must complete cleanly.
    Pipeline().run(program, compiler=compiler, name=path.stem)


def test_shape_constraint_builder_handles_donotcare_import_and_kparam():
    """ShapeConstraintBuilder must tolerate DoNotCare params, Import decls, and **kwargs."""
    from pyflow.analysis.shape.constraintbuilder import ShapeConstraintBuilder
    from pyflow.language.python import ast as py_ast

    class _DummySys:
        pass

    builder = ShapeConstraintBuilder(_DummySys())
    assert builder.localExpr(py_ast.DoNotCare()) is None

    # visitDeclaration on Import must be a no-op instead of failing dispatch.
    imp = py_ast.Import("math", [], 0)
    assert builder.visitDeclaration(imp) is None

    # transferParameters with DoNotCare selfparam/params and a kparam must not assert.
    code_params = py_ast.CodeParameters(
        selfparam=py_ast.DoNotCare(),
        posonlyparams=[],
        posonlynames=[],
        params=[py_ast.DoNotCare()],
        paramnames=["x"],
        defaults=[],
        vparam=None,
        kparam=py_ast.Local("kwargs"),
        returnparams=[],
        type_params=None,
    )

    class _DummyCode:
        codeparameters = code_params

    builder.transferParameters(_DummyCode())


def test_resolve_forward_reference_uses_cache_and_handles_invalid_inputs():
    """resolve_forward_reference delegates to cached parser and never crashes on bad inputs."""
    from pyflow.analysis.typeinfo.resolution.annotations import (
        BuiltinTypeLookup,
        _parse_annotation_expr,
        resolve_forward_reference,
    )

    lookup = BuiltinTypeLookup()
    _parse_annotation_expr.cache_clear()
    resolved = resolve_forward_reference("list[int]", lookup)
    assert resolved is not None
    info1 = _parse_annotation_expr.cache_info()
    resolved2 = resolve_forward_reference("list[int]", lookup)
    assert resolved2 is not None
    info2 = _parse_annotation_expr.cache_info()
    assert info2.hits > info1.hits

    assert resolve_forward_reference("", lookup) is None
    assert resolve_forward_reference("def invalid(:", lookup) is None
    assert resolve_forward_reference("a\x00b", lookup) is None


def test_constraint_callgraph_follow_imports_false_and_trystar_directives(tmp_path: Path):
    """follow_imports=False avoids crawling sibling modules; _symbols handles TryStar & closures."""
    from pyflow.analysis.callgraph.constraint_based import (
        AnalysisOptions,
        ConstraintCallGraphBuilder,
    )

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "helper.py").write_text("def helper_fn():\n    return 42\n", encoding="utf-8")
    main_py = pkg / "main.py"
    main_src = (
        "from pkg.helper import helper_fn\n"
        "def local_fn():\n"
        "    return 1\n"
        "def entry():\n"
        "    return local_fn() + helper_fn()\n"
    )
    main_py.write_text(main_src, encoding="utf-8")

    b_no_follow = ConstraintCallGraphBuilder(
        main_src,
        entry_path=str(main_py),
        project_root=str(tmp_path),
        options=AnalysisOptions(follow_imports=False),
    )
    cg_no_follow = b_no_follow.build()

    b_follow = ConstraintCallGraphBuilder(
        main_src,
        entry_path=str(main_py),
        project_root=str(tmp_path),
        options=AnalysisOptions(follow_imports=True),
    )
    b_follow.build()

    assert len(b_no_follow.modules) == 1
    assert len(b_follow.modules) >= 2
    assert any(
        "local_fn" in str(callee) for callees in cg_no_follow.get().values() for callee in callees
    )

    # TryStar directives + single-pass closure/global/nonlocal inference
    fn_ast = ast.parse(
        "def outer(captured):\n"
        "    x = 1\n"
        "    def inner():\n"
        "        try:\n"
        "            pass\n"
        "        except* ValueError:\n"
        "            global G_VAR\n"
        "            nonlocal x\n"
        "            G_VAR = captured\n"
        "            x = 2\n"
        "    return inner\n"
    ).body[0]
    inner_ast = fn_ast.body[1]
    globals_set, nonlocals_set = b_no_follow._infer_scope_directives(inner_ast.body)
    assert globals_set == {"G_VAR"}
    assert nonlocals_set == {"x"}
    g2, nl2, closures = b_no_follow._infer_function_scope_vars(inner_ast)
    assert g2 == {"G_VAR"}
    assert nl2 == {"x"}
    assert "captured" in closures


def test_kcfa_stable_token_alloc_site_hash_and_worklist_arena_rebase():
    """k-CFA stable_token folds deep contexts; AllocSite caches hash; Worklist rebases to arena."""
    from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.context import (
        CallStringContext,
        Ctx,
        ParamContext,
        Scope,
    )
    from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import (
        AbstractObject,
        AllocKind,
        AllocSite,
    )
    from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.points_to_set import (
        AnalysisArena,
        PointsToSet,
    )
    from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.stable_key import (
        stable_token,
    )
    from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.state import Worklist
    from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.variable import (
        Variable,
        VariableKind,
    )

    # AllocSite cached hash + replace reset
    s1 = AllocSite(stmt="s1", kind=AllocKind.OBJECT)
    s2 = AllocSite(stmt="s1", kind=AllocKind.OBJECT)
    s3 = replace(s1, kind=AllocKind.LIST)
    assert s1 == s2 and hash(s1) == hash(s2)
    assert s1 != s3 and hash(s3) == hash(AllocSite(stmt="s1", kind=AllocKind.LIST))

    # Deeply nested ParamContext produces short bounded stable_token
    ctx: object = CallStringContext((), 1)
    for i in range(6):
        ctx = ParamContext(((ctx, f"p{i}"),), 2)
    tok1 = stable_token("k", ctx)
    tok2 = stable_token("k", ctx)
    assert tok1 == tok2
    assert len(tok1) == 16

    from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRModule

    # Scope + Ctx structural description works without to_string blowup
    ir_mod = IRModule("mod", ast.parse("x = 1"))
    scope = Scope(stmt=ir_mod, obj=AbstractObject(ctx, s1), context=ctx, _parent=None, _module=None)
    wrapped = Ctx(context=ctx, scope=scope, content=Variable("x", VariableKind.LOCAL))
    assert len(stable_token("ctx", wrapped)) == 16

    # Worklist arena alignment + PointsToSet.rebase fast paths (empty, singleton, multi)
    arena_a = AnalysisArena()
    arena_b = AnalysisArena()
    o1 = AbstractObject(CallStringContext((), 1), s1)
    o2 = AbstractObject(CallStringContext((), 1), s3)

    pts_empty = PointsToSet.empty(arena=arena_a)
    pts_one = PointsToSet.singleton(o1, arena=arena_a)
    pts_two = PointsToSet.from_objects([o1, o2], arena=arena_a)

    assert pts_empty.rebase(arena_b).is_empty()
    r1 = pts_one.rebase(arena_b)
    assert r1.arena is arena_b and set(r1) == {o1}
    r2 = pts_two.rebase(arena_b)
    assert r2.arena is arena_b and set(r2) == {o1, o2}

    from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.pointer_flow_graph import (
        NormalNode,
    )

    wl = Worklist(arena=arena_b)
    node = NormalNode(wrapped)
    wl.add((scope, node, pts_one))
    wl.add((scope, node, pts_two))
    popped_scope, popped_node, merged = wl.pop()
    assert popped_scope is scope and popped_node == node
    assert merged.arena is arena_b
    assert set(merged) == {o1, o2}


def test_taint_state_root_indexed_lattice_laws_and_operations():
    """Root-indexed TaintState with lazy flat sets preserves all lattice laws and transitions."""
    from pyflow.checker.common.taint import (
        AnalysisUncertainty,
        PrecisionLevel,
        TaintFact,
        TaintLocation,
        TaintOrigin,
        TaintState,
    )

    origin_a = TaintOrigin("user_input", "a.py", 1, 0, "src_a")
    origin_b = TaintOrigin("sql", "a.py", 2, 0, "src_b")
    loc_x = TaintLocation("x")
    loc_y = TaintLocation("y")
    loc_z = TaintLocation("z")

    s0 = TaintState()
    with pytest.raises(AttributeError):
        s0.reachable = False  # type: ignore[misc]

    sx = s0.introduce(loc_x, {"user_input"}, origin_a)
    sy = s0.introduce(loc_y.key("k"), {"sql"}, origin_b)
    sxy = sx.join(sy)
    syx = sy.join(sx)

    assert sxy == syx
    assert hash(sxy) == hash(syx)
    assert sx.leq(sxy) and sy.leq(sxy)
    assert not sxy.leq(sx)
    assert sxy.facts == (sx.facts | sy.facts)

    # Explicit constructor with facts round-trips cleanly
    explicit = TaintState(facts=frozenset({TaintFact(loc_x, "user_input", origin_a)}))
    assert explicit == sx
    assert explicit.facts_at(loc_x) == sx.facts_at(loc_x)

    # Strong overwrite on root clears previous facts and records guarantee
    cleaned = sxy.write(loc_x, (), strong=True)
    assert not cleaned.is_tainted(loc_x)
    assert cleaned.is_tainted(loc_y.key("k"), {"sql"})
    assert (loc_x, "user_input") in cleaned.guarantees

    # Copy preserves nested selectors and works after provenance overflow
    overflow_state = TaintState(max_provenance_edges=1).introduce(
        loc_x.attribute("a"), {"user_input"}, origin_a
    )
    overflow_state = overflow_state.copy(loc_x, loc_y, strong=True)
    overflow_state = overflow_state.copy(loc_x, loc_z, strong=True)
    assert overflow_state.provenance_is_top
    assert overflow_state.is_tainted(loc_z.attribute("a"), {"user_input"})

    # Join across different max_access_path normalizes deep paths per root
    deep = TaintState(max_access_path=4).introduce(
        loc_x.attribute("a").attribute("b").attribute("c"), {"user_input"}, origin_a
    )
    shallow = TaintState(max_access_path=2).with_uncertainty(
        AnalysisUncertainty("note", "shallow", PrecisionLevel.CONSERVATIVE)
    )
    joined = deep.join(shallow)
    assert joined.max_access_path == 2
    assert all(len(f.location.selectors) <= 2 for f in joined.facts)
