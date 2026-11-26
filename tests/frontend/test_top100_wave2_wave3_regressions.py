"""Regression tests for Wave 2, Wave 3, and Wave 4 top100 fixes across PyFlow subsystems."""

from __future__ import annotations

import ast
import io
import warnings
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

from pyflow.analysis.alias.flow_sensitive import HeapAnalysis
from pyflow.analysis.callgraph.pycg_mir import analyze_file_pycg_mir
from pyflow.analysis.ipa.calling.cpa import CPATypeSigBuilder, anyType, nullIter
from pyflow.analysis.taint_policy.policy import TaintPolicy
from pyflow.analysis.typeinfo.query.service import TypeFact, TypeInfoService
from pyflow.api.queries import create_query_components
from pyflow.application.context import CompilerContext
from pyflow.application.pipeline import Pipeline
from pyflow.application.program import Program
from pyflow.checker.ast_rules.core.blacklist import BlacklistItem, BlacklistManager
from pyflow.checker.ast_rules.core.config import SecurityConfig
from pyflow.checker.ast_rules.core.manager import SecurityManager
from pyflow.checker.cpg.taint.formal import FormalCPGTaintAnalysis
from pyflow.checker.supply_chain import analyze_reachability, scan_targets
from pyflow.checker.supply_chain.scanner import _is_excluded
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.interface_builder import InterfaceBuildOptions, build_interface_from_paths
from pyflow.ir.cfg import ssa as cfg_ssa
from pyflow.ir.cfg import transform as cfg_transform
from pyflow.ir.core.catalog import IRCatalog
from pyflow.ir.core.index import index_code
from pyflow.ir.cpg.graph import CPGEdgeKind
from pyflow.ir.mir.lowering import lower_source
from pyflow.language.modules.project_resolution import ProjectContext
from pyflow.language.python import ast as py_ast
from pyflow.optimization.source import optimize_source
from pyflow.util.application.console import Console


def _extract_single_file(tmp_path: Path, filename: str, source: str):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    compiler = CompilerContext(Console(verbose=False))
    program = Program()
    compiler.program = program
    extractor = Extractor(
        compiler,
        verbose=False,
        source_code={str(path): source},
        analysis_root=str(tmp_path),
    )
    compiler.extractor = extractor
    with redirect_stdout(io.StringIO()):
        interface, _all_source = build_interface_from_paths(
            [str(path)],
            options=InterfaceBuildOptions(verbose=False, dependency_strategy="noop"),
        )
        program.interface = interface
        extract_program(compiler, program)
    return compiler, program, path


def test_typeinfo_refresh_import_facts_tolerates_dict_mutation(tmp_path: Path):
    """_refresh_import_facts iterates over a snapshot so callback mutations cannot raise RuntimeError."""
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    service = TypeInfoService(ProjectContext(tmp_path))
    mutated = False
    original_lookup = service._lookup_project_type

    def _mutating_lookup(qualified_name: str, *, allow_synthetic: bool = True):
        nonlocal mutated
        if not mutated:
            mutated = True
            service._module_facts["late_added_mod"] = {}
            service._module_facts["a"]["late_sym"] = TypeFact(
                name="late_sym", typ=int, raw_annotation="int", source="inferred", kind="variable"
            )
        return original_lookup(qualified_name, allow_synthetic=allow_synthetic)

    service._module_facts["a"] = {
        "imported_x": TypeFact(
            name="imported_x",
            typ=object,
            raw_annotation="b.Target",
            source="import",
            kind="variable",
        )
    }
    service._lookup_project_type = _mutating_lookup  # type: ignore[method-assign]
    service._refresh_import_facts()
    assert mutated


def test_flow_sensitive_alias_nested_call_in_for_iterator_and_loop_convergence(tmp_path: Path):
    """Nested call inside `for` iterator must not raise IndexError and loop calls must converge."""
    source = (
        "def inner(n):\n"
        "    return [n, n + 1]\n"
        "\n"
        "def outer(items):\n"
        "    return list(items)\n"
        "\n"
        "def driver(seq):\n"
        "    acc = []\n"
        "    for x in outer(inner(seq)):\n"
        "        acc.append(x)\n"
        "    total = 0\n"
        "    for i in range(10):\n"
        "        for j in range(10):\n"
        "            val = outer(inner(i + j))\n"
        "            total += len(val)\n"
        "    return acc, total\n"
    )
    compiler, program, _path = _extract_single_file(tmp_path, "alias_loop.py", source)
    analysis = HeapAnalysis()
    result = analysis.analyze(compiler, program)
    assert result is not None


def test_pycg_mir_direct_literal_lowering_and_budget_enforcement(tmp_path: Path):
    """Large dict/list literals lower directly without per-element $site CFG blowup."""
    entries = ", ".join(f"'k{i}': {i}" for i in range(400))
    source = f"MAPPING = {{{entries}}}\nITEMS = [{', '.join(str(i) for i in range(400))}]\n"
    prog = lower_source(source, module_name="litmod")
    # Direct lowering avoids per-element synthetic $site CFGs for plain dict/list literals.
    site_cfgs = [name for name in prog.cfgs if "$site" in name]
    assert site_cfgs == []

    # Tight budget triggers partial lowering gracefully instead of crashing.
    target = tmp_path / "litmod.py"
    target.write_text(source, encoding="utf-8")
    with redirect_stdout(io.StringIO()), warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cg = analyze_file_pycg_mir(
            str(target),
            project_root=str(tmp_path),
            max_seconds=0.000001,
            max_import_depth=0,
            import_policy="opaque",
        )
    assert cg is not None


def test_taint_policy_suffix_index_matches_full_and_shortened_names():
    """Precomputed dotted suffix indexes preserve exact matching semantics."""
    policy = TaintPolicy(
        source_kinds_by_call={
            "flask.request.args.get": frozenset({"user_input"}),
            "input": frozenset({"user_input"}),
        },
        sink_kinds_by_call={
            "sqlite3.Cursor.execute": frozenset({"sql"}),
            "os.system": frozenset({"command"}),
        },
        sink_cwe_by_call={"sqlite3.Cursor.execute": "CWE-89"},
        sanitizer_kinds_by_call={"markupsafe.escape": frozenset({"xss"})},
    )
    assert policy.source_kinds_for("flask.request.args.get") == frozenset({"user_input"})
    assert policy.source_kinds_for("request.args.get") == frozenset({"user_input"})
    assert policy.source_kinds_for("args.get") == frozenset({"user_input"})
    # Single-segment leaf must NOT suffix-match a dotted qualified name.
    assert policy.source_kinds_for("get") == frozenset()
    assert policy.source_kinds_for("input") == frozenset({"user_input"})
    assert policy.sink_kinds_for("Cursor.execute") == frozenset({"sql"})
    assert policy.sink_cwe_for("Cursor.execute") == "CWE-89"
    assert policy.sanitizer_kinds_for("pkg.markupsafe.escape") == frozenset({"xss"})


def test_optimization_pipeline_handles_conditional_asyncfor_trystar_and_clone_refresh(
    tmp_path: Path,
):
    """Pipeline with simplify + clone must not crash on ConditionalExpr/AsyncFor/TryStar or CPA refresh cycle."""
    source = (
        "def choose(flag, a, b):\n"
        "    x = 1 + 2\n"
        "    return (a if flag else b) + x\n"
        "\n"
        "async def consume(stream):\n"
        "    total = 0\n"
        "    async for item in stream:\n"
        "        total += item\n"
        "    return total\n"
        "\n"
        "def group_handler(fn):\n"
        "    try:\n"
        "        return fn()\n"
        "    except* ValueError:\n"
        "        return 0\n"
    )
    compiler, program, _path = _extract_single_file(tmp_path, "opt_pipe.py", source)
    with redirect_stdout(io.StringIO()):
        Pipeline().run(program, compiler=compiler)
    assert program.liveCode


def test_optimize_source_preserves_generator_and_non_empty_bodies():
    """optimize_source(level=2) must preserve generator semantics and never emit empty suites."""
    src = (
        "async def gen():\n"
        "    if False:\n"
        "        yield 1\n"
        "\n"
        "def sync_gen():\n"
        "    if False:\n"
        "        yield from ()\n"
        "\n"
        "def guarded(x):\n"
        "    try:\n"
        "        return x\n"
        "    except Exception:\n"
        "        assert True\n"
    )
    optimized = optimize_source(src, level=2)
    tree = ast.parse(optimized.source)
    # Both generators must still contain yield / yield from so generator semantics hold.
    func_map = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert any(isinstance(n, ast.Yield) for n in ast.walk(func_map["gen"]))
    assert any(isinstance(n, ast.YieldFrom) for n in ast.walk(func_map["sync_gen"]))
    # Emptied except handler must contain `pass` and parse cleanly.
    try_node = func_map["guarded"].body[0]
    assert isinstance(try_node, ast.Try)
    assert len(try_node.handlers[0].body) >= 1


def test_cpg_taint_tarjan_scc_iterative_handles_deep_cfg():
    """_compute_loop_nodes uses iterative Tarjan SCC and handles >1500 sequential nodes without RecursionError."""
    nodes = [SimpleNamespace(node_id=i) for i in range(1500)]
    edges_out = {
        i: [SimpleNamespace(target=nodes[i + 1], kind=CPGEdgeKind.CFG_NEXT)]
        for i in range(len(nodes) - 1)
    }
    edges_out[1499] = [SimpleNamespace(target=nodes[1495], kind=CPGEdgeKind.CFG_NEXT)]

    stub_cpg = SimpleNamespace(
        nodes=lambda: nodes,
        node_func_name=lambda _node: "deep_fn",
        _cpg_edges_out=edges_out,
    )
    engine = object.__new__(FormalCPGTaintAnalysis)
    engine.cpg = stub_cpg
    engine._budget_exhausted = lambda _stage: False  # type: ignore[method-assign]
    loop_nodes = engine._compute_loop_nodes()
    assert all(i in loop_nodes for i in range(1495, 1500))
    assert 0 not in loop_nodes


def test_index_code_and_ssa_handle_unnamed_locals_and_donotcare_params():
    """Unnamed Local(None) and DoNotCare stub parameters must not fail SSA renaming."""
    unnamed_param = py_ast.Local(None)
    ret_local = py_ast.Local(None)
    code = py_ast.Code(
        "stub_fn",
        py_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[unnamed_param],
            paramnames=["p0"],
            defaults=[],
            vparam=None,
            kparam=py_ast.DoNotCare(),
            returnparams=[ret_local],
            type_params=None,
        ),
        py_ast.Suite([py_ast.Return([unnamed_param])]),
    )
    compiler = CompilerContext(Console(verbose=False))
    catalog = IRCatalog()
    index_code(catalog, code, module="stub_mod")
    cfg = cfg_transform.evaluate(compiler, code)
    cfg_ssa.evaluate(compiler, cfg, commit_revision=False)
    assert cfg is not None


def test_graph_query_engine_get_cfg_and_ssa_preserve_published_callgraph_facts(tmp_path: Path):
    """Read-only get_cfg() and get_ssa() must not bump IR revision and invalidate callgraph facts."""
    source = (
        "def helper(x):\n" "    return x + 1\n" "\n" "def caller(y):\n" "    return helper(y)\n"
    )
    from pyflow.analysis import cpa, ipa

    compiler, program, _path = _extract_single_file(tmp_path, "queries_rev.py", source)
    with redirect_stdout(io.StringIO()):
        ipa.evaluate(compiler, program)
        cpa.evaluate(compiler, program)
    queries = create_query_components(compiler, program)
    rev_before = program.ir.revision
    cfg = queries.graph_engine.get_cfg("caller")
    cfg_struct = queries.graph_engine.get_cfg_structure("caller")
    ssa_cfg = queries.graph_engine.get_ssa("caller")
    assert cfg is not None and cfg_struct["blocks"] and ssa_cfg is not None
    assert program.ir.revision == rev_before
    callees = queries.call_graph.get_callees("caller")
    assert callees is not None


def test_cpa_type_sig_builder_caps_megamorphic_cartesian_explosion():
    """CPATypeSigBuilder collapses polymorphic splits until Cartesian product <= 64."""
    import pyflow.analysis.ipa.calling.cpa as cpa_mod

    class _FakeTypeSplit:
        def __init__(self, objs):
            self.objects = list(objs)
            self.megamorphic = False

        def makeMegamorphic(self):
            self.megamorphic = True
            self.objects = [anyType]

        def types(self):
            return list(self.objects)

    class _FakeInfo:
        def numParams(self):
            return 4

        def numVParams(self):
            return 0

        def numKParams(self):
            return 0

        def transfer(self, src, dst):
            dst.unusedSelfParam()
            for idx in range(4):
                dst.setParam(idx, src.getArg(idx))

    # 5 values across each of 4 params = 5**4 = 625 > 64 combinations.
    args = [
        SimpleNamespace(typeSplit=_FakeTypeSplit([object() for _ in range(5)])) for _ in range(4)
    ]
    fake_call = SimpleNamespace(
        code=SimpleNamespace(name="mega"),
        selfarg=None,
        args=args,
        vargSlots=[],
        defaultSlots=[],
    )
    info = _FakeInfo()
    builder = CPATypeSigBuilder(analysis=None, call=fake_call, info=info)
    info.transfer(builder, builder)

    orig_sig = cpa_mod.CPAContextSignature
    try:
        cpa_mod.CPAContextSignature = lambda code, sp, params, vp: (sp, params, vp)
        seen = list(builder.signatures())
    finally:
        cpa_mod.CPAContextSignature = orig_sig

    assert 1 <= len(seen) <= 64
    assert sum(1 for a in args if a.typeSplit.megamorphic) >= 2


def test_supply_chain_excludes_and_reachability_pep263_and_ignored_dirs(tmp_path: Path):
    """Precompiled exclude matcher preserves exact semantics; reachability handles PEP 263 and skips .git."""
    assert _is_excluded(tmp_path / ".git" / "config", (".git", "node_modules"))
    assert _is_excluded(tmp_path / "sub" / "node_modules" / "pkg.json", (".git", "node_modules"))
    assert not _is_excluded(tmp_path / "src" / "app.py", (".git", "node_modules"))
    assert _is_excluded(tmp_path / "foo.pyc", ("*.pyc",))

    # Build minimal project with requirements.txt, a Latin-1 PEP 263 file, and a .git decoy file.
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n", encoding="utf-8")
    latin1_src = b"# -*- coding: latin-1 -*-\n# caf\xe9\nimport requests\n"
    (tmp_path / "app.py").write_bytes(latin1_src)
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "decoy.py").write_text("import flask\n", encoding="utf-8")

    scan = scan_targets([tmp_path], recursive=True)
    reachable, findings = analyze_reachability(scan, [tmp_path])
    assert not any(f.kind == "reachability-source-error" for f in findings)
    assert any("requests" in ref for ref in reachable)
    assert not any("flask" in ref for ref in reachable)


def test_ast_rules_no_deprecation_warnings_cache_invalidation_and_blacklist_priority(
    tmp_path: Path,
):
    """ast_rules emits zero ast.Str DeprecationWarnings, invalidates import caches, and keeps blacklist order."""
    src = (
        "def early():\n"
        "    return 'safe'\n"
        "\n"
        "import boto3\n"
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        "password = 'supersecretpassword123'\n"
        "import pickle\n"
        "pickle.loads(b'data')\n"
    )
    target = tmp_path / "sample.py"
    target.write_text(src, encoding="utf-8")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        mgr = SecurityManager(SecurityConfig(), quiet=True)
        mgr.files_list = [str(target)]
        mgr.run_tests()

    ast_deprecations = [w for w in caught if "ast." in str(w.message)]
    assert ast_deprecations == []
    assert mgr.errors == []
    rule_ids = {issue.test_id for issue in mgr.results}
    assert "B9026" in rule_ids  # AWS access key via shared _collect_strings
    assert "B301" in rule_ids  # pickle.loads via indexed BlacklistManager

    # Verify BlacklistManager preserves priority order when a wildcard precedes an exact entry.
    bm = BlacklistManager()
    first = BlacklistItem("wild", "B991", 0, ["custom.*"], "wild {name}", "HIGH")
    second = BlacklistItem("exact", "B992", 0, ["custom.fn"], "exact {name}", "LOW")
    bm.blacklists["Call"] = [first, second]
    ctx = SimpleNamespace(node=SimpleNamespace(lineno=1, col_offset=0))
    matched = bm.check_blacklist("Call", "custom.fn", ctx)
    assert matched is not None
    assert matched.test_id == "B991"
