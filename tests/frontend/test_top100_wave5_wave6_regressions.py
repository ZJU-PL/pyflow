"""Regression tests for Wave 5 and Wave 6 top100 fixes across PyFlow subsystems."""

from __future__ import annotations

import ast
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import pytest

from pyflow.analysis.alias.flow_sensitive import HeapAnalysis
from pyflow.analysis.alias.kcfa.bridge import PointerAnalysis
from pyflow.analysis.callgraph.publication import analyze_constraint_callgraph_edges
from pyflow.analysis.typeinfo.core.typesystem import ANY
from pyflow.analysis.typeinfo.query.service import TypeInfoService
from pyflow.analysis.typeinfo.resolution.annotations import BuiltinTypeLookup
from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.checker.ast_dataflow.core.context import AnalysisSession
from pyflow.checker.ast_dataflow.detectors.taint import ASTDataflowTaintDetector
from pyflow.checker.ast_dataflow.solver.cfg import SolverOptions
from pyflow.checker.common.taint import (
    AccessSelector,
    AnalysisUncertainty,
    PrecisionLevel,
    TaintFact,
    TaintLocation,
    TaintOrigin,
    TaintState,
)
from pyflow.cli.lsp import _run_callgraph_analysis
from pyflow.concolic import scan_project
from pyflow.concolic.project.worker import decode_worker_value, encode_worker_value
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.interface_builder import InterfaceBuildOptions, build_interface_from_paths
from pyflow.ir.mir.lowering import lower_file, lower_source
from pyflow.language.modules.project_resolution import ProjectContext
from pyflow.lsp.document_analysis import _comment_suppressions, document_diagnostics
from pyflow.lsp.workspace import SourceIndex
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


def test_kcfa_handles_pep758_and_unparseable_imported_sibling(tmp_path: Path):
    """k-CFA parses PEP 758 except clauses and degrades unparseable imported siblings."""
    broken = tmp_path / "legacy_helper.py"
    broken.write_text("def old():\n    print 'py2'\n", encoding="utf-8")

    entry = tmp_path / "app.py"
    entry.write_text(
        "import legacy_helper\n"
        "\n"
        "def run(flag):\n"
        "    try:\n"
        "        x = [1, 2]\n"
        "    except ValueError, TypeError:\n"
        "        x = [3]\n"
        "    return x\n"
        "\n"
        "result = run(True)\n",
        encoding="utf-8",
    )

    result = PointerAnalysis.from_project(
        entry,
        project_path=tmp_path,
        max_import_depth=1,
        analyze_all_scopes=True,
    ).run()
    assert result is not None


def test_kcfa_iterative_cfg_and_elif_ladder_without_recursion_error():
    """Iterative CFG and three-address if/elif flattening avoid RecursionError on large blocks/ladders."""
    lines = ["def big(x):", "    if x == 0:", "        return 0"]
    for i in range(1, 400):
        lines.append(f"    elif x == {i}:")
        lines.append(f"        return {i}")
    lines.append("    return -1")
    lines.append("out = big(5)")
    source = "\n".join(lines) + "\n"

    result = PointerAnalysis(source, max_iterations=500).run()
    assert result is not None


def test_constraint_callgraph_publication_skips_unparseable_files(tmp_path: Path):
    """analyze_constraint_callgraph_edges skips Python 2 files and falls back cleanly."""
    py2 = tmp_path / "py2_only.py"
    py2.write_text("print 'legacy'\n", encoding="utf-8")
    good = tmp_path / "good.py"
    good.write_text(
        "def helper():\n    return 1\n\ndef entry():\n    return helper()\n", encoding="utf-8"
    )

    # Entry fails to parse -> falls back to parseable sibling
    res_mixed = analyze_constraint_callgraph_edges([py2, good], entry_path=py2, max_iterations=64)
    assert res_mixed.edges is not None

    # All files fail to parse -> returns empty result instead of crashing
    res_all_bad = analyze_constraint_callgraph_edges([py2], entry_path=py2, max_iterations=64)
    assert dict(res_all_bad.edges) == {}
    assert res_all_bad.iterations == 0
    assert res_all_bad.truncated is False


def test_flow_sensitive_alias_nested_try_blocks_and_ref_counts(tmp_path: Path):
    """Nested try blocks with many leaf reads must stay fast and produce accurate points-to graphs."""
    source = (
        "def nested_try(a, b, c):\n"
        "    box = [a, b]\n"
        "    try:\n"
        "        x1 = a\n"
        "        x2 = b\n"
        "        x3 = c\n"
        "        try:\n"
        "            y1 = x1\n"
        "            y2 = x2\n"
        "            try:\n"
        "                z1 = y1\n"
        "                z2 = y2\n"
        "                box.append(z1)\n"
        "                box.append(z2)\n"
        "            except ValueError:\n"
        "                box.append(x3)\n"
        "        except KeyError:\n"
        "            box.append(a)\n"
        "    except Exception:\n"
        "        box.append(c)\n"
        "    return box\n"
    )
    compiler, program, _ = _extract_single_file(tmp_path, "nested_try.py", source)
    analysis = HeapAnalysis()
    result = analysis.analyze(compiler, program)
    assert result is not None
    # Verify single-pass ref-count index matches per-root reference_count_for_root
    heap = analysis._heap
    assert heap is not None
    all_counts = heap._all_reference_counts_by_root()
    for root in {entry.location.root for entry in result.iter_entries()}:
        assert all_counts.get(root, 0) == heap.reference_count_for_root(root)


def test_typeinfo_unparameterized_contextvar_does_not_crash(tmp_path: Path):
    """Calling .get()/.set() on an unparameterized ContextVar must not raise AttributeError."""
    mod = tmp_path / "ctx_mod.py"
    mod.write_text(
        "import contextvars\n"
        "\n"
        "_VAR: contextvars.ContextVar = contextvars.ContextVar('v', default=None)\n"
        "\n"
        "def read_var():\n"
        "    token = _VAR.set('ok')\n"
        "    val = _VAR.get()\n"
        "    _VAR.reset(token)\n"
        "    return val\n",
        encoding="utf-8",
    )
    service = TypeInfoService(ProjectContext(tmp_path))
    service.collect_module("ctx_mod")
    res = service.inference_result("ctx_mod")
    assert res is not None


def test_typeinfo_cyclic_reexports_and_pep758_do_not_recurse(tmp_path: Path):
    """Cyclic re-exports between modules must not trigger RecursionError in _lookup_project_type."""
    (tmp_path / "mod_a.py").write_text(
        "from mod_b import Thing\n"
        "\n"
        "def use_a(x: Thing) -> Thing:\n"
        "    try:\n"
        "        return x\n"
        "    except ValueError, TypeError:\n"
        "        return x\n",
        encoding="utf-8",
    )
    (tmp_path / "mod_b.py").write_text(
        "from mod_a import Thing\n" "\n" "def use_b(y: Thing) -> Thing:\n" "    return y\n",
        encoding="utf-8",
    )
    service = TypeInfoService(ProjectContext(tmp_path))
    service.collect_module("mod_a")
    assert service.inference_result("mod_a") is not None


def test_typeinfo_builtin_lookup_cache_consistency():
    """BuiltinTypeLookup caching preserves behavior both with and without custom fallback."""
    lookup = BuiltinTypeLookup()
    assert lookup("builtins.int") == lookup("int")
    assert lookup("nonexistent.TypeName") is None
    assert lookup("nonexistent.TypeName") is None

    with_fallback = BuiltinTypeLookup(fallback=lambda name: ANY if name == "custom.X" else None)
    assert with_fallback("custom.X") is ANY
    assert with_fallback("int") == lookup("int")


def test_concolic_worker_value_codec_and_bytes_scan_project(tmp_path: Path):
    """Concolic worker value codec round-trips bytes/bytearray/tuple/set/frozenset/complex/non-str dicts."""
    payload = {
        "b": b"\x00\x01hello\xff",
        "ba": bytearray(b"abc"),
        "t": (1, b"two", (3, 4)),
        "s": {1, 2, 3},
        "fs": frozenset({"a", "b"}),
        "c": complex(1.5, -2.5),
        "d": {1: "one", (2, 3): b"bytes"},
    }
    encoded = encode_worker_value(payload)
    round_tripped = decode_worker_value(json.loads(json.dumps(encoded)))
    assert round_tripped == payload
    assert isinstance(round_tripped["b"], bytes)
    assert isinstance(round_tripped["ba"], bytearray)
    assert isinstance(round_tripped["t"], tuple)
    assert isinstance(round_tripped["s"], set)
    assert isinstance(round_tripped["fs"], frozenset)
    assert isinstance(round_tripped["c"], complex)

    target = tmp_path / "bytes_mod.py"
    target.write_text(
        "def parse_frame(data: bytes = b'ping') -> int:\n"
        "    if data.startswith(b'ping'):\n"
        "        return len(data)\n"
        "    return 0\n",
        encoding="utf-8",
    )
    report = scan_project(
        target,
        max_functions=2,
        function_timeout=5.0,
        exploration_options={"max_runs": 4, "max_depth": 4},
    )
    assert report is not None


def test_mir_lowering_inspection_only_preserves_stacks_and_handles_pep758(tmp_path: Path):
    """Unsupported async comprehension inside a loop must not corrupt loop/state stacks."""
    # Pattern from django/core/management/commands/makemessages.py:
    # unsupported construct inside loop + nested function + with statement
    source = (
        "async def run(items, cm):\n"
        "    for item in items:\n"
        "        with cm as handle:\n"
        "            try:\n"
        "                vals = [x async for x in item]\n"
        "            except ValueError, TypeError:\n"
        "                vals = []\n"
        "    return vals\n"
    )
    program = lower_source(source, module_name="sample", import_policy="opaque")
    assert program is not None
    assert program.cfgs


def test_mir_lower_file_opaque_skips_unparseable_imported_sibling(tmp_path: Path):
    """Under import_policy='opaque', an unparseable imported sibling degrades cleanly."""
    (tmp_path / "broken_dep.py").write_text("print 'py2 only'\n", encoding="utf-8")
    entry = tmp_path / "main.py"
    entry.write_text(
        "import broken_dep\n" "\n" "def f():\n" "    return broken_dep\n",
        encoding="utf-8",
    )
    program = lower_file(
        str(entry),
        project_root=str(tmp_path),
        import_policy="opaque",
        max_import_depth=1,
    )
    assert program is not None


def test_lsp_comment_suppressions_and_references_for_uri(tmp_path: Path):
    """Single-pass _comment_suppressions tolerates TokenError and SourceIndex.references_for_uri isolates files."""
    # Unterminated triple-quoted string raises tokenize.TokenError
    broken_text = 'x = 1  # type: ignore\ny = 2  # noqa: F821\nz = """unterminated\n'
    type_ignored, undef_ignored = _comment_suppressions(broken_text)
    assert 0 in type_ignored
    assert 0 in undef_ignored
    assert 1 in undef_ignored

    file_a = tmp_path / "a.py"
    file_b = tmp_path / "b.py"
    src_a = "def foo():\n    return 1\n\ndef main():\n    foo()\n"
    src_b = "def bar():\n    return 2\n\nbar()\n"
    file_a.write_text(src_a, encoding="utf-8")
    file_b.write_text(src_b, encoding="utf-8")

    index = SourceIndex(
        {str(file_a.resolve()): src_a, str(file_b.resolve()): src_b},
        (tmp_path.resolve(),),
    )
    uri_a = file_a.resolve().as_uri()
    uri_b = file_b.resolve().as_uri()
    refs_a = index.references_for_uri(uri_a)
    refs_b = index.references_for_uri(uri_b)
    assert refs_a and all(ref.location.uri == uri_a for ref in refs_a)
    assert refs_b and all(ref.location.uri == uri_b for ref in refs_b)

    # PEP 758 syntax in document_diagnostics must not crash
    pep758_file = tmp_path / "pep758.py"
    pep758_src = (
        "def f():\n"
        "    try:\n"
        "        return 1\n"
        "    except ValueError, TypeError:\n"
        "        return 2\n"
    )
    pep758_file.write_text(pep758_src, encoding="utf-8")
    pep758_index = SourceIndex(
        {str(pep758_file.resolve()): pep758_src},
        (tmp_path.resolve(),),
    )
    diags = document_diagnostics(
        pep758_index,
        pep758_file.resolve().as_uri(),
        include_security=False,
    )
    assert isinstance(diags, list)


def test_cli_query_callgraph_uses_skip_external_and_read_python_source(tmp_path: Path):
    """_run_callgraph_analysis handles PEP 263 encoded files and stays project-local."""
    script = tmp_path / "latin1_mod.py"
    script.write_bytes(
        b"# -*- coding: latin-1 -*-\n"
        b"# caf\xe9\n"
        b"def callee():\n"
        b"    return 42\n"
        b"\n"
        b"def caller():\n"
        b"    return callee()\n"
    )
    graph = _run_callgraph_analysis(script)
    assert any("caller" in k for k in graph)


def test_taint_state_fast_paths_and_batched_havoc_preserve_lattice():
    """Cached hashes, fast-path prefix checks, and batched havoc/write preserve TaintState semantics."""
    loc_a = TaintLocation(("fn", "a"))
    loc_a_attr = loc_a.attribute("x")
    loc_b = TaintLocation(("fn", "b"))
    origin = TaintOrigin("user_input", "f.py", 1, symbol="src")

    assert loc_a.is_prefix_of(loc_a_attr)
    assert not loc_a_attr.is_prefix_of(loc_a)
    assert loc_a.may_overlap(loc_a_attr)
    assert not loc_a.may_overlap(loc_b)
    assert hash(loc_a_attr) == hash(TaintLocation(("fn", "a"), (AccessSelector.attribute("x"),)))

    unc = AnalysisUncertainty(
        code="test-unc",
        message="test",
        level=PrecisionLevel.CONSERVATIVE,
        function="fn",
    )
    state = TaintState()
    havoc_state = state.havoc((loc_a, loc_b), ("sql", "xss"), origin, unc)
    assert havoc_state.is_tainted(loc_a, ("sql",))
    assert havoc_state.is_tainted(loc_b, ("xss",))
    assert unc in havoc_state.uncertainties

    # Repeating with_uncertainty / identical write is a no-op returning self
    assert havoc_state.with_uncertainty(unc) is havoc_state
    copied = havoc_state.copy(loc_a, loc_a_attr, strong=True)
    assert copied.is_tainted(loc_a_attr, ("sql",))
    assert copied.facts_at(loc_a_attr)
    # Provenance node is cached and equal across repeated accesses
    fact = next(iter(copied.facts))
    assert fact.provenance_node is fact.provenance_node


def test_ast_dataflow_detector_interprocedural_summary_after_optimizations(tmp_path: Path):
    """ASTDataflowTaintDetector preserves interprocedural taint flow across summary rounds."""
    src = (
        "import os\n"
        "\n"
        "def passthrough(v):\n"
        "    return v\n"
        "\n"
        "def handler(user_cmd):\n"
        "    cmd = passthrough(user_cmd)\n"
        "    os.system(cmd)\n"
    )
    path = tmp_path / "app.py"
    path.write_text(src, encoding="utf-8")
    src_map = {str(path.resolve()): src}
    sources, filenames, imports = AnalysisSession._collect_sources_and_imports(Program(), src_map)
    session = SimpleNamespace(
        program=Program(),
        sources_by_name=sources,
        func_to_file=filenames,
        file_imports=imports,
        all_source_code=src_map,
        analysis_facts=None,
    )
    result = ASTDataflowTaintDetector(
        solver_options=SolverOptions(max_steps=2000),
        max_summary_rounds=8,
    ).analyze(session)
    assert result.status == "complete"
    assert len(result.findings) >= 1
