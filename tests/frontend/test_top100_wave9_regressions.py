"""Regression tests for Wave 9 top-100 compatibility fixes."""

from __future__ import annotations

import ast
from pathlib import Path

_PEP758_AND_PEP810_SOURCE = (
    "lazy import os\n"
    "lazy import requests\n"
    "lazy from pathlib import Path\n"
    "\n"
    "def helper(value: int) -> int:\n"
    "    try:\n"
    "        return int(value)\n"
    "    except ValueError, TypeError:\n"
    "        return 0\n"
    "\n"
    "def run(cmd: str) -> int:\n"
    "    x = 1 + 2\n"
    "    os.system(cmd)\n"
    "    return helper(x)\n"
)


def test_source_compat_supports_pep758_pep810_py2_and_bytes():
    """parse_python_source normalizes PEP 758, PEP 810 lazy imports, Py2 except, and bytes."""
    from pyflow.language.source_compat import (
        normalize_legacy_python_syntax,
        parse_python_source,
    )

    tree = parse_python_source(_PEP758_AND_PEP810_SOURCE, filename="modern.py")
    func_lines = {node.name: node.lineno for node in tree.body if isinstance(node, ast.FunctionDef)}
    # Normalization must preserve exact line numbers.
    assert func_lines == {"helper": 5, "run": 11}

    # Bytes input with PEP 263 coding cookie + PEP 758 / PEP 810 syntax
    raw_bytes = (
        "# -*- coding: utf-8 -*-\n"
        "lazy import json\n"
        "def f():\n"
        "    try:\n"
        "        return json.loads('{}')\n"
        "    except KeyError, ValueError:\n"
        "        return {}\n"
    ).encode("utf-8")
    btree = parse_python_source(raw_bytes, filename="bytes_mod.py")
    assert any(isinstance(n, ast.Import) for n in btree.body)

    # Python 2 `except E, e:` still normalizes to `except E as e:`
    py2_norm = normalize_legacy_python_syntax("try:\n    x()\nexcept ValueError, err:\n    pass\n")
    assert "except ValueError as err:" in py2_norm


def test_pep758_and_pep810_supported_across_subsystems(tmp_path: Path):
    """Optimizer, ast_based CG, LSP, ast_rules, supply_chain, concolic, typeinfo, kcfa parse PEP 758/810."""
    from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRModule
    from pyflow.analysis.callgraph.ast_based import extract_call_graph
    from pyflow.analysis.typeinfo.inference.engine import _cached_parse
    from pyflow.analysis.typeinfo.query.evidence import collect_python_type_info
    from pyflow.checker.ast_rules.core.config import SecurityConfig
    from pyflow.checker.ast_rules.core.manager import SecurityManager
    from pyflow.checker.supply_chain import analyze_reachability, scan_targets
    from pyflow.concolic import discover_operations, discover_targets
    from pyflow.lsp.workspace import SourceIndex
    from pyflow.optimization.source import optimize_source

    mod_path = tmp_path / "modern_mod.py"
    mod_path.write_text(_PEP758_AND_PEP810_SOURCE, encoding="utf-8")

    # 1. Source optimizer produces syntactically valid Python with constant folding
    opt = optimize_source(_PEP758_AND_PEP810_SOURCE, filename=str(mod_path), level=2)
    ast.parse(opt.source, filename=str(mod_path))
    assert opt.constant_folds >= 1

    # 2. AST-based callgraph extracts real edges instead of returning only module node
    cg = extract_call_graph(_PEP758_AND_PEP810_SOURCE, module_name="modern_mod")
    assert "modern_mod.run" in cg.get()
    assert "modern_mod.helper" in cg.get()["modern_mod.run"]

    # 3. LSP SourceIndex indexes symbols and emits no false syntax diagnostics
    idx = SourceIndex({str(mod_path): _PEP758_AND_PEP810_SOURCE}, [str(tmp_path)])
    fi = idx._file_indices[str(mod_path.resolve())]
    assert fi.module is not None
    assert any(sym.name == "helper" for sym in fi.symbols)
    assert idx.diagnostics_for_uri(mod_path.as_uri()) == []

    # 4. ast_rules SecurityManager scans without skipping and reports os.system
    mgr = SecurityManager(SecurityConfig())
    mgr.discover_files([str(mod_path)])
    mgr.run_tests()
    assert mgr.skipped == []
    assert len(mgr.get_issue_list()) >= 1

    # 5. supply_chain reachability inspects imports without false source errors
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    scan = scan_targets([tmp_path])
    reachable, reach_findings = analyze_reachability(scan, [tmp_path])
    assert "pkg:pypi/requests@2.31.0" in reachable
    assert not any(f.kind == "reachability-source-error" for f in reach_findings)

    # 6. concolic target & operation discovery finds both functions and calls
    targets = discover_targets(mod_path)
    assert {t.entry for t in targets} == {"helper", "run"}
    ops = discover_operations(mod_path)
    assert len(ops.operations) >= 1

    # 7. typeinfo parser & evidence collector succeed
    assert isinstance(_cached_parse(_PEP758_AND_PEP810_SOURCE, str(mod_path)), ast.Module)
    ev = collect_python_type_info(_PEP758_AND_PEP810_SOURCE, filename=str(mod_path))
    assert ev is not None

    # 8. k-CFA IRModule.load_module succeeds
    ir_mod = IRModule.load_module("modern_mod", str(mod_path))
    assert ir_mod.name == "modern_mod"
