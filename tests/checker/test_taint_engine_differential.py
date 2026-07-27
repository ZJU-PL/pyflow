"""Shared behavioral corpus for the three taint-style engines."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pyflow.analysis.ifds.api import run_taint_analysis
from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
from pyflow.analysis.taint import TaintPolicy, TaintRule
from pyflow.checker.ast_dataflow.detectors.taint import ASTDataflowTaintDetector
from pyflow.ir.cpg.build import build_cpg
from pyflow.ir.cpg.taint import CPGTaintEngine


class _NoQueries:
    def get_ipa_analysis(self):
        raise RuntimeError("IPA is intentionally unavailable in this corpus")


MODELS = CallModelRegistry(
    [
        CallModel("source", source_kinds=frozenset({"test.source"})),
        CallModel("sink", sink_kinds=frozenset({"test.sink"})),
        CallModel("clean", sanitizer_kinds=frozenset({"*"})),
    ]
)
RULES = (
    TaintRule(
        "TEST-DIFFERENTIAL-TAINT",
        "Differential test flow",
        frozenset({"test.source"}),
        frozenset({"test.sink"}),
    ),
)
POLICY = TaintPolicy.from_call_models(MODELS, RULES)


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("value", True),
        ("clean(value)", False),
    ],
)
def test_taint_engines_agree_on_direct_and_sanitized_flows(
    tmp_path, expression, expected
):
    source = (
        "def source():\n"
        "    return 1\n"
        "def clean(value):\n"
        "    return value\n"
        "def sink(value):\n"
        "    return value\n"
        "def main():\n"
        "    value = source()\n"
        f"    sink({expression})\n"
    )
    target = tmp_path / "differential.py"
    target.write_text(source, encoding="utf-8")

    ast_dataflow_session = SimpleNamespace(
        sources_by_name={"main": source},
        func_to_file={"main": str(target)},
        queries=_NoQueries(),
    )
    ast_dataflow = ASTDataflowTaintDetector(policy=POLICY).analyze(ast_dataflow_session)

    cpg_engine = CPGTaintEngine(build_cpg(source), policy=POLICY)
    cpg = cpg_engine.analyze()

    _session, ifds, _adapter = run_taint_analysis(
        [target],
        function="main",
        call_models=MODELS,
        rules=RULES,
    )

    assert bool(ast_dataflow.findings) is expected
    assert bool(cpg.findings) is expected
    assert bool(ifds.findings) is expected
