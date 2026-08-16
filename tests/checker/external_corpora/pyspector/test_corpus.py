"""Run the adapted PySpector regression corpus against pyflow engines."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pyflow.analysis.ifds.api import run_taint_analysis
from pyflow.analysis.ifds.modeling.calls import (
    CallModel,
    CallModelRegistry,
    TaintModelPort,
    TaintPropagation,
)
from pyflow.analysis.ifds.modeling.registry import load_registry
from pyflow.analysis.taint import TaintPolicy, TaintRule
from pyflow.checker.ast_dataflow.detectors.taint import ASTDataflowTaintDetector
from pyflow.ir.cpg.build import build_cpg
from pyflow.ir.cpg.taint import CPGTaintEngine

from .cases import (
    NON_SINK_CASES,
    PATTERN_CASES,
    TAINT_CASES,
    ModelSpec,
    PatternCase,
    TaintCase,
)


pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


class _NoQueries:
    def get_ipa_function_summaries(self):
        raise RuntimeError("IPA is intentionally unavailable in this corpus")


def _call_model(spec: ModelSpec) -> CallModel:
    propagations = frozenset()
    if spec.propagate_all_to_return:
        propagations = frozenset(
            {
                TaintPropagation(
                    TaintModelPort("all"),
                    TaintModelPort("return"),
                )
            }
        )
    return CallModel(
        spec.name,
        source_kinds=frozenset(spec.sources),
        sink_kinds=frozenset(spec.sinks),
        sanitizer_kinds=frozenset(spec.sanitizers),
        taint_propagations=propagations,
        sink_arg_positions=frozenset(spec.sink_positions),
        sink_receiver=spec.sink_receiver,
    )


def _configuration(case: TaintCase):
    models = CallModelRegistry(_call_model(model) for model in case.models)
    rules = tuple(
        TaintRule(
            rule.rule_id,
            f"PySpector regression: {case.name}",
            frozenset(rule.sources),
            frozenset(rule.sinks),
        )
        for rule in case.rules
    )
    return models, rules, TaintPolicy.from_call_models(models, rules)


def _run_taint_case(case: TaintCase, engine: str, tmp_path) -> frozenset[str]:
    models, rules, policy = _configuration(case)
    target = tmp_path / f"{case.name}.py"
    target.write_text(case.source, encoding="utf-8")

    if engine == "ast-dataflow":
        session = SimpleNamespace(
            sources_by_name={"main": case.source},
            func_to_file={"main": str(target)},
            queries=_NoQueries(),
        )
        result = ASTDataflowTaintDetector(policy=policy).analyze(session)
        return frozenset(finding.rule_id for finding in result.findings)

    if engine == "cpg":
        result = CPGTaintEngine(build_cpg(case.source), policy=policy).analyze()
        return frozenset(finding.effective_rule_id for finding in result.findings)

    if engine == "ifds":
        _session, result, _adapter = run_taint_analysis(
            [target],
            function="main",
            call_models=models,
            rules=rules,
        )
        return frozenset(finding.rule.rule_id for finding in result.findings)

    raise AssertionError(f"unknown corpus engine: {engine}")


TAINT_PARAMETERS = [
    pytest.param(case, engine, id=f"{engine}-{case.name}")
    for case in TAINT_CASES
    for engine in case.engines
]


@pytest.mark.parametrize(("case", "engine"), TAINT_PARAMETERS)
def test_pyspector_taint_regression_corpus(case, engine, tmp_path):
    assert _run_taint_case(case, engine, tmp_path) == case.expected_rule_ids


@pytest.mark.parametrize("case", NON_SINK_CASES, ids=lambda case: case.name)
def test_pyspector_disabled_generic_sinks_remain_non_sinks(case, tmp_path):
    registry = load_registry()
    registry.activate("stdlib", type="taint")
    models = registry.active_models(type="taint")
    policy = registry.as_taint_policy()
    source = (
        "def source():\n"
        "    return input()\n"
        "def main():\n"
        "    value = source()\n"
        f"    {case.statement}\n"
    )
    target = tmp_path / f"non_sink_{case.name}.py"
    target.write_text(source, encoding="utf-8")

    session = SimpleNamespace(
        sources_by_name={"main": source},
        func_to_file={"main": str(target)},
        queries=_NoQueries(),
    )
    ast_result = ASTDataflowTaintDetector(policy=policy).analyze(session)
    cpg_result = CPGTaintEngine(build_cpg(source), policy=policy).analyze()
    _session, ifds_result, _adapter = run_taint_analysis(
        [target],
        function="main",
        call_models=models,
        rules=policy.rules,
    )

    assert ast_result.findings == ()
    assert cpg_result.findings == ()
    assert ifds_result.findings == ()


@pytest.mark.parametrize("case", PATTERN_CASES, ids=lambda case: case.name)
def test_pyspector_fast_scanner_regression_corpus(case: PatternCase, scan):
    result = scan(case.source, filename=case.filename)
    ids = set(result.ids())
    assert case.required_ids <= ids
    assert case.forbidden_ids.isdisjoint(ids)
