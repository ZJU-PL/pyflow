"""Shared behavioral corpus for the three taint-style engines."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pyflow.analysis.ifds.api import run_taint_analysis
from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
from pyflow.analysis.ifds.modeling.registry import load_registry
from pyflow.analysis.taint import TaintPolicy, TaintRule
from pyflow.checker.ast_dataflow.detectors.taint import ASTDataflowTaintDetector
from pyflow.ir.cpg.build import build_cpg
from pyflow.ir.cpg.taint import CPGTaintEngine


class _NoQueries:
    def get_ipa_function_summaries(self):
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


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("subprocess.run(['tool', value])", False),
        ("subprocess.run(f'tool {value}', shell=True)", True),
    ],
)
def test_taint_engines_distinguish_argv_execution_from_shell_execution(
    tmp_path, command, expected
):
    models = CallModelRegistry(
        [
            CallModel("source", source_kinds=frozenset({"user_input"})),
            CallModel(
                "subprocess.run",
                sink_kinds=frozenset({"rce"}),
                cwe="CWE-78",
            ),
        ]
    )
    rules = (
        TaintRule(
            "TEST-SHELL",
            "Untrusted data reaches a command shell",
            frozenset({"user_input"}),
            frozenset({"rce"}),
            cwe="CWE-78",
        ),
    )
    policy = TaintPolicy.from_call_models(models, rules)
    source = (
        "import subprocess\n"
        "def source():\n"
        "    return 1\n"
        "def main():\n"
        "    value = source()\n"
        f"    {command}\n"
    )
    target = tmp_path / "shell_boundary.py"
    target.write_text(source, encoding="utf-8")
    session = SimpleNamespace(
        sources_by_name={"main": source},
        func_to_file={"main": str(target)},
        queries=_NoQueries(),
    )

    ast_dataflow = ASTDataflowTaintDetector(policy=policy).analyze(session)
    cpg = CPGTaintEngine(build_cpg(source), policy=policy).analyze()
    _session, ifds, _adapter = run_taint_analysis(
        [target], function="main", call_models=models, rules=rules
    )

    assert bool(ast_dataflow.findings) is expected
    assert bool(cpg.findings) is expected
    assert bool(ifds.findings) is expected


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        (
            "cursor.execute('SELECT * FROM users WHERE name = ?', (value,))",
            False,
        ),
        ("cursor.execute(f'SELECT * FROM users WHERE name = {value}')", True),
    ],
)
def test_taint_engines_only_treat_sql_statement_as_execute_sink(
    tmp_path, statement, expected
):
    models = CallModelRegistry(
        [
            CallModel("source", source_kinds=frozenset({"user_input"})),
            CallModel(
                "cursor.execute",
                sink_kinds=frozenset({"sql"}),
                sink_arg_positions=frozenset({0, 1}),
                cwe="CWE-89",
            ),
        ]
    )
    rules = (
        TaintRule(
            "TEST-SQL",
            "Untrusted data reaches a SQL statement",
            frozenset({"user_input"}),
            frozenset({"sql"}),
            cwe="CWE-89",
        ),
    )
    policy = TaintPolicy.from_call_models(models, rules)
    source = (
        "def source():\n"
        "    return 'name'\n"
        "def main(cursor):\n"
        "    value = source()\n"
        f"    {statement}\n"
    )
    target = tmp_path / "sql_boundary.py"
    target.write_text(source, encoding="utf-8")
    session = SimpleNamespace(
        sources_by_name={"main": source},
        func_to_file={"main": str(target)},
        queries=_NoQueries(),
    )

    ast_dataflow = ASTDataflowTaintDetector(policy=policy).analyze(session)
    cpg = CPGTaintEngine(build_cpg(source), policy=policy).analyze()
    _session, ifds, _adapter = run_taint_analysis(
        [target], function="main", call_models=models, rules=rules
    )

    assert bool(ast_dataflow.findings) is expected
    assert bool(cpg.findings) is expected
    assert bool(ifds.findings) is expected


def test_taint_engines_apply_registry_archive_member_source_to_loop_target(tmp_path):
    registry = load_registry()
    registry.activate("stdlib", type="taint")
    models = registry.active_models(type="taint")
    policy = registry.as_taint_policy()
    source = (
        "import os\n"
        "def main(archive):\n"
        "    for member in archive.getnames():\n"
        "        os.remove(member)\n"
    )
    target = tmp_path / "archive_loop.py"
    target.write_text(source, encoding="utf-8")
    session = SimpleNamespace(
        sources_by_name={"main": source},
        func_to_file={"main": str(target)},
        queries=_NoQueries(),
    )

    ast_dataflow = ASTDataflowTaintDetector(policy=policy).analyze(session)
    cpg = CPGTaintEngine(build_cpg(source), policy=policy).analyze()
    _session, ifds, _adapter = run_taint_analysis(
        [target],
        function="main",
        call_models=models,
        rules=policy.rules,
    )

    for result in (ast_dataflow, cpg, ifds):
        assert any(finding.cwe == "CWE-22" for finding in result.findings)
