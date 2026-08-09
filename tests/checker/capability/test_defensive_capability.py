from __future__ import annotations

from pyflow.checker.capability import (
    CapabilityRegistry,
    CapabilityOperation,
    CapabilityPattern,
    CapabilityReportKind,
    DefensiveCapabilityAnalysis,
    ExternalEffectKind,
    ExternalEffectSummary,
    default_capability_registry,
)


def _findings(source: str):
    return DefensiveCapabilityAnalysis().analyze_source(source).findings


def test_reports_sensitive_callable_after_aliasing() -> None:
    findings = _findings(
        "from subprocess import run\n"
        "execute = run\n"
        "execute(['id'])\n"
    )

    assert any(
        finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.DIRECT
        and finding.location.line == 3
        for finding in findings
    )


def test_tracks_sensitive_callable_through_container() -> None:
    findings = _findings(
        "from subprocess import run\n"
        "handlers = {'task': run}\n"
        "execute = handlers['task']\n"
        "execute(['id'])\n"
    )

    assert any(
        finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.DIRECT
        and finding.location.line == 4
        for finding in findings
    )


def test_open_mode_distinguishes_read_and_write() -> None:
    read = _findings("open('input.txt', 'r')\n")
    write = _findings("open('output.txt', 'w')\n")

    assert {finding.capability for finding in read} == {"file.read"}
    assert {finding.capability for finding in write} == {"file.write"}


def test_reports_escape_into_unanalyzed_external_call() -> None:
    findings = _findings(
        "from subprocess import run\n"
        "import plugin_api\n"
        "plugin_api.register(run)\n"
    )
    assert any(
        finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.INDIRECT
        and "plugin_api.register" in finding.reason
        for finding in findings
    )


def test_reports_sensitive_object_nested_in_escaping_carrier() -> None:
    findings = _findings(
        "from subprocess import run\n"
        "import plugin_api\n"
        "handlers = {'task': run}\n"
        "plugin_api.register(handlers)\n"
    )
    assert any(
        finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.INDIRECT
        and any("carrier field" in step for step in finding.trace)
        for finding in findings
    )


def test_benign_alias_has_no_capability() -> None:
    assert _findings("value = len\nresult = value([1, 2])\n") == []


def test_cross_module_return_preserves_sensitive_identity(tmp_path) -> None:
    (tmp_path / "helper.py").write_text(
        "from subprocess import run\n"
        "def get_runner():\n"
        "    return run\n",
        encoding="utf-8",
    )
    entry = tmp_path / "main.py"
    entry.write_text(
        "from helper import get_runner\n"
        "execute = get_runner()\n"
        "execute(['id'])\n",
        encoding="utf-8",
    )

    result = DefensiveCapabilityAnalysis().analyze_project(
        entry,
        project_path=tmp_path,
    )

    assert result.status == "complete"
    assert any(
        finding.capability == "process.execute"
        and finding.location.filename == str(entry)
        and finding.location.line == 3
        for finding in result.findings
    )


def test_reports_sensitive_callable_returned_from_function() -> None:
    findings = _findings(
        "from subprocess import run\n"
        "def make_runner():\n"
        "    return run\n"
        "exported = make_runner()\n"
    )
    assert any(
        finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.INDIRECT
        and "returned" in finding.reason
        for finding in findings
    )


def test_unresolved_call_makes_result_partial() -> None:
    result = DefensiveCapabilityAnalysis().analyze_source(
        "mapping = globals()\n"
        "unknown = mapping['callback']\n"
        "unknown()\n"
    )
    assert result.status == "partial"
    assert any(diagnostic.kind == "unknown" for diagnostic in result.diagnostics)


def test_supports_hybrid_context_policy() -> None:
    result = DefensiveCapabilityAnalysis(context_policy="1c1o").analyze_source(
        "from subprocess import run\nrun(['id'])\n"
    )
    assert any(finding.capability == "process.execute" for finding in result.findings)


def test_reports_capability_escaping_through_raise() -> None:
    findings = _findings("from subprocess import run\nraise run\n")
    assert any(
        finding.capability == "process.execute"
        and "exception propagation" in finding.reason
        and finding.location.line == 2
        for finding in findings
    )


def test_reports_capability_yielded_by_generator() -> None:
    findings = _findings(
        "from subprocess import run\n"
        "def callbacks():\n"
        "    yield run\n"
        "values = callbacks()\n"
    )
    assert any(
        finding.capability == "process.execute"
        and "yielded" in finding.reason
        and finding.location.line == 3
        for finding in findings
    )


def test_callback_summary_traverses_captured_closure() -> None:
    findings = _findings(
        "from subprocess import run\n"
        "import atexit\n"
        "def register():\n"
        "    capability = run\n"
        "    def callback():\n"
        "        return capability\n"
        "    atexit.register(callback)\n"
        "register()\n"
    )
    assert any(
        finding.capability == "process.execute"
        and "invoked as a callback" in finding.reason
        and finding.escape_kind == "callback_registration"
        and any("closure cell capability" in step for step in finding.trace)
        for finding in findings
    )


def test_external_return_argument_summary_preserves_capability_identity() -> None:
    base = default_capability_registry()
    registry = CapabilityRegistry(
        base.patterns,
        (
            *base.effects,
            ExternalEffectSummary(
                "vendor.identity",
                ExternalEffectKind.RETURN_ARGUMENT,
                (0,),
            ),
        ),
    )
    result = DefensiveCapabilityAnalysis(registry).analyze_source(
        "import vendor\n"
        "from subprocess import run\n"
        "callback = vendor.identity(run)\n"
        "callback(['id'])\n"
    )
    assert any(
        finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.DIRECT
        and finding.location.line == 4
        and finding.access_path == "subprocess.run"
        for finding in result.findings
    )


def test_default_spawn_summary_reports_callback_authority() -> None:
    findings = _findings(
        "from concurrent.futures import Executor\n"
        "from subprocess import run\n"
        "Executor.submit(run)\n"
    )
    assert any(
        finding.capability == "process.execute"
        and "spawned task or process" in finding.reason
        and finding.escape_kind == "task_spawn"
        and finding.location.line == 3
        for finding in findings
    )


def test_stub_library_summary_reports_serialized_authority() -> None:
    findings = _findings(
        "import pickle\n"
        "from subprocess import run\n"
        "pickle.dumps(run)\n"
    )
    assert any(
        finding.capability == "process.execute"
        and "serialized" in finding.reason
        and finding.escape_kind == "serialization"
        and finding.location.line == 3
        for finding in findings
    )


def test_stub_return_effect_preserves_identity() -> None:
    result = DefensiveCapabilityAnalysis().analyze_source(
        "import copy\n"
        "from subprocess import run\n"
        "callback = copy.copy(run)\n"
        "callback(['id'])\n"
    )
    assert any(
        finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.DIRECT
        and finding.access_path == "subprocess.run"
        and finding.location.line == 4
        for finding in result.findings
    )


def test_return_receiver_effect_preserves_fluent_authority() -> None:
    registry = CapabilityRegistry(
        patterns=(
            CapabilityPattern(
                "vendor.builder.execute",
                CapabilityOperation.CALL,
                "vendor.execute",
                "vendor",
            ),
        ),
        effects=(
            ExternalEffectSummary(
                "vendor.builder.configure",
                ExternalEffectKind.RETURN_RECEIVER,
            ),
        ),
    )
    result = DefensiveCapabilityAnalysis(registry).analyze_source(
        "import vendor\n"
        "builder = vendor.builder\n"
        "configured = builder.configure()\n"
        "configured.execute()\n"
    )
    assert any(
        finding.capability == "vendor.execute"
        and finding.report_kind is CapabilityReportKind.DIRECT
        and finding.access_path == "vendor.builder.execute"
        for finding in result.findings
    )
