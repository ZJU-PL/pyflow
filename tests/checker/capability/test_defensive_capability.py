from __future__ import annotations

import pytest

from pyflow.analysis.alias.kcfa import PointerAnalysis
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


def _findings(source: str, **options):
    return DefensiveCapabilityAnalysis(**options).analyze_source(source).findings


def test_reports_sensitive_callable_after_aliasing() -> None:
    findings = _findings("from subprocess import run\n" "execute = run\n" "execute(['id'])\n")

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


@pytest.mark.parametrize("callee", ["open", "io.open"])
@pytest.mark.parametrize(
    "mode, expected",
    [
        ("r", {"file.read"}),
        ("w", {"file.write"}),
        ("a", {"file.write"}),
        ("x", {"file.write"}),
        ("r+", {"file.read", "file.write"}),
        ("w+", {"file.read", "file.write"}),
    ],
)
def test_open_keyword_modes(callee, mode, expected) -> None:
    findings = _findings(f"import io\n{callee}('out.txt', mode={mode!r})\n")
    assert {finding.capability for finding in findings if finding.location.line == 2} == expected


@pytest.mark.parametrize(
    "source",
    [
        "def use(mode):\n    open('out.txt', mode=mode)\nuse('r')\nuse('w')\n",
        "import vendor\nopen('out.txt', mode=vendor.mode)\n",
        "import vendor\nopen('out.txt', **vendor.options)\n",
        "open(*('out.txt', 'w'))\n",
        "import vendor\nmode = 'r' if vendor.flag else vendor.mode\nopen('out.txt', mode=mode)\n",
    ],
)
def test_uncertain_open_modes_report_read_and_write(source) -> None:
    findings = _findings(source, k=0, report_public_exports=False)
    assert {
        finding.capability
        for finding in findings
        if finding.access_path == "builtins.open"
        and finding.report_kind is CapabilityReportKind.DIRECT
    } == {"file.read", "file.write"}


def test_reports_escape_into_unanalyzed_external_call() -> None:
    findings = _findings(
        "from subprocess import run\n" "import plugin_api\n" "plugin_api.register(run)\n"
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
        "from subprocess import run\n" "def get_runner():\n" "    return run\n",
        encoding="utf-8",
    )
    entry = tmp_path / "main.py"
    entry.write_text(
        "from helper import get_runner\n" "execute = get_runner()\n" "execute(['id'])\n",
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
        "exported = make_runner()\n",
        report_callable_boundaries=True,
    )
    assert any(
        finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.INDIRECT
        and "returned" in finding.reason
        for finding in findings
    )


def test_unresolved_call_makes_result_partial() -> None:
    result = DefensiveCapabilityAnalysis().analyze_source(
        "mapping = globals()\n" "unknown = mapping['callback']\n" "unknown()\n"
    )
    assert result.status == "partial"
    assert any(diagnostic.kind == "unknown" for diagnostic in result.diagnostics)


def test_unresolved_call_diagnostic_includes_source_location() -> None:
    result = DefensiveCapabilityAnalysis().analyze_source("missing()\n")
    diagnostic = next(
        diagnostic
        for diagnostic in result.diagnostics
        if diagnostic.message.startswith("unresolved call target:")
    )
    assert result.status == "partial"
    assert diagnostic.kind == "unknown"
    assert diagnostic.location is not None
    assert diagnostic.location.line == 1


def test_local_return_preserves_identity_without_callable_boundary_report() -> None:
    findings = _findings(
        "from subprocess import run\n"
        "def make_runner():\n"
        "    return run\n"
        "_execute = make_runner()\n"
        "_execute(['id'])\n",
        report_public_exports=False,
    )
    assert any(
        finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.DIRECT
        and finding.location.line == 5
        for finding in findings
    )
    assert not any(finding.escape_kind == "return" for finding in findings)


def test_external_transfer_is_reported_after_internal_return() -> None:
    findings = _findings(
        "from subprocess import run\n"
        "import plugin_api\n"
        "def make_runner():\n"
        "    return run\n"
        "plugin_api.register(make_runner())\n",
        report_public_exports=False,
    )
    assert any(
        finding.escape_kind == "argument"
        and finding.boundary == "plugin_api.register"
        and finding.capability == "process.execute"
        for finding in findings
    )
    assert not any(finding.escape_kind == "return" for finding in findings)


def test_heap_is_indexed_once_for_multiple_cyclic_carrier_transfers() -> None:
    pointer = PointerAnalysis(
        "from subprocess import run\n"
        "import plugin_api\n"
        "carrier = {'task': run}\n"
        "carrier['self'] = carrier\n"
        "plugin_api.first(carrier)\n"
        "plugin_api.second(carrier)\n"
    ).run()

    class CountingEnvironment(dict):
        scans = 0

        def items(self):
            self.scans += 1
            return super().items()

    environment = CountingEnvironment(pointer.state._env)
    pointer.state._env = environment
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_pointer_result(
        pointer
    )
    transfers = [finding for finding in result.findings if finding.escape_kind == "argument"]
    assert {finding.boundary for finding in transfers} == {"plugin_api.first", "plugin_api.second"}
    assert all(any("carrier field" in step for step in finding.trace) for finding in transfers)
    assert environment.scans == 1


def test_supports_hybrid_context_policy() -> None:
    result = DefensiveCapabilityAnalysis(context_policy="1c1o").analyze_source(
        "from subprocess import run\nrun(['id'])\n"
    )
    assert any(finding.capability == "process.execute" for finding in result.findings)


def test_reports_capability_escaping_through_raise() -> None:
    findings = _findings("from subprocess import run\nraise run\n", report_callable_boundaries=True)
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
        "values = callbacks()\n",
        report_callable_boundaries=True,
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
    findings = _findings("import pickle\n" "from subprocess import run\n" "pickle.dumps(run)\n")
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
