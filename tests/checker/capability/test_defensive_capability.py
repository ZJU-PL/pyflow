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


def test_open_method_chain_has_no_unknown_builtin_noise() -> None:
    result = DefensiveCapabilityAnalysis().analyze_source("open('input.txt').read()\n")

    assert result.status == "complete"
    assert not any("unknown_builtin" in diagnostic.message for diagnostic in result.diagnostics)
    assert any(
        finding.capability == "file.read" and finding.report_kind is CapabilityReportKind.DIRECT
        for finding in result.findings
    )


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


def test_package_relative_imports_are_analyzed(tmp_path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    views = package / "views.py"
    views.write_text(
        "import subprocess\n" "def run_it(command):\n" "    subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    entry = package / "main.py"
    entry.write_text(
        "from . import views\n"
        'views.run_it("ls")\n'
        "def later():\n"
        "    from . import views as v\n"
        '    v.run_it("id")\n'
        "later()\n",
        encoding="utf-8",
    )

    result = DefensiveCapabilityAnalysis().analyze_project(
        entry,
        project_path=tmp_path,
    )

    assert result.status == "complete", [d.message for d in result.diagnostics]
    assert any(
        finding.capability == "process.execute"
        and finding.location.filename == str(views)
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


def test_unknown_diagnostic_uses_source_filename_instead_of_entry_scope(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("value = 1\nvalue()\n")
    result = DefensiveCapabilityAnalysis().analyze_project(path)
    diagnostic = next(item for item in result.diagnostics if "callee_empty:" in item.message)
    assert f"{path.resolve()}:2:0" in diagnostic.message
    assert "__main__:" not in diagnostic.message
    assert diagnostic.location.filename == str(path.resolve())
    assert diagnostic.location.line == 2


def test_pathlib_import_does_not_expand_to_every_class_method() -> None:
    result = DefensiveCapabilityAnalysis().analyze_source("from pathlib import Path\n")

    assert result.findings == []


def test_pathlib_instance_calls_report_file_access() -> None:
    result = DefensiveCapabilityAnalysis().analyze_source(
        "from pathlib import Path\n" 'Path("input.txt").read_text()\n'
    )

    assert any(
        finding.capability == "file.read"
        and finding.report_kind is CapabilityReportKind.DIRECT
        and finding.access_path == "pathlib.Path.read_text"
        and finding.location.line == 2
        for finding in result.findings
    )
    assert not any(
        finding.access_path.startswith("pathlib.Path.cwd") for finding in result.findings
    )


def test_os_environ_item_and_get_are_environment_reads() -> None:
    result = DefensiveCapabilityAnalysis().analyze_source(
        "import os\n"
        'first = os.environ["SECRET_TOKEN"]\n'
        'second = os.environ.get("OTHER_TOKEN")\n'
    )

    direct = [
        finding
        for finding in result.findings
        if finding.capability == "information.environment"
        and finding.report_kind is CapabilityReportKind.DIRECT
    ]
    assert {finding.location.line for finding in direct} >= {2, 3}
    assert all(finding.location.line != 0 for finding in result.findings)


def test_importing_a_module_is_not_itself_a_capability() -> None:
    result = DefensiveCapabilityAnalysis().analyze_source("import requests\nimport sys\n")

    assert result.findings == []


def test_added_process_and_network_models_are_detected() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import asyncio\n"
        "import aiohttp\n"
        "import os\n"
        'asyncio.create_subprocess_exec("id")\n'
        'asyncio.create_subprocess_shell("id")\n'
        'aiohttp.ClientSession().get("https://example.test")\n'
        'os.popen("id")\n'
        'os.execv("/bin/sh", ["sh"])\n'
    )

    direct = {
        (finding.capability, finding.access_path)
        for finding in result.findings
        if finding.report_kind is CapabilityReportKind.DIRECT
    }
    assert ("process.execute", "asyncio.create_subprocess_exec") in direct
    assert ("process.execute", "asyncio.create_subprocess_shell") in direct
    assert ("network.io", "aiohttp.ClientSession.<return>.get") in direct
    assert ("process.execute", "os.popen") in direct
    assert ("process.execute", "os.execv") in direct


def test_broad_library_prefixes_do_not_report_non_io_helpers() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import tempfile\n"
        "import shutil\n"
        "import requests\n"
        "import httpx\n"
        "tempfile.gettempdir()\n"
        'shutil.copystat("a", "b")\n'
        'shutil.copymode("a", "b")\n'
        'requests.utils.quote("x")\n'
        'httpx.URL("https://example.test")\n'
    )

    assert not any(
        finding.capability in {"file.write", "network.io"} for finding in result.findings
    )


def test_explicit_temp_and_copy_helpers_remain_file_writes() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import tempfile\n"
        "import shutil\n"
        "tempfile.NamedTemporaryFile()\n"
        'shutil.copy("a", "b")\n'
    )

    assert {
        finding.access_path
        for finding in result.findings
        if finding.capability == "file.write" and finding.report_kind is CapabilityReportKind.DIRECT
    } == {"tempfile.NamedTemporaryFile", "shutil.copy"}


def test_with_body_capabilities_are_analyzed() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import subprocess\n"
        "def use():\n"
        "    with open('input.txt') as stream:\n"
        "        stream.read()\n"
        "        subprocess.run(['id'])\n"
        "use()\n"
    )

    assert any(
        finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.DIRECT
        and finding.location.line == 5
        for finding in result.findings
    )


@pytest.mark.parametrize(
    "source, expected",
    [
        ("from pathlib import Path\nPath('out.txt').open('w')\n", {"file.write"}),
        ("from pathlib import Path\nPath('out.txt').open('rb')\n", {"file.read"}),
        ("from pathlib import Path\nPath('out.txt').open(mode='a')\n", {"file.write"}),
        ("from pathlib import Path\nPath('out.txt').open()\n", {"file.read"}),
        ("from pathlib import Path\nPath.open(Path('out.txt'), 'w')\n", {"file.write"}),
    ],
)
def test_pathlib_open_respects_mode(source, expected) -> None:
    findings = _findings(source, report_public_exports=False)

    assert {
        finding.capability
        for finding in findings
        if finding.access_path == "pathlib.Path.open"
        and finding.report_kind is CapabilityReportKind.DIRECT
    } == expected


def test_class_body_capability_assignments_are_not_calls() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import signal\n"
        "import socket\n"
        "import subprocess\n"
        "class Handlers:\n"
        "    sock = socket.socket\n"
        "    stop = signal.signal\n"
        "    spawn = subprocess.Popen\n"
    )

    assert result.findings == []
    assert result.status == "complete"


def test_descriptor_access_reports_one_direct_finding() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import subprocess\n"
        "class Handler:\n"
        "    @property\n"
        "    def run(self):\n"
        "        return subprocess.run\n"
        "Handler().run(['id'])\n"
    )

    direct = [
        finding
        for finding in result.findings
        if finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.DIRECT
    ]
    assert len(direct) == 1
    assert direct[0].access_path == "subprocess.run"
    assert direct[0].location.line == 6


def test_print_does_not_make_analysis_partial() -> None:
    result = DefensiveCapabilityAnalysis().analyze_source("print('hello')\nprint('world')\n")

    assert result.status == "complete"
    assert result.diagnostics == []


def test_attribute_access_ending_in_open_does_not_crash() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import socket\n"
        "s = socket.socket()\n"
        "x = s.open\n"
        "from pathlib import Path\n"
        "p = Path('test.txt')\n"
        "y = p.open\n"
    )
    assert isinstance(result.findings, list)


def test_global_and_builtin_not_treated_as_leaking_closure_cell() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import external_decorator\n"
        "def decorated():\n"
        "    with open('test.txt') as f:\n"
        "        return f.read()\n"
        "external_decorator.register(decorated)\n"
    )
    # The external registration should not report builtins.open leaking as a closure cell
    leaked = [
        finding
        for finding in result.findings
        if finding.report_kind is CapabilityReportKind.INDIRECT and "closure cell" in finding.reason
    ]
    assert leaked == []


def test_builtin_operations_do_not_report_indirect_leaks() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "from subprocess import run\n"
        "commands = [run]\n"
        "count = len(commands)\n"
        "check = isinstance(commands, list)\n"
        "for cmd in commands:\n"
        "    pass\n"
    )
    indirect_builtins = [
        finding
        for finding in result.findings
        if finding.report_kind is CapabilityReportKind.INDIRECT
        and any(
            f"builtins.{name}" in finding.reason for name in ("len", "iter", "next", "isinstance")
        )
    ]
    assert indirect_builtins == []


def test_pathlib_mutations_reported_as_file_writes() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "from pathlib import Path\n"
        "p = Path('test.txt')\n"
        "p.unlink()\n"
        "p.mkdir()\n"
        "p.rmdir()\n"
        "p.touch()\n"
        "p.rename('new.txt')\n"
        "p.replace('new2.txt')\n"
    )
    writes = [
        finding
        for finding in result.findings
        if finding.capability == "file.write" and finding.report_kind is CapabilityReportKind.DIRECT
    ]
    assert len(writes) == 6


def test_urllib3_reported_as_network_io() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import urllib3\n"
        "http = urllib3.PoolManager()\n"
        "http.request('GET', 'https://example.test')\n"
    )
    network_findings = [
        finding
        for finding in result.findings
        if finding.capability == "network.io" and finding.report_kind is CapabilityReportKind.DIRECT
    ]
    assert len(network_findings) >= 1


def test_platform_return_string_methods_not_flagged() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import platform\n" "name = platform.system()\n" "clean = name.strip().lower().split()\n"
    )
    direct_findings = [
        finding for finding in result.findings if finding.report_kind is CapabilityReportKind.DIRECT
    ]
    # Only platform.system should be flagged as information.system, not .strip/.lower/.split
    assert len(direct_findings) == 1
    assert direct_findings[0].access_path == "platform.system"


def test_async_with_lowering_propagates_capability() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import asyncio\n"
        "import subprocess\n"
        "class AsyncRunner:\n"
        "    async def __aenter__(self):\n"
        "        return subprocess.run\n"
        "    async def __aexit__(self, *args):\n"
        "        pass\n"
        "async def main():\n"
        "    async with AsyncRunner() as r:\n"
        "        r(['ls'])\n"
        "asyncio.run(main())\n"
    )
    assert any(
        finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.DIRECT
        for finding in result.findings
    )


def test_os_putenv_and_unsetenv_reported_as_environment_calls() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import os\n" "os.putenv('KEY', 'VAL')\n" "os.unsetenv('KEY')\n"
    )
    env_findings = [
        finding
        for finding in result.findings
        if finding.capability == "information.environment"
        and finding.report_kind is CapabilityReportKind.DIRECT
    ]
    assert len(env_findings) == 2


def test_os_environ_delitem_reported_as_environment_call() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import os\n" "del os.environ['KEY']\n"
    )
    env_findings = [
        finding
        for finding in result.findings
        if finding.capability == "information.environment"
        and finding.access_path == "os.environ.__delitem__"
    ]
    assert len(env_findings) >= 1
    assert any(finding.report_kind is CapabilityReportKind.DIRECT for finding in env_findings)


def test_sys_path_modifications_reported() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import sys\n" "sys.path.append('/custom/path')\n" "sys.path = ['/other/path']\n"
    )
    path_findings = [
        finding
        for finding in result.findings
        if finding.capability == "module.loader_mutation"
        and finding.report_kind is CapabilityReportKind.DIRECT
    ]
    assert len(path_findings) >= 2


def test_functools_partial_propagates_capability_without_spurious_escape() -> None:
    result = DefensiveCapabilityAnalysis(report_public_exports=False).analyze_source(
        "import subprocess\n"
        "from functools import partial\n"
        "runner = partial(subprocess.run, ['ls'])\n"
        "runner()\n"
    )
    direct = [
        f
        for f in result.findings
        if f.capability == "process.execute" and f.report_kind is CapabilityReportKind.DIRECT
    ]
    assert len(direct) >= 1
    assert direct[0].location.line == 4
    # Ensure synthetic __init__ call did not leak as an unanalyzed escape
    escapes = [
        f
        for f in result.findings
        if f.report_kind is CapabilityReportKind.INDIRECT
        and "functools.partial.__init__" in f.reason
    ]
    assert len(escapes) == 0
