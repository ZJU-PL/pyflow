"""Regression tests for capability-analysis coverage and identity gaps."""

from __future__ import annotations

import json
from argparse import Namespace

import pytest

from pyflow.checker.capability import (
    CapabilityReportKind,
    CapabilityViolation,
    DefensiveCapabilityAnalysis,
    capability_for_audit_event,
)


def _result(source: str, **options):
    options.setdefault("report_public_exports", False)
    return DefensiveCapabilityAnalysis(**options).analyze_source(source)


def _capabilities(result, *, report_kind=None) -> set[str]:
    return {
        finding.capability
        for finding in result.findings
        if report_kind is None or finding.report_kind is report_kind
    }


def test_match_case_bodies_are_analyzed() -> None:
    result = _result(
        "def f(x):\n"
        "    match x:\n"
        "        case 1:\n"
        "            return open('a').read()\n"
        "    return ''\n"
        "f(1)\n"
    )

    assert "file.read" in _capabilities(result)


def test_match_binds_capture_names() -> None:
    result = _result(
        "def f(pair):\n"
        "    match pair:\n"
        "        case (path, mode):\n"
        "            return open(path, mode).read()\n"
        "    return ''\n"
        "f(('a', 'r'))\n"
    )

    assert "file.read" in _capabilities(result)


def test_try_star_body_and_handler_are_analyzed() -> None:
    source = (
        "try:\n"
        "    raise ExceptionGroup('g', [ValueError()])\n"
        "except* ValueError:\n"
        "    open('a').read()\n"
        "finally:\n"
        "    open('b').write('x')\n"
    )
    result = _result(source)

    assert {"file.read", "file.write"} <= _capabilities(result)


@pytest.mark.parametrize(
    "source",
    [
        "def open(x):\n    return x\nopen('hello')\n",
        "def compile(x):\n    return x\ncompile('y')\n",
        "open = print\nopen('hello')\n",
    ],
)
def test_module_level_builtin_shadowing_is_not_reported_as_builtin(source: str) -> None:
    result = _result(source)

    assert result.findings == []
    assert result.status == "complete"


def test_shadowed_open_object_is_not_reported_as_builtin_open() -> None:
    result = _result("open = object()\nopen.read()\n")

    assert result.findings == []


def test_os_open_keeps_its_own_identity() -> None:
    result = _result("import os\nos.open('/etc/passwd', os.O_RDONLY)\n")

    paths = {finding.access_path for finding in result.findings}
    assert "os.open" in paths
    assert "builtins.open" not in paths


def test_io_open_keeps_its_own_identity() -> None:
    result = _result("import io\nio.open('out.txt', 'w')\n")

    assert {finding.access_path for finding in result.findings} == {"io.open"}
    assert _capabilities(result) == {"file.write"}


def test_pathlib_slash_chain_keeps_path_identity() -> None:
    result = _result("from pathlib import Path\n(Path('a') / 'b').read_text()\n")

    assert "file.read" in _capabilities(result)
    assert result.status == "complete"


def test_pathlib_parent_and_with_suffix_keep_identity() -> None:
    result = _result(
        "from pathlib import Path\n"
        "p = Path('a')\n"
        "p.parent.joinpath('b').write_text('x')\n"
        "p.with_suffix('.txt').read_text()\n"
    )

    assert {"file.write", "file.read"} <= _capabilities(result)


def test_open_handle_transfer_is_reported() -> None:
    result = _result("import plugin_api\nwith open('x', 'w') as f:\n    plugin_api.register(f)\n")

    indirect = [
        finding
        for finding in result.findings
        if finding.report_kind is CapabilityReportKind.INDIRECT
    ]
    assert [finding.capability for finding in indirect] == ["file.write"]
    assert indirect[0].access_path == "builtins.open.<return>"


def test_handle_method_call_is_reported() -> None:
    result = _result("fh = open('x', 'w')\nfh.write('y')\n")

    assert any(
        finding.capability == "file.write" and finding.access_path == "builtins.open.<return>.write"
        for finding in result.findings
    )


def test_scalar_return_of_read_text_is_not_a_handle() -> None:
    result = _result(
        "import plugin_api\n"
        "from pathlib import Path\n"
        "plugin_api.register(Path('a').read_text())\n"
    )

    assert not any(
        finding.report_kind is CapabilityReportKind.INDIRECT for finding in result.findings
    )


def test_bound_method_transfer_exposes_instance_capability() -> None:
    source = (
        "import os\n"
        "import plugin_api\n"
        "class Runner:\n"
        "    def __init__(self):\n"
        "        self.cb = os.system\n"
        "    def run(self):\n"
        "        return self.cb('ls')\n"
        "plugin_api.register(Runner().run)\n"
    )
    result = _result(source)

    assert "process.execute" in _capabilities(result, report_kind=CapabilityReportKind.INDIRECT)


def test_class_attribute_capability_escapes_with_instance() -> None:
    source = (
        "import os\n"
        "import plugin_api\n"
        "class Runner:\n"
        "    cap = os.system\n"
        "    def run(self, arg):\n"
        "        return self.cap(arg)\n"
        "plugin_api.register(Runner())\n"
    )
    result = _result(source)

    assert "process.execute" in _capabilities(result, report_kind=CapabilityReportKind.INDIRECT)


def test_unresolved_callback_reports_argument_escape() -> None:
    source = (
        "def inner(fh, cb):\n"
        "    cb(fh)\n"
        "def outer():\n"
        "    inner(open('x'), object().__class__)\n"
        "outer()\n"
    )
    result = _result(source)

    assert any(
        finding.report_kind is CapabilityReportKind.INDIRECT
        and finding.boundary == "unresolved call"
        for finding in result.findings
    )


def test_coverage_reports_solver_completeness() -> None:
    result = _result("import plugin_api\nplugin_api.register(1)\n")

    assert result.coverage["solver_complete"] is False
    assert result.coverage["semantic_complete"] is False
    # Unmodelled native calls do not hide a transfer by themselves.
    assert result.status == "complete"
    assert any(diagnostic.kind == "note" for diagnostic in result.diagnostics)


def test_coverage_is_serialized() -> None:
    payload = _result("open('x')\n").to_dict()

    assert payload["coverage"]["fixpoint_complete"] is True
    assert payload["coverage"]["stop_reason"] == "fixpoint"
    assert payload["statistics"]["coverage"]["solver_complete"] is True


def test_runtime_guard_classifies_mutating_audit_events() -> None:
    assert capability_for_audit_event("os.chmod", ("x", 0o600)) == "file.metadata"
    assert capability_for_audit_event("os.symlink", ("a", "b")) == "file.write"
    assert capability_for_audit_event("os.link", ("a", "b")) == "file.write"
    assert capability_for_audit_event("os.truncate", ("a", 0)) == "file.write"
    assert capability_for_audit_event("os.utime", ("a", None)) == "file.metadata"
    assert capability_for_audit_event("os.killpg", (1, 0)) == "process.control"
    assert capability_for_audit_event("shutil.copyfile", ("a", "b")) == "file.write"
    assert capability_for_audit_event("tempfile.mkdtemp", ()) == "file.write"
    assert capability_for_audit_event("mmap.__new__", (-1, 1)) == "native.access"


def test_denied_capability_is_not_catchable_as_oserror() -> None:
    assert not issubclass(CapabilityViolation, OSError)


def test_single_file_namespace_package_resolves_absolute_imports(tmp_path, capsys) -> None:
    from pyflow.cli.capabilities import run_capabilities

    package = tmp_path / "pkg"
    package.mkdir()
    (package / "util.py").write_text(
        "import os\ndef run(command):\n    os.system(command)\n", encoding="utf-8"
    )
    entry = package / "mod.py"
    entry.write_text("from pkg.util import run\nrun('ls')\n", encoding="utf-8")

    args = Namespace(
        input_path=str(entry),
        entry=None,
        context_depth=1,
        import_depth=-1,
        format="json",
        output=None,
        max_iterations=20000,
        max_seconds=60.0,
    )
    assert run_capabilities(args) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["status"] == "complete"
    assert any(finding["capability"] == "process.execute" for finding in payload["findings"])


def test_recursive_reports_entry_coverage(tmp_path, capsys) -> None:
    from pyflow.cli.capabilities import run_capabilities

    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text("import os\nos.getcwd()\n", encoding="utf-8")

    args = Namespace(
        input_path=str(tmp_path),
        entry=None,
        recursive=True,
        context_depth=1,
        import_depth=-1,
        format="json",
        output=None,
        max_iterations=20000,
        max_seconds=120.0,
    )
    assert run_capabilities(args) == 0
    payload = json.loads(capsys.readouterr().out)

    coverage = payload["coverage"]
    assert coverage["entries_total"] == 2
    assert coverage["entries_analyzed"] == 2
    assert coverage["entries_skipped"] == 0


def test_star_argument_forwarding_does_not_report_missing_arguments() -> None:
    result = _result(
        "import functools\n"
        "def deco(fn):\n"
        "    @functools.wraps(fn)\n"
        "    def wrapper(*a, **k):\n"
        "        return fn(*a, **k)\n"
        "    return wrapper\n"
        "@deco\n"
        "def handler(path, mode='r'):\n"
        "    return open(path, mode).read()\n"
        "handler('x')\n"
    )

    assert "file.read" in _capabilities(result)
    assert not any("Unexpected keyword arguments" in d.message for d in result.diagnostics)


def test_string_methods_keep_flow_through_split() -> None:
    result = _result(
        "import os\n"
        "parts = os.environ.get('X', 'a,b').split(',')\n"
        "for item in parts:\n"
        "    open(item.strip()).read()\n"
    )

    assert "file.read" in _capabilities(result)
    assert result.status == "complete"


def test_path_class_methods_resolve() -> None:
    result = _result("from pathlib import Path\nPath.home().joinpath('x').read_text()\n")

    assert "file.read" in _capabilities(result)
    assert not any("missing required argument" in d.message for d in result.diagnostics)


def test_native_base_class_keeps_subclass_analyzable() -> None:
    result = _result(
        "from pydantic import BaseModel\n"
        "class Payload(BaseModel):\n"
        "    def read(self):\n"
        "        return open('x').read()\n"
        "Payload().read()\n"
    )

    assert "file.read" in _capabilities(result)
    assert not any("__mro_entries__" in d.message for d in result.diagnostics)


def test_native_return_data_is_not_a_capability_transfer() -> None:
    result = _result(
        "import importlib\n"
        "import plugin_api\n"
        "plugin_api.register(importlib.import_module('json'))\n"
    )

    assert not any(
        finding.report_kind is CapabilityReportKind.INDIRECT for finding in result.findings
    )


def test_diagnostics_are_deduplicated_across_contexts() -> None:
    result = _result(
        "def deco(fn):\n"
        "    def wrapper(*a, **k):\n"
        "        return fn(*a, **k)\n"
        "    return wrapper\n"
        "@deco\n"
        "def handler(x):\n"
        "    return x\n" + "".join(f"handler({index})\n" for index in range(12)),
        k=2,
    )

    assert len(result.diagnostics) < 12
    assert all(len(diagnostic.message) < 600 for diagnostic in result.diagnostics)


def test_solver_budget_suppresses_unresolved_call_noise() -> None:
    result = _result(
        "import os\n"
        + "".join(
            f"def f{index}(x):\n    return os.system(x)\nf{index}('ls')\n" for index in range(40)
        ),
        max_iterations=5,
    )

    assert result.status == "partial"
    assert result.statistics["diagnostics"] == 1
    assert result.diagnostics[0].kind == "budget"


def test_dict_keys_yield_real_key_objects() -> None:
    result = _result(
        "import os\n"
        "import plugin_api\n"
        "handlers = {'run': os.system}\n"
        "for name in handlers.keys():\n"
        "    plugin_api.register(name)\n"
    )

    names = [
        finding
        for finding in result.findings
        if finding.report_kind is CapabilityReportKind.INDIRECT
    ]
    # ``keys()`` must expose the key objects, never the dict's values.
    assert all(finding.capability != "process.execute" for finding in names)
    assert result.status == "complete"


def test_class_annotations_are_published() -> None:
    from pyflow.analysis.alias.kcfa import PointerAnalysis

    result = PointerAnalysis("class C:\n    cb: object\na = C.__annotations__\n", k=1).run()

    assert any("DICT" in str(obj) for obj in result.points_to("a"))


def test_function_assigned_to_class_attribute_binds_self() -> None:
    result = _result(
        "import os\n"
        "def make_init(self, cb):\n"
        "    self.cb = cb\n"
        "class C:\n"
        "    pass\n"
        "C.__init__ = make_init\n"
        "c = C(os.system)\n"
        "c.cb('ls')\n"
    )

    assert "process.execute" in _capabilities(result)
