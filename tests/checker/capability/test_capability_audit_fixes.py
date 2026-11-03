"""Regression tests for audit-scope, precision, model, and CLI fixes."""

from __future__ import annotations

from argparse import Namespace

import pytest
import json

from pyflow.checker.capability import (
    CapabilityReportKind,
    DefensiveCapabilityAnalysis,
)


def _result(source: str, **options):
    options.setdefault("report_public_exports", False)
    return DefensiveCapabilityAnalysis(**options).analyze_source(source)


def _cli_args(**overrides) -> Namespace:
    values = {
        "input_path": "",
        "entry": None,
        "recursive": False,
        "context_depth": 1,
        "context_policy": None,
        "import_depth": None,
        "format": "json",
        "output": None,
        "max_iterations": 20000,
        "max_seconds": 60.0,
        "verbose": False,
        "exit_code_policy": "report",
        "capability_model": [],
        "no_public_exports": True,
        "report_callable_boundaries": False,
        "reachable_only": False,
    }
    values.update(overrides)
    return Namespace(**values)


def test_uncalled_function_scope_is_audited() -> None:
    result = _result(
        "import os\n" "def handler():\n" "    os.system('boom')\n",
        analyze_all_scopes=True,
    )

    assert any(
        finding.capability == "process.execute"
        and finding.report_kind is CapabilityReportKind.DIRECT
        and finding.location.line == 3
        for finding in result.findings
    )


def test_uncalled_project_function_is_audited(tmp_path) -> None:
    entry = tmp_path / "library.py"
    entry.write_text(
        "import subprocess\n" "def run(command):\n" "    subprocess.run(command)\n",
        encoding="utf-8",
    )

    result = DefensiveCapabilityAnalysis(
        report_public_exports=False,
        analyze_all_scopes=True,
    ).analyze_project(entry, import_level=0)

    assert any(
        finding.capability == "process.execute" and finding.location.line == 3
        for finding in result.findings
    )


def test_path_values_are_not_capability_handles() -> None:
    result = _result(
        "from pathlib import Path\n"
        "import json\n"
        "import plugin_api\n"
        "config = Path('config.json')\n"
        "json.dumps(config)\n"
        "plugin_api.sink(config)\n"
        "open(config)\n"
    )

    assert not any(
        finding.access_path.startswith("pathlib.Path")
        and finding.report_kind is CapabilityReportKind.INDIRECT
        for finding in result.findings
    )
    assert any(
        finding.capability == "file.read"
        and finding.report_kind is CapabilityReportKind.DIRECT
        and finding.access_path == "builtins.open"
        for finding in result.findings
    )


def test_path_public_constant_is_not_reported() -> None:
    result = DefensiveCapabilityAnalysis().analyze_source(
        "from pathlib import Path\n" "CONFIG = Path('config.json')\n"
    )

    assert result.findings == []


def test_sys_argv_method_chains_are_not_environment_reads() -> None:
    result = _result(
        "import sys\n"
        "from pathlib import Path\n"
        "def validate(skill_path):\n"
        "    skill_path = Path(skill_path)\n"
        "    skill_md = skill_path / 'SKILL.md'\n"
        "    if not skill_md.exists():\n"
        "        return False\n"
        "    content = skill_md.read_text()\n"
        "    return content.startswith('---')\n"
        "validate(sys.argv[1])\n"
    )

    env_paths = {
        finding.access_path
        for finding in result.findings
        if finding.capability == "information.environment"
    }
    assert env_paths
    assert not any(
        marker in path
        for path in env_paths
        for marker in ("__truediv__", "__bool__", "__len__", "startswith", "read_text")
    )
    assert all(path in {"sys.argv.__getitem__", "sys.argv.1"} for path in env_paths)


def test_return_only_effect_summaries_are_not_external_escapes() -> None:
    for source in (
        "from subprocess import run\n" "import copy\n" "copy.copy(run)\n",
        "from subprocess import run\n" "from typing import cast\n" "cast(object, run)\n",
    ):
        result = _result(source)
        assert not any(
            finding.report_kind is CapabilityReportKind.INDIRECT for finding in result.findings
        )


def test_path_open_handle_method_is_reported() -> None:
    result = _result("from pathlib import Path\n" "p = Path('x').open('r')\n" "p.read()\n")

    assert any(
        finding.capability == "file.read"
        and finding.access_path == "pathlib.Path.open.<return>.read"
        for finding in result.findings
    )


def test_named_temporary_file_handle_methods_are_reported() -> None:
    result = _result(
        "import tempfile\n" "t = tempfile.NamedTemporaryFile()\n" "t.write(b'x')\n" "t.read()\n"
    )

    paths = {(finding.capability, finding.access_path) for finding in result.findings}
    assert ("file.write", "tempfile.NamedTemporaryFile.<return>.write") in paths
    assert ("file.read", "tempfile.NamedTemporaryFile.<return>.read") in paths


def test_os_mutation_and_path_link_models_are_detected() -> None:
    result = _result(
        "import os\n"
        "from pathlib import Path\n"
        "os.chdir('/tmp')\n"
        "os.link('a', 'b')\n"
        "os.symlink('a', 'b')\n"
        "os.utime('a')\n"
        "Path('a').symlink_to('b')\n"
    )

    capabilities = {finding.capability for finding in result.findings}
    assert {"file.write", "file.metadata"} <= capabilities


def test_common_ecosystem_file_models_are_detected() -> None:
    result = _result(
        "import boto3, yaml, aiofiles, openpyxl, pandas, numpy\n"
        "from PIL import Image\n"
        "boto3.client('s3')\n"
        "yaml.load_all('a: 1')\n"
        "aiofiles.open('x')\n"
        "openpyxl.load_workbook('x.xlsx')\n"
        "pandas.read_csv('x.csv')\n"
        "numpy.load('x.npy')\n"
        "Image.open('x.png')\n"
    )

    capabilities = {finding.capability for finding in result.findings}
    assert {"information.credentials", "deserialization.unsafe", "file.read"} <= capabilities


def test_bom_and_pep263_sources_are_analyzed(tmp_path, capsys) -> None:
    from pyflow.cli.capabilities import run_capabilities

    bom_file = tmp_path / "bom.py"
    bom_file.write_bytes("\ufeffimport os\nos.system('x')\n".encode("utf-8"))

    latin_file = tmp_path / "latin.py"
    latin_file.write_bytes(b"# -*- coding: latin-1 -*-\nimport os\n# caf\xe9\nos.system('y')\n")

    for source in (bom_file, latin_file):
        args = _cli_args(input_path=str(source), reachable_only=True)
        assert run_capabilities(args) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["coverage"]["entries_analyzed"] == 1
        assert any(finding["capability"] == "process.execute" for finding in payload["findings"])


def test_recursion_error_is_reported_as_failed_entry(tmp_path, capsys) -> None:
    from pyflow.cli.capabilities import run_capabilities

    source = tmp_path / "long_chain.py"
    source.write_text(
        "import os\nx = " + "+".join(["1"] * 600) + "\nos.system('x')\n",
        encoding="utf-8",
    )

    assert run_capabilities(_cli_args(input_path=str(source), reachable_only=True)) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert any("RecursionError" in diagnostic["message"] for diagnostic in payload["diagnostics"])


def test_package_directory_uses_parent_import_root(tmp_path, capsys) -> None:
    from pyflow.cli.capabilities import run_capabilities

    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "util.py").write_text(
        "import os\ndef run():\n    os.system('x')\n", encoding="utf-8"
    )
    (package / "mod.py").write_text(
        "from . import util\ndef main():\n    util.run()\nmain()\n",
        encoding="utf-8",
    )

    args = _cli_args(
        input_path=str(package),
        recursive=True,
        import_depth=-1,
    )
    assert run_capabilities(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(finding["capability"] == "process.execute" for finding in payload["findings"])
    assert not any(
        "unresolved project import" in diagnostic["message"]
        for diagnostic in payload["diagnostics"]
    )


def test_async_context_manager_aliases_are_collapsed() -> None:
    result = _result(
        "import os\n"
        "class Client:\n"
        "    async def __aenter__(self):\n"
        "        return self\n"
        "    async def __aexit__(self, *args):\n"
        "        pass\n"
        "    async def post(self, url):\n"
        "        os.system(url)\n"
        "async def run():\n"
        "    async with Client() as client:\n"
        "        await client.post('x')\n",
        analyze_all_scopes=True,
    )

    assert len([f for f in result.findings if f.access_path == "os.system"]) == 1
    assert not any(
        marker in finding.access_path
        for finding in result.findings
        for marker in ("$await_result", "__aenter__", ".*")
    )


def test_annotated_path_parameter_supports_method_and_avoids_transfer_noise() -> None:
    result = _result(
        "from pathlib import Path\n"
        "import shutil\n"
        "def save(p: Path):\n"
        "    shutil.copyfile(p, 'out')\n"
        "    return p.read_text()\n",
        analyze_all_scopes=True,
    )

    assert any(
        finding.capability == "file.read" and finding.access_path == "pathlib.Path.read_text"
        for finding in result.findings
    )
    assert not any(
        finding.access_path.startswith("pathlib.Path")
        and finding.report_kind is CapabilityReportKind.INDIRECT
        for finding in result.findings
    )


def test_derived_environment_values_are_not_new_capability_transfers() -> None:
    result = _result(
        "import os\n" "import plugin_api\n" "plugin_api.sink(os.environ.get('LIST').split(','))\n"
    )

    assert not any(
        finding.capability == "information.environment"
        and finding.report_kind is CapabilityReportKind.INDIRECT
        for finding in result.findings
    )
    assert any(
        finding.capability == "information.environment" and finding.access_path == "os.environ.get"
        for finding in result.findings
    )


def test_native_method_reassignment_reaches_fixpoint() -> None:
    result = DefensiveCapabilityAnalysis(
        report_public_exports=False,
        analyze_all_scopes=True,
        max_iterations=3000,
    ).analyze_source(
        "import PIL.Image\n"
        "def convert(file, mode='RGB'):\n"
        "    image = PIL.Image.open(file)\n"
        "    image = image.convert(mode)\n"
        "    return image\n"
    )

    assert result.coverage["fixpoint_complete"] is True
    assert any(
        finding.capability == "file.read" and finding.access_path == "PIL.Image.open"
        for finding in result.findings
    )


def test_absolute_local_import_triggers_deep_audit_fallback(tmp_path, capsys) -> None:
    from pyflow.cli.capabilities import run_capabilities

    (tmp_path / "util.py").write_text(
        "import subprocess\ndef run():\n    subprocess.run(['id'])\n",
        encoding="utf-8",
    )
    entry = tmp_path / "app.py"
    entry.write_text("from util import run\nrun()\n", encoding="utf-8")

    args = _cli_args(input_path=str(entry), import_depth=None, include_imports=True)
    assert run_capabilities(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(finding["capability"] == "process.execute" for finding in payload["findings"])


def test_single_file_report_excludes_imported_modules_by_default(tmp_path, capsys) -> None:
    from pyflow.cli.capabilities import run_capabilities

    (tmp_path / "config.py").write_text("import os\nCONFIG = os.getenv('Y')\n", encoding="utf-8")
    (tmp_path / "util.py").write_text(
        "import os\nfrom config import CONFIG\nTOKEN = os.getenv('X')\n", encoding="utf-8"
    )
    entry = tmp_path / "app.py"
    entry.write_text("from util import TOKEN\n", encoding="utf-8")

    args = _cli_args(input_path=str(entry), import_depth=None)
    assert run_capabilities(args) == 0
    payload = json.loads(capsys.readouterr().out)
    files = {finding["location"]["file"] for finding in payload["findings"]}
    assert str((tmp_path / "util.py").resolve()) in files
    assert str((tmp_path / "config.py").resolve()) not in files

    args = _cli_args(input_path=str(entry), import_depth=None, include_imports=True)
    assert run_capabilities(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(
        finding["capability"] == "information.environment"
        and finding["location"]["file"].endswith("config.py")
        for finding in payload["findings"]
    )


def test_nested_response_data_access_is_not_network_io() -> None:
    pytest.importorskip("httpx")
    result = _result(
        "import httpx\n"
        "async def f():\n"
        "    async with httpx.AsyncClient() as client:\n"
        "        response = await client.get('http://x')\n"
        "        return response.json().get('items', []).get('value')\n",
        analyze_all_scopes=True,
    )

    network_paths = {
        finding.access_path for finding in result.findings if finding.capability == "network.io"
    }
    assert network_paths
    assert not any("json" in path or path.count(".<return>") >= 2 for path in network_paths)


def test_environment_item_access_reports_one_operation() -> None:
    result = _result('import os\nos.environ["X"] = "y"\nvalue = os.environ["Y"]\n')
    paths = [finding.access_path for finding in result.findings]
    assert paths.count("os.environ.__setitem__") == 1
    assert paths.count("os.environ.__getitem__") == 1


def test_read_update_open_requires_both_file_capabilities() -> None:
    from pyflow.checker.capability import (
        capability_for_audit_event,
        capabilities_for_audit_event,
    )

    assert capability_for_audit_event("open", ("x", "r+", 0)) == "file.write"
    assert capabilities_for_audit_event("open", ("x", "r+", 0)) == frozenset(
        {"file.read", "file.write"}
    )
    assert capabilities_for_audit_event("open", ("x", "w", 0)) == frozenset({"file.write"})


def test_network_io_policy_covers_socket_and_dns_events() -> None:
    from pyflow.checker.capability.runtime import (
        RuntimeCapabilityGuard,
        RuntimeCapabilityPolicy,
    )

    for event in ("socket.__new__", "socket.connect", "socket.getaddrinfo"):
        guard = RuntimeCapabilityGuard(RuntimeCapabilityPolicy.allowing(["network.io"]))
        guard(event, (None,))  # must not raise
    guard = RuntimeCapabilityGuard(RuntimeCapabilityPolicy.allowing(["network.socket"]))
    guard("socket.__new__", (None,))
