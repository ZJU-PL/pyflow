from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from pyflow.checker.supply_chain import (
    ScanLimits,
    SupplyChainScan,
    audit_license_policy,
    audit_provenance,
    audit_vulnerabilities,
    build_requirements_text,
    resolve_environment,
    scan_targets,
    write_baseline,
)
from pyflow.checker.supply_chain.licenses import license_entry

from ._helpers import write_record as _write_record


def _dist(root: Path, name: str, version: str, metadata_extra: str = "") -> Path:
    dist_info = root / f"{name}-{version}.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        f"Name: {name}\nVersion: {version}\nLicense-Expression: MIT\n{metadata_extra}",
        encoding="utf-8",
    )
    (dist_info / "RECORD").write_text("", encoding="utf-8")
    _write_record(dist_info, [dist_info / "METADATA"])
    return dist_info


def test_empty_directory_cannot_claim_a_complete_inventory(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    scan = scan_targets([empty])
    assert not scan.metadata["inventoryComplete"]
    assert any(f.kind == "empty-supply-chain-inventory" for f in scan.findings)


def test_explicit_virtualenv_target_is_scanned(tmp_path):
    site = tmp_path / ".venv" / "lib" / "python3.13" / "site-packages"
    site.mkdir(parents=True)
    _dist(site, "demo", "1.0")
    scan = scan_targets([tmp_path / ".venv"])
    assert any(component["name"] == "demo" for component in scan.components)


def test_symlinked_manifest_is_followed(tmp_path):
    real = tmp_path / "reqs" / "base.txt"
    real.parent.mkdir()
    real.write_text("flask==3.0.0\n", encoding="utf-8")
    try:
        (tmp_path / "requirements.txt").symlink_to(real)
    except OSError:
        pytest.skip("symlinks unavailable")
    scan = scan_targets([tmp_path], recursive=True)
    assert any(component["name"] == "flask" for component in scan.components)


def test_missing_bytecode_cache_is_not_an_integrity_finding(tmp_path):
    dist_info = _dist(tmp_path, "demo", "1.0")
    (dist_info / "RECORD").write_text(
        "demo-1.0.dist-info/METADATA,,\n"
        "demo-1.0.dist-info/RECORD,,\n"
        "demo/__pycache__/missing.cpython-313.pyc,,\n",
        encoding="utf-8",
    )
    (tmp_path / "demo").mkdir()
    scan = scan_targets([tmp_path], recursive=True)
    assert not any(f.kind == "record-missing-file" for f in scan.findings)


def test_shared_namespace_is_not_attributed_to_each_distribution(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    for name in ("a", "b", "injected"):
        (shared / f"{name}.py").write_text("x = 1\n", encoding="utf-8")
    first = _dist(tmp_path, "first", "1.0")
    second = _dist(tmp_path, "second", "1.0")
    (first / "top_level.txt").write_text("shared\n", encoding="utf-8")
    (second / "top_level.txt").write_text("shared\n", encoding="utf-8")
    _write_record(first, [first / "METADATA", first / "top_level.txt", shared / "a.py"])
    _write_record(second, [second / "METADATA", second / "top_level.txt", shared / "b.py"])

    scan = scan_targets([tmp_path], recursive=True)

    assert not any(f.kind == "record-unlisted-owned-file" for f in scan.findings)
    assert any(f.kind == "shared-python-namespace" for f in scan.findings)


def test_data_files_outside_site_packages_are_expected(tmp_path):
    site = tmp_path / "venv" / "lib" / "python3.13" / "site-packages"
    site.mkdir(parents=True)
    dist_info = _dist(site, "demo", "1.0")
    (dist_info / "RECORD").write_text(
        "demo-1.0.dist-info/METADATA,,\n"
        "demo-1.0.dist-info/RECORD,,\n"
        "../../../share/man/demo.1,,\n",
        encoding="utf-8",
    )
    scan = scan_targets([site], recursive=True)
    assert not any(f.kind == "record-external-path" for f in scan.findings)


def test_license_file_and_metadata_dependencies_do_not_report_missing_license(tmp_path):
    dist_info = tmp_path / "demo-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: demo\nVersion: 1.0\nLicense-File: LICENSE\nRequires-Dist: requests>=2\n",
        encoding="utf-8",
    )
    (dist_info / "LICENSE").write_text("MIT\n", encoding="utf-8")
    _write_record(dist_info, [dist_info / "METADATA", dist_info / "LICENSE"])

    scan = scan_targets([tmp_path], recursive=True)
    findings = audit_license_policy(scan)

    assert not any(f.kind == "license-not-declared" for f in findings)
    root = next(c for c in scan.components if c["name"] == "demo")
    assert any(p["name"] == "pyflow:license-file" for p in root["properties"])


def test_free_text_licenses_are_classified_instead_of_dumped_as_expressions():
    scan = SupplyChainScan(
        components=(
            {
                "name": "gpl",
                "purl": "pkg:pypi/gpl@1",
                "licenses": [license_entry("GNU General Public License v3 (GPLv3)")],
            },
            {
                "name": "apache",
                "purl": "pkg:pypi/apache@1",
                "licenses": [license_entry("Apache Software License 2.0")],
            },
            {"name": "mit0", "purl": "pkg:pypi/mit0@1", "licenses": [license_entry("MIT-0")]},
        ),
        findings=(),
    )
    findings = audit_license_policy(scan)
    assert [(f.kind, f.location) for f in findings] == [("license-not-allowed", "pkg:pypi/gpl@1")]


def test_setup_py_reads_all_platform_files_with_comments_and_includes(tmp_path):
    req = tmp_path / "requirements"
    req.mkdir()
    (req / "common.txt").write_text(
        "numpy>=1 # numeric\n-r extra.txt\nrequests==2.31.0\n", encoding="utf-8"
    )
    (req / "extra.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (req / "xpu.txt").write_text("datasets # benchmark scripts\n", encoding="utf-8")
    (tmp_path / "setup.py").write_text(
        """
from setuptools import setup

def get_requirements():
    if True:
        return _read("common.txt")
    return _read("xpu.txt")

def _read(name):
    return open("requirements/" + name).readlines()

setup(name="demo", version="1.0", install_requires=get_requirements())
""",
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path / "setup.py"])
    names = {component["name"] for component in scan.components}
    assert {"demo", "numpy", "flask", "requests", "datasets"} <= names
    assert not any(f.kind == "invalid-requirement" for f in scan.findings)


def test_setup_py_with_open_list_comprehension_falls_back_to_files(tmp_path):
    (tmp_path / "req").mkdir()
    (tmp_path / "req" / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (tmp_path / "setup.py").write_text(
        """
from setuptools import setup
with open("req/requirements.txt") as handle:
    requirements = [line.strip() for line in handle if line.strip()]
setup(name="demo", version="1.0", install_requires=requirements)
""",
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path / "setup.py"])
    assert {"demo", "flask"} <= {component["name"] for component in scan.components}


def test_setup_py_manifest_limit_is_enforced(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n" * 2000, encoding="utf-8")
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\n"
        'setup(name="demo", install_requires=open("requirements.txt").read().splitlines())\n',
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path / "setup.py"], limits=ScanLimits(max_manifest_size=1000))
    assert any(f.kind == "manifest-size-limit" for f in scan.findings)
    assert not scan.metadata["inventoryComplete"]


def test_declared_markers_are_kept_but_explicit_environment_filters(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
version = "1.0"
dependencies = [
  "pywin32>=306; sys_platform == 'win32'",
  "winonly>=1; platform_system == 'Windows'",
  "oldpy>=1; python_version < '3.10'",
]
""",
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path / "pyproject.toml"])
    declared = resolve_environment(scan)
    assert {"pywin32", "winonly", "oldpy"} <= {c["name"] for c in declared.components}
    assert declared.metadata["declaredOnly"] is True

    targeted = resolve_environment(
        scan,
        environment={
            "sys_platform": "win32",
            "platform_system": "Windows",
            "python_version": "3.12",
            "python_full_version": "3.12.0",
        },
    )
    assert {c["name"] for c in targeted.components if c["name"] != "demo"} == {
        "pywin32",
        "winonly",
    }


def test_poetry_only_project_has_root_edges_license_and_optional_scope(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.poetry]
name = "demo"
version = "1.0.0"
license = "MIT"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.31"
ipywidgets = { version = ">=7.5.1,<9", optional = true }

[tool.poetry.extras]
jupyter = ["ipywidgets"]
""",
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path / "pyproject.toml"])
    root = next(c for c in scan.components if c["name"] == "demo")
    assert root["type"] == "application"
    assert root["licenses"] == [{"license": {"id": "MIT"}}]
    assert any(edge["ref"] == root["purl"] for edge in scan.dependencies)
    ipywidgets = next(c for c in scan.components if c["name"] == "ipywidgets")
    assert {"optional:jupyter", 'extra == "jupyter"'} <= {
        prop["value"] for prop in ipywidgets["properties"]
    }


def test_lockfile_groups_and_markers_are_not_treated_as_runtime(tmp_path):
    (tmp_path / "poetry.lock").write_text(
        """
[[package]]
name = "devtool"
version = "1.0"
groups = ["dev"]

[[package]]
name = "winonly"
version = "1.0"
markers = "sys_platform == 'win32'"
""",
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path / "poetry.lock"])
    props = {c["name"]: {p["value"] for p in c.get("properties", [])} for c in scan.components}
    assert "dev" in props["devtool"]
    assert "sys_platform == 'win32'" in props["winonly"]


def test_uv_sources_list_index_audit_and_dev_dependencies(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
version = "1.0"
dependencies = ["torch"]

[[tool.uv.index]]
name = "cpu"
url = "http://insecure.example/simple"

[tool.uv.sources]
torch = [{ index = "cpu" }, { index = "cpu", marker = "sys_platform == 'linux'" }]

[tool.uv]
dev-dependencies = ["pytest==8.0.0"]
""",
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path / "pyproject.toml"])
    assert not any(
        f.kind == "invalid-pyproject" and "tool.uv.sources" in str(f.details) for f in scan.findings
    )
    assert any(f.kind == "insecure-package-index" for f in scan.findings)
    assert any(f.kind == "multiple-package-indexes" for f in scan.findings)
    pytest_component = next(c for c in scan.components if c["name"] == "pytest")
    assert "dev" in {p["value"] for p in pytest_component["properties"]}


def test_uv_virtual_source_is_not_a_registry_with_missing_hash(tmp_path):
    (tmp_path / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "demo"\nversion = "1.0"\nsource = { virtual = "." }\n',
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path / "uv.lock"])
    assert not any(f.kind == "lock-artifact-missing-hash" for f in scan.findings)


def test_baseline_ids_survive_line_shifts(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("flask\nrequests\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    write_baseline(baseline, scan_targets([requirements]).findings)
    requirements.write_text("# moved\n\nflask\nrequests\n", encoding="utf-8")
    from pyflow.checker.supply_chain import apply_finding_policy, load_baseline

    policy = __import__(
        "pyflow.checker.supply_chain.policy", fromlist=["FindingPolicy"]
    ).FindingPolicy(baseline_ids=load_baseline(baseline))
    kept, suppressed = apply_finding_policy(scan_targets([requirements]).findings, policy)
    assert not kept
    assert len(suppressed) == 2


def test_invalid_requirement_redacts_embedded_credentials(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "foo @ https://user:topsecret@host/pkg.whl extra-token\n", encoding="utf-8"
    )
    scan = scan_targets([tmp_path / "requirements.txt"])
    assert "topsecret" not in json.dumps([f.to_dict() for f in scan.findings])


def test_corrupt_zip_reports_archive_error_instead_of_crashing(tmp_path):
    archive_path = tmp_path / "corrupt.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", "hello " * 1000)
    data = bytearray(archive_path.read_bytes())
    local = data.find(b"PK\x03\x04")
    name_len = int.from_bytes(data[local + 26 : local + 28], "little")
    extra_len = int.from_bytes(data[local + 28 : local + 30], "little")
    start = local + 30 + name_len + extra_len
    for offset in range(start, min(start + 20, len(data))):
        data[offset] ^= 0xFF
    archive_path.write_bytes(data)
    scan = scan_targets([archive_path])
    assert any(f.kind == "archive-read-error" for f in scan.findings)


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("uv.lock", "package = 1\n"),
        ("pylock.toml", 'lock-version = "1.0"\npackages = 1\n'),
        ("Pipfile.lock", '{"default": {"demo": {"version": "==1", "hashes": 1}}}'),
    ],
)
def test_malformed_lockfile_types_do_not_crash(tmp_path, filename, content):
    (tmp_path / filename).write_text(content, encoding="utf-8")
    scan = scan_targets([tmp_path / filename])
    assert scan.findings


def test_requirements_output_preserves_urls_and_comments_conflicts():
    scan = SupplyChainScan(
        components=(
            {
                "name": "mypkg",
                "properties": [
                    {"name": "pyflow:source-url", "value": "https://files.example/mypkg-1.0.whl"}
                ],
            },
            {"name": "numpy", "version": "1.0"},
            {"name": "numpy", "version": "2.0"},
        ),
        findings=(),
    )
    text = build_requirements_text(scan)
    assert "mypkg @ https://files.example/mypkg-1.0.whl" in text
    assert "# numpy==1.0" in text and "# numpy==2.0" in text


def test_wheel_does_not_export_itself_and_spdx_describes_wheel(tmp_path):
    from pyflow.checker.supply_chain import build_spdx_document

    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo/__init__.py", "")
        archive.writestr(
            "demo-1.0.dist-info/METADATA", "Name: demo\nVersion: 1.0\nLicense-Expression: MIT\n"
        )
        archive.writestr(
            "demo-1.0.dist-info/RECORD",
            "demo/__init__.py,,\ndemo-1.0.dist-info/METADATA,,\ndemo-1.0.dist-info/RECORD,,\n",
        )
    scan = scan_targets([wheel])
    assert "demo==1.0" not in build_requirements_text(scan)
    document = build_spdx_document(scan)
    described = next(p for p in document["packages"] if p["name"] == "demo")
    assert document["documentDescribes"] == [described["SPDXID"]]


def test_archive_startup_hooks_include_dot_pth_and_sitecustomize(tmp_path):
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo/__init__.py", "")
        archive.writestr(".pth", "import os\n")
        archive.writestr("sitecustomize.py", "import os\n")
        archive.writestr("demo-1.0.dist-info/METADATA", "Name: demo\nVersion: 1.0\n")
        archive.writestr("demo-1.0.dist-info/RECORD", "")
    kinds = {f.kind for f in scan_targets([wheel]).findings}
    assert {"archive-pth-file", "archive-startup-hook"} <= kinds


def test_build_hooks_and_python_dash_c_are_high_risk(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
version = "1.0"
[tool.hatch.build.hooks.custom]
path = "evil.py"
""",
        encoding="utf-8",
    )
    (tmp_path / "setup.py").write_text(
        """
import subprocess
from setuptools import setup
subprocess.run(["python3", "-c", "print('payload')"])
setup(name="demo")
""",
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path], recursive=True)
    assert any(f.kind == "build-hook-code-execution" for f in scan.findings)
    assert any(
        f.kind == "install-script-dangerous-behavior" and f.severity == "HIGH"
        for f in scan.findings
    )


def test_slsa_v1_builder_identity_is_recognized(tmp_path):
    artifact = tmp_path / "demo.whl"
    artifact.write_bytes(b"demo")
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": "demo.whl", "digest": {"sha256": hashlib.sha256(b"demo").hexdigest()}}
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"runDetails": {"builder": {"id": "https://github.com/actions/runner"}}},
    }
    attestation = tmp_path / "att.json"
    attestation.write_text(json.dumps(statement), encoding="utf-8")
    findings = audit_provenance(
        [artifact],
        [attestation],
        trusted_builders=["https://github.com/actions/runner"],
        require_provenance=True,
    )
    assert not any(f.kind == "untrusted-provenance-builder" for f in findings)


def test_vex_suppression_is_not_counted_by_low_fail_gate():
    from pyflow.cli.supply_chain import _should_fail
    from pyflow.checker.supply_chain import SupplyChainFinding

    finding = SupplyChainFinding(
        kind="vulnerability-suppressed-by-vex",
        message="suppressed",
        location="pkg:pypi/demo@1",
        severity="LOW",
    )
    assert not _should_fail([finding], "low")


def test_bom_is_stripped_from_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_bytes(b"\xef\xbb\xbfflask==3.0.0\n")
    scan = scan_targets([tmp_path / "requirements.txt"])
    assert any(component["name"] == "flask" for component in scan.components)


def test_pipfile_is_inventoried(tmp_path):
    (tmp_path / "Pipfile").write_text(
        '[packages]\nflask = "*"\nrequests = {version = ">=2", extras = ["socks"]}\n'
        '[dev-packages]\npytest = "*"\n',
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path / "Pipfile"])
    names = {component["name"] for component in scan.components}
    assert {"flask", "requests", "pytest"} <= names
    pytest_component = next(c for c in scan.components if c["name"] == "pytest")
    assert "dev" in {p["value"] for p in pytest_component["properties"]}


def test_requirements_scope_is_inferred_from_filename(tmp_path):
    (tmp_path / "requirements_test_all.txt").write_text("pytest==8.0.0\n", encoding="utf-8")
    (tmp_path / "package_constraints.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    scan = scan_targets([tmp_path], recursive=True)
    scopes = {
        c["name"]: {p["value"] for p in c.get("properties", []) if p["name"] == "pyflow:scope"}
        for c in scan.components
    }
    assert "test" in scopes["pytest"]
    assert "constraint" in scopes["flask"]
    text = build_requirements_text(scan)
    assert "# pytest==8.0.0" in text
    assert "# flask==3.0.0" in text


def test_purl_encoded_local_version_resolves_dependency_edge():
    from pyflow.checker.supply_chain.inventory import best_dependency_ref

    refs = {
        "torch": [
            "pkg:pypi/torch@2.9.1",
            "pkg:pypi/torch@2.9.1%2Bcpu",
            "pkg:pypi/torch@2.9.1%2Bcu128",
        ]
    }
    assert best_dependency_ref("torch", refs, "==2.9.1+cpu") == "pkg:pypi/torch@2.9.1%2Bcpu"


def test_unversioned_component_is_not_arbitrarily_pinned_to_one_locked_version():
    from pyflow.checker.supply_chain.inventory import dedupe_components

    deduped = dedupe_components(
        [
            {"name": "numpy", "purl": "pkg:pypi/numpy"},
            {"name": "numpy", "version": "1.0", "purl": "pkg:pypi/numpy@1.0"},
            {"name": "numpy", "version": "2.0", "purl": "pkg:pypi/numpy@2.0"},
        ]
    )
    assert {(c["name"], c.get("version")) for c in deduped} == {
        ("numpy", None),
        ("numpy", "1.0"),
        ("numpy", "2.0"),
    }


def test_requirements_output_ors_multiple_markers():
    scan = SupplyChainScan(
        components=(
            {
                "name": "demo",
                "version": "1.0",
                "properties": [
                    {"name": "pyflow:marker", "value": 'python_version < "3.10"'},
                    {"name": "pyflow:marker", "value": 'python_version >= "3.10"'},
                ],
            },
        ),
        findings=(),
    )
    text = build_requirements_text(scan)
    assert 'python_version < "3.10"' in text
    assert 'python_version >= "3.10"' in text
    assert " or " in text


def test_installed_startup_hook_not_in_record_is_high_severity(tmp_path):
    site = tmp_path / "site-packages"
    site.mkdir()
    _dist(site, "demo", "1.0")
    (site / "evil.pth").write_text("import os\n", encoding="utf-8")
    scan = scan_targets([site], recursive=True)
    assert any(f.kind == "python-startup-hook" and f.severity == "HIGH" for f in scan.findings)


def test_windows_record_separators_do_not_produce_missing_file(tmp_path):
    dist_info = _dist(tmp_path, "demo", "1.0")
    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / "__init__.py").write_text("", encoding="utf-8")
    (dist_info / "RECORD").write_text(
        "demo\\__init__.py,,\ndemo-1.0.dist-info/METADATA,,\ndemo-1.0.dist-info/RECORD,,\n",
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path], recursive=True)
    assert not any(f.kind == "record-missing-file" for f in scan.findings)


def test_vulnerability_ids_ignore_database_fixed_version_updates(tmp_path):
    component = {
        "name": "foo",
        "version": "1.5",
        "purl": "pkg:pypi/foo@1.5",
        "type": "library",
    }
    scan = SupplyChainScan(components=(component,), findings=())
    base = {
        "id": "GHSA-foo-test",
        "modified": "2026-01-01T00:00:00Z",
        "summary": "foo issue",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "foo"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "2.0"}]}
                ],
            }
        ],
    }
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text(json.dumps(base), encoding="utf-8")
    updated = json.loads(json.dumps(base))
    updated["modified"] = "2026-02-01T00:00:00Z"
    updated["affected"][0]["ranges"][0]["events"].append({"fixed": "9.9"})
    second.write_text(json.dumps(updated), encoding="utf-8")

    first_ids = [
        f.to_dict()["id"]
        for f in audit_vulnerabilities(scan, [first])
        if f.kind == "known-vulnerability"
    ]
    second_ids = [
        f.to_dict()["id"]
        for f in audit_vulnerabilities(scan, [second])
        if f.kind == "known-vulnerability"
    ]
    assert first_ids == second_ids


def test_audit_json_exposes_inventory_metadata(tmp_path, capsys):
    from types import SimpleNamespace

    from pyflow.cli.supply_chain import run_supply_chain

    empty = tmp_path / "empty"
    empty.mkdir()
    args = SimpleNamespace(
        supply_chain_command="audit",
        targets=[str(empty)],
        recursive=False,
        exclude="",
        output=None,
        format="json",
        fail_on="none",
    )
    assert run_supply_chain(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["metadata"]["inventoryComplete"] is False
    assert "empty-supply-chain-inventory" in result["metadata"]["inventoryLimitations"]


def test_setup_cfg_file_directive_is_inventoried(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (tmp_path / "setup.cfg").write_text(
        "[metadata]\nname = demo\nversion = 1.0\nlicense = MIT\n\n"
        "[options]\ninstall_requires =\n    file: requirements.txt\n",
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path / "setup.cfg"])
    assert {"demo", "flask"} <= {c["name"] for c in scan.components}


def test_archive_filename_version_normalization_is_accepted(tmp_path):
    wheel = tmp_path / "demo-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo/__init__.py", "")
        archive.writestr(
            "demo-1.0.0.dist-info/METADATA", "Name: demo\nVersion: 1.0\nLicense-Expression: MIT\n"
        )
        archive.writestr("demo-1.0.0.dist-info/RECORD", "")
    scan = scan_targets([wheel])
    assert not any(f.kind == "archive-metadata-version-mismatch" for f in scan.findings)


def test_primary_and_find_links_indexes_are_flagged(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "--index-url https://attacker.example/simple\n"
        "--find-links https://attacker.example/wheels\n"
        "flask==3.0.0\n",
        encoding="utf-8",
    )
    kinds = {f.kind for f in scan_targets([tmp_path / "requirements.txt"]).findings}
    assert {"non-default-package-index", "multiple-package-indexes"} <= kinds


def test_deterministic_sbom_is_byte_stable_across_roots(tmp_path):
    from pyflow.checker.supply_chain import build_cyclonedx_document

    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    (first_root / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (second_root / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    first = build_cyclonedx_document(scan_targets([first_root]), deterministic=True)
    second = build_cyclonedx_document(scan_targets([second_root]), deterministic=True)
    assert first == second


def test_direct_url_editable_install_is_reported(tmp_path):
    dist_info = _dist(tmp_path, "demo", "1.0")
    (dist_info / "direct_url.json").write_text(
        json.dumps({"url": "file:///tmp/src/demo", "dir_info": {"editable": True}}),
        encoding="utf-8",
    )
    _write_record(dist_info, [dist_info / "METADATA", dist_info / "direct_url.json"])
    kinds = {f.kind for f in scan_targets([tmp_path], recursive=True).findings}
    assert {"editable-install", "local-path-requirement"} <= kinds
    assert "unpinned-vcs-dependency" not in kinds


def test_uv_optional_variant_markers_filter_with_selected_extra(tmp_path):
    (tmp_path / "uv.lock").write_text(
        """
version = 1

[[package]]
name = "demo"
version = "1.0"
source = { virtual = "." }

[package.optional-dependencies]
cpu = [{ name = "torch", version = "2.0+cpu" }]
gpu = [{ name = "torch", version = "2.0+cu" }]

[[package]]
name = "torch"
version = "2.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "torch"
version = "2.0+cpu"
source = { registry = "https://download.pytorch.org/whl/cpu" }

[[package]]
name = "torch"
version = "2.0+cu"
source = { registry = "https://download.pytorch.org/whl/cu" }
""",
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path / "uv.lock"])
    resolved = resolve_environment(scan, extras=("cpu",))
    versions = {c.get("version") for c in resolved.components if c["name"] == "torch"}
    assert versions == {"2.0", "2.0+cpu"}


def test_installed_root_is_not_filtered_by_merged_extra_markers(tmp_path):
    site = tmp_path / "site-packages"
    site.mkdir()
    demo = _dist(site, "demo", "1.0")
    (demo / "METADATA").write_text(
        "Name: demo\nVersion: 1.0\nLicense-Expression: MIT\n"
        'Requires-Dist: pytest>=8; extra == "test"\n',
        encoding="utf-8",
    )
    _dist(site, "pytest", "8.0.0")
    resolved = resolve_environment(scan_targets([site], recursive=True))
    names = {c["name"] for c in resolved.components}
    assert {"demo", "pytest"} <= names
