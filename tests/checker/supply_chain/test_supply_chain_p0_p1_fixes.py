from __future__ import annotations

import json
from pathlib import Path

from pyflow.checker.supply_chain import (
    SupplyChainScan,
    audit_license_policy,
    build_requirements_text,
    resolve_environment,
    scan_targets,
)
from pyflow.checker.supply_chain.manifests import (
    _components_from_pipfile_lock,
    _components_from_pyproject,
    _components_from_toml_lock,
)
from pyflow.checker.supply_chain.models import ScanLimits


def test_uv_lock_dependency_markers_are_parsed_and_evaluated(tmp_path: Path):
    lock_content = """version = 1
revision = 1
requires-python = ">=3.10"

[[package]]
name = "demo"
version = "1.0.0"
source = { virtual = "." }
dependencies = [
    { name = "backport", marker = "python_version < '3.11'" },
    { name = "always-needed" },
]

[[package]]
name = "backport"
version = "0.5.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "always-needed"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
"""
    lock_file = tmp_path / "uv.lock"
    lock_file.write_text(lock_content, encoding="utf-8")

    findings = []
    components, edges = _components_from_toml_lock(lock_file, findings, ScanLimits())

    backport = next(c for c in components if c["name"] == "backport")
    markers = [
        p["value"] for p in backport.get("properties", ()) if p.get("name") == "pyflow:marker"
    ]
    assert "python_version < '3.11'" in markers

    # Full scan with environment resolution
    scan = scan_targets([lock_file])
    scan_312 = resolve_environment(
        scan, environment={"python_version": "3.12", "python_full_version": "3.12.0"}
    )
    names_312 = {c["name"] for c in scan_312.components}
    assert "backport" not in names_312
    assert "always-needed" in names_312

    scan_310 = resolve_environment(
        scan, environment={"python_version": "3.10", "python_full_version": "3.10.0"}
    )
    names_310 = {c["name"] for c in scan_310.components}
    assert "backport" in names_310
    assert "always-needed" in names_310


def test_pipfile_lock_markers_and_extras_are_parsed(tmp_path: Path):
    lock_content = {
        "default": {
            "pywin32": {
                "version": "==306",
                "markers": "sys_platform == 'win32'",
                "hashes": ["sha256:" + "a" * 64],
            },
            "requests": {
                "version": "==2.31.0",
                "extras": ["security", "socks"],
                "hashes": ["sha256:" + "b" * 64],
            },
        }
    }
    lock_file = tmp_path / "Pipfile.lock"
    lock_file.write_text(json.dumps(lock_content), encoding="utf-8")

    findings = []
    components = _components_from_pipfile_lock(lock_file, findings, ScanLimits())

    pywin32 = next(c for c in components if c["name"] == "pywin32")
    markers = [
        p["value"] for p in pywin32.get("properties", ()) if p.get("name") == "pyflow:marker"
    ]
    assert "sys_platform == 'win32'" in markers

    requests_comp = next(c for c in components if c["name"] == "requests")
    extras = [
        p["value"] for p in requests_comp.get("properties", ()) if p.get("name") == "pyflow:extras"
    ]
    assert "security,socks" in extras


def test_license_allowlist_spdx_plus_suffix():
    scan = SupplyChainScan(
        components=(
            {
                "name": "apache-plus",
                "purl": "pkg:pypi/apache-plus@1",
                "licenses": [{"expression": "Apache-2.0+"}],
            },
            {
                "name": "lgpl-plus",
                "purl": "pkg:pypi/lgpl-plus@1",
                "licenses": [{"license": {"id": "LGPL-2.1+"}}],
            },
            {
                "name": "gpl-plus",
                "purl": "pkg:pypi/gpl-plus@1",
                "licenses": [{"expression": "GPL-3.0+"}],
            },
        ),
        findings=(),
        dependencies=(),
        metadata={},
    )

    findings = audit_license_policy(scan)
    locations = [f.location for f in findings if f.kind == "license-not-allowed"]
    assert "pkg:pypi/apache-plus@1" not in locations
    assert "pkg:pypi/lgpl-plus@1" not in locations
    assert "pkg:pypi/gpl-plus@1" in locations


def test_license_audit_skips_application_component():
    scan = SupplyChainScan(
        components=(
            {
                "name": "my-app",
                "type": "application",
                "purl": "pkg:pypi/my-app@1",
                "licenses": [{"license": {"id": "GPL-3.0-or-later"}}],
            },
            {
                "name": "dep-mit",
                "type": "library",
                "purl": "pkg:pypi/dep-mit@1",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            {
                "name": "dep-disallowed",
                "type": "library",
                "purl": "pkg:pypi/dep-disallowed@1",
                "licenses": [{"license": {"id": "GPL-3.0-only"}}],
            },
        ),
        findings=(),
        dependencies=(),
        metadata={},
    )

    findings = audit_license_policy(scan)
    disallowed_comps = [
        f.details.get("component") for f in findings if f.kind == "license-not-allowed"
    ]
    assert "my-app" not in disallowed_comps
    assert "dep-mit" not in disallowed_comps
    assert "dep-disallowed" in disallowed_comps

    # With include_application=True, the root application is audited
    app_findings = audit_license_policy(scan, include_application=True)
    app_disallowed = [
        f.details.get("component") for f in app_findings if f.kind == "license-not-allowed"
    ]
    assert "my-app" in app_disallowed


def test_setuptools_dynamic_dependencies_file_is_parsed_without_finding(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\nclick>=8.0.0\n", encoding="utf-8")

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[build-system]
requires = ["setuptools>=77"]
build-backend = "setuptools.build_meta"

[project]
name = "my-project"
version = "1.0.0"
dynamic = ["dependencies"]

[tool.setuptools.dynamic]
dependencies = {file = "requirements.txt"}
""",
        encoding="utf-8",
    )

    scan = scan_targets([tmp_path])
    names = {c["name"] for c in scan.components}
    assert "my-project" in names
    assert "requests" in names
    assert "click" in names

    assert not any(f.kind == "dynamic-dependency-metadata" for f in scan.findings)


def test_hatch_dynamic_requirements_txt_is_parsed(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("fastapi==0.110.0\n", encoding="utf-8")

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "hatch-project"
version = "1.0.0"
dynamic = ["dependencies"]

[tool.hatch.metadata.hooks.requirements_txt]
files = ["requirements.txt"]
""",
        encoding="utf-8",
    )

    scan = scan_targets([tmp_path])
    names = {c["name"] for c in scan.components}
    assert "hatch-project" in names
    assert "fastapi" in names
    assert not any(f.kind == "dynamic-dependency-metadata" for f in scan.findings)


def test_unresolved_dynamic_dependencies_still_reports_finding(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[project]
name = "unresolved-project"
version = "1.0.0"
dynamic = ["dependencies"]
""",
        encoding="utf-8",
    )

    scan = scan_targets([tmp_path])
    assert any(f.kind == "dynamic-dependency-metadata" for f in scan.findings)


def test_trusted_build_backends_include_modern_standards(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[build-system]
requires = ["scikit-build-core"]
build-backend = "scikit_build_core.build"

[project]
name = "scikit-project"
version = "1.0.0"
dependencies = []
""",
        encoding="utf-8",
    )

    scan = scan_targets([tmp_path])
    assert not any(f.kind == "unrecognized-build-backend" for f in scan.findings)


def test_transitive_scope_propagation_in_lockfiles(tmp_path: Path):
    lock_content = """version = 1
revision = 1

[[package]]
name = "app"
version = "1.0.0"
source = { virtual = "." }
dependencies = [
    { name = "runtime-lib" },
]

[package.optional-dependencies]
typing = [
    { name = "mypy" },
]

[[package]]
name = "runtime-lib"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "runtime-transitive" },
]

[[package]]
name = "runtime-transitive"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "mypy"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "mypy-transitive" },
]

[[package]]
name = "mypy-transitive"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"""
    lock_file = tmp_path / "uv.lock"
    lock_file.write_text(lock_content, encoding="utf-8")

    scan = scan_targets([lock_file])
    requirements_text = build_requirements_text(scan)

    # Active lines must only contain runtime dependencies
    active_lines = [
        l.split("==")[0]
        for l in requirements_text.splitlines()
        if not l.startswith("#") and l.strip()
    ]
    assert "runtime-lib" in active_lines
    assert "runtime-transitive" in active_lines
    assert "mypy" not in active_lines
    assert "mypy-transitive" not in active_lines

    # Commented lines must contain dev/typing dependencies with scope annotation
    commented_lines = [l for l in requirements_text.splitlines() if l.startswith("#")]
    assert any("mypy-transitive" in l and "scope: optional:typing" in l for l in commented_lines)
