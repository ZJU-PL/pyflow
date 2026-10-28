from __future__ import annotations

import json
import zipfile

import pytest

from pyflow.checker.supply_chain import (
    ScanLimits,
    SupplyChainScan,
    audit_vulnerabilities,
    build_cyclonedx_document,
    resolve_environment,
    scan_targets,
)


def test_non_recursive_scan_does_not_descend(tmp_path):
    (tmp_path / "requirements.txt").write_text("top==1\n", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "requirements.txt").write_text("hidden==2\n", encoding="utf-8")

    shallow = scan_targets([tmp_path], recursive=False)
    recursive = scan_targets([tmp_path], recursive=True)

    assert {item["name"] for item in shallow.components} == {"top"}
    assert {item["name"] for item in recursive.components} == {"hidden", "top"}


def test_unsupported_direct_target_cannot_claim_a_complete_inventory(tmp_path):
    target = tmp_path / "package.json"
    target.write_text('{"dependencies": {"demo": "1"}}', encoding="utf-8")

    scan = scan_targets([target])

    assert not scan.metadata["inventoryComplete"]
    assert scan.metadata["inventoryLimitations"] == ["unsupported-supply-chain-target"]
    assert any(finding.kind == "unsupported-supply-chain-target" for finding in scan.findings)


def test_directory_and_archive_input_limits_are_enforced(tmp_path):
    for index in range(3):
        (tmp_path / f"requirements-{index}.txt").write_text(f"demo-{index}==1\n", encoding="utf-8")
    limited_directory = scan_targets(
        [tmp_path], recursive=True, limits=ScanLimits(max_scan_entries=2)
    )
    assert any(finding.kind == "scan-entry-limit" for finding in limited_directory.findings)

    archive_path = tmp_path / "large.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("file.txt", "content")
    limited_archive = scan_targets([archive_path], limits=ScanLimits(max_archive_size=1))
    assert any(finding.kind == "archive-file-size-limit" for finding in limited_archive.findings)

    with pytest.raises(ValueError):
        scan_targets([], limits=ScanLimits(max_compression_ratio=float("nan")))
    with pytest.raises(ValueError):
        audit_vulnerabilities(
            SupplyChainScan(components=(), findings=()),
            [],
            max_database_age_days=float("inf"),
        )


def test_environment_markers_filter_non_matching_dependencies(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        'old-only==1; python_version < "3.11"\n' 'new-only==1; python_version >= "3.11"\n',
        encoding="utf-8",
    )

    resolved = resolve_environment(
        scan_targets([requirements]),
        environment={"python_version": "3.12", "python_full_version": "3.12.0"},
    )

    assert {component["name"] for component in resolved.components} == {"new-only"}
    assert resolved.metadata["environment"]["python_version"] == "3.12"


def test_requirements_includes_hashes_and_index_risks(tmp_path):
    digest = "a" * 64
    (tmp_path / "base.in").write_text(
        "safe==1.0 \\\n    --hash=sha256:" + digest + "\n",
        encoding="utf-8",
    )
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "-r base.in\n" "--extra-index-url http://packages.example/simple\n" "floating>=2\n",
        encoding="utf-8",
    )

    scan = scan_targets([requirements])

    safe = next(item for item in scan.components if item["name"] == "safe")
    assert safe["hashes"] == [{"alg": "SHA-256", "content": digest}]
    kinds = {finding.kind for finding in scan.findings}
    assert "multiple-package-indexes" in kinds
    assert "insecure-package-index" in kinds
    assert "unpinned-requirement" in kinds
    assert "requirement-missing-hash" not in {
        finding.kind
        for finding in scan.findings
        if finding.details.get("requirement", "").startswith("safe")
    }


def test_dependency_url_query_credentials_are_detected_and_redacted(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "demo @ https://packages.example/demo.whl?token=super-secret\n",
        encoding="utf-8",
    )

    scan = scan_targets([requirements])

    credential = next(
        finding for finding in scan.findings if finding.kind == "embedded-credentials"
    )
    assert "super-secret" not in json.dumps(credential.to_dict())
    reference = scan.components[0]["externalReferences"][0]["url"]
    assert "super-secret" not in reference
    assert "redacted" in reference


def test_additional_lock_and_build_metadata_are_scanned(tmp_path):
    (tmp_path / "poetry.lock").write_text(
        """
[[package]]
name = "demo"
version = "1.0"
[package.dependencies]
child = ">=2"

[[package]]
name = "child"
version = "2.1"
""",
        encoding="utf-8",
    )
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps(
            {
                "default": {
                    "pipenv-demo": {
                        "version": "==3.0",
                        "hashes": ["sha256:" + "a" * 64],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "setup.cfg").write_text(
        "[options]\ninstall_requires =\n    cfg-demo==4\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "dynamic-demo"
dynamic = ["dependencies"]
[build-system]
requires = ["custom-builder==1"]
build-backend = "company.backend"
backend-path = ["backend"]
""",
        encoding="utf-8",
    )

    scan = scan_targets([tmp_path], recursive=True)
    names = {component["name"] for component in scan.components}
    kinds = {finding.kind for finding in scan.findings}

    assert {"demo", "child", "pipenv-demo", "cfg-demo", "dynamic-demo"} <= names
    assert {
        "dynamic-dependency-metadata",
        "local-build-backend",
        "unrecognized-build-backend",
    } <= kinds
    assert any(
        dependency["ref"] == "pkg:pypi/demo@1.0"
        and dependency["dependsOn"] == ["pkg:pypi/child@2.1"]
        for dependency in scan.dependencies
    )


def test_pyproject_builds_dependency_graph_and_normalizes_poetry_constraints(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "demo-app"
version = "1.0"
dependencies = ["requests==2.31.0"]

[build-system]
requires = ["setuptools>=70"]

[tool.poetry.dependencies]
click = "^8.1"
""",
        encoding="utf-8",
    )

    scan = scan_targets([pyproject])
    document = build_cyclonedx_document(scan)

    assert {item["name"] for item in scan.components} == {
        "click",
        "demo-app",
        "requests",
        "setuptools",
    }
    assert any(item["ref"] == "pkg:pypi/demo-app@1.0" for item in scan.dependencies)
    assert document["dependencies"] == list(scan.dependencies)
    click = next(item for item in scan.components if item["name"] == "click")
    property_values = {prop["value"] for prop in click["properties"]}
    assert "runtime" in property_values
    assert any(">=8.1" in value and "<9.0.0" in value for value in property_values)


def test_setup_script_reports_install_time_execution(tmp_path):
    setup = tmp_path / "setup.py"
    setup.write_text(
        "import subprocess\n"
        "subprocess.run(['curl', 'https://example.invalid'])\n"
        "setup(install_requires=['requests'])\n",
        encoding="utf-8",
    )

    scan = scan_targets([setup])

    assert any(
        finding.kind == "install-script-dangerous-behavior" and finding.severity == "HIGH"
        for finding in scan.findings
    )
    assert any(component["name"] == "requests" for component in scan.components)


def test_setup_script_ignores_unreachable_dangerous_function(tmp_path):
    setup = tmp_path / "setup.py"
    setup.write_text(
        "import subprocess\n"
        "def dormant():\n"
        "    subprocess.run(['curl', 'https://example.invalid'])\n"
        "setup(name='demo')\n",
        encoding="utf-8",
    )

    scan = scan_targets([setup])

    assert not any(finding.kind == "install-script-dangerous-behavior" for finding in scan.findings)


def test_setup_script_follows_reachable_local_function(tmp_path):
    setup = tmp_path / "setup.py"
    setup.write_text(
        "import subprocess\n"
        "def payload():\n"
        "    subprocess.run(['curl', 'https://example.invalid'])\n"
        "payload()\n"
        "setup(name='demo')\n",
        encoding="utf-8",
    )

    scan = scan_targets([setup])

    assert any(finding.kind == "install-script-dangerous-behavior" for finding in scan.findings)


def test_uv_sdist_and_wheel_hashes_are_all_retained(tmp_path):
    lock = tmp_path / "uv.lock"
    lock.write_text(
        """version = 1
[[package]]
name = "demo"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://example.org/demo.tar.gz", hash = "sha256:"""
        + "a" * 64
        + """" }
wheels = [{ url = "https://example.org/demo.whl", hash = "sha256:"""
        + "b" * 64
        + """" }]
"""
    )
    scan = scan_targets([lock])
    assert scan.components[0]["hashes"] == [
        {"alg": "SHA-256", "content": "a" * 64},
        {"alg": "SHA-256", "content": "b" * 64},
    ]
    assert not any(f.kind == "lock-artifact-missing-hash" for f in scan.findings)


def test_dynamic_project_license_survives_locked_root_version(tmp_path):
    from pyflow.checker.supply_chain import audit_license_policy

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\ndynamic=["version"]\nlicense="BSD-3-Clause"\ndependencies=["click>=8"]\n'
    )
    (tmp_path / "uv.lock").write_text(
        'version=1\n[[package]]\nname="demo"\nversion="1.0"\nsource={editable="."}\n'
    )
    scan = scan_targets([tmp_path])
    roots = [c for c in scan.components if c["name"] == "demo"]
    assert roots and all(c.get("licenses") for c in roots)
    assert all(c["type"] == "application" for c in roots)
    assert not any(f.kind == "license-not-declared" for f in audit_license_policy(scan))


def test_equivalent_pep440_root_versions_preserve_project_license(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="3.2.0.dev"\nlicense="BSD-3-Clause"\n'
    )
    (tmp_path / "uv.lock").write_text(
        'version=1\n[[package]]\nname="demo"\nversion="3.2.0.dev0"\nsource={editable="."}\n'
    )
    scan = scan_targets([tmp_path])
    assert all(component.get("licenses") for component in scan.components)
    assert all(component["type"] == "application" for component in scan.components)


def test_requirements_whole_line_comments_not_invalid_requirements(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "# Header comment\n"
        "   # Indented comment\n"
        "# Comment ending with backslash \\\n"
        "click==8.1.7 # inline comment\n"
        "# Middle comment\n"
        "requests>=2.28.0\n"
        "# Trailing comment\n",
        encoding="utf-8",
    )
    scan = scan_targets([req_file])
    kinds = {finding.kind for finding in scan.findings}
    assert "invalid-requirement" not in kinds
    assert {c["name"] for c in scan.components} == {"click", "requests"}


def test_setup_py_ast_expression_resolution(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "numpy>=1.20\n# comment\npandas>=2.0\n", encoding="utf-8"
    )
    setup = tmp_path / "setup.py"
    setup.write_text(
        """
import os
from pathlib import Path
from setuptools import setup

_deps = ["click>=8.0", "pyyaml>=6.0"]
core_reqs = [_deps[0]]
extra_reqs = ["pydantic>=2.0"]
all_reqs = core_reqs + extra_reqs

def load_file_requirements():
    return open("requirements.txt").readlines()

setup(
    name="my-pkg",
    version="0.1.0",
    install_requires=list(all_reqs),
    tests_require=load_file_requirements(),
)
""",
        encoding="utf-8",
    )
    scan = scan_targets([setup])
    assert {c["name"] for c in scan.components} == {
        "click",
        "my-pkg",
        "pydantic",
        "numpy",
        "pandas",
    }
    assert not any(f.kind == "invalid-setup-script" for f in scan.findings)


def test_reconcile_abstract_pyproject_and_concrete_lockfile(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "my-service"
version = "1.0.0"
dependencies = [
    "click>=8.0",
    "flask>=3.0",
]
""",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        """version = 1
[[package]]
name = "click"
version = "8.4.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "flask"
version = "3.2.0"
source = { editable = "." }
dependencies = [
    { name = "click" },
]
""",
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path], recursive=True)
    assert len(scan.components) == 3
    by_name = {c["name"]: c for c in scan.components}
    assert by_name["click"]["version"] == "8.4.0"
    assert by_name["click"]["purl"] == "pkg:pypi/click@8.4.0"
    assert by_name["flask"]["version"] == "3.2.0"
    assert by_name["my-service"]["type"] == "application"

    assert any(
        dep["ref"] == "pkg:pypi/flask@3.2.0" and dep["dependsOn"] == ["pkg:pypi/click@8.4.0"]
        for dep in scan.dependencies
    )

    vuln_db = tmp_path / "osv.json"
    vuln_db.write_text(
        json.dumps(
            [
                {
                    "id": "VULN-CLICK-1",
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "click"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "99.0"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    vuln_findings = audit_vulnerabilities(scan, [vuln_db])
    assert any(
        f.kind == "known-vulnerability" and f.details.get("component") == "click"
        for f in vuln_findings
    )
    assert not any(
        f.kind == "vulnerability-scan-unresolved-version" and f.details.get("component") == "click"
        for f in vuln_findings
    )


def test_abstract_pyproject_and_workspace_root_editable_no_spurious_findings(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "clean-lib"
version = "0.1.0"
dependencies = [
    "requests>=2.0.0",
]
""",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        """version = 1
[[package]]
name = "clean-lib"
version = "0.1.0"
source = { editable = "." }
""",
        encoding="utf-8",
    )
    scan = scan_targets([tmp_path])
    kinds = {f.kind for f in scan.findings}
    assert "unpinned-requirement" not in kinds
    assert "requirement-missing-hash" not in kinds
    assert "local-path-requirement" not in kinds
    assert scan.metadata["inventoryComplete"] is True


def test_setup_py_inventories_root_and_extras_require(tmp_path):
    setup = tmp_path / "setup.py"
    setup.write_text(
        """
from setuptools import setup

EXTRAS = {"dev": ["pytest>=7"], "docs": ["sphinx"]}

setup(
    name="demo",
    version="1.0",
    license="MIT",
    install_requires=["requests>=2"],
    extras_require=EXTRAS,
)
""",
        encoding="utf-8",
    )

    scan = scan_targets([setup])
    by_name = {component["name"]: component for component in scan.components}

    assert by_name["demo"]["type"] == "application"
    assert by_name["demo"]["licenses"] == [{"license": {"id": "MIT"}}]
    pytest_properties = {prop["value"] for prop in by_name["pytest"]["properties"]}
    assert {"optional:dev", 'extra == "dev"'} <= pytest_properties


def test_setup_script_distinguishes_build_tools_from_downloaders(tmp_path):
    setup = tmp_path / "setup.py"
    setup.write_text(
        "import subprocess\n"
        "subprocess.run(['git', 'describe'])\n"
        "subprocess.run(['curl', 'https://example.invalid'])\n"
        "setup(name='demo')\n",
        encoding="utf-8",
    )

    findings = [
        finding
        for finding in scan_targets([setup]).findings
        if finding.kind == "install-script-dangerous-behavior"
    ]

    assert {finding.severity for finding in findings} == {"MEDIUM", "HIGH"}


def test_pyproject_type_confusion_is_reported_without_crashing(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
dependencies = "requests>=2"

[build-system]
requires = "setuptools"

[tool]
poetry = "not-a-table"
""",
        encoding="utf-8",
    )

    scan = scan_targets([tmp_path / "pyproject.toml"])

    assert any(finding.kind == "invalid-pyproject" for finding in scan.findings)
    assert "setuptools" in {component["name"] for component in scan.components}


def test_lockfile_type_confusion_is_reported_without_crashing(tmp_path):
    (tmp_path / "Pipfile.lock").write_text("[]", encoding="utf-8")
    (tmp_path / "pylock.toml").write_text(
        'lock-version = "1.0"\n[[packages]]\nname = "demo"\nversion = "1.0"\nvcs = "git"\n',
        encoding="utf-8",
    )

    scan = scan_targets([tmp_path / "Pipfile.lock", tmp_path / "pylock.toml"])

    kinds = {finding.kind for finding in scan.findings}
    assert "invalid-lockfile" in kinds
    assert "invalid-pylock" in kinds


def test_vcs_path_revision_counts_as_pinned(tmp_path):
    revision = "a" * 40
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        f"git+https://github.com/example/demo@{revision}#egg=demo\n",
        encoding="utf-8",
    )

    scan = scan_targets([requirements])

    assert not any(finding.kind == "unpinned-vcs-dependency" for finding in scan.findings)
    remote = next(finding for finding in scan.findings if finding.kind == "remote-requirement")
    assert remote.severity == "MEDIUM"


def test_requirement_content_sniff_ignores_distribution_text_metadata(tmp_path):
    (tmp_path / "deps.txt").write_text("numpy==1.0\n", encoding="utf-8")
    (tmp_path / "README.txt").write_text("This is prose, not a requirement.\n", encoding="utf-8")
    dist_info = tmp_path / "demo-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text("Name: demo\nVersion: 1.0\n", encoding="utf-8")
    (dist_info / "top_level.txt").write_text("demo\n", encoding="utf-8")

    scan = scan_targets([tmp_path], recursive=True)

    assert "numpy" in {component["name"] for component in scan.components}
    assert not any(finding.kind == "unpinned-requirement" for finding in scan.findings)


def test_default_excludes_can_be_disabled(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "requirements.txt").write_text("hidden==1\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("visible==1\n", encoding="utf-8")

    default_scan = scan_targets([tmp_path], recursive=True)
    full_scan = scan_targets([tmp_path], recursive=True, default_excludes=False)

    assert {component["name"] for component in default_scan.components} == {"visible"}
    assert {component["name"] for component in full_scan.components} == {"hidden", "visible"}


def test_pkg_info_and_installed_tree_are_discovered(tmp_path):
    site_packages = tmp_path / "site-packages"
    egg_info = site_packages / "demo.egg-info"
    egg_info.mkdir(parents=True)
    (egg_info / "PKG-INFO").write_text("Name: demo\nVersion: 1.0\n", encoding="utf-8")

    shallow = scan_targets([site_packages], recursive=False)

    assert {component["name"] for component in shallow.components} == {"demo"}
    assert not any(finding.kind == "missing-record" for finding in shallow.findings)
