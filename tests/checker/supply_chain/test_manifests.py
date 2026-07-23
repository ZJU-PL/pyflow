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
    assert any(
        finding.kind == "unsupported-supply-chain-target" for finding in scan.findings
    )


def test_directory_and_archive_input_limits_are_enforced(tmp_path):
    for index in range(3):
        (tmp_path / f"requirements-{index}.txt").write_text(
            f"demo-{index}==1\n", encoding="utf-8"
        )
    limited_directory = scan_targets(
        [tmp_path], recursive=True, limits=ScanLimits(max_scan_entries=2)
    )
    assert any(
        finding.kind == "scan-entry-limit" for finding in limited_directory.findings
    )

    archive_path = tmp_path / "large.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("file.txt", "content")
    limited_archive = scan_targets(
        [archive_path], limits=ScanLimits(max_archive_size=1)
    )
    assert any(
        finding.kind == "archive-file-size-limit"
        for finding in limited_archive.findings
    )

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
        'old-only==1; python_version < "3.11"\n'
        'new-only==1; python_version >= "3.11"\n',
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
        "-r base.in\n"
        "--extra-index-url http://packages.example/simple\n"
        "floating>=2\n",
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
        finding.kind == "install-script-dangerous-behavior"
        and finding.severity == "HIGH"
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

    assert not any(
        finding.kind == "install-script-dangerous-behavior" for finding in scan.findings
    )


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

    assert any(
        finding.kind == "install-script-dangerous-behavior" for finding in scan.findings
    )
