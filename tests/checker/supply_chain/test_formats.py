from __future__ import annotations

import json

import pytest

from pyflow.checker.supply_chain import (
    SupplyChainFinding,
    SupplyChainScan,
    build_cyclonedx_document,
    build_requirements_text,
    build_sarif_document,
    build_spdx_document,
    scan_targets,
    validate_cyclonedx_document,
    validate_json_schema,
    validate_spdx_document,
)
from pyflow.checker.supply_chain.validation import SbomValidationError

from ._helpers import write_record as _write_record


def test_sbom_from_dist_info_metadata(tmp_path):
    dist_info = tmp_path / "Demo_Pkg-1.2.3.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: Demo_Pkg\nVersion: 1.2.3\nSummary: Demo package\nLicense: MIT\n",
        encoding="utf-8",
    )
    _write_record(dist_info, [dist_info / "METADATA"])

    scan = scan_targets([tmp_path], recursive=True)
    doc = build_cyclonedx_document(scan)

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.7"
    assert len(doc["components"]) == 1
    component = doc["components"][0]
    assert component["type"] == "library"
    assert component["name"] == "demo-pkg"
    assert component["purl"] == "pkg:pypi/demo-pkg@1.2.3"
    assert component["bom-ref"] == "pkg:pypi/demo-pkg@1.2.3"
    assert component["version"] == "1.2.3"
    assert component["description"] == "Demo package"
    assert component["licenses"] == [{"license": {"id": "MIT"}}]
    assert any(prop["name"] == "pyflow:source-file" for prop in component["properties"])


def test_sbom_from_requirements_and_pyproject(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nflask>=3\nhttps://example.invalid/pkg.whl\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
dependencies = ["Django==5.0.1"]

[project.optional-dependencies]
dev = ["pytest"]
""",
        encoding="utf-8",
    )

    scan = scan_targets([tmp_path], recursive=True)

    purls = {component["purl"] for component in scan.components}
    assert "pkg:pypi/requests@2.31.0" in purls
    assert "pkg:pypi/flask" in purls
    assert "pkg:pypi/django@5.0.1" in purls
    assert "pkg:pypi/pytest" in purls
    assert any(finding.kind == "remote-requirement" for finding in scan.findings)


def test_build_requirements_text_formats_components(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nflask>=3\n", encoding="utf-8"
    )
    scan = scan_targets([tmp_path], recursive=True)
    text = build_requirements_text(scan)
    assert "requests==2.31.0" in text
    assert "flask" in text
    assert "\n" in text


def test_build_requirements_text_preserves_markers_extras_and_hashes():
    scan = SupplyChainScan(
        components=(
            {
                "name": "demo",
                "version": "1.0",
                "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                "properties": [
                    {"name": "pyflow:extras", "value": "security"},
                    {
                        "name": "pyflow:marker",
                        "value": 'python_version >= "3.11"',
                    },
                ],
            },
        ),
        findings=(),
    )

    text = build_requirements_text(scan)

    assert "demo[security]==1.0" in text
    assert 'python_version >= "3.11"' in text
    assert "--hash=sha256:" + "a" * 64 in text


def test_build_spdx_document_outputs_valid_structure(tmp_path):
    dist_info = tmp_path / "Demo_Pkg-1.2.3.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: Demo_Pkg\nVersion: 1.2.3\nLicense: MIT\n",
        encoding="utf-8",
    )
    _write_record(dist_info, [dist_info / "METADATA"])

    scan = scan_targets([tmp_path], recursive=True)
    doc = build_spdx_document(scan)

    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["documentNamespace"].startswith("https://pyflow.dev/spdx/")
    assert len(doc["packages"]) == 1
    pkg = doc["packages"][0]
    assert pkg["name"] == "demo-pkg"
    assert pkg["versionInfo"] == "1.2.3"
    assert pkg["licenseDeclared"] == "MIT"
    assert pkg["SPDXID"].startswith("SPDXRef-")


def test_deterministic_sboms_are_stable_and_validate(tmp_path, monkeypatch):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0\n", encoding="utf-8")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "123")
    scan = scan_targets([requirements])

    first = build_cyclonedx_document(scan, deterministic=True)
    second = build_cyclonedx_document(scan, deterministic=True)
    spdx_first = build_spdx_document(scan, deterministic=True)
    spdx_second = build_spdx_document(scan, deterministic=True)

    assert first == second
    assert spdx_first == spdx_second
    validate_cyclonedx_document(first)
    assert first["metadata"]["timestamp"] == "1970-01-01T00:02:03Z"


def test_sbom_semantic_validation_rejects_broken_references():
    with pytest.raises(SbomValidationError):
        validate_cyclonedx_document(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [{"type": "library", "name": "demo", "bom-ref": "demo"}],
                "dependencies": [{"ref": "demo", "dependsOn": ["missing"]}],
            }
        )


def test_schema_validation_is_local_and_resolves_pinned_siblings(tmp_path):
    pytest.importorskip("jsonschema")
    child = tmp_path / "child.json"
    child.write_text(
        json.dumps(
            {
                "$id": "https://schemas.example/child.json",
                "type": "string",
                "const": "safe",
            }
        ),
        encoding="utf-8",
    )
    root = tmp_path / "root.json"
    root.write_text(
        json.dumps(
            {
                "$id": "https://schemas.example/root.json",
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {"value": {"$ref": "child.json"}},
                "required": ["value"],
            }
        ),
        encoding="utf-8",
    )

    validate_json_schema({"value": "safe"}, root)
    with pytest.raises(SbomValidationError):
        validate_json_schema({"value": "unsafe"}, root)

    child.unlink()
    with pytest.raises(SbomValidationError, match="pinned local bundle"):
        validate_json_schema({"value": "safe"}, root)
    with pytest.raises(SbomValidationError):
        validate_spdx_document(
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "packages": [{"name": "demo", "SPDXID": "bad"}],
            }
        )


def test_sarif_contains_stable_fingerprints():
    finding = SupplyChainFinding(
        kind="known-vulnerability",
        message="demo",
        location="pkg:pypi/demo@1",
        severity="HIGH",
    )
    document = build_sarif_document(SupplyChainScan(components=(), findings=(finding,)))

    result = document["runs"][0]["results"][0]
    assert document["version"] == "2.1.0"
    assert result["ruleId"] == "known-vulnerability"
    assert result["partialFingerprints"]["pyflowFindingId"]
