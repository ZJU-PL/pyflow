"""Semantic validation for SBOM documents emitted by PyFlow."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .input_safety import load_json_file


class SbomValidationError(ValueError):
    pass


def validate_json_schema(document: Mapping[str, Any], schema_path: str | Path) -> None:
    """Validate against a caller-pinned official schema when jsonschema exists."""

    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise SbomValidationError(
            "JSON Schema validation requires the 'supply-chain' optional dependencies"
        ) from exc
    try:
        schema = load_json_file(Path(schema_path))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(document, schema)
    except (OSError, ValueError, jsonschema.exceptions.SchemaError) as exc:
        raise SbomValidationError(f"Could not load SBOM schema: {exc}") from exc
    except jsonschema.exceptions.ValidationError as exc:
        location = "/".join(str(item) for item in exc.absolute_path)
        raise SbomValidationError(
            f"SBOM schema validation failed at {location or '<document>'}: {exc.message}"
        ) from exc


def validate_cyclonedx_document(document: Mapping[str, Any]) -> None:
    errors: list[str] = []
    if document.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be CycloneDX")
    if document.get("specVersion") != "1.7":
        errors.append("specVersion must be 1.7")
    components = document.get("components", ())
    if not isinstance(components, list):
        errors.append("components must be an array")
        components = []
    refs: set[str] = set()
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            errors.append(f"components[{index}] must be an object")
            continue
        if not component.get("name") or not component.get("type"):
            errors.append(f"components[{index}] requires name and type")
        reference = str(component.get("bom-ref", ""))
        if not reference:
            errors.append(f"components[{index}] requires bom-ref")
        elif reference in refs:
            errors.append(f"duplicate bom-ref {reference}")
        refs.add(reference)
    for index, dependency in enumerate(document.get("dependencies", ()) or ()):
        if not isinstance(dependency, dict):
            errors.append(f"dependencies[{index}] must be an object")
            continue
        source = str(dependency.get("ref", ""))
        if source not in refs:
            errors.append(f"dependency source {source} is not a component")
        for target in dependency.get("dependsOn", ()) or ():
            if str(target) not in refs:
                errors.append(f"dependency target {target} is not a component")
    if errors:
        raise SbomValidationError("; ".join(errors))


def validate_spdx_document(document: Mapping[str, Any]) -> None:
    errors: list[str] = []
    if document.get("spdxVersion") != "SPDX-2.3":
        errors.append("spdxVersion must be SPDX-2.3")
    if document.get("dataLicense") != "CC0-1.0":
        errors.append("dataLicense must be CC0-1.0")
    packages = document.get("packages", ())
    if not isinstance(packages, list):
        errors.append("packages must be an array")
        packages = []
    identifiers = {"SPDXRef-DOCUMENT"}
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            errors.append(f"packages[{index}] must be an object")
            continue
        identifier = str(package.get("SPDXID", ""))
        if not identifier.startswith("SPDXRef-"):
            errors.append(f"packages[{index}] has invalid SPDXID")
        elif identifier in identifiers:
            errors.append(f"duplicate SPDXID {identifier}")
        identifiers.add(identifier)
        if not package.get("name"):
            errors.append(f"packages[{index}] requires name")
    for relationship in document.get("relationships", ()) or ():
        if not isinstance(relationship, dict):
            errors.append("relationship must be an object")
            continue
        source = str(relationship.get("spdxElementId", ""))
        target = str(relationship.get("relatedSpdxElement", ""))
        if source not in identifiers or target not in identifiers:
            errors.append(
                f"relationship references unknown elements {source}, {target}"
            )
    if errors:
        raise SbomValidationError("; ".join(errors))
