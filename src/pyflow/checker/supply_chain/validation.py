"""Semantic validation for SBOM documents emitted by PyFlow."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .input_safety import load_json_file


class SbomValidationError(ValueError):
    pass


def validate_json_schema(document: Mapping[str, Any], schema_path: str | Path) -> None:
    """Validate against a caller-pinned, fully local schema bundle.

    Neighboring JSON schemas are registered for relative ``$ref`` resolution.
    Network retrieval is deliberately disabled so validation remains pinned and
    reproducible instead of silently trusting mutable remote dependencies.
    """

    try:
        import jsonschema  # type: ignore[import-untyped]
        from referencing import Registry, Resource
        from referencing.exceptions import (
            NoSuchResource,
            Unresolvable,
        )
        from referencing.jsonschema import (
            DRAFT202012,
            specification_with,
        )
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise SbomValidationError(
            "JSON Schema validation requires the 'supply-chain' optional dependencies"
        ) from exc
    try:
        path = Path(schema_path)
        schema = load_json_file(path)
        validator_class = jsonschema.validators.validator_for(schema)
        validator_class.check_schema(schema)
        dialect = specification_with(
            str(schema.get("$schema", "")), default=DRAFT202012
        )
        resources: list[tuple[str, Any]] = []
        for sibling in path.parent.glob("*.json"):
            candidate = load_json_file(sibling)
            resource = Resource.from_contents(candidate, default_specification=dialect)
            resources.append((sibling.resolve(strict=False).as_uri(), resource))
            if isinstance(candidate, dict) and candidate.get("$id"):
                resources.append((str(candidate["$id"]), resource))

        def deny_remote(uri: str) -> Any:
            raise NoSuchResource(uri)

        registry = Registry(retrieve=deny_remote).with_resources(resources)
        validator_class(schema, registry=registry).validate(document)
    except SbomValidationError:
        raise
    except jsonschema.exceptions.ValidationError as exc:
        location = "/".join(str(item) for item in exc.absolute_path)
        raise SbomValidationError(
            f"SBOM schema validation failed at {location or '<document>'}: {exc.message}"
        ) from exc
    except (
        OSError,
        ValueError,
        jsonschema.exceptions.SchemaError,
    ) as exc:
        raise SbomValidationError(f"Could not load SBOM schema: {exc}") from exc
    except Unresolvable as exc:
        raise SbomValidationError(
            "schema reference is not available in the pinned local bundle: "
            f"{exc.ref}"
        ) from exc


def validate_cyclonedx_document(document: Mapping[str, Any]) -> None:
    errors: list[str] = []
    if document.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be CycloneDX")
    if document.get("specVersion") != "1.7":
        errors.append("specVersion must be 1.7")
    if not str(document.get("serialNumber", "")).startswith("urn:uuid:"):
        errors.append("serialNumber must be a UUID URN")
    if not isinstance(document.get("version"), int) or document.get("version", 0) < 1:
        errors.append("version must be a positive integer")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict) or not metadata.get("timestamp"):
        errors.append("metadata.timestamp is required")
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
        purl = component.get("purl")
        if purl is not None and not str(purl).startswith("pkg:"):
            errors.append(f"components[{index}] has an invalid purl")
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
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        errors.append("document SPDXID must be SPDXRef-DOCUMENT")
    namespace = str(document.get("documentNamespace", ""))
    if not namespace or not urlparse(namespace).scheme:
        errors.append("documentNamespace must be an absolute URI")
    creation_info = document.get("creationInfo")
    if not isinstance(creation_info, dict):
        errors.append("creationInfo is required")
    else:
        if not creation_info.get("created"):
            errors.append("creationInfo.created is required")
        creators = creation_info.get("creators")
        if not isinstance(creators, list) or not creators:
            errors.append("creationInfo.creators is required")
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
        for required in (
            "downloadLocation",
            "filesAnalyzed",
            "licenseConcluded",
            "licenseDeclared",
            "copyrightText",
        ):
            if required not in package:
                errors.append(f"packages[{index}] requires {required}")
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
