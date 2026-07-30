"""Convert analyzer-specific reports into one stable finding schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .mapping import CweMappings, cwes_from


def normalize_run(
    result: Mapping[str, Any], result_path: Path, mappings: CweMappings
) -> dict[str, Any]:
    engine = _string(result.get("engine")) or "unknown"
    findings: list[dict[str, Any]] = []
    normalization_error = None
    raw_name = result.get("raw_output")
    if isinstance(raw_name, str):
        try:
            raw_path = (result_path.parent / raw_name).resolve()
            if not raw_path.is_relative_to(result_path.parent.resolve()):
                raise ValueError("raw_output escapes the run directory")
            payload, report_format = _load_report(raw_path)
            findings = _normalize_payload(engine, payload, report_format, mappings)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            normalization_error = str(exc)
    return {
        "schema_version": 1,
        "benchmark": result.get("benchmark"),
        "sample_id": result.get("sample_id"),
        "engine": engine,
        "run_status": result.get("status"),
        "analysis_status": result.get("analysis_status"),
        "labels": result.get("labels", {}),
        "normalized_finding_count": len(findings),
        "findings": findings,
        "normalization_error": normalization_error,
        "source_result": str(result_path),
    }


def _load_report(path: Path) -> tuple[Any, str]:
    if path.suffix.lower() == ".sarif":
        return json.loads(path.read_text(encoding="utf-8")), "sarif"
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text), "json"
    except json.JSONDecodeError as json_error:
        rows = []
        try:
            for line in text.splitlines():
                if line.strip():
                    rows.append(json.loads(line))
        except json.JSONDecodeError:
            raise json_error
        return rows, "jsonl"


def _normalize_payload(
    engine: str, payload: Any, report_format: str, mappings: CweMappings
) -> list[dict[str, Any]]:
    if report_format == "sarif" or (
        isinstance(payload, dict) and isinstance(payload.get("runs"), list)
    ):
        return _normalize_sarif(engine, payload, mappings)
    if engine == "pysa":
        rows = payload if isinstance(payload, list) else []
        issues = [
            row.get("data", {})
            for row in rows
            if isinstance(row, dict)
            and row.get("kind") == "issue"
            and isinstance(row.get("data"), dict)
        ]
    elif report_format == "jsonl":
        issues = payload if isinstance(payload, list) else []
    elif isinstance(payload, list):
        issues = payload
    elif isinstance(payload, dict):
        issues = _first_list(payload, ("results", "findings", "issues", "alerts"))
    else:
        issues = []
    return [
        _generic_finding(engine, item, index, mappings)
        for index, item in enumerate(issues)
        if isinstance(item, dict)
    ]


def _generic_finding(
    engine: str, item: Mapping[str, Any], index: int, mappings: CweMappings
) -> dict[str, Any]:
    rule_id = _first_string(
        item, ("rule_id", "ruleId", "check_id", "test_id", "code", "id")
    )
    raw_location = item.get("location")
    location: Mapping[str, Any] = raw_location if isinstance(raw_location, dict) else {}
    raw_start = item.get("start")
    start: Mapping[str, Any] = raw_start if isinstance(raw_start, dict) else {}
    raw_extra = item.get("extra")
    extra: Mapping[str, Any] = raw_extra if isinstance(raw_extra, dict) else {}
    raw_metadata = extra.get("metadata")
    metadata: Mapping[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    cwes = set()
    for key in ("cwe", "cwes", "issue_cwe", "tags"):
        cwes.update(cwes_from(item.get(key)))
        cwes.update(cwes_from(metadata.get(key)))
    cwes.update(mappings.cwes_for(engine, rule_id))
    return {
        "rule_id": rule_id,
        "cwes": sorted(cwes),
        "message": _message(item) or _message(extra),
        "severity": _first_string(item, ("severity", "issue_severity", "level"))
        or _first_string(extra, ("severity", "level")),
        "file": _first_string(item, ("filename", "file", "path"))
        or _first_string(location, ("path", "filename", "file")),
        "line": _first_int(item, ("line", "line_number", "start_line"))
        or _first_int(location, ("line", "start", "start_line"))
        or _first_int(start, ("line",)),
        "column": _first_int(item, ("column", "column_number", "start_column"))
        or _first_int(location, ("column", "start_column"))
        or _first_int(start, ("col", "column")),
        "raw_index": index,
    }


def _normalize_sarif(
    engine: str, payload: Any, mappings: CweMappings
) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        raise ValueError("invalid SARIF report")
    normalized = []
    raw_index = 0
    for run in payload["runs"]:
        if not isinstance(run, dict):
            continue
        rules = _sarif_rules(run)
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            rule_id = _string(result.get("ruleId"))
            rule = rules.get(rule_id or "", {})
            cwes = _sarif_cwes(result) | _sarif_cwes(rule)
            cwes.update(mappings.cwes_for(engine, rule_id))
            location = _sarif_location(result)
            message = result.get("message", {})
            normalized.append(
                {
                    "rule_id": rule_id,
                    "cwes": sorted(cwes),
                    "message": _message(message if isinstance(message, dict) else {}),
                    "severity": _string(result.get("level")),
                    "file": location.get("file"),
                    "line": location.get("line"),
                    "column": location.get("column"),
                    "raw_index": raw_index,
                }
            )
            raw_index += 1
    return normalized


def _sarif_rules(run: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    tool = run.get("tool", {})
    driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
    raw_rules = driver.get("rules", []) if isinstance(driver, dict) else []
    return {
        rule["id"]: rule
        for rule in raw_rules
        if isinstance(rule, dict) and isinstance(rule.get("id"), str)
    }


def _sarif_cwes(value: Mapping[str, Any]) -> set[str]:
    candidates: list[object] = [value.get("tags")]
    properties = value.get("properties")
    if isinstance(properties, dict):
        candidates.extend([properties.get("tags"), properties.get("cwe")])
    result: set[str] = set()
    for candidate in candidates:
        result.update(cwes_from(candidate))
    return result


def _sarif_location(result: Mapping[str, Any]) -> dict[str, Any]:
    locations = result.get("locations", [])
    if (
        not isinstance(locations, list)
        or not locations
        or not isinstance(locations[0], dict)
    ):
        return {}
    physical = locations[0].get("physicalLocation", {})
    if not isinstance(physical, dict):
        return {}
    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})
    return {
        "file": artifact.get("uri") if isinstance(artifact, dict) else None,
        "line": region.get("startLine") if isinstance(region, dict) else None,
        "column": region.get("startColumn") if isinstance(region, dict) else None,
    }


def _first_list(value: Mapping[str, Any], keys: Iterable[str]) -> list[Any]:
    for key in keys:
        candidate = value.get(key)
        if isinstance(candidate, list):
            return candidate
    return []


def _first_string(value: Mapping[str, Any], keys: Iterable[str]) -> str | None:
    for key in keys:
        candidate = _string(value.get(key))
        if candidate is not None:
            return candidate
    return None


def _first_int(value: Mapping[str, Any], keys: Iterable[str]) -> int | None:
    for key in keys:
        candidate = value.get(key)
        if isinstance(candidate, int) and not isinstance(candidate, bool):
            return candidate
    return None


def _message(value: Mapping[str, Any]) -> str | None:
    for key in ("message", "text", "issue_text", "description", "name"):
        candidate = value.get(key)
        if isinstance(candidate, dict):
            candidate = candidate.get("text")
        if isinstance(candidate, str):
            return candidate
    return None


def _string(value: object) -> str | None:
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        return str(value)
    return None
