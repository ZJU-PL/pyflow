#
# SPDX-License-Identifier: Apache-2.0
r"""
==============
SARIF formatter
==============

This formatter outputs issues in SARIF (Static Analysis Results Interchange Format)
version 2.1.0.

SARIF is an industry standard format for static analysis tools to output their results in a
standardized, tool-agnostic way. This allows security scanning results to be easily consumed
by other tools and integrated into development workflows.

:Example:

.. code-block:: javascript

    {
      "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "PyFlow",
              "version": "0.1.0",
              "informationUri": "https://pyflow.readthedocs.io/",
              "rules": [
                {
                  "id": "B301",
                  "name": "blacklist_calls",
                  "shortDescription": {
                    "text": "Use of unsafe yaml load"
                  },
                  "helpUri": "https://pyflow.readthedocs.io/"
                }
              ]
            }
          },
          "artifacts": [
            {
              "location": {
                "uri": "examples/yaml_load.py"
              }
            }
          ],
          "results": [
            {
              "ruleId": "B301",
              "message": {
                "text": "Use yaml.safe_load() instead of unsafe YAML loading."
              },
              "level": "warning",
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": {
                      "uri": "examples/yaml_load.py"
                    },
                    "region": {
                      "startLine": 5,
                      "startColumn": 1
                    }
                  }
                }
              ]
            }
          ]
        }
      ]
    }

.. versionadded:: 0.10.0

"""

import json
import logging
import sys
from typing import Dict, Any

from .utils import wrap_file_object, issue_sort_key

LOG = logging.getLogger(__name__)


SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)


def severity_level(severity: str | None, *, default: str = "warning") -> str:
    """Normalize checker rankings and SARIF levels at the reporting boundary."""
    levels = {
        "undefined": "none",
        "none": "none",
        "low": "note",
        "note": "note",
        "info": "note",
        "informational": "note",
        "medium": "warning",
        "warning": "warning",
        "high": "error",
        "critical": "error",
        "error": "error",
    }
    return levels.get((severity or "").lower(), default)


def physical_location(uri, *, line=None, column=None, end_line=None, end_column=None):
    """Build a SARIF location from zero-based source columns."""
    physical = {"artifactLocation": {"uri": uri}}
    region = {}
    if line is not None and line > 0:
        region["startLine"] = line
    if column is not None and column >= 0:
        region["startColumn"] = column + 1
    if end_line is not None and end_line > 0:
        region["endLine"] = end_line
    if end_column is not None and end_column >= 0:
        region["endColumn"] = end_column + 1
    if region:
        physical["region"] = region
    return {"physicalLocation": physical}


def location_from_span(span):
    if not span:
        return None
    return physical_location(
        span.get("uri", ""),
        line=max(int(span.get("start_line") or 1), 1),
        column=max(int(span["start_column"]), 0) if span.get("start_column") is not None else None,
        end_line=int(span["end_line"]) if span.get("end_line") is not None else None,
        end_column=int(span["end_column"]) if span.get("end_column") is not None else None,
    )


def sarif_document(
    tool_name,
    results,
    *,
    rules=None,
    artifacts=None,
    invocations=None,
    driver_properties=None,
    run_properties=None,
    schema=SARIF_SCHEMA,
    omit_empty_run=False,
):
    """Assemble the shared SARIF envelope without engine or CLI dependencies."""
    results = list(results)
    document = {"$schema": schema, "version": "2.1.0", "runs": []}
    if omit_empty_run and not results:
        return document
    driver = {"name": tool_name, **(driver_properties or {})}
    if rules is not None:
        driver["rules"] = list(rules)
    run = {"tool": {"driver": driver}, "results": results}
    if artifacts is not None:
        run["artifacts"] = list(artifacts)
    if invocations is not None:
        run["invocations"] = list(invocations)
    if run_properties is not None:
        run["properties"] = dict(run_properties)
    document["runs"].append(run)
    return document


def _map_confidence_to_sarif_properties(confidence: str) -> Dict[str, str]:
    """Map PyFlow confidence levels to SARIF properties."""
    return {"confidence": confidence.lower()}


def _create_sarif_rule(test_id: str, test_name: str) -> Dict[str, Any]:
    """Create a SARIF rule object from PyFlow test information."""
    return {
        "id": test_id,
        "name": test_name,
        "shortDescription": {"text": f"Security issue detected by {test_id}"},
        "helpUri": "https://pyflow.readthedocs.io/",  # TODO: Update with actual docs URL
    }


def _create_sarif_artifact(file_path: str) -> Dict[str, Any]:
    """Create a SARIF artifact object for a file."""
    return {"location": {"uri": file_path}}


def _create_sarif_location(issue) -> Dict[str, Any]:
    """Create a SARIF location object from a PyFlow issue."""
    return physical_location(
        issue.fname,
        line=issue.lineno,
        column=issue.col_offset,
        end_column=(
            issue.end_col_offset if issue.end_col_offset and issue.end_col_offset > 0 else None
        ),
    )


def _create_sarif_result(issue) -> Dict[str, Any]:
    """Create a SARIF result object from a PyFlow issue."""
    result = {
        "ruleId": issue.test_id,
        "message": {"text": issue.text},
        "level": severity_level(issue.severity),
        "locations": [_create_sarif_location(issue)],
        "properties": _map_confidence_to_sarif_properties(issue.confidence),
    }

    # Add CWE information if available
    if issue.cwe and issue.cwe.id != 0:
        result["properties"]["cwe"] = {"id": issue.cwe.id, "url": issue.cwe.link()}

    return result


def _collect_unique_rules_and_artifacts(
    issues,
) -> tuple[Dict[str, Dict], Dict[str, Dict]]:
    """Collect unique rules and artifacts from issues."""
    rules = {}
    artifacts = {}

    for issue in issues:
        # Collect rules
        rule_key = issue.test_id
        if rule_key not in rules:
            rules[rule_key] = _create_sarif_rule(issue.test_id, issue.test)

        # Collect artifacts (files)
        artifact_key = issue.fname
        if artifact_key not in artifacts:
            artifacts[artifact_key] = _create_sarif_artifact(issue.fname)

    sorted_rules = dict(sorted(rules.items(), key=lambda kv: kv[0]))
    sorted_artifacts = dict(sorted(artifacts.items(), key=lambda kv: kv[0]))
    return sorted_rules, sorted_artifacts


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints issues in SARIF format

    :param manager: the checker manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all (unused in SARIF)
    """

    # Get filtered issues
    results = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)

    baseline = not isinstance(results, list)

    if baseline:
        issues = []
        for r in results:
            issues.extend(results[r])
    else:
        issues = results
    issues = sorted(issues, key=issue_sort_key)

    rules, artifacts = _collect_unique_rules_and_artifacts(issues)
    from pyflow import __version__

    errors = (
        list(manager.get_errors())
        if hasattr(manager, "get_errors")
        else [
            {"filename": filename, "reason": reason}
            for filename, reason in getattr(manager, "get_skipped", lambda: ())()
        ]
    )
    sarif_output = sarif_document(
        "PyFlow",
        [_create_sarif_result(issue) for issue in issues],
        rules=rules.values(),
        artifacts=artifacts.values(),
        driver_properties={
            "version": __version__,
            "informationUri": "https://pyflow.readthedocs.io/",
        },
        invocations=[
            {
                "executionSuccessful": not errors,
                "properties": {"analysisStatus": "partial" if errors else "complete"},
                "toolExecutionNotifications": [
                    {"level": "error", "message": {"text": item["reason"]}} for item in errors
                ],
            }
        ],
        schema="https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        omit_empty_run=not errors,
    )

    # Write SARIF output
    result = json.dumps(sarif_output, indent=2, separators=(",", ": "), ensure_ascii=False)

    writer = wrap_file_object(fileobj)
    writer.write(result)
    if writer is not fileobj and hasattr(writer, "flush"):
        writer.flush()

    # Check if this is a real file (not stdout) and log accordingly
    if hasattr(fileobj, "name") and fileobj.name != sys.stdout.name:
        LOG.info("SARIF output written to file: %s", fileobj.name)
