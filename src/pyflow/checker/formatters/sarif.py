#
# SPDX-License-Identifier: Apache-2.0
r"""
==============
SARIF formatter
==============

This formatter outputs the issues in SARIF (Static Analysis Results Interchange Format) version 2.1.0.

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
                "text": "Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load()."
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

import datetime
import json
import logging
import sys
from typing import Dict, List, Any, Optional

from ..pattern.core.test_properties import accepts_baseline
from .utils import wrap_file_object

LOG = logging.getLogger(__name__)


def _issue_sort_key(issue) -> tuple:
    return (
        str(getattr(issue, "fname", "")),
        int(getattr(issue, "lineno", -1) or -1),
        str(getattr(issue, "test_id", "")),
        str(getattr(issue, "test", "")),
        str(getattr(issue, "text", "")),
    )


def _map_severity_to_sarif_level(severity: str) -> str:
    """Map PyFlow severity levels to SARIF result levels.

    SARIF levels: none, note, warning, error
    PyFlow levels: UNDEFINED, LOW, MEDIUM, HIGH
    """
    mapping = {"UNDEFINED": "none", "LOW": "note", "MEDIUM": "warning", "HIGH": "error"}
    return mapping.get(severity, "warning")


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
    location = {"physicalLocation": {"artifactLocation": {"uri": issue.fname}}}

    # Add region information if we have line/column data
    region = {}
    if issue.lineno is not None and issue.lineno > 0:
        region["startLine"] = issue.lineno

    if issue.col_offset is not None and issue.col_offset >= 0:
        region["startColumn"] = issue.col_offset + 1  # SARIF is 1-based

    if issue.end_col_offset is not None and issue.end_col_offset > 0:
        region["endColumn"] = issue.end_col_offset + 1  # SARIF is 1-based

    if region:
        location["physicalLocation"]["region"] = region

    return location


def _create_sarif_result(issue) -> Dict[str, Any]:
    """Create a SARIF result object from a PyFlow issue."""
    result = {
        "ruleId": issue.test_id,
        "message": {"text": issue.text},
        "level": _map_severity_to_sarif_level(issue.severity),
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


@accepts_baseline
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
    issues = sorted(issues, key=_issue_sort_key)

    # If no issues, return empty SARIF document
    if not issues:
        sarif_output = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [],
        }
    else:
        # Collect unique rules and artifacts
        rules, artifacts = _collect_unique_rules_and_artifacts(issues)

        # Create SARIF results
        sarif_results = []
        for issue in issues:
            sarif_results.append(_create_sarif_result(issue))

        # Create the SARIF run
        sarif_run = {
            "tool": {
                "driver": {
                    "name": "PyFlow",
                    "version": "0.1.0",
                    "informationUri": "https://pyflow.readthedocs.io/",  # TODO: Update with actual docs URL
                    "rules": list(rules.values()),
                }
            },
            "artifacts": list(artifacts.values()),
            "results": sarif_results,
        }

        # Create the complete SARIF document
        sarif_output = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [sarif_run],
        }

    # Write SARIF output
    result = json.dumps(
        sarif_output, indent=2, separators=(",", ": "), ensure_ascii=False
    )

    wrap_file_object(fileobj).write(result)

    # Check if this is a real file (not stdout) and log accordingly
    if hasattr(fileobj, "name") and fileobj.name != sys.stdout.name:
        LOG.info("SARIF output written to file: %s", fileobj.name)
