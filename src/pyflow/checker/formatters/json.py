#
# SPDX-License-Identifier: Apache-2.0
r"""
==============
JSON formatter
==============

This formatter outputs the issues in JSON format.

:Example:

.. code-block:: javascript

    {
      "errors": [],
      "generated_at": "2015-12-16T22:27:34Z",
      "metrics": {
        "_totals": {
          "CONFIDENCE.HIGH": 1,
          "CONFIDENCE.LOW": 0,
          "CONFIDENCE.MEDIUM": 0,
          "CONFIDENCE.UNDEFINED": 0,
          "SEVERITY.HIGH": 0,
          "SEVERITY.LOW": 0,
          "SEVERITY.MEDIUM": 1,
          "SEVERITY.UNDEFINED": 0,
          "loc": 5,
          "nosec": 0
        },
        "examples/yaml_load.py": {
          "CONFIDENCE.HIGH": 1,
          "CONFIDENCE.LOW": 0,
          "CONFIDENCE.MEDIUM": 0,
          "CONFIDENCE.UNDEFINED": 0,
          "SEVERITY.HIGH": 0,
          "SEVERITY.LOW": 0,
          "SEVERITY.MEDIUM": 1,
          "SEVERITY.UNDEFINED": 0,
          "loc": 5,
          "nosec": 0
        }
      },
      "results": [
        {
          "code": "5     y = yaml.load(ystr)\n",
          "filename": "examples/yaml_load.py",
          "issue_confidence": "HIGH",
          "issue_severity": "MEDIUM",
          "issue_cwe": {
            "id": 20,
            "link": "https://cwe.mitre.org/data/definitions/20.html"
          },
          "issue_text": "Use yaml.safe_load() instead.\n",
          "line_number": 5,
          "line_range": [5],
          "more_info": "https://bandit.readthedocs.io/en/latest/",
          "test_name": "blacklist_calls",
          "test_id": "B301"
        }
      ]
    }

.. versionadded:: 0.10.0

.. versionchanged:: 1.5.0
    New field `more_info` added to output

.. versionchanged:: 1.7.3
    New field `CWE` added to output

"""

import json
import logging
import sys

from .utils import wrap_file_object, issue_report

LOG = logging.getLogger(__name__)


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints issues in JSON format

    :param manager: the checker manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """

    machine_output = issue_report(manager, sev_level, conf_level, lines=lines)
    machine_output["status"] = "partial" if machine_output["errors"] else "complete"

    result = json.dumps(machine_output, sort_keys=True, indent=2, separators=(",", ": "))

    writer = wrap_file_object(fileobj)
    writer.write(result)
    if writer is not fileobj and hasattr(writer, "flush"):
        writer.flush()

    if hasattr(fileobj, "name") and fileobj.name != sys.stdout.name:
        LOG.info("JSON output written to file: %s", fileobj.name)


def findings_json(findings) -> str:
    """Serialize native finding records without importing their engine."""
    return json.dumps([finding.to_dict() for finding in findings], indent=2)
