# SPDX-License-Identifier: Apache-2.0
r"""
==============
Text Formatter
==============

This formatter outputs the issues as plain text.

:Example:

.. code-block:: none

    >> Issue: [B301:blacklist_calls] Use of unsafe yaml load. Allows
       instantiation of arbitrary objects. Consider yaml.safe_load().

       Severity: Medium   Confidence: High
       CWE: CWE-20 (https://cwe.mitre.org/data/definitions/20.html)
       More Info: https://bandit.readthedocs.io/en/latest/
       Location: examples/yaml_load.py:5
    4       ystr = yaml.dump({'a' : 1, 'b' : 2, 'c' : 3})
    5       y = yaml.load(ystr)
    6       yaml.dump(y)

.. versionadded:: 0.9.0

.. versionchanged:: 1.5.0
    New field `more_info` added to output

.. versionchanged:: 1.7.3
    New field `CWE` added to output

"""
import datetime
import logging
import sys

from ..pattern.core import constants
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


def get_verbose_details(manager):
    bits = []
    bits.append(f"Files in scope ({len(manager.files_list)}):")
    tpl = "\t%s (score: {SEVERITY: %i, CONFIDENCE: %i})"
    bits.extend(
        [
            tpl % (item, sum(score["SEVERITY"]), sum(score["CONFIDENCE"]))
            for (item, score) in zip(manager.files_list, manager.scores)
        ]
    )
    bits.append(f"Files excluded ({len(manager.excluded_files)}):")
    bits.extend([f"\t{fname}" for fname in manager.excluded_files])
    return "\n".join([bit for bit in bits])


def get_metrics(manager):
    bits = []
    bits.append("\nRun metrics:")
    for criteria, _ in constants.CRITERIA:
        bits.append(f"\tTotal issues (by {criteria.lower()}):")
        for rank in constants.RANKING:
            bits.append(
                "\t\t%s: %s"
                % (
                    rank.capitalize(),
                    manager.metrics.data["_totals"][f"{criteria}.{rank}"],
                )
            )
    return "\n".join([bit for bit in bits])


def _output_issue_str(issue, indent, show_lineno=True, show_code=True, lines=-1):
    # returns a list of lines that should be added to the existing lines list
    bits = [
        f"{indent}>> Issue: [{issue.test_id}:{issue.test}] {issue.text}",
        f"{indent}   Severity: {issue.severity.capitalize()}   Confidence: {issue.confidence.capitalize()}",
        f"{indent}   CWE: {str(issue.cwe)}",
        f"{indent}   More Info: https://pyflow.readthedocs.io/",  # TODO: Update with actual docs URL
        f"{indent}   Location: {issue.fname}:{issue.lineno if show_lineno else ''}:{issue.col_offset if show_lineno else ''}",
    ]

    if show_code and getattr(issue, "lineno", None) is not None:
        try:
            code = issue.get_code(lines, True)
            bits.extend(indent + line for line in code.split("\n"))
        except (TypeError, AttributeError):
            pass

    return "\n".join(bits)


def get_results(manager, sev_level, conf_level, lines):
    bits = []
    issues = manager.get_issue_list(sev_level, conf_level)
    baseline = not isinstance(issues, list)
    candidate_indent = " " * 10

    if not len(issues):
        return "\tNo issues identified."

    ordered_issues = sorted(issues, key=_issue_sort_key)
    for issue in ordered_issues:
        # if not a baseline or only one candidate we know the issue
        if not baseline or len(issues[issue]) == 1:
            bits.append(_output_issue_str(issue, "", lines=lines))

        # otherwise show the finding and the candidates
        else:
            bits.append(
                _output_issue_str(issue, "", show_lineno=False, show_code=False)
            )
            bits.append("\n-- Candidate Issues --")
            for candidate in sorted(issues[issue], key=_issue_sort_key):
                bits.append(_output_issue_str(candidate, candidate_indent, lines=lines))
                bits.append("\n")
        bits.append("-" * 50)
    return "\n".join(bits)


@accepts_baseline
def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints discovered issues in the text format

    :param manager: the checker manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """
    if getattr(manager, "quiet", False) and not getattr(manager, "results_count", lambda s, c: False)(sev_level, conf_level):
        return

    bits = [f"Run started:{datetime.datetime.now(datetime.timezone.utc)}"]

    if manager.verbose:
        bits.append(get_verbose_details(manager))

    bits.extend(
        [
            "\nTest results:",
            get_results(manager, sev_level, conf_level, lines),
            "\nCode scanned:",
            f"\tTotal lines of code: {manager.metrics.data['_totals']['loc']}",
            f"\tTotal lines skipped (#nosec): {manager.metrics.data['_totals']['nosec']}",
            f"\tTotal potential issues skipped due to specifically being disabled (e.g., #nosec BXXX): {manager.metrics.data['_totals']['skipped_tests']}",
        ]
    )

    skipped = sorted(manager.get_skipped(), key=lambda s: (s[0], s[1]))
    bits.extend([get_metrics(manager), f"Files skipped ({len(skipped)}):"])
    bits.extend(f"\t{skip[0]} ({skip[1]})" for skip in skipped)

    writer = wrap_file_object(fileobj)
    writer.write("\n".join(bits) + "\n")
    if writer is not fileobj and hasattr(writer, "flush"):
        writer.flush()

    if hasattr(fileobj, "name") and fileobj.name != sys.stdout.name:
        LOG.info("Text output written to file: %s", fileobj.name)
