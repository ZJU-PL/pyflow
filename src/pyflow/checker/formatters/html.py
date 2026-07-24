"""HTML formatter for PyFlow Checker.

Outputs issues as a styled HTML report.
"""
import logging
import sys
from html import escape as html_escape

from ..pattern.core.test_properties import accepts_baseline
from .utils import wrap_file_object

LOG = logging.getLogger(__name__)

HEADER_BLOCK = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>PyFlow Checker Report</title>
<style>
html * { font-family: "Arial", sans-serif; }
pre { font-family: "Monaco", monospace; }
.bordered-box { border: 1px solid black; padding-top:.5em; padding-bottom:.5em; padding-left:1em; }
.metrics-box { font-size: 1.1em; line-height: 130%; }
.metrics-title { font-size: 1.5em; font-weight: 500; margin-bottom: .25em; }
.issue-description { font-size: 1.3em; font-weight: 500; }
.candidate-issues { margin-left: 2em; border-left: solid 1px LightGray; padding-left: 5%; margin-top: .2em; margin-bottom: .2em; }
.issue-block { border: 1px solid LightGray; padding-left: .5em; padding-top: .5em; padding-bottom: .5em; margin-bottom: .5em; }
.issue-sev-high { background-color: Pink; }
.issue-sev-medium { background-color: NavajoWhite; }
.issue-sev-low { background-color: LightCyan; }
</style>
</head>
"""

REPORT_BLOCK = """<body>
{metrics}
{skipped}
<br>
<div id="results">
    {results}
</div>
</body>
</html>
"""

ISSUE_BLOCK = """<div id="issue-{issue_no}">
<div class="issue-block {issue_class}">
    <b>{test_name}: </b> {test_text}<br>
    <b>Test ID:</b> {test_id}<br>
    <b>Severity: </b>{severity}<br>
    <b>Confidence: </b>{confidence}<br>
    <b>CWE: </b><a href="{cwe_link}" target="_blank">CWE-{cwe_id}</a><br>
    <b>File: </b><a href="{path}" target="_blank">{path}</a><br>
    <b>Line number: </b>{line_number}<br>
    <b>More info: </b><a href="{url}" target="_blank">{url}</a><br>
{code}
{candidates}
</div>
</div>
"""

CODE_BLOCK = """<div class="code">
<pre>
{code}
</pre>
</div>
"""

CANDIDATE_BLOCK = """<div class="candidates">
<br>
<b>Candidates: </b>
{candidate_list}
</div>
"""

CANDIDATE_ISSUE = """<div class="candidate">
<div class="candidate-issues">
<pre>{code}</pre>
</div>
</div>
"""

SKIPPED_BLOCK = """<br>
<div id="skipped">
<div class="bordered-box">
<b>Skipped files:</b><br><br>
{files_list}
</div>
</div>
"""

METRICS_BLOCK = """<div id="metrics">
    <div class="metrics-box bordered-box">
        <div class="metrics-title">
            Metrics:<br>
        </div>
        Total lines of code: <span id="loc">{loc}</span><br>
        Total lines skipped (#nosec): <span id="nosec">{nosec}</span>
    </div>
</div>
"""


@accepts_baseline
def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Write issues to fileobj in HTML format.

    :param manager: the checker manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """
    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)

    baseline = not isinstance(issues, list)

    # build the skipped string
    skipped_str = "".join(
        f"{fname} <b>reason:</b> {reason}<br>"
        for fname, reason in manager.get_skipped()
    )
    if skipped_str:
        skipped_text = SKIPPED_BLOCK.format(files_list=skipped_str)
    else:
        skipped_text = ""

    # build the results
    results_str = ""
    for index, issue in enumerate(issues if not baseline else list(issues.keys())):
        if not baseline or len(issues[issue]) == 1:
            candidates = ""
            safe_code = ""
            if getattr(issue, "lineno", None) is not None:
                try:
                    safe_code = html_escape(
                        issue.get_code(lines, True).strip("\n").lstrip(" ")
                    )
                except (TypeError, AttributeError):
                    pass
            code = CODE_BLOCK.format(code=safe_code)
        else:
            candidates_str = ""
            code = ""
            for candidate in issues[issue]:
                candidate_code = ""
                if getattr(candidate, "lineno", None) is not None:
                    try:
                        candidate_code = html_escape(
                            candidate.get_code(lines, True).strip("\n").lstrip(" ")
                        )
                    except (TypeError, AttributeError):
                        pass
                candidates_str += CANDIDATE_ISSUE.format(code=candidate_code)
            candidates = CANDIDATE_BLOCK.format(candidate_list=candidates_str)

        url = "https://pyflow.readthedocs.io/"
        cwe_link = issue.cwe.link() if issue.cwe and issue.cwe.id != 0 else ""
        cwe_id = issue.cwe.id if issue.cwe and issue.cwe.id != 0 else ""
        results_str += ISSUE_BLOCK.format(
            issue_no=index,
            issue_class=f"issue-sev-{issue.severity.lower()}",
            test_name=issue.test,
            test_id=issue.test_id,
            test_text=issue.text,
            severity=issue.severity,
            confidence=issue.confidence,
            cwe_id=cwe_id,
            cwe_link=cwe_link,
            path=issue.fname,
            code=code,
            candidates=candidates,
            url=url,
            line_number=issue.lineno,
        )

    # build the metrics
    metrics_summary = METRICS_BLOCK.format(
        loc=manager.metrics.data["_totals"]["loc"],
        nosec=manager.metrics.data["_totals"]["nosec"],
    )

    # build the report and output it
    report_contents = REPORT_BLOCK.format(
        metrics=metrics_summary, skipped=skipped_text, results=results_str
    )

    writer = wrap_file_object(fileobj)
    writer.write(HEADER_BLOCK)
    writer.write(report_contents)

    if hasattr(fileobj, "name") and fileobj.name != sys.stdout.name:
        LOG.info("HTML output written to file: %s", fileobj.name)
