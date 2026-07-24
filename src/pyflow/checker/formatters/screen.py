"""Screen formatter for PyFlow Checker.

Outputs issues as color-coded text to screen, using VT100 terminal codes.
"""
import datetime
import logging
import sys

from ..pattern.core import constants
from ..pattern.core.test_properties import accepts_baseline
from .utils import wrap_file_object

LOG = logging.getLogger(__name__)

IS_WIN_PLATFORM = sys.platform.startswith("win32")
_colorama = None

if IS_WIN_PLATFORM:
    try:
        import colorama  # type: ignore  # noqa: F811,E0401

        _colorama = colorama
    except ImportError:
        pass

COLOR = {
    "DEFAULT": "\033[0m",
    "HEADER": "\033[95m",
    "LOW": "\033[94m",
    "MEDIUM": "\033[93m",
    "HIGH": "\033[91m",
}


def header(text, *args):
    return f"{COLOR['HEADER']}{text % args}{COLOR['DEFAULT']}"


def get_verbose_details(manager):
    bits = []
    bits.append(header("Files in scope (%i):", len(manager.files_list)))
    tpl = "\t%s (score: {SEVERITY: %i, CONFIDENCE: %i})"
    bits.extend(
        [
            tpl % (item, sum(score["SEVERITY"]), sum(score["CONFIDENCE"]))
            for (item, score) in zip(manager.files_list, manager.scores)
        ]
    )
    bits.append(header("Files excluded (%i):", len(manager.excluded_files)))
    bits.extend([f"\t{fname}" for fname in manager.excluded_files])
    return "\n".join([str(bit) for bit in bits])


def get_metrics(manager):
    bits = []
    bits.append(header("\nRun metrics:"))
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
    return "\n".join([str(bit) for bit in bits])


def _output_issue_str(issue, indent, show_lineno=True, show_code=True, lines=-1):
    bits = []
    bits.append(
        "%s%s>> Issue: [%s:%s] %s"
        % (
            indent,
            COLOR[issue.severity],
            issue.test_id,
            issue.test,
            issue.text,
        )
    )
    bits.append(
        "%s   Severity: %s   Confidence: %s"
        % (
            indent,
            issue.severity.capitalize(),
            issue.confidence.capitalize(),
        )
    )
    bits.append(f"{indent}   CWE: {str(issue.cwe)}")
    bits.append(f"{indent}   More Info: https://pyflow.readthedocs.io/")
    bits.append(
        "%s   Location: %s:%s:%s%s"
        % (
            indent,
            issue.fname,
            issue.lineno if show_lineno else "",
            issue.col_offset if show_lineno else "",
            COLOR["DEFAULT"],
        )
    )
    if show_code and getattr(issue, "lineno", None) is not None:
        try:
            code = issue.get_code(lines, True)
            bits.extend([indent + line for line in code.split("\n")])
        except (TypeError, AttributeError):
            pass
    return "\n".join([bit for bit in bits])


def get_results(manager, sev_level, conf_level, lines):
    bits = []
    issues = manager.get_issue_list(sev_level, conf_level)
    baseline = not isinstance(issues, list)
    candidate_indent = " " * 10

    if not len(issues):
        return "\tNo issues identified."

    for issue in issues:
        if not baseline or len(issues[issue]) == 1:
            bits.append(_output_issue_str(issue, "", lines=lines))
        else:
            bits.append(
                _output_issue_str(
                    issue, "", show_lineno=False, show_code=False
                )
            )
            bits.append("\n-- Candidate Issues --")
            for candidate in issues[issue]:
                bits.append(
                    _output_issue_str(candidate, candidate_indent, lines=lines)
                )
                bits.append("\n")
        bits.append("-" * 50)
    return "\n".join([bit for bit in bits])


def do_print(bits):
    print("\n".join([bit for bit in bits]))


@accepts_baseline
def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Print discovered issues formatted for screen reading.

    Uses VT100 terminal codes for colored text.

    :param manager: the checker manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """
    if IS_WIN_PLATFORM and _colorama is not None:
        _colorama.init()

    bits = []
    if not getattr(manager, "quiet", False) or getattr(manager, "results_count", lambda s, c: False)(sev_level, conf_level):
        bits.append(
            header("Run started:%s", datetime.datetime.now(datetime.timezone.utc))
        )

        if manager.verbose:
            bits.append(get_verbose_details(manager))

        bits.append(header("\nTest results:"))
        bits.append(get_results(manager, sev_level, conf_level, lines))
        bits.append(header("\nCode scanned:"))
        bits.append(
            "\tTotal lines of code: %i"
            % (manager.metrics.data["_totals"]["loc"])
        )
        bits.append(
            "\tTotal lines skipped (#nosec): %i"
            % (manager.metrics.data["_totals"]["nosec"])
        )
        bits.append(get_metrics(manager))
        skipped = manager.get_skipped()
        bits.append(header("Files skipped (%i):", len(skipped)))
        bits.extend(["\t%s (%s)" % skip for skip in skipped])
        do_print(bits)

    if hasattr(fileobj, "name") and fileobj.name != sys.stdout.name:
        LOG.info(
            "Screen formatter output was not written to file: %s, "
            "consider '-f txt'",
            fileobj.name,
        )

    if IS_WIN_PLATFORM and _colorama is not None:
        _colorama.deinit()
