"""XML formatter for PyFlow Checker.

Outputs issues in XML format using a JUnit-style testsuite layout.
"""
import logging
import sys
from xml.etree import ElementTree as ET

from .utils import wrap_file_object

LOG = logging.getLogger(__name__)


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Write issues to fileobj in XML format.

    :param manager: the checker manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """
    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)

    root = ET.Element("testsuite", name="pyflow-checker", tests=str(len(issues)))

    for issue in issues:
        test = issue.test
        testcase = ET.SubElement(
            root, "testcase", classname=issue.fname, name=test
        )

        text = (
            "Test ID: %s Severity: %s Confidence: %s\nCWE: %s\n%s\n"
            "Location %s:%s"
        )
        text %= (
            issue.test_id,
            issue.severity,
            issue.confidence,
            issue.cwe,
            issue.text,
            issue.fname,
            issue.lineno,
        )
        ET.SubElement(
            testcase,
            "error",
            more_info="https://pyflow.readthedocs.io/",
            type=issue.severity,
            message=issue.text,
        ).text = text

    tree = ET.ElementTree(root)

    writer = wrap_file_object(fileobj)
    tree.write(writer, encoding="unicode", xml_declaration=True)

    if hasattr(fileobj, "name") and fileobj.name != sys.stdout.name:
        LOG.info("XML output written to file: %s", fileobj.name)
