"""CSV formatter for PyFlow Checker.

Outputs issues in comma-separated values format.
"""
import csv
import logging
import sys

from .utils import wrap_file_object

LOG = logging.getLogger(__name__)


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Write issues to fileobj in CSV format.

    :param manager: the checker manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """
    results = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)

    baseline = not isinstance(results, list)

    writer = wrap_file_object(fileobj)

    fieldnames = [
        "filename",
        "test_name",
        "test_id",
        "issue_severity",
        "issue_confidence",
        "issue_cwe",
        "issue_text",
        "line_number",
        "col_offset",
        "end_col_offset",
        "line_range",
        "more_info",
    ]

    csv_writer = csv.DictWriter(writer, fieldnames=fieldnames, extrasaction="ignore")
    csv_writer.writeheader()

    if baseline:
        for r in results:
            d = r.as_dict(with_code=False)
            d["issue_cwe"] = d["issue_cwe"]["link"]
            d["more_info"] = "https://pyflow.readthedocs.io/"
            csv_writer.writerow(d)
            if len(results[r]) > 1:
                for c in results[r]:
                    cd = c.as_dict(with_code=False)
                    cd["issue_cwe"] = cd["issue_cwe"]["link"]
                    cd["more_info"] = "https://pyflow.readthedocs.io/"
                    csv_writer.writerow(cd)
    else:
        for result in results:
            r = result.as_dict(with_code=False)
            r["issue_cwe"] = r["issue_cwe"]["link"]
            r["more_info"] = "https://pyflow.readthedocs.io/"
            csv_writer.writerow(r)

    if hasattr(fileobj, "name") and fileobj.name != sys.stdout.name:
        LOG.info("CSV output written to file: %s", fileobj.name)
