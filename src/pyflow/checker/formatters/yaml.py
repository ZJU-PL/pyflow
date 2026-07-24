"""YAML formatter for PyFlow Checker.

Outputs issues in YAML format. Requires PyYAML to be installed.
"""
import datetime
import logging
import operator
import sys

from ..pattern.core.test_properties import accepts_baseline
from .utils import wrap_file_object

LOG = logging.getLogger(__name__)

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


@accepts_baseline
def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Write issues to fileobj in YAML format.

    Requires PyYAML to be installed (pip install pyyaml).

    :param manager: the checker manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """
    if yaml is None:
        raise ImportError(
            "PyYAML is required for YAML format output. "
            "Install it with: pip install pyyaml"
        )

    machine_output = {"results": [], "errors": []}
    for fname, reason in manager.get_skipped():
        machine_output["errors"].append({"filename": fname, "reason": reason})
    machine_output["errors"] = sorted(
        machine_output["errors"], key=lambda x: (x["filename"], x["reason"])
    )

    results = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)

    baseline = not isinstance(results, list)

    if baseline:
        collector = []
        for r in results:
            d = r.as_dict(max_lines=lines)
            d["more_info"] = "https://pyflow.readthedocs.io/"
            if len(results[r]) > 1:
                d["candidates"] = [c.as_dict(max_lines=lines) for c in results[r]]
            collector.append(d)
    else:
        collector = [r.as_dict(max_lines=lines) for r in results]
        for elem in collector:
            elem["more_info"] = "https://pyflow.readthedocs.io/"

    itemgetter = operator.itemgetter
    machine_output["results"] = sorted(collector, key=itemgetter("filename"))

    machine_output["metrics"] = manager.metrics.data

    for result in machine_output["results"]:
        if "code" in result:
            code = result["code"].replace("\n", "\\n")
            result["code"] = code

    TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
    time_string = datetime.datetime.now(datetime.timezone.utc).strftime(TS_FORMAT)
    machine_output["generated_at"] = time_string

    writer = wrap_file_object(fileobj)
    yaml.safe_dump(machine_output, writer, default_flow_style=False)

    if hasattr(fileobj, "name") and fileobj.name != sys.stdout.name:
        LOG.info("YAML output written to file: %s", fileobj.name)
