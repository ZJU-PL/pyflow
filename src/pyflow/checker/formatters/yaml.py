"""YAML formatter for PyFlow Checker.

Outputs issues in YAML format. Requires PyYAML to be installed.
"""

import logging
import sys

from .utils import wrap_file_object, issue_report

LOG = logging.getLogger(__name__)

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


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
            "PyYAML is required for YAML format output. " "Install it with: pip install pyyaml"
        )

    machine_output = issue_report(manager, sev_level, conf_level, lines=lines)

    for result in machine_output["results"]:
        if "code" in result:
            code = result["code"].replace("\n", "\\n")
            result["code"] = code

    writer = wrap_file_object(fileobj)
    yaml.safe_dump(machine_output, writer, default_flow_style=False)

    if hasattr(fileobj, "name") and fileobj.name != sys.stdout.name:
        LOG.info("YAML output written to file: %s", fileobj.name)
