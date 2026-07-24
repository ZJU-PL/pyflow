"""Custom formatter for PyFlow Checker.

Outputs issues using a user-defined template string.

Default template: ``{abspath}:{line}: {test_id}[pyflow]: {severity}: {msg}``
"""
import logging
import os
import re
import string
import sys

from ..pattern.core.test_properties import accepts_baseline
from .utils import wrap_file_object

LOG = logging.getLogger(__name__)


class SafeMapper(dict):
    """Safe mapper to handle format key errors."""

    @classmethod
    def __missing__(cls, key):
        return "{%s}" % key


@accepts_baseline
def report(manager, fileobj, sev_level, conf_level, template=None):
    """Write issues to fileobj in custom format.

    :param manager: the checker manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param template: Output template with non-terminal tags <N>
                     (default: '{abspath}:{line}: '
                     '{test_id}[pyflow]: {severity}: {msg}')
    """
    results = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)

    msg_template = template
    if template is None:
        msg_template = (
            "{abspath}:{line}: {test_id}[pyflow]: {severity}: {msg}"
        )

    # Dictionary of non-terminal tags that will be expanded
    tag_mapper = {
        "abspath": lambda issue: os.path.abspath(issue.fname),
        "relpath": lambda issue: os.path.relpath(issue.fname),
        "line": lambda issue: issue.lineno,
        "col": lambda issue: issue.col_offset,
        "end_col": lambda issue: issue.end_col_offset,
        "test_id": lambda issue: issue.test_id,
        "severity": lambda issue: issue.severity,
        "msg": lambda issue: issue.text,
        "confidence": lambda issue: issue.confidence,
        "range": lambda issue: issue.linerange,
        "cwe": lambda issue: issue.cwe,
    }

    # Create dictionary with tag sets to speed up search for similar tags
    tag_sim_dict = {tag: set(tag) for tag, _ in tag_mapper.items()}

    # Parse the format_string template and check the validity of tags
    try:
        parsed_template_orig = list(string.Formatter().parse(msg_template))
        # of type (literal_text, field_name, fmt_spec, conversion)

        # Check the format validity only, ignore keys
        string.Formatter().vformat(msg_template, (), SafeMapper(line=0))
    except ValueError as e:
        LOG.error("Template is not in valid format: %s", e.args[0])
        sys.exit(2)

    tag_set = {t[1] for t in parsed_template_orig if t[1] is not None}
    if not tag_set:
        LOG.error("No tags were found in the template. Are you missing '{}'?")
        sys.exit(2)

    def get_similar_tag(tag):
        similarity_list = [
            (len(set(tag) & t_set), t) for t, t_set in tag_sim_dict.items()
        ]
        return sorted(similarity_list)[-1][1]

    tag_blacklist = []
    for tag in tag_set:
        # check if the tag is in dictionary
        if tag not in tag_mapper:
            similar_tag = get_similar_tag(tag)
            LOG.warning(
                "Tag '%s' was not recognized and will be skipped, "
                "did you mean to use '%s'?",
                tag,
                similar_tag,
            )
            tag_blacklist += [tag]

    # Compose the message template back with the valid values only
    msg_parsed_template_list = []
    for literal_text, field_name, fmt_spec, conversion in parsed_template_orig:
        if literal_text:
            # if there is '{' or '}', double it to prevent expansion
            literal_text = re.sub("{", "{{", literal_text)
            literal_text = re.sub("}", "}}", literal_text)
            msg_parsed_template_list.append(literal_text)

        if field_name is not None:
            if field_name in tag_blacklist:
                msg_parsed_template_list.append(field_name)
                continue
            # Append the fmt_spec part
            params = [field_name, fmt_spec, conversion]
            markers = ["", ":", "!"]
            msg_parsed_template_list.append(
                ["{"] + [f"{m + p}" if p else "" for m, p in zip(markers, params)] + ["}"]
            )

    msg_parsed_template = (
        "".join([item for lst in msg_parsed_template_list for item in lst])
        + "\n"
    )

    writer = wrap_file_object(fileobj)
    for defect in results:
        evaluated_tags = SafeMapper(
            (k, v(defect)) for k, v in tag_mapper.items()
        )
        output = msg_parsed_template.format(**evaluated_tags)
        writer.write(output)

    if hasattr(fileobj, "name") and fileobj.name != sys.stdout.name:
        LOG.info("Result written to file: %s", fileobj.name)
