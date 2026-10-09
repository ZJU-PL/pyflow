"""CLI output stream selection for the shared checker formatters."""

import json
import sys

from pyflow.checker.common import constants as b_constants
from pyflow.checker.formatters.security import security_json, security_sarif, security_text


def _output_results(engine: str, result, args) -> None:
    """Write analysis results in the requested format."""
    fmt = getattr(args, "format", "text")
    if fmt == "json" and getattr(args, "json_schema", "legacy") == "unified":
        from .filters import unified_report

        document = unified_report(engine, result)
        if getattr(args, "output", None):
            args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        else:
            json.dump(document, sys.stdout, indent=2)
            sys.stdout.write("\n")
        return

    # Pattern scanning and non-normalized AST-dataflow formats use checker
    # formatters.
    # which need a manager object. IFDS/CPG use shared report rendering.
    if (
        engine == "ast-scanner"
        or (engine == "ast-dataflow" and fmt not in ("text", "json", "sarif"))
    ) and fmt in (
        "csv",
        "html",
        "screen",
        "text",
        "xml",
        "yaml",
        "json",
        "sarif",
        "custom",
    ):
        _output_via_formatter(engine, result, args, fmt)
        return

    # Fallback for ifds / cpg engines (dict-based results)
    out_file = None
    try:
        if getattr(args, "output", None):
            out_file = open(args.output, "w", encoding="utf-8")
        output = out_file or sys.stdout

        if fmt == "text":
            output.write(security_text(engine, result))
            output.write("\n")
        elif fmt == "json":
            json.dump(security_json(engine, result), output, indent=2)
            output.write("\n")
        elif fmt == "sarif":
            sarif_doc = security_sarif(
                engine,
                result,
                artifact_uri=str(args.targets[0]) if getattr(args, "targets", None) else "",
            )
            json.dump(sarif_doc, output, indent=2)
            output.write("\n")
        else:
            # Unsupported format for dict-based engines, fall back to text
            output.write(security_text(engine, result))
            output.write("\n")
    finally:
        if out_file:
            out_file.close()


def _output_via_formatter(engine: str, result, args, fmt: str) -> None:
    """Route scanner-based results through the appropriate checker formatter."""
    from pyflow.checker.common import constants as b_constants

    sev_level = b_constants.LOW
    conf_level = b_constants.LOW
    lines = -1

    out_file = None
    try:
        if getattr(args, "output", None):
            out_file = open(
                args.output,
                "wb" if fmt in ("xml",) else "w",
                encoding="utf-8" if fmt != "xml" else None,
            )
        fileobj = out_file or sys.stdout

        if fmt == "json":
            from pyflow.checker.formatters import json as json_fmt

            json_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "sarif":
            from pyflow.checker.formatters import sarif as sarif_fmt

            sarif_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "text":
            from pyflow.checker.formatters import text as text_fmt

            text_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "csv":
            from pyflow.checker.formatters import csv as csv_fmt

            csv_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "html":
            from pyflow.checker.formatters import html as html_fmt

            html_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "screen":
            from pyflow.checker.formatters import screen as screen_fmt

            screen_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "xml":
            from pyflow.checker.formatters import xml as xml_fmt

            xml_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "yaml":
            from pyflow.checker.formatters import yaml as yaml_fmt

            yaml_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "custom":
            from pyflow.checker.formatters import custom as custom_fmt

            template = getattr(args, "custom_template", None)
            custom_fmt.report(result, fileobj, sev_level, conf_level, template=template)
    finally:
        if out_file:
            out_file.close()
