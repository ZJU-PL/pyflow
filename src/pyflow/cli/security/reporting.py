"""CLI output dispatch over the canonical :class:`SecurityReport`."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from pyflow.checker.formatters.report_model import SecurityReport, build_security_report
from pyflow.checker.formatters.report_render import (
    render_bug_report_csv,
    render_bug_report_custom,
    render_bug_report_html,
    render_bug_report_markdown,
    render_bug_report_text,
    render_bug_report_xml,
    render_bug_report_yaml,
)
from pyflow.checker.formatters.sarif import render_sarif


def _resolve_cli_base_dir(args) -> Path | None:
    targets = getattr(args, "targets", None) or ()
    if len(targets) != 1:
        return None
    target_path = Path(targets[0])
    return target_path if target_path.is_dir() else target_path.parent


def _output_results(engine: str, result, args) -> None:
    """Write a canonical :class:`SecurityReport` in any supported CLI format."""
    report = result if isinstance(result, SecurityReport) else build_security_report(engine, result)
    fmt = getattr(args, "format", "text")
    verbose = bool(getattr(args, "verbose", False))
    base_dir = _resolve_cli_base_dir(args)
    artifact_uri = str(args.targets[0]) if getattr(args, "targets", None) else ""

    if fmt == "text":
        rendered = render_bug_report_text(report, color=False, verbose=verbose, base_dir=base_dir)
    elif fmt == "screen":
        rendered = render_bug_report_text(report, color=True, verbose=verbose, base_dir=base_dir)
    elif fmt == "markdown":
        rendered = render_bug_report_markdown(report, base_dir=base_dir, verbose=verbose)
    elif fmt == "html":
        rendered = render_bug_report_html(report, base_dir=base_dir, verbose=verbose)
    elif fmt == "json":
        rendered = json.dumps(report.to_dict(), indent=2)
    elif fmt == "sarif":
        rendered = json.dumps(render_sarif(report, artifact_uri=artifact_uri), indent=2)
    elif fmt == "custom":
        rendered = render_bug_report_custom(report, template=getattr(args, "custom_template", None))
    elif fmt == "csv":
        rendered = render_bug_report_csv(report)
    elif fmt == "xml":
        rendered = render_bug_report_xml(report)
    elif fmt == "yaml":
        rendered = render_bug_report_yaml(report)
    else:
        raise ValueError(
            f"Format '{fmt}' is not supported; "
            "use one of: text, screen, markdown, html, json, sarif, custom, csv, xml, yaml"
        )

    out_path = getattr(args, "output", None)
    if out_path:
        Path(out_path).write_text(rendered + "\n", encoding="utf-8")
    else:
        sys.stdout.write(rendered + "\n")
