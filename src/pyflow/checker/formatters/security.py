"""Unified security report facade for all engines (AST-scanner, AST-dataflow, IFDS, CPG)."""

from __future__ import annotations

from typing import Any, Dict

from .report_model import SecurityReport, build_security_report
from .report_render import (
    render_bug_report_csv,
    render_bug_report_custom,
    render_bug_report_html,
    render_bug_report_markdown,
    render_bug_report_text,
    render_bug_report_xml,
    render_bug_report_yaml,
)
from .sarif import render_sarif


def security_report(engine: str, result: Any) -> SecurityReport:
    """Normalize any engine output into the canonical :class:`SecurityReport`."""
    return build_security_report(engine, result)


def security_json(engine: str, result: Any) -> Dict[str, Any]:
    """Serialize any engine output into the canonical JSON envelope."""
    return build_security_report(engine, result).to_dict()


def security_sarif(engine: str, result: Any, *, artifact_uri: str = "") -> Dict[str, Any]:
    """Render any engine output as SARIF v2.1.0."""
    return render_sarif(build_security_report(engine, result), artifact_uri=artifact_uri)


def security_text(
    engine: str,
    result: Any,
    *,
    color: bool = False,
    verbose: bool = False,
    context_lines: int = 1,
    base_dir=None,
) -> str:
    """Render plain text or ANSI-colored terminal bug report."""
    return render_bug_report_text(
        build_security_report(engine, result),
        color=color,
        verbose=verbose,
        context_lines=context_lines,
        base_dir=base_dir,
    )


def security_markdown(engine: str, result: Any, *, base_dir=None) -> str:
    """Render GitHub-Flavored Markdown bug report."""
    return render_bug_report_markdown(build_security_report(engine, result), base_dir=base_dir)


def security_html(engine: str, result: Any, *, base_dir=None) -> str:
    """Render standalone interactive HTML bug report."""
    return render_bug_report_html(build_security_report(engine, result), base_dir=base_dir)


def security_custom(engine: str, result: Any, *, template: str | None = None) -> str:
    """Render line-oriented custom template output."""
    return render_bug_report_custom(build_security_report(engine, result), template=template)


def security_csv(engine: str, result: Any) -> str:
    """Render CSV report."""
    return render_bug_report_csv(build_security_report(engine, result))


def security_xml(engine: str, result: Any) -> str:
    """Render JUnit-compatible XML report."""
    return render_bug_report_xml(build_security_report(engine, result))


def security_yaml(engine: str, result: Any) -> str:
    """Render YAML report."""
    return render_bug_report_yaml(build_security_report(engine, result))


__all__ = [
    "security_csv",
    "security_custom",
    "security_html",
    "security_json",
    "security_markdown",
    "security_report",
    "security_sarif",
    "security_text",
    "security_xml",
    "security_yaml",
]
