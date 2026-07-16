"""Tests for the IFDS shadow scan differential engine."""
from __future__ import annotations

import types

from pyflow.analysis.ifds import (
    DiffEntry,
    ShadowMatch,
    ShadowScanReport,
    diff_scans,
    generate_shadow_report,
    run_shadow_scan,
)


def test_run_shadow_scan_detects_subprocess_run_shell_true():
    code = 'subprocess.run("ls", shell=True)'
    matches = run_shadow_scan(code)
    cwes = [m.cwe for m in matches]
    assert "CWE-78" in cwes


def test_run_shadow_scan_detects_eval():
    code = "eval(user_input)"
    matches = run_shadow_scan(code)
    cwes = [m.cwe for m in matches]
    assert "CWE-95" in cwes


def test_run_shadow_scan_detects_pickle_loads():
    code = "pickle.loads(data)"
    matches = run_shadow_scan(code)
    cwes = [m.cwe for m in matches]
    assert "CWE-502" in cwes


def test_run_shadow_scan_detects_md5_hash():
    code = "hashlib.md5(b'data')"
    matches = run_shadow_scan(code)
    cwes = [m.cwe for m in matches]
    assert "CWE-327" in cwes


def test_run_shadow_scan_empty_code_returns_empty():
    matches = run_shadow_scan("")
    assert matches == []


def test_run_shadow_scan_no_matches_for_clean_code():
    code = "x = 1 + 2\nprint(x)"
    matches = run_shadow_scan(code)
    assert matches == []


def test_run_shadow_scan_deduplicates_same_cwe_same_line():
    code = "subprocess.run('ls', shell=True); subprocess.run('cat', shell=True)"
    matches = run_shadow_scan(code)
    cwe78_matches = [m for m in matches if m.cwe == "CWE-78"]
    assert len(cwe78_matches) == 1


def test_diff_scans_both_hit():
    finding = types.SimpleNamespace(cwe="CWE-78", line=5)
    shadow = ShadowMatch(
        cwe="CWE-78",
        severity="critical",
        label="shell injection",
        line=5,
        pattern="shell",
        snippet="subprocess.run",
    )
    report = diff_scans([finding], [shadow])
    assert len(report.both_hit) == 1
    assert report.both_hit[0].category == "both_hit"
    assert report.both_hit[0].cwe == "CWE-78"
    assert report.both_hit[0].line == 5
    assert len(report.ifds_only) == 0
    assert len(report.shadow_only) == 0


def test_diff_scans_ifds_only():
    finding = types.SimpleNamespace(cwe="CWE-73", line=12)
    shadow = ShadowMatch(
        cwe="CWE-78",
        severity="critical",
        label="shell injection",
        line=5,
        pattern="shell",
        snippet="subprocess.run",
    )
    report = diff_scans([finding], [shadow])
    assert len(report.ifds_only) == 1
    assert report.ifds_only[0].cwe == "CWE-73"
    assert report.ifds_only[0].category == "ifds_only"
    assert len(report.shadow_only) == 1


def test_diff_scans_shadow_only():
    shadow = ShadowMatch(
        cwe="CWE-78",
        severity="critical",
        label="shell injection",
        line=7,
        pattern="shell",
        snippet="subprocess.run",
    )
    report = diff_scans([], [shadow])
    assert len(report.shadow_only) == 1
    assert report.shadow_only[0].cwe == "CWE-78"
    assert report.shadow_only[0].category == "shadow_only"
    assert report.shadow_only[0].line == 7
    assert len(report.ifds_only) == 0
    assert len(report.both_hit) == 0


def test_shadow_scan_report_total_diffs():
    finding = types.SimpleNamespace(cwe="CWE-73", line=1)
    shadow_only = ShadowMatch(
        cwe="CWE-78",
        severity="critical",
        label="shell injection",
        line=7,
        pattern="shell",
        snippet="subprocess.run",
    )
    report = diff_scans([finding], [shadow_only])
    assert report.total_diffs == 2


def test_generate_shadow_report():
    code = 'subprocess.run("ls", shell=True)'
    finding = types.SimpleNamespace(cwe="CWE-78", line=1)
    report = generate_shadow_report(code, [finding])
    assert isinstance(report, ShadowScanReport)
    assert len(report.both_hit) == 1
    assert report.both_hit[0].cwe == "CWE-78"


def test_shadow_match_is_frozen():
    match = ShadowMatch(
        cwe="CWE-78",
        severity="critical",
        label="shell injection",
        line=5,
        pattern="shell",
        snippet="subprocess.run",
    )
    try:
        match.cwe = "CWE-99"
    except AttributeError:
        pass
    else:
        assert False, "Expected AttributeError when mutating frozen ShadowMatch"


def test_diff_entry_is_frozen():
    entry = DiffEntry(
        cwe="CWE-78",
        rule_id="",
        line=5,
        category="both_hit",
        attribution="detected",
        flow_break_at="",
        heuristic_trigger="",
    )
    try:
        entry.cwe = "CWE-99"
    except AttributeError:
        pass
    else:
        assert False, "Expected AttributeError when mutating frozen DiffEntry"
