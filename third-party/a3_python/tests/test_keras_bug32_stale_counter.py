"""
Tests for keras bug 32: counter update after comparison (STALE_VALUE).

The buggy code places ``self.wait += 1`` after ``if self.wait >= self.patience``,
causing the comparison to use a stale (pre-increment) counter value (off-by-one).

The fixed code moves the increment before the comparison.

We verify:
  - Buggy fixture triggers STALE_VALUE
  - Fixed fixture does NOT trigger STALE_VALUE
"""

import importlib.util
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _get_crash_summary_bugs(filepath: Path) -> set:
    """Run crash summary analysis and return set of bug types across all functions."""
    from a3_python.cfg.call_graph import build_call_graph_from_file
    from a3_python.semantics.crash_summaries import BytecodeCrashSummaryComputer

    call_graph = build_call_graph_from_file(filepath)
    computer = BytecodeCrashSummaryComputer(call_graph)
    summaries = computer.compute_all()
    bug_types = set()
    for summary in summaries.values():
        bug_types.update(summary.may_trigger)
    return bug_types


def _get_interproc_bugs(filepath: Path) -> set:
    """Run full interprocedural analysis (without intent filtering) and return bug types."""
    from a3_python.semantics.interprocedural_bugs import (
        InterproceduralBugTracker,
        compute_all_bug_summaries,
    )
    from a3_python.semantics.summaries import SummaryComputer
    from a3_python.cfg.call_graph import build_call_graph_from_file
    from a3_python.semantics.crash_summaries import BytecodeCrashSummaryComputer
    from a3_python.contracts.security_lattice import (
        get_source_contracts_for_summaries,
        get_sink_contracts_for_summaries,
        get_sanitizer_contracts_for_summaries,
        init_security_contracts,
    )

    init_security_contracts()
    call_graph = build_call_graph_from_file(filepath)
    entry_points = set(call_graph.functions.keys())

    crash_computer = BytecodeCrashSummaryComputer(call_graph)
    crash_summaries = crash_computer.compute_all()

    taint_computer = SummaryComputer(
        call_graph,
        source_contracts=get_source_contracts_for_summaries(),
        sink_contracts=get_sink_contracts_for_summaries(),
        sanitizer_contracts=get_sanitizer_contracts_for_summaries(),
    )
    taint_summaries = taint_computer.compute_all()
    combined = compute_all_bug_summaries(call_graph, taint_summaries)

    tracker = InterproceduralBugTracker(
        call_graph=call_graph,
        entry_points=entry_points,
        reachable_functions=entry_points.copy(),
        taint_summaries=taint_summaries,
        crash_summaries=crash_summaries,
        combined_summaries=combined,
    )

    # Disable intent filtering since fixtures live in tests/fixtures/
    bugs = tracker.find_all_bugs(apply_intent_filter=False)
    return {b.bug_type for b in bugs}


class TestKerasBug32StaleCounter:
    """Test detection of counter-update-after-check (STALE_VALUE)."""

    def test_buggy_triggers_stale_value_in_summary(self):
        """Buggy version: crash summary flags STALE_VALUE for on_epoch_end."""
        buggy_path = FIXTURES / "keras_bug32_buggy.py"
        findings = _get_crash_summary_bugs(buggy_path)
        assert "STALE_VALUE" in findings, (
            f"Expected STALE_VALUE in buggy keras#32 crash summaries, got: {findings}"
        )

    def test_fixed_no_stale_value_in_summary(self):
        """Fixed version: no STALE_VALUE in any crash summary."""
        fixed_path = FIXTURES / "keras_bug32_fixed.py"
        findings = _get_crash_summary_bugs(fixed_path)
        assert "STALE_VALUE" not in findings, (
            f"Fixed keras#32 should not trigger STALE_VALUE, got: {findings}"
        )

    def test_buggy_triggers_stale_value_interproc(self):
        """Buggy version: interprocedural analysis reports STALE_VALUE."""
        buggy_path = FIXTURES / "keras_bug32_buggy.py"
        findings = _get_interproc_bugs(buggy_path)
        assert "STALE_VALUE" in findings, (
            f"Expected STALE_VALUE in buggy keras#32 interproc, got: {findings}"
        )

    def test_fixed_no_stale_value_interproc(self):
        """Fixed version: interprocedural analysis does NOT report STALE_VALUE."""
        fixed_path = FIXTURES / "keras_bug32_fixed.py"
        findings = _get_interproc_bugs(fixed_path)
        assert "STALE_VALUE" not in findings, (
            f"Fixed keras#32 should not trigger STALE_VALUE interproc, got: {findings}"
        )

    def test_buggy_findings_differ_from_fixed(self):
        """Buggy and fixed crash summary findings must differ (not SAME-FINDINGS)."""
        buggy_path = FIXTURES / "keras_bug32_buggy.py"
        fixed_path = FIXTURES / "keras_bug32_fixed.py"
        buggy_findings = _get_crash_summary_bugs(buggy_path)
        fixed_findings = _get_crash_summary_bugs(fixed_path)
        assert "STALE_VALUE" in buggy_findings
        assert "STALE_VALUE" not in fixed_findings
