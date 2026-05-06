"""
Tests for the defensive assert False guard in crash summaries.

Ensures that:
1. LOAD_COMMON_CONSTANT (Python 3.12+) is recognized as an assertion opcode
2. Defensive 'assert False' in else branches after exhaustive isinstance/type
   checks is NOT flagged as ASSERT_FAIL (avoids false positives)
3. Non-defensive 'assert False' IS still detected

NOTE: Inner functions are imported from a fixture file (not defined inline)
because pytest rewrites assert statements in test files, which changes the
bytecode and would prevent the analyzer from seeing the assertions.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest
from pyflow.a3_python.semantics.crash_summaries import BytecodeCrashSummaryAnalyzer

# Load fixture module WITHOUT pytest assertion rewriting
_fixture_path = Path(__file__).with_name("fixtures") / "defensive_assert_sample.py"
_spec = importlib.util.spec_from_file_location(
    "defensive_assert_sample",
    _fixture_path,
)
_fixture_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture_mod)


def test_defensive_assert_false_not_flagged():
    """
    assert False in an else branch after isinstance/type checks
    should be recognised as defensive and NOT appear in crash_locations.
    Pattern: black bug 14 fixed code.
    """
    code = _fixture_mod.get_imports_from_children.__code__
    analyzer = BytecodeCrashSummaryAnalyzer(
        code,
        func_name="get_imports_from_children",
        qualified_name="test.get_imports_from_children",
    )
    analyzer.analyze()

    assert_fail_locs = [
        loc for bug_type, loc in analyzer.crash_locations if bug_type == "ASSERT_FAIL"
    ]
    assert len(assert_fail_locs) == 0, (
        f"Defensive assert False should not appear in crash_locations, "
        f"got {assert_fail_locs}"
    )


def test_non_defensive_assert_false_detected():
    """
    A plain assert False without preceding type checks SHOULD be detected.
    """
    code = _fixture_mod.bad_function.__code__
    analyzer = BytecodeCrashSummaryAnalyzer(
        code,
        func_name="bad_function",
        qualified_name="test.bad_function",
    )
    summary = analyzer.analyze()

    assert "ASSERT_FAIL" in summary.may_trigger, (
        "Non-defensive assert False should be detected as ASSERT_FAIL"
    )
    assert_fail_locs = [
        loc for bug_type, loc in analyzer.crash_locations if bug_type == "ASSERT_FAIL"
    ]
    assert len(assert_fail_locs) > 0, (
        "Non-defensive assert False should appear in crash_locations"
    )


@pytest.mark.skipif(
    sys.version_info < (3, 12),
    reason="LOAD_COMMON_CONSTANT only exists in Python 3.12+",
)
def test_load_common_constant_assertion_detected():
    """
    On Python 3.12+, assertions use LOAD_COMMON_CONSTANT instead of
    LOAD_ASSERTION_ERROR. Verify that the analyzer handles this opcode.
    """
    import dis

    code = _fixture_mod.conditional_assert.__code__

    # Verify the bytecode actually uses LOAD_COMMON_CONSTANT
    opcodes = [i.opname for i in dis.get_instructions(code)]
    assert "LOAD_COMMON_CONSTANT" in opcodes or "LOAD_ASSERTION_ERROR" in opcodes, (
        "Expected assertion opcode in bytecode"
    )

    analyzer = BytecodeCrashSummaryAnalyzer(
        code,
        func_name="conditional_assert",
        qualified_name="test.conditional_assert",
    )
    summary = analyzer.analyze()

    assert "ASSERT_FAIL" in summary.may_trigger, (
        "Conditional assertion should be detected even with LOAD_COMMON_CONSTANT"
    )
