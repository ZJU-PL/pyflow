from __future__ import annotations

from a3_python.semantics.crash_summaries import BytecodeCrashSummaryAnalyzer, ExceptionType


def test_compact_proof_suppresses_div_zero_precondition() -> None:
    def f(d: int) -> int:
        while 1 <= d <= 5:
            _ = 10 / d
            d -= 1
        return 0

    summary = BytecodeCrashSummaryAnalyzer(
        f.__code__,
        func_name="f",
        qualified_name="test.f",
    ).analyze()

    assert "DIV_ZERO" not in summary.may_trigger
    assert ExceptionType.ZERO_DIVISION_ERROR not in summary.may_raise
    assert summary.requires_not_zero(0) is False


def test_compact_proof_not_applied_if_var_modified_before_division() -> None:
    def g(d: int) -> int:
        while 1 <= d <= 5:
            d = d - 1
            _ = 10 / d
        return 0

    summary = BytecodeCrashSummaryAnalyzer(
        g.__code__,
        func_name="g",
        qualified_name="test.g",
    ).analyze()

    assert "DIV_ZERO" in summary.may_trigger
    assert ExceptionType.ZERO_DIVISION_ERROR in summary.may_raise
