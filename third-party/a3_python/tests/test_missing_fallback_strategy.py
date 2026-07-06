"""Tests for the missing-fallback-strategy detector (black#23 pattern)."""

import pytest
import tempfile
import textwrap
from pathlib import Path
from a3_python.semantics.missing_fallback_strategy_detector import (
    scan_file_for_missing_fallback_strategy_bugs,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestMissingFallbackStrategyDetector:
    """Test the AST + Z3 missing-fallback-strategy detector."""

    def test_buggy_version_detected(self):
        """Buggy version: single grammar, catch-transform-raise → BUG."""
        bugs = scan_file_for_missing_fallback_strategy_bugs(
            FIXTURES / "black_bug23_buggy.py"
        )
        assert len(bugs) >= 1
        bug = bugs[0]
        assert bug.pattern == "catch_transform_raise_no_fallback"
        assert "single strategy" in bug.reason or "alternative" in bug.reason.lower()
        assert bug.confidence >= 0.6

    def test_fixed_version_clean(self):
        """Fixed version: for-loop over GRAMMARS with break → SAFE."""
        bugs = scan_file_for_missing_fallback_strategy_bugs(
            FIXTURES / "black_bug23_fixed.py"
        )
        assert len(bugs) == 0

    def test_analyzer_buggy_reports_bug(self):
        """End-to-end: Analyzer.analyze_file reports BUG on buggy fixture."""
        from a3_python.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(FIXTURES / "black_bug23_buggy.py")
        assert result.verdict == "BUG"
        assert result.bug_type == "MISSING_FALLBACK_STRATEGY"
        assert "catch_transform_raise_no_fallback" in result.counterexample.get("pattern", "")

    def test_analyzer_fixed_no_bug(self):
        """End-to-end: Analyzer.analyze_file reports no MISSING_FALLBACK_STRATEGY on fixed."""
        from a3_python.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(FIXTURES / "black_bug23_fixed.py")
        if result.verdict == "BUG":
            assert result.bug_type != "MISSING_FALLBACK_STRATEGY" or \
                "catch_transform_raise_no_fallback" not in result.counterexample.get("pattern", "")

    def test_proper_fallback_not_flagged(self):
        """Function with for-loop fallback over strategies → no bug."""
        code = textwrap.dedent("""\
            class Parser:
                def __init__(self, mode):
                    self.mode = mode
                def parse(self, text):
                    if self.mode == "strict" and "bad" in text:
                        raise SyntaxError("fail")
                    return text

            MODES = ["lenient", "strict", "compat"]

            def parse_with_fallback(text):
                for mode in MODES:
                    p = Parser(mode)
                    try:
                        result = p.parse(text)
                        break
                    except SyntaxError:
                        exc = ValueError("parse failed")
                else:
                    raise exc
                return result
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_missing_fallback_strategy_bugs(Path(f.name))
        assert len(bugs) == 0

    def test_no_alternatives_not_flagged(self):
        """Catch-transform-raise with no alternatives in module → no bug."""
        code = textwrap.dedent("""\
            class ParseError(Exception):
                pass

            def parse_input(text):
                try:
                    result = eval(text)
                except SyntaxError as e:
                    raise ValueError(f"bad input: {e}") from None
                return result
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_missing_fallback_strategy_bugs(Path(f.name))
        assert len(bugs) == 0

    def test_same_exception_type_not_flagged(self):
        """Catching and re-raising the SAME exception type → no bug."""
        code = textwrap.dedent("""\
            config_a = {"mode": "fast"}
            config_b = {"mode": "slow"}
            config_c = {"mode": "safe"}

            def process(config, data):
                if config["mode"] == "fast" and len(data) > 100:
                    raise ValueError("too large for fast mode")
                return data

            def run(data):
                config = config_a
                try:
                    return process(config, data)
                except ValueError as e:
                    raise ValueError(f"failed: {e}")
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_missing_fallback_strategy_bugs(Path(f.name))
        assert len(bugs) == 0

    def test_bare_reraise_not_flagged(self):
        """Bare re-raise (not type transformation) → not this pattern."""
        code = textwrap.dedent("""\
            codec_utf8 = "utf-8"
            codec_latin1 = "latin-1"
            codec_ascii = "ascii"

            def decode_text(data):
                codec = codec_utf8
                try:
                    return data.decode(codec)
                except UnicodeDecodeError:
                    raise
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_missing_fallback_strategy_bugs(Path(f.name))
        assert len(bugs) == 0
