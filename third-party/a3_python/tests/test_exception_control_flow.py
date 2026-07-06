"""Tests for the exception-control-flow state-mutation detector (black#15 pattern)."""

import pytest
from pathlib import Path
from a3_python.semantics.exception_control_flow_detector import (
    scan_file_for_exception_control_flow_bugs,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestExceptionControlFlowDetector:
    """Test the AST + Z3 exception-control-flow detector."""

    def test_buggy_version_detected(self):
        """Buggy version: mutate self.leaves then re-raise FormatOn → BUG."""
        bugs = scan_file_for_exception_control_flow_bugs(
            FIXTURES / "black_bug15_buggy.py"
        )
        assert len(bugs) >= 1
        bug = bugs[0]
        assert bug.pattern == "mutate_then_reraise"
        assert "FormatOn" in bug.reason
        assert "leaves" in bug.reason
        assert bug.confidence >= 0.6
        assert "leaves" in (bug.variable or "")

    def test_fixed_version_clean(self):
        """Fixed version: no FormatOn / UnformattedLines → SAFE."""
        bugs = scan_file_for_exception_control_flow_bugs(
            FIXTURES / "black_bug15_fixed.py"
        )
        assert len(bugs) == 0

    def test_analyzer_buggy_reports_bug(self):
        """End-to-end: Analyzer.analyze_file reports BUG on buggy fixture."""
        from a3_python.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(FIXTURES / "black_bug15_buggy.py")
        assert result.verdict == "BUG"
        assert result.bug_type == "EXCEPTION_CONTROL_FLOW"
        assert "mutate_then_reraise" in result.counterexample.get("pattern", "")

    def test_analyzer_fixed_no_bug(self):
        """End-to-end: Analyzer.analyze_file reports no EXCEPTION_CONTROL_FLOW on fixed."""
        from a3_python.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(FIXTURES / "black_bug15_fixed.py")
        # Fixed version should be SAFE or UNKNOWN — not BUG with EXCEPTION_CONTROL_FLOW
        if result.verdict == "BUG":
            assert result.bug_type != "EXCEPTION_CONTROL_FLOW" or \
                "mutate_then_reraise" not in result.counterexample.get("pattern", "")

    def test_safe_pattern_not_flagged(self):
        """Normal try/except with mutation but no re-raise → no bug."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            class MyList:
                def __init__(self):
                    self.items = []

                def safe_append(self, item):
                    try:
                        validated = int(item)
                    except ValueError:
                        self.items.append(None)  # mutation but NO re-raise
                        return
                    self.items.append(validated)
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_exception_control_flow_bugs(Path(f.name))
        assert len(bugs) == 0

    def test_reraise_without_mutation_not_flagged(self):
        """Re-raise without self mutation → no bug."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            import logging

            class Processor:
                def __init__(self):
                    self.items = []

                def process(self, data):
                    try:
                        result = transform(data)
                    except Exception:
                        logging.error("failed")
                        raise  # re-raise but no self mutation
                    self.items.append(result)
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_exception_control_flow_bugs(Path(f.name))
        assert len(bugs) == 0

    def test_stdlib_exception_lower_confidence(self):
        """Catching a stdlib exception (ValueError) with mutate+reraise → lower confidence."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            class Parser:
                def __init__(self):
                    self.errors = []

                def parse(self, text):
                    try:
                        result = int(text)
                    except ValueError:
                        self.errors.append(text)
                        raise
                    return result
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_exception_control_flow_bugs(Path(f.name))
        # ValueError is a stdlib exception, not custom → should NOT be flagged
        # (we only flag custom exception classes)
        assert len(bugs) == 0

    def test_custom_exception_control_flow_from_generator(self):
        """Custom exception raised from generator + caught with mutate+reraise → BUG."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            class StopIteration2(Exception):
                pass

            def my_generator(items):
                for item in items:
                    if item is None:
                        raise StopIteration2(0)
                    yield item

            class Collector:
                def __init__(self):
                    self.collected = []

                def collect(self, items):
                    try:
                        list(my_generator(items))
                    except StopIteration2 as e:
                        self.collected.append(e)
                        raise
                    self.collected.extend(items)
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_exception_control_flow_bugs(Path(f.name))
        assert len(bugs) >= 1
        assert bugs[0].pattern == "mutate_then_reraise"
        assert bugs[0].confidence >= 0.6
