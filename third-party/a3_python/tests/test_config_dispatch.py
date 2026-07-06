"""Tests for the config dispatch completeness detector (black#6 pattern)."""

import pytest
from pathlib import Path
from a3_python.semantics.config_dispatch_detector import (
    scan_file_for_config_dispatch_bugs,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestConfigDispatchDetector:
    """Test the AST + Z3 config dispatch completeness detector."""

    def test_buggy_version_detected(self):
        """Buggy version: 3+ versions map to identical feature sets → BUG."""
        bugs = scan_file_for_config_dispatch_bugs(FIXTURES / "config_dispatch_buggy.py")
        assert len(bugs) == 1
        bug = bugs[0]
        assert bug.pattern == "indistinguishable_versions"
        assert "PY36" in bug.reason
        assert "PY37" in bug.reason
        assert "PY38" in bug.reason
        assert bug.confidence >= 0.8
        assert bug.variable == "VERSION_TO_FEATURES"

    def test_fixed_version_clean(self):
        """Fixed version: no group of 3+ identical feature sets → SAFE."""
        bugs = scan_file_for_config_dispatch_bugs(FIXTURES / "config_dispatch_fixed.py")
        assert len(bugs) == 0

    def test_analyzer_buggy_reports_bug(self):
        """End-to-end: Analyzer.analyze_file reports BUG on buggy fixture."""
        from a3_python.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(FIXTURES / "config_dispatch_buggy.py")
        assert result.verdict == "BUG"
        assert result.bug_type == "TYPE_CONFUSION"
        assert "VERSION_TO_FEATURES" in result.counterexample.get("reason", "")

    def test_analyzer_fixed_no_bug(self):
        """End-to-end: Analyzer.analyze_file reports no TYPE_CONFUSION on fixed."""
        from a3_python.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(FIXTURES / "config_dispatch_fixed.py")
        # Fixed version should be SAFE or UNKNOWN — not BUG with TYPE_CONFUSION
        if result.verdict == "BUG":
            assert result.bug_type != "TYPE_CONFUSION" or \
                "indistinguishable_versions" not in result.counterexample.get("pattern", "")

    def test_two_identical_entries_not_flagged(self):
        """Only 2 identical entries is below threshold → no bug."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            from enum import Enum

            class Version(Enum):
                V1 = 1
                V2 = 2
                V3 = 3

            class Feat(Enum):
                A = 0
                B = 1

            MAPPING = {
                Version.V1: set(),
                Version.V2: {Feat.A, Feat.B},
                Version.V3: {Feat.A, Feat.B},
            }
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_config_dispatch_bugs(Path(f.name))
        assert len(bugs) == 0

    def test_three_identical_entries_flagged(self):
        """Three identical entries → bug."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            from enum import Enum

            class Version(Enum):
                V1 = 1
                V2 = 2
                V3 = 3
                V4 = 4

            class Feat(Enum):
                A = 0
                B = 1

            MAPPING = {
                Version.V1: set(),
                Version.V2: {Feat.A, Feat.B},
                Version.V3: {Feat.A, Feat.B},
                Version.V4: {Feat.A, Feat.B},
            }
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_config_dispatch_bugs(Path(f.name))
        assert len(bugs) == 1
        assert "V2" in bugs[0].reason
        assert "V3" in bugs[0].reason
        assert "V4" in bugs[0].reason
