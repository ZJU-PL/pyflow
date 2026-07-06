"""Tests for the unhandled-path-exception detector (black#16 pattern)."""

import pytest
from pathlib import Path
from a3_python.semantics.unhandled_path_exception_detector import (
    scan_file_for_unhandled_path_exception_bugs,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestUnhandledPathExceptionDetector:
    """Test the AST + Z3 unhandled Path.relative_to() exception detector."""

    def test_buggy_version_detected(self):
        """Buggy version: relative_to() without try/except ValueError → BUG."""
        bugs = scan_file_for_unhandled_path_exception_bugs(
            FIXTURES / "black_bug16_buggy.py"
        )
        assert len(bugs) >= 1
        bug = bugs[0]
        assert bug.pattern == "unguarded_relative_to"
        assert "relative_to" in bug.reason
        assert "ValueError" in bug.reason
        assert bug.confidence >= 0.6

    def test_fixed_version_clean(self):
        """Fixed version: relative_to() wrapped in try/except ValueError → SAFE."""
        bugs = scan_file_for_unhandled_path_exception_bugs(
            FIXTURES / "black_bug16_fixed.py"
        )
        # Fixed version should have no bugs since relative_to is guarded
        assert len(bugs) == 0

    def test_analyzer_buggy_reports_bug(self):
        """End-to-end: Analyzer.analyze_file reports BUG on buggy fixture."""
        from a3_python.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(FIXTURES / "black_bug16_buggy.py")
        assert result.verdict == "BUG"
        # The analyzer runs multiple detectors in sequence; it should report
        # a BUG (the specific bug_type depends on which detector fires first).
        # Verify our detector finds the bug independently.
        from a3_python.semantics.unhandled_path_exception_detector import (
            scan_file_for_unhandled_path_exception_bugs,
        )
        bugs = scan_file_for_unhandled_path_exception_bugs(FIXTURES / "black_bug16_buggy.py")
        assert len(bugs) >= 1
        assert bugs[0].pattern == "unguarded_relative_to"

    def test_analyzer_fixed_no_bug(self):
        """End-to-end: Analyzer.analyze_file reports no UNHANDLED_PATH_EXCEPTION on fixed."""
        from a3_python.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(FIXTURES / "black_bug16_fixed.py")
        # Fixed version should not report UNHANDLED_PATH_EXCEPTION
        if result.verdict == "BUG":
            assert result.bug_type != "UNHANDLED_PATH_EXCEPTION"

    def test_safe_pattern_not_flagged(self):
        """relative_to() inside try/except ValueError → no bug."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            from pathlib import Path

            def safe_relative(child, root):
                try:
                    return child.resolve().relative_to(root)
                except ValueError:
                    return None
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_unhandled_path_exception_bugs(Path(f.name))
            assert len(bugs) == 0

    def test_bare_except_not_flagged(self):
        """relative_to() inside bare except → no bug."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            from pathlib import Path

            def safe_with_bare_except(child, root):
                try:
                    return child.resolve().relative_to(root)
                except:
                    return None
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_unhandled_path_exception_bugs(Path(f.name))
            assert len(bugs) == 0

    def test_except_exception_not_flagged(self):
        """relative_to() inside except Exception → no bug (catches ValueError)."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            from pathlib import Path

            def safe_with_exception(child, root):
                try:
                    return child.resolve().relative_to(root)
                except Exception:
                    return None
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_unhandled_path_exception_bugs(Path(f.name))
            assert len(bugs) == 0

    def test_outside_loop_lower_confidence(self):
        """relative_to() outside dir iteration → lower confidence but still detected."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            from pathlib import Path

            def risky_relative(child, root):
                return child.resolve().relative_to(root).as_posix()
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_unhandled_path_exception_bugs(Path(f.name))
            assert len(bugs) >= 1
            # Outside loop context → lower confidence
            assert bugs[0].confidence < 0.80

    def test_in_iterdir_loop_higher_confidence(self):
        """relative_to() inside iterdir() loop → higher confidence."""
        import tempfile, textwrap
        code = textwrap.dedent("""\
            from pathlib import Path

            def process_dir(path, root):
                for child in path.iterdir():
                    rel = child.resolve().relative_to(root)
                    print(rel)
        """)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            bugs = scan_file_for_unhandled_path_exception_bugs(Path(f.name))
            assert len(bugs) >= 1
            assert bugs[0].confidence >= 0.70
