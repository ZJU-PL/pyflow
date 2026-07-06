"""Tests for the subprocess exit code detector (cookiecutter#4 pattern).

Validates that the AST + CFG + Z3 detector correctly identifies functions
that return subprocess exit codes without checking for non-zero status,
and that the fixed version (which raises an exception) is clean.
"""

import pytest
from pathlib import Path
from a3_python.semantics.subprocess_exit_code_detector import (
    scan_file_for_subprocess_exit_code_bugs,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestSubprocessExitCodeDetector:
    """Test the AST + CFG + Z3 subprocess exit code detector."""

    def test_buggy_version_detected(self):
        """Buggy version: run_script returns proc.wait() unchecked → BUG."""
        bugs = scan_file_for_subprocess_exit_code_bugs(
            FIXTURES / "cookiecutter_bug4_buggy.py"
        )
        assert len(bugs) >= 1
        bug = bugs[0]
        assert bug.pattern == "unchecked_exit_code"
        assert "run_script" in bug.function_name
        assert bug.confidence >= 0.6
        assert "proc" in (bug.variable or "")

    def test_fixed_version_clean(self):
        """Fixed version: run_script raises FailedHookException → SAFE."""
        bugs = scan_file_for_subprocess_exit_code_bugs(
            FIXTURES / "cookiecutter_bug4_fixed.py"
        )
        assert len(bugs) == 0, f"Expected no bugs in fixed version, got: {bugs}"

    def test_analyzer_buggy_reports_bug(self):
        """End-to-end: Analyzer.analyze_file reports BUG on buggy fixture."""
        from a3_python.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(FIXTURES / "cookiecutter_bug4_buggy.py")
        assert result.verdict == "BUG"
        assert result.bug_type == "UNCHECKED_RETURN"
        assert "unchecked_exit_code" in result.counterexample.get("pattern", "")

    def test_analyzer_fixed_no_unchecked_return(self):
        """End-to-end: Analyzer does NOT report UNCHECKED_RETURN on fixed."""
        from a3_python.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(FIXTURES / "cookiecutter_bug4_fixed.py")
        # Fixed version should not have UNCHECKED_RETURN
        if result.verdict == "BUG":
            assert result.bug_type != "UNCHECKED_RETURN", (
                f"Fixed version should not have UNCHECKED_RETURN, got: {result.message}"
            )

    def test_confidence_factors(self):
        """Verify confidence scoring includes Z3 and heuristic factors."""
        bugs = scan_file_for_subprocess_exit_code_bugs(
            FIXTURES / "cookiecutter_bug4_buggy.py"
        )
        assert len(bugs) >= 1
        # run_script: direct return proc.wait() (+0.10) + name suggests exec (+0.10)
        # + called internally (+0.05) + Z3 (+0.15) + shell usage (+0.05) = high confidence
        assert bugs[0].confidence >= 0.65

    def test_detector_handles_empty_file(self):
        """Detector returns empty list on file with no subprocess usage."""
        bugs = scan_file_for_subprocess_exit_code_bugs(
            FIXTURES / "empty.py"
        )
        assert bugs == []

    def test_detector_handles_checked_exit_code(self):
        """Inline test: exit code checked against 0 → no bug."""
        import tempfile
        import os

        code = '''
import subprocess

def run_checked(cmd):
    proc = subprocess.Popen(cmd)
    exit_code = proc.wait()
    if exit_code != 0:
        raise RuntimeError("Command failed")
    return exit_code
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            try:
                bugs = scan_file_for_subprocess_exit_code_bugs(Path(f.name))
                assert len(bugs) == 0, f"Should not report bug when exit code is checked, got: {bugs}"
            finally:
                os.unlink(f.name)

    def test_detector_direct_return_wait(self):
        """Inline test: direct 'return proc.wait()' detected."""
        import tempfile
        import os

        code = '''
import subprocess

def run_unchecked(cmd):
    proc = subprocess.Popen(cmd)
    return proc.wait()
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            try:
                bugs = scan_file_for_subprocess_exit_code_bugs(Path(f.name))
                assert len(bugs) >= 1
                assert bugs[0].pattern == "unchecked_exit_code"
            finally:
                os.unlink(f.name)
