"""
Basic test to verify the CLI exists and is runnable.
"""

import subprocess
import sys
from pathlib import Path


def test_cli_exists():
    """Test that the CLI module can be imported and executed."""
    result = subprocess.run(
        [sys.executable, "-m", "pyflow.a3_python.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "A³: Python semantics + barrier-certificate verifier" in result.stdout
    assert "scan" in result.stdout


def test_cli_handles_nonexistent_file():
    """Test that the CLI properly handles nonexistent files."""
    result = subprocess.run(
        [sys.executable, "-m", "pyflow.a3_python.cli", "nonexistent_file.py"],
        capture_output=True,
        text=True,
    )
    # Exit code 3 = error (file not found)
    assert result.returncode == 3
    assert "not found" in result.stderr.lower()


def test_cli_accepts_existing_file(tmp_path):
    """Test that the CLI accepts an existing file and produces a valid verdict."""
    test_file = tmp_path / "test.py"
    test_file.write_text("# empty test file\n")
    
    result = subprocess.run(
        [sys.executable, "-m", "pyflow.a3_python.cli", str(test_file)],
        capture_output=True,
        text=True,
    )
    # Empty program should be SAFE (exit code 0) with barrier certificate
    # since there are no unsafe operations
    assert result.returncode == 0, f"Expected SAFE (0), got {result.returncode}: {result.stdout}"
    assert "Analyzing" in result.stdout
    assert "SAFE" in result.stdout
    assert "barrier" in result.stdout.lower()


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
