"""
Test that subprocess.run/call/Popen correctly distinguish shell=True vs shell=False.

ITERATION 557: Fix false positives for subprocess functions with shell=False.
"""

import pytest
from pathlib import Path
import tempfile
import subprocess
import sys


def test_subprocess_run_shell_false_no_violation(tmp_path):
    """subprocess.run with shell=False should NOT trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def safe_run(user_input):
    """shell=False means no shell parsing, so tainted input is safe"""
    subprocess.run(["cat", user_input], shell=False)
'''
    
    test_file = tmp_path / "test_shell_false.py"
    test_file.write_text(code)
    
    result = subprocess.run(
        [sys.executable, "-m", "pyfromscratch.cli", str(test_file)],
        capture_output=True,
        text=True
    )
    
    # Should find NO violations (shell=False is safe)
    # Exit code 0 = SAFE, no bugs found
    assert result.returncode == 0, f"Expected SAFE (0), got {result.returncode}: stdout={result.stdout}, stderr={result.stderr}"
    assert "COMMAND_INJECTION" not in result.stdout, f"Should not detect COMMAND_INJECTION with shell=False"


def test_subprocess_run_no_shell_kwarg_no_violation(tmp_path):
    """subprocess.run without shell kwarg (defaults to False) should NOT trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def safe_run_default(user_input):
    """No shell kwarg means shell=False (default), so tainted input is safe"""
    subprocess.run(["ls", "-l", user_input])
'''
    
    test_file = tmp_path / "test_no_shell.py"
    test_file.write_text(code)
    
    result = subprocess.run(
        [sys.executable, "-m", "pyfromscratch.cli", str(test_file)],
        capture_output=True,
        text=True
    )
    
    # Should find NO violations (shell defaults to False)
    assert result.returncode == 0, f"Expected SAFE (0), got {result.returncode}: stdout={result.stdout}, stderr={result.stderr}"
    assert "COMMAND_INJECTION" not in result.stdout, f"Should not detect COMMAND_INJECTION without shell kwarg"


def test_subprocess_run_shell_true_violation(tmp_path):
    """subprocess.run with shell=True SHOULD trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def unsafe_run(user_input):
    """shell=True means shell parsing, so tainted input is dangerous"""
    subprocess.run(f"cat {user_input}", shell=True)
'''
    
    test_file = tmp_path / "test_shell_true.py"
    test_file.write_text(code)
    
    result = subprocess.run(
        [sys.executable, "-m", "pyfromscratch.cli", str(test_file)],
        capture_output=True,
        text=True
    )
    
    # Should find COMMAND_INJECTION violation
    # Exit code 1 = BUG found
    assert result.returncode == 1, f"Expected BUG (1), got {result.returncode}: stdout={result.stdout}, stderr={result.stderr}"
    assert "COMMAND_INJECTION" in result.stdout, f"Should detect COMMAND_INJECTION with shell=True"


def test_subprocess_call_shell_false_no_violation(tmp_path):
    """subprocess.call with shell=False should NOT trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def safe_call(user_input):
    subprocess.call(["grep", "pattern", user_input], shell=False)
'''
    
    test_file = tmp_path / "test_call_false.py"
    test_file.write_text(code)
    
    result = subprocess.run(
        [sys.executable, "-m", "pyfromscratch.cli", str(test_file)],
        capture_output=True,
        text=True
    )
    
    # Should find NO violations
    assert result.returncode == 0, f"Expected SAFE (0), got {result.returncode}: stdout={result.stdout}, stderr={result.stderr}"
    assert "COMMAND_INJECTION" not in result.stdout


def test_subprocess_call_shell_true_violation(tmp_path):
    """subprocess.call with shell=True SHOULD trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def unsafe_call(user_input):
    subprocess.call("grep pattern " + user_input, shell=True)
'''
    
    test_file = tmp_path / "test_call_true.py"
    test_file.write_text(code)
    
    result = subprocess.run(
        [sys.executable, "-m", "pyfromscratch.cli", str(test_file)],
        capture_output=True,
        text=True
    )
    
    # Should find COMMAND_INJECTION violation
    assert result.returncode == 1, f"Expected BUG (1), got {result.returncode}: stdout={result.stdout}, stderr={result.stderr}"
    assert "COMMAND_INJECTION" in result.stdout


def test_subprocess_popen_shell_false_no_violation(tmp_path):
    """subprocess.Popen with shell=False should NOT trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def safe_popen(user_input):
    subprocess.Popen(["echo", user_input], shell=False)
'''
    
    test_file = tmp_path / "test_popen_false.py"
    test_file.write_text(code)
    
    result = subprocess.run(
        [sys.executable, "-m", "pyfromscratch.cli", str(test_file)],
        capture_output=True,
        text=True
    )
    
    # Should find NO violations
    assert result.returncode == 0, f"Expected SAFE (0), got {result.returncode}: stdout={result.stdout}, stderr={result.stderr}"
    assert "COMMAND_INJECTION" not in result.stdout


def test_subprocess_popen_shell_true_violation(tmp_path):
    """subprocess.Popen with shell=True SHOULD trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def unsafe_popen(user_input):
    subprocess.Popen("echo " + user_input, shell=True)
'''
    
    test_file = tmp_path / "test_popen_true.py"
    test_file.write_text(code)
    
    result = subprocess.run(
        [sys.executable, "-m", "pyfromscratch.cli", str(test_file)],
        capture_output=True,
        text=True
    )
    
    # Should find COMMAND_INJECTION violation
    assert result.returncode == 1, f"Expected BUG (1), got {result.returncode}: stdout={result.stdout}, stderr={result.stderr}"
    assert "COMMAND_INJECTION" in result.stdout


if __name__ == '__main__':
    # Run tests
    pytest.main([__file__, '-v'])
