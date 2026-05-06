"""
Test that subprocess.run/call/Popen correctly distinguish shell=True vs shell=False.

ITERATION 557: Fix false positives for subprocess functions with shell=False.
"""

import pytest
from pathlib import Path
import tempfile

from pyflow.a3_python.semantics.intraprocedural_taint import analyze_file_intraprocedural


def analyze_code(code: str):
    """Analyze a temporary file with the intraprocedural taint engine."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        temp_path = Path(f.name)

    try:
        return analyze_file_intraprocedural(temp_path)
    finally:
        temp_path.unlink()


def test_subprocess_run_shell_false_no_violation():
    """subprocess.run with shell=False should NOT trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def safe_run(user_input):
    """shell=False means no shell parsing, so tainted input is safe"""
    subprocess.run(["cat", user_input], shell=False)
'''
    
    bugs = analyze_code(code)
    assert "COMMAND_INJECTION" not in [b.bug_type for b in bugs]


def test_subprocess_run_no_shell_kwarg_no_violation():
    """subprocess.run without shell kwarg (defaults to False) should NOT trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def safe_run_default(user_input):
    """No shell kwarg means shell=False (default), so tainted input is safe"""
    subprocess.run(["ls", "-l", user_input])
'''
    
    bugs = analyze_code(code)
    assert "COMMAND_INJECTION" not in [b.bug_type for b in bugs]


def test_subprocess_run_shell_true_violation():
    """subprocess.run with shell=True SHOULD trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def unsafe_run(user_input):
    """shell=True means shell parsing, so tainted input is dangerous"""
    subprocess.run(f"cat {user_input}", shell=True)
'''
    
    bugs = analyze_code(code)
    assert "COMMAND_INJECTION" in [b.bug_type for b in bugs]


def test_subprocess_call_shell_false_no_violation():
    """subprocess.call with shell=False should NOT trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def safe_call(user_input):
    subprocess.call(["grep", "pattern", user_input], shell=False)
'''
    
    bugs = analyze_code(code)
    assert "COMMAND_INJECTION" not in [b.bug_type for b in bugs]


def test_subprocess_call_shell_true_violation():
    """subprocess.call with shell=True SHOULD trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def unsafe_call(user_input):
    subprocess.call("grep pattern " + user_input, shell=True)
'''
    
    bugs = analyze_code(code)
    assert "COMMAND_INJECTION" in [b.bug_type for b in bugs]


def test_subprocess_popen_shell_false_no_violation():
    """subprocess.Popen with shell=False should NOT trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def safe_popen(user_input):
    subprocess.Popen(["echo", user_input], shell=False)
'''
    
    bugs = analyze_code(code)
    assert "COMMAND_INJECTION" not in [b.bug_type for b in bugs]


def test_subprocess_popen_shell_true_violation():
    """subprocess.Popen with shell=True SHOULD trigger COMMAND_INJECTION."""
    
    code = '''
import subprocess

def unsafe_popen(user_input):
    subprocess.Popen("echo " + user_input, shell=True)
'''
    
    bugs = analyze_code(code)
    assert "COMMAND_INJECTION" in [b.bug_type for b in bugs]


if __name__ == '__main__':
    # Run tests
    pytest.main([__file__, '-v'])
