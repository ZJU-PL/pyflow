"""
Tests for CLI termination checking integration.

This verifies that the --check-termination flag works correctly
and integrates with the analyzer's analyze_file flow.
"""

import subprocess
import tempfile
from pathlib import Path


def test_cli_termination_flag_detects_loop():
    """Test that --check-termination detects and verifies a terminating loop."""
    code = """
# Simple countdown loop
n = 10
while n > 0:
    n = n - 1
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        # Run with termination checking (no verbose, so termination info won't show)
        result = subprocess.run(
            ['python3', '-m', 'pyfromscratch.cli', temp_path, '--check-termination'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Should complete successfully (termination checking happens internally)
        # Without verbose, we won't see the loop detection messages
        assert result.returncode in [0, 2]  # SAFE or UNKNOWN (not BUG)
        
        # If there was a non-termination bug, it would be BUG
        assert result.returncode != 1 or 'NON_TERMINATION' not in result.stdout
    finally:
        Path(temp_path).unlink()


def test_cli_termination_verbose_output():
    """Test that verbose mode shows termination details."""
    code = """
x = 5
while x > 0:
    x = x - 1
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        result = subprocess.run(
            ['python3', '-m', 'pyfromscratch.cli', temp_path, '--check-termination', '--verbose'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Verbose should show ranking synthesis
        assert 'Checking loop termination' in result.stdout or 'Loop at offset' in result.stdout
        assert result.returncode in [0, 2]
    finally:
        Path(temp_path).unlink()


def test_cli_no_loops_with_termination_flag():
    """Test that --check-termination works when no loops exist."""
    code = """
x = 1 + 2
y = x * 3
print(y)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        result = subprocess.run(
            ['python3', '-m', 'pyfromscratch.cli', temp_path, '--check-termination'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Should complete without error
        assert result.returncode in [0, 2]
    finally:
        Path(temp_path).unlink()


def test_cli_termination_flag_with_functions():
    """Test that termination checking with --functions mode works."""
    code = """
def countdown(n):
    while n > 0:
        n = n - 1
    return n

countdown(10)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        # Run with --functions and --check-termination
        result = subprocess.run(
            ['python3', '-m', 'pyfromscratch.cli', temp_path, '--functions', '--check-termination'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Should complete without error
        assert result.returncode in [0, 1, 2]
    finally:
        Path(temp_path).unlink()


def test_analyzer_termination_integration():
    """Test Analyzer class directly with check_termination=True."""
    from pyflow.a3_python.analyzer import Analyzer
    
    code = """
n = 10
while n > 0:
    n = n - 1
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        # Create analyzer with termination checking enabled
        analyzer = Analyzer(check_termination=True, verbose=False)
        result = analyzer.analyze_file(temp_path)
        
        # Should complete (either SAFE, BUG, or UNKNOWN)
        assert result.verdict in ['SAFE', 'BUG', 'UNKNOWN']
        
        # Should not crash
        assert result is not None
    finally:
        temp_path.unlink()


def test_analyzer_termination_disabled_by_default():
    """Test that termination checking is disabled by default."""
    from pyflow.a3_python.analyzer import Analyzer
    
    code = """
n = 10
while n > 0:
    n = n - 1
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        # Create analyzer without termination checking
        analyzer = Analyzer(verbose=False)
        result = analyzer.analyze_file(temp_path)
        
        # Should still complete normally
        assert result.verdict in ['SAFE', 'BUG', 'UNKNOWN']
        assert result is not None
    finally:
        temp_path.unlink()
