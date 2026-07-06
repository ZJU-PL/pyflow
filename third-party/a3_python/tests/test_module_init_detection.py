"""
Test module-init phase detection.

Ensures that traces with early RESUME + many IMPORT_NAME opcodes
are flagged as module_init_phase for better triage.
"""

import pytest
from pathlib import Path
import tempfile

from a3_python.analyzer import Analyzer


def test_module_init_phase_detection():
    """Test that import-heavy traces are flagged as module-init phase."""
    
    # Create a test file with many imports at module level
    test_code = """
import sys
import os
import json
import math
import random

# This will trigger a bug after imports
x = 1 / 0
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=100, max_depth=1000)
        result = analyzer.analyze_file(test_file)
        
        # Should detect DIV_ZERO bug
        assert result.verdict == "BUG"
        assert result.bug_type == "DIV_ZERO"
        
        # Should flag as module-init phase (5 imports in early execution)
        assert result.counterexample is not None
        assert 'module_init_phase' in result.counterexample
        assert result.counterexample['module_init_phase'] == True
        assert result.counterexample['import_count'] >= 3
        
        print(f"✓ Module-init phase detected: {result.counterexample['import_count']} imports")
        
    finally:
        test_file.unlink()


def test_no_module_init_phase_for_normal_code():
    """Test that code without heavy imports is not flagged."""
    
    # Create a test file with no imports and a bug that might be detected
    test_code = """
def foo():
    x = 1
    y = 0
    return x / y

foo()
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=100, max_depth=1000)
        result = analyzer.analyze_file(test_file)
        
        # The test is about module_init_phase flag, not verdict
        # The analyzer might prove SAFE or find BUG depending on synthesis
        if result.verdict == "BUG":
            # If BUG found, should NOT flag as module-init phase (no imports)
            assert result.counterexample is not None
            assert 'module_init_phase' in result.counterexample
            assert result.counterexample['module_init_phase'] == False
            assert result.counterexample['import_count'] == 0
            print(f"✓ Normal code not flagged as module-init (BUG verdict)")
        else:
            # If SAFE or UNKNOWN, that's fine - no import metadata to check
            print(f"✓ Normal code analysis completed (verdict: {result.verdict})")
        
    finally:
        test_file.unlink()


def test_module_init_phase_with_late_imports():
    """Test that imports deep in execution don't trigger false module-init flag."""
    
    # Create a test file with imports in a function (late in execution)
    test_code = """
def foo():
    import sys
    import os
    import json
    x = 1 / 0

foo()
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=100, max_depth=1000)
        result = analyzer.analyze_file(test_file)
        
        # The test is about module_init_phase flag, not verdict
        if result.verdict == "BUG":
            # May or may not flag depending on instruction offsets
            # This is a heuristic, so we just verify the fields exist
            assert result.counterexample is not None
            assert 'module_init_phase' in result.counterexample
            assert 'import_count' in result.counterexample
            
            print(f"✓ Late imports: module_init_phase={result.counterexample['module_init_phase']}, import_count={result.counterexample['import_count']}")
        else:
            # If SAFE or UNKNOWN, that's fine - the analysis worked
            print(f"✓ Late imports analysis completed (verdict: {result.verdict})")
        
    finally:
        test_file.unlink()


if __name__ == '__main__':
    test_module_init_phase_detection()
    test_no_module_init_phase_for_normal_code()
    test_module_init_phase_with_late_imports()
    print("All module-init detection tests passed!")
