#!/usr/bin/env python3
"""Quick test for varargs taint propagation fix in Iteration 601."""

from pathlib import Path
from a3_python.analyzer import Analyzer

def test_varargs_propagation():
    """Test that PATH_INJECTION is detected through varargs in interprocedural analysis."""
    test_file = Path("py_synthetic/standalone/path_injection_interprocedural_001.py")
    
    print("Testing varargs taint propagation...")
    print(f"File: {test_file}")
    
    analyzer = Analyzer(verbose=False, enable_interprocedural=True)
    result = analyzer.analyze_file(test_file)
    
    print(f"Verdict: {result.verdict}")
    print(f"Bug Type: {result.bug_type}")
    
    # Check result
    if result.verdict == "BUG":
        if result.bug_type == "PATH_INJECTION":
            print("✅ SUCCESS: Detected PATH_INJECTION via varargs")
            return True
        else:
            print(f"⚠ PARTIAL: Found {result.bug_type} but expected PATH_INJECTION")
            return False
    else:
        print(f"❌ FAILURE: Expected BUG but got {result.verdict}")
        return False

if __name__ == "__main__":
    success = test_varargs_propagation()
    exit(0 if success else 1)
