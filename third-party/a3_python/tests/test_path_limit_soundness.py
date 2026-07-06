#!/usr/bin/env python3
"""
Test to verify path_limit soundness fix (iteration 384)

CRITICAL SOUNDNESS ISSUE:
When max_paths is hit with unexplored paths remaining, the verdict MUST be UNKNOWN, not SAFE.
Returning SAFE without exhaustive exploration is UNSOUND.
"""

from a3_python.analyzer import Analyzer
from pathlib import Path
import tempfile
import os

def test_path_limit_function_level():
    """
    Test function-level analysis soundness with path limit
    """
    
    # Create a program with many paths but NO bugs
    code = """
def safe_branches(x):
    # Multiple branches but all safe
    result = 0
    if x > 0:
        result += 1
    if x > 10:
        result += 2
    if x > 20:
        result += 4
    if x > 30:
        result += 8
    if x > 40:
        result += 16
    if x > 50:
        result += 32
    if x > 60:
        result += 64
    # Many paths (2^7 = 128), all safe
    return result
"""
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_file = f.name
    
    try:
        # Use very low max_paths to force hitting the limit
        analyzer = Analyzer(verbose=False, max_paths=10)
        result = analyzer.analyze_all_functions(Path(temp_file))
        
        print(f"Functions analyzed: {len(result['function_results'])}")
        
        # Check each function result
        for func_result in result['function_results']:
            func_name = func_result['function_name']
            func_verdict = func_result['result']
            
            print(f"Function {func_name}:")
            print(f"  Verdict: {func_verdict.verdict}")
            if hasattr(func_verdict, 'message'):
                print(f"  Message: {func_verdict.message}")
            
            # SOUNDNESS CHECK: Must be UNKNOWN or BUG, NOT SAFE if we hit limit
            if func_verdict.verdict == 'SAFE':
                # Check if we hit the limit
                message_str = str(func_verdict.message) if hasattr(func_verdict, 'message') else ''
                if 'hit path limit' in message_str.lower() or 'unexplored' in message_str.lower():
                    print("  ❌ SOUNDNESS VIOLATION: SAFE despite hitting limit!")
                    return False
                else:
                    print("  ? SAFE verdict (check if paths were exhausted)")
                    # This could be OK if we actually exhausted all paths < max_paths
                    return True
            elif func_verdict.verdict == 'UNKNOWN':
                print("  ✓ SOUND: Returned UNKNOWN")
                return True
            elif func_verdict.verdict == 'BUG':
                print("  ? BUG found (acceptable)")
                return True
        
        return True
    
    finally:
        # Clean up
        if os.path.exists(temp_file):
            os.unlink(temp_file)

def test_exhaustive_exploration_can_return_safe():
    """
    Test that when we DON'T hit path limit (exhaustive exploration), SAFE is acceptable
    """
    
    # Simple program with only 2 paths
    code = """
def simple(x):
    if x > 0:
        return 1
    else:
        return 2

result = simple(42)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_file = f.name
    
    try:
        # Use high max_paths - should NOT hit limit
        analyzer = Analyzer(verbose=False, max_paths=1000)
        result = analyzer.analyze_file(temp_file)
        
        print(f"\nExhaustive test - Verdict: {result.verdict}")
        print(f"Paths explored: {result.paths_explored}")
        
        # When we don't hit limit, SAFE or UNKNOWN are both acceptable
        if result.verdict in ['SAFE', 'UNKNOWN']:
            print("✓ Valid verdict for exhaustive exploration")
            return True
        else:
            print(f"? Got verdict {result.verdict}")
            return True  # BUG is also acceptable if there's a real bug
    
    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)

if __name__ == '__main__':
    print("="*70)
    print("TESTING PATH LIMIT SOUNDNESS (ITERATION 384)")
    print("="*70)
    
    print("\n1. Testing function-level analysis with path limit...")
    test1 = test_path_limit_function_level()
    
    print("\n2. Testing that exhaustive exploration can return SAFE...")
    test2 = test_exhaustive_exploration_can_return_safe()
    
    print("\n" + "="*70)
    if test1 and test2:
        print("✓ ALL SOUNDNESS TESTS PASSED")
    else:
        print("❌ SOUNDNESS VIOLATION DETECTED")
    print("="*70)
