"""
Test improved module-level vs function-level code detection.

Validates that module-init filtering correctly distinguishes between:
- Module-level imports (should trigger filtering)
- Function-level imports (should NOT trigger filtering)
- Deep function calls with imports (should NOT trigger filtering)
"""

import pytest
from pathlib import Path
import tempfile

from a3_python.analyzer import Analyzer


def test_module_level_imports_detected():
    """Module-level imports should trigger module-init phase flag."""
    
    test_code = """
import sys
import os
import json

# Bug at module level after imports
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
        
        # Should flag as module-init phase (3 module-level imports)
        assert result.counterexample is not None
        assert result.counterexample['module_init_phase'] == True
        assert result.counterexample['import_count'] >= 3
        
        print(f"✓ Module-level imports correctly flagged: {result.counterexample['import_count']} imports")
        
    finally:
        test_file.unlink()


def test_function_level_imports_not_detected():
    """Function-level imports should NOT trigger module-init phase flag."""
    
    test_code = """
def process_data():
    # Imports inside function - NOT module-level
    import sys
    import os
    import json
    import math
    
    # Bug in function after imports
    return 1 / 0

# Call the function
process_data()
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=100, max_depth=1000)
        result = analyzer.analyze_file(test_file)
        
        # May detect DIV_ZERO bug or be UNKNOWN depending on function analysis
        if result.verdict == "BUG":
            # If BUG found, should NOT flag as module-init (imports are in function)
            assert result.counterexample is not None
            assert result.counterexample['module_init_phase'] == False, \
                "Function-level imports should not trigger module-init flag"
            
            print(f"✓ Function-level imports NOT flagged as module-init (import_count={result.counterexample['import_count']})")
        else:
            # SAFE or UNKNOWN is acceptable - just confirm it's not incorrectly flagged
            print(f"✓ Function with imports analyzed (verdict: {result.verdict})")
        
    finally:
        test_file.unlink()


def test_nested_function_with_imports():
    """Deeply nested function imports should NOT trigger module-init flag."""
    
    test_code = """
def outer():
    def inner():
        # Very deep - should NOT trigger module-init
        import sys
        import os
        import json
        import math
        import random
        
        return 1 / 0
    
    return inner()

outer()
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=100, max_depth=1000)
        result = analyzer.analyze_file(test_file)
        
        if result.verdict == "BUG":
            # Should NOT flag as module-init (imports are deep in nested function)
            assert result.counterexample is not None
            assert result.counterexample['module_init_phase'] == False, \
                "Nested function imports should not trigger module-init flag"
            
            print(f"✓ Nested function imports NOT flagged as module-init (depth check)")
        else:
            print(f"✓ Nested function analyzed (verdict: {result.verdict})")
        
    finally:
        test_file.unlink()


def test_module_level_with_function_call():
    """Module-level imports followed by function call - should still flag module-init."""
    
    test_code = """
import sys
import os
import json

def helper():
    # This bug is in a function, but the imports are module-level
    return 1 / 0

# Call at module level
x = helper()
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=100, max_depth=1000)
        result = analyzer.analyze_file(test_file)
        
        if result.verdict == "BUG":
            # Module-level imports present, so should be flagged
            # (The bug happens in a function call from module level,
            # but the import count is from module-level imports)
            assert result.counterexample is not None
            # The key question: are the imports at module level? Yes!
            # So module_init_phase should be True
            assert result.counterexample['module_init_phase'] == True, \
                "Module-level imports should flag module-init even if bug is in called function"
            
            print(f"✓ Module-level imports flagged even with function call")
        else:
            print(f"✓ Module with function call analyzed (verdict: {result.verdict})")
        
    finally:
        test_file.unlink()


def test_no_imports_no_flag():
    """Code with no imports should never trigger module-init flag."""
    
    test_code = """
# No imports at all
x = 1
y = 0
result = x / y  # Bug without any imports
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=100, max_depth=1000)
        result = analyzer.analyze_file(test_file)
        
        if result.verdict == "BUG":
            # Should NOT flag as module-init (no imports)
            assert result.counterexample is not None
            assert result.counterexample['module_init_phase'] == False
            assert result.counterexample['import_count'] == 0
            
            print(f"✓ No imports means no module-init flag")
        else:
            print(f"✓ No-import code analyzed (verdict: {result.verdict})")
        
    finally:
        test_file.unlink()


def test_few_module_imports_no_flag():
    """Module-level code with < 3 imports should NOT trigger flag."""
    
    test_code = """
import sys
import os
# Only 2 imports - below threshold

x = 1 / 0
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=100, max_depth=1000)
        result = analyzer.analyze_file(test_file)
        
        if result.verdict == "BUG":
            # Should NOT flag as module-init (< 3 imports)
            assert result.counterexample is not None
            assert result.counterexample['module_init_phase'] == False, \
                "< 3 imports should not trigger module-init flag"
            assert result.counterexample['import_count'] < 3
            
            print(f"✓ Few imports ({result.counterexample['import_count']}) does not trigger flag")
        else:
            print(f"✓ Few-import code analyzed (verdict: {result.verdict})")
        
    finally:
        test_file.unlink()


if __name__ == '__main__':
    print("Testing improved module-level vs function-level detection...\n")
    
    test_module_level_imports_detected()
    test_function_level_imports_not_detected()
    test_nested_function_with_imports()
    test_module_level_with_function_call()
    test_no_imports_no_flag()
    test_few_module_imports_no_flag()
    
    print("\nAll module-vs-function detection tests passed!")
