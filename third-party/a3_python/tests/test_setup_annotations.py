"""
Tests for SETUP_ANNOTATIONS opcode.

SETUP_ANNOTATIONS creates the __annotations__ dict if it doesn't exist at
module or class scope. This opcode is used when type annotations are present.

Semantic requirement: The analyzer must handle annotation setup without
falsely reporting bugs or missing the dict creation.
"""

import pytest
import dis
import tempfile
from pathlib import Path
from a3_python.analyzer import Analyzer


def test_setup_annotations_opcode_exists():
    """Verify SETUP_ANNOTATIONS opcode is handled."""
    # This is a simple smoke test - just ensure the opcode doesn't crash
    # when encountered in bytecode
    code = """
x: int = 5
"""
    
    # Write to temp file and analyze
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=10, max_depth=100)
        result = analyzer.analyze_file(temp_path)
        
        # Should not crash on SETUP_ANNOTATIONS
        # If BUG, should not be from missing SETUP_ANNOTATIONS opcode
        if result.verdict == "BUG":
            assert "SETUP_ANNOTATIONS" not in str(result.message), \
                f"Should not crash on SETUP_ANNOTATIONS: {result.message}"
    finally:
        temp_path.unlink()


def test_setup_annotations_multiple():
    """Test multiple annotations don't cause SETUP_ANNOTATIONS issues."""
    code = """
x: int
y: str
z: float
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=10, max_depth=200)
        result = analyzer.analyze_file(temp_path)
        
        if result.verdict == "BUG":
            assert "SETUP_ANNOTATIONS" not in str(result.message), \
                f"Should not crash on SETUP_ANNOTATIONS: {result.message}"
    finally:
        temp_path.unlink()


def test_setup_annotations_with_code():
    """Test annotations mixed with code don't cause issues."""
    code = """
x: int = 1
y = 2
result = x + y
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=20, max_depth=300)
        result = analyzer.analyze_file(temp_path)
        
        # Should analyze successfully, not crash on SETUP_ANNOTATIONS
        if result.verdict == "BUG":
            assert "SETUP_ANNOTATIONS" not in str(result.message), \
                f"Should not crash on SETUP_ANNOTATIONS: {result.message}"
    finally:
        temp_path.unlink()


def test_setup_annotations_in_function():
    """Test function annotations don't cause SETUP_ANNOTATIONS issues."""
    code = """
def foo(x: int) -> str:
    y: int = x + 1
    return str(y)

result = foo(42)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=50, max_depth=500)
        result = analyzer.analyze_file(temp_path)
        
        # Should not crash on SETUP_ANNOTATIONS
        if result.verdict == "BUG":
            assert "SETUP_ANNOTATIONS" not in str(result.message), \
                f"Should not crash on SETUP_ANNOTATIONS: {result.message}"
    finally:
        temp_path.unlink()


def test_setup_annotations_in_class():
    """Test class annotations don't cause SETUP_ANNOTATIONS issues."""
    code = """
class MyClass:
    x: int
    y: str = "hello"
    
    def __init__(self):
        self.x = 1
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=30, max_depth=500)
        result = analyzer.analyze_file(temp_path)
        
        # Should not crash on SETUP_ANNOTATIONS
        if result.verdict == "BUG":
            assert "SETUP_ANNOTATIONS" not in str(result.message), \
                f"Should not crash on SETUP_ANNOTATIONS: {result.message}"
    finally:
        temp_path.unlink()


def test_setup_annotations_comprehensive():
    """Comprehensive test of annotation patterns."""
    code = """
# Module-level annotations
x: int = 10
y: str

def func(a: int, b: str) -> bool:
    # Function-level annotation
    result: bool = True
    return result

class Foo:
    # Class-level annotations
    attr1: int
    attr2: str = "default"
    
    def method(self, val: int) -> None:
        # Method annotation
        local_var: int = val * 2
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        analyzer = Analyzer(verbose=False, max_paths=100, max_depth=1000)
        result = analyzer.analyze_file(temp_path)
        
        # Should handle all annotation types without SETUP_ANNOTATIONS crashes
        if result.verdict == "BUG":
            assert "SETUP_ANNOTATIONS" not in str(result.message), \
                f"Should not crash on SETUP_ANNOTATIONS: {result.message}"
    finally:
        temp_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


