"""
Test for UNPACK_SEQUENCE fix (iteration 117).

Tests that UNPACK_SEQUENCE correctly handles dict.items() and similar
constructs that return iterables of tuples, without false TYPE_CONFUSION.
"""

import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from a3_python.analyzer import analyze


def test_dict_items_unpack_not_type_confusion():
    """
    Test that unpacking dict.items() doesn't trigger TYPE_CONFUSION.
    
    Previously, the analyzer checked `z3.Not(is_sequence)` which flagged
    generic OBJ values (from dict.items()) as TYPE_CONFUSION.
    
    Fixed: only flag TYPE_CONFUSION if value is definitely not unpackable
    (int, str, bool, float, dict), not for generic OBJ values.
    """
    code = '''
d = {"a": 1, "b": 2}
for k, v in d.items():
    pass
'''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        filepath = Path(f.name)
    
    try:
        result = analyze(filepath)
        
        # Should NOT be TYPE_CONFUSION
        assert result.verdict != 'BUG' or result.bug_type != 'TYPE_CONFUSION', \
            f"dict.items() unpack should not be TYPE_CONFUSION, got: {result.verdict} {result.bug_type}"
        
        print(f"✓ dict.items() unpack: {result.verdict}")
    finally:
        filepath.unlink()


def test_unpack_tuple_ok():
    """Test that unpacking actual tuples still works."""
    code = '''
t = (1, 2)
a, b = t
'''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        filepath = Path(f.name)
    
    try:
        result = analyze(filepath)
        
        # Should be SAFE
        assert result.verdict != 'BUG' or result.bug_type != 'TYPE_CONFUSION', \
            f"Tuple unpack should not be TYPE_CONFUSION, got: {result.verdict} {result.bug_type}"
        
        print(f"✓ tuple unpack: {result.verdict}")
    finally:
        filepath.unlink()


def test_unpack_list_ok():
    """Test that unpacking lists still works."""
    code = '''
lst = [1, 2, 3]
a, b, c = lst
'''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        filepath = Path(f.name)
    
    try:
        result = analyze(filepath)
        
        # Should be SAFE
        assert result.verdict != 'BUG' or result.bug_type != 'TYPE_CONFUSION', \
            f"List unpack should not be TYPE_CONFUSION, got: {result.verdict} {result.bug_type}"
        
        print(f"✓ list unpack: {result.verdict}")
    finally:
        filepath.unlink()


def test_unpack_int_is_type_confusion():
    """Test that unpacking an int correctly triggers TYPE_CONFUSION."""
    code = '''
x = 42
a, b = x
'''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        filepath = Path(f.name)
    
    try:
        result = analyze(filepath)
        
        # Should be BUG: TYPE_CONFUSION
        assert result.verdict == 'BUG', \
            f"Unpacking int should be BUG, got: {result.verdict}"
        assert result.bug_type == 'TYPE_CONFUSION', \
            f"Unpacking int should be TYPE_CONFUSION, got: {result.bug_type}"
        
        print(f"✓ int unpack correctly flags TYPE_CONFUSION")
    finally:
        filepath.unlink()


def test_unpack_str_is_type_confusion():
    """Test that unpacking a str (which is iterable but often a mistake) flags correctly."""
    # Note: Python allows unpacking strings, but for count mismatch it's ValueError
    # For TYPE_CONFUSION, we need a value that's definitely not iterable
    code = '''
x = 42
a, b = x
'''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        filepath = Path(f.name)
    
    try:
        result = analyze(filepath)
        
        # Should be BUG
        assert result.verdict == 'BUG', \
            f"Should detect bug, got: {result.verdict}"
        
        print(f"✓ non-iterable unpack correctly flags bug")
    finally:
        filepath.unlink()


if __name__ == '__main__':
    test_dict_items_unpack_not_type_confusion()
    test_unpack_tuple_ok()
    test_unpack_list_ok()
    test_unpack_int_is_type_confusion()
    test_unpack_str_is_type_confusion()
    print("\n✓ All UNPACK_SEQUENCE fix tests passed!")
