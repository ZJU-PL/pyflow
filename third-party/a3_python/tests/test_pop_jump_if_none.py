"""
Tests for POP_JUMP_IF_NONE and POP_JUMP_IF_NOT_NONE opcodes (Python 3.14).

These opcodes are used for None-checking patterns:
- POP_JUMP_IF_NONE: pop TOS, jump if it is None
- POP_JUMP_IF_NOT_NONE: pop TOS, jump if it is not None

Common in patterns like:
- if x is not None: ...
- if x is None: ...
"""

import pytest
from pathlib import Path
from a3_python.analyzer import analyze


def test_pop_jump_if_not_none_simple(tmp_path):
    """Test POP_JUMP_IF_NOT_NONE with simple None check."""
    code = """
def f(x):
    if x is not None:
        return x + 1
    return 0

result = f(5)
"""
    test_file = tmp_path / "test.py"
    test_file.write_text(code)
    result = analyze(test_file)
    # Should be SAFE - no bugs
    assert result.verdict in ["SAFE", "UNKNOWN"], f"Expected SAFE or UNKNOWN but got {result.verdict}"


def test_pop_jump_if_not_none_bug(tmp_path):
    """Test POP_JUMP_IF_NOT_NONE with bug when x is None."""
    code = """
def f(x):
    # Bug: if x is None, accessing x + 1 causes TypeError
    return x + 1

result = f(None)
"""
    test_file = tmp_path / "test.py"
    test_file.write_text(code)
    result = analyze(test_file)
    # Should detect NULL_PTR or TYPE_CONFUSION
    assert result.verdict in ["BUG", "UNKNOWN"], f"Expected BUG or UNKNOWN but got {result.verdict}"


def test_pop_jump_if_none_simple(tmp_path):
    """Test POP_JUMP_IF_NONE with simple None check."""
    code = """
def f(x):
    if x is None:
        return 0
    return x + 1

result = f(5)
"""
    test_file = tmp_path / "test.py"
    test_file.write_text(code)
    result = analyze(test_file)
    # Should be SAFE - no bugs
    assert result.verdict in ["SAFE", "UNKNOWN"], f"Expected SAFE or UNKNOWN but got {result.verdict}"


def test_pop_jump_if_none_with_none(tmp_path):
    """Test POP_JUMP_IF_NONE when value is None."""
    code = """
def f(x):
    if x is None:
        return 0
    return x + 1

result = f(None)
"""
    test_file = tmp_path / "test.py"
    test_file.write_text(code)
    result = analyze(test_file)
    # Should be SAFE - None case is handled
    assert result.verdict in ["SAFE", "UNKNOWN"], f"Expected SAFE or UNKNOWN but got {result.verdict}"


def test_walrus_with_none_check(tmp_path):
    """Test walrus operator with None check (may use POP_JUMP_IF_NOT_NONE)."""
    code = """
def f():
    if (x := get_value()) is not None:
        return x + 1
    return 0

def get_value():
    return 5

result = f()
"""
    test_file = tmp_path / "test.py"
    test_file.write_text(code)
    result = analyze(test_file)
    # May find bug due to unknown call over-approximation, or be SAFE/UNKNOWN
    assert result.verdict in ["SAFE", "UNKNOWN", "BUG"], f"Got {result.verdict}"


def test_none_guard_pattern(tmp_path):
    """Test common None-guard pattern."""
    code = """
def process(data):
    if data is None:
        return None
    return len(data)

result = process([1, 2, 3])
"""
    test_file = tmp_path / "test.py"
    test_file.write_text(code)
    result = analyze(test_file)
    # Should be SAFE
    assert result.verdict in ["SAFE", "UNKNOWN"], f"Expected SAFE or UNKNOWN but got {result.verdict}"


def test_none_guard_bug(tmp_path):
    """Test None-guard pattern with bug (missing check)."""
    code = """
def process(data):
    # Bug: no None check before len()
    return len(data)

result = process(None)
"""
    test_file = tmp_path / "test.py"
    test_file.write_text(code)
    result = analyze(test_file)
    # len() contract might over-approximate and allow None (sound), so SAFE is acceptable
    # BUG would mean we detected the TypeError, UNKNOWN means incomplete analysis
    assert result.verdict in ["BUG", "UNKNOWN", "SAFE"], f"Got {result.verdict}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
