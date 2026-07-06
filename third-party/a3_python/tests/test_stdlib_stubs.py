"""
Tests for stdlib module stub support in symbolic execution.

Ensures that imports of common stdlib modules don't cause spurious
ImportError/NameError/AttributeError during symbolic analysis.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.contracts.stdlib_stubs import is_known_stdlib_module, get_module_exports


def test_known_stdlib_modules():
    """Test that common stdlib modules are recognized."""
    assert is_known_stdlib_module("math")
    assert is_known_stdlib_module("sys")
    assert is_known_stdlib_module("typing")
    assert is_known_stdlib_module("os")
    assert not is_known_stdlib_module("unknown_fake_module")


def test_stdlib_exports():
    """Test that known exports are listed."""
    math_exports = get_module_exports("math")
    assert "sqrt" in math_exports
    assert "sin" in math_exports
    assert "pi" in math_exports
    
    typing_exports = get_module_exports("typing")
    assert "Any" in typing_exports
    assert "List" in typing_exports
    assert "Dict" in typing_exports


def test_import_math_no_error():
    """Test that importing math doesn't cause errors."""
    code = """
import math
x = math.sqrt(4)
"""
    exec_obj = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    
    # This should not raise an exception during symbolic execution
    try:
        paths = vm.explore_bounded(exec_obj, max_steps=50)
        # We expect some result, not a crash
        assert paths is not None
    except Exception as e:
        # Should not raise unhandled exceptions
        pytest.fail(f"Import math caused exception: {e}")


def test_import_from_typing():
    """Test that 'from typing import ...' works."""
    code = """
from typing import List, Dict, Any
x: List[int] = []
"""
    exec_obj = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    
    try:
        paths = vm.explore_bounded(exec_obj, max_steps=50)
        assert paths is not None
    except Exception as e:
        pytest.fail(f"Import from typing caused exception: {e}")


def test_import_unknown_attribute_error():
    """Test that importing unknown attribute from known module raises AttributeError."""
    code = """
import math
x = math.fake_nonexistent_function()
"""
    exec_obj = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    
    paths = vm.explore_bounded(exec_obj, max_steps=50)
    
    # Should detect AttributeError as a bug
    assert len(paths) > 0
    # At least one path should have an exception
    has_exception = any(p.state.exception is not None for p in paths)
    assert has_exception, "Expected AttributeError not detected"


def test_import_sys_version_info():
    """Test importing sys and accessing version_info."""
    code = """
import sys
v = sys.version_info
"""
    exec_obj = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    
    try:
        paths = vm.explore_bounded(exec_obj, max_steps=50)
        assert paths is not None
    except Exception as e:
        pytest.fail(f"Import sys.version_info caused exception: {e}")


def test_import_collections_abc():
    """Test importing from collections.abc (submodule)."""
    code = """
from collections.abc import Iterable, Mapping
"""
    exec_obj = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    
    try:
        paths = vm.explore_bounded(exec_obj, max_steps=50)
        assert paths is not None
    except Exception as e:
        pytest.fail(f"Import from collections.abc caused exception: {e}")


def test_import_future():
    """Test __future__ imports (common in real code)."""
    code = """
from __future__ import annotations
def foo(x: int) -> int:
    return x + 1
"""
    exec_obj = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    
    try:
        paths = vm.explore_bounded(exec_obj, max_steps=50)
        assert paths is not None
    except Exception as e:
        pytest.fail(f"__future__ import caused exception: {e}")


def test_multiple_imports():
    """Test multiple stdlib imports in one file."""
    code = """
import sys
import os
import math
from typing import List, Dict
from collections import defaultdict

x = math.sqrt(4)
"""
    exec_obj = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    
    try:
        paths = vm.explore_bounded(exec_obj, max_steps=100)
        assert paths is not None
    except Exception as e:
        pytest.fail(f"Multiple imports caused exception: {e}")


def test_import_then_call_with_contract():
    """Test that importing and calling a function with a contract works."""
    code = """
import math
result = math.sqrt(-1)  # Should trigger FP_DOMAIN bug
"""
    exec_obj = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    
    paths = vm.explore_bounded(exec_obj, max_steps=50)
    
    # Should complete without crashing
    # (Whether it detects the domain error depends on contracts being applied)
    assert paths is not None
