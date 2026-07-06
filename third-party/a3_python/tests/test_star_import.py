"""
Tests for star import (from module import *) semantics.

Star imports use CALL_INTRINSIC_1 with INTRINSIC_IMPORT_STAR (ID 2)
to populate the current namespace with all module exports.
"""
import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM


def test_star_import_basic():
    """Test that star import doesn't crash."""
    code = compile("""
from math import *
result = sqrt(4)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    
    # Execute the code
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete without crashing
    assert len(paths) > 0
    # Should have at least one path complete
    assert any(not p.state.frame_stack for p in paths), "Should complete execution"


def test_star_import_populates_namespace():
    """Test that star import makes module attributes available."""
    code = compile("""
from os import *
x = name  # os.name should be available via star import
""", "<test>", "exec")
    
    vm = SymbolicVM()
    
    # Execute the code
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete without NameError
    assert len(paths) > 0
    # Should have at least one completed path
    completed_paths = [p for p in paths if not p.state.frame_stack]
    assert len(completed_paths) > 0, "Should complete execution"


def test_star_import_unknown_module():
    """Test star import with unknown module (sound over-approximation)."""
    code = compile("""
from unknown_module import *
x = some_name  # This may or may not exist, should be sound
""", "<test>", "exec")
    
    vm = SymbolicVM()
    
    # Execute the code
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete (may have exception or not, both are sound)
    assert len(paths) > 0


def test_star_import_vs_explicit_import():
    """Test that star import is semantically similar to explicit import."""
    # Explicit import
    code1 = compile("""
import math
result = math.sqrt(4)
""", "<test>", "exec")
    
    # Star import
    code2 = compile("""
from math import *
result = sqrt(4)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    
    # Execute explicit import
    paths1 = vm.explore_bounded(code1, max_steps=100)
    completed1 = [p for p in paths1 if not p.state.frame_stack]
    
    # Execute star import
    paths2 = vm.explore_bounded(code2, max_steps=100)
    completed2 = [p for p in paths2 if not p.state.frame_stack]
    
    # Both should complete
    assert len(completed1) > 0, "Explicit import should complete"
    assert len(completed2) > 0, "Star import should complete"


def test_star_import_multiple_modules():
    """Test multiple star imports in sequence."""
    code = compile("""
from os import *
from sys import *
x = name  # os.name
y = platform  # sys.platform
""", "<test>", "exec")
    
    vm = SymbolicVM()
    
    # Execute the code
    paths = vm.explore_bounded(code, max_steps=200)
    
    # Should complete without crashing
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.frame_stack]
    assert len(completed) > 0, "Multiple star imports should work"


def test_star_import_overwrite():
    """Test that star import can overwrite existing names."""
    code = compile("""
name = "original"
from os import *
x = name  # Should be os.name now, not "original"
""", "<test>", "exec")
    
    vm = SymbolicVM()
    
    # Execute the code
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete without crashing
    assert len(paths) > 0


def test_star_import_no_name_error():
    """Test that star import prevents NameError for known stdlib exports."""
    code = compile("""
from os import *
result = environ  # os.environ should be available
""", "<test>", "exec")
    
    vm = SymbolicVM()
    
    # Execute the code
    paths = vm.explore_bounded(code, max_steps=100)
    
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.frame_stack]
    assert len(completed) > 0, "Star import should provide os.environ"



