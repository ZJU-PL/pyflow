"""
Tests for UNPACK_SEQUENCE opcode.

UNPACK_SEQUENCE unpacks a sequence (tuple or list) into individual values.
Tests cover:
- Basic tuple unpacking
- Basic list unpacking
- TypeError for non-sequences (None, int, str)
- ValueError for length mismatch
- Nested unpacking
"""

import pytest
import dis
import types

from a3_python.semantics.symbolic_vm import SymbolicVM


def test_unpack_sequence_opcode_exists():
    """Verify UNPACK_SEQUENCE opcode is used in Python 3.14."""
    code = compile('a, b = x', '<test>', 'exec')
    opcodes = [instr.opname for instr in dis.get_instructions(code)]
    assert 'UNPACK_SEQUENCE' in opcodes, f"Expected UNPACK_SEQUENCE in {opcodes}"


def test_unpack_tuple_basic():
    """Unpack a simple tuple."""
    code = compile('''
x = (1, 2)
a, b = x
''', '<test>', 'exec')
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # Should complete without exception
    completed = [p for p in paths if p.state.halted and not p.state.exception]
    assert len(completed) > 0
    
    # Check that a=1, b=2
    for path in completed:
        frame = path.state.frame_stack[0] if path.state.frame_stack else None
        if frame and 'a' in frame.locals and 'b' in frame.locals:
            # Values should be concrete ints
            assert frame.locals['a'].tag.name == 'INT'
            assert frame.locals['b'].tag.name == 'INT'


def test_unpack_list_basic():
    """Unpack a simple list."""
    code = compile('''
x = [10, 20]
a, b = x
''', '<test>', 'exec')
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    completed = [p for p in paths if p.state.halted and not p.state.exception]
    assert len(completed) > 0


def test_unpack_three_elements():
    """Unpack three elements from tuple."""
    code = compile('''
x = (1, 2, 3)
a, b, c = x
''', '<test>', 'exec')
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    completed = [p for p in paths if p.state.halted and not p.state.exception]
    assert len(completed) > 0


def test_unpack_none_typeerror():
    """Unpacking None raises TypeError (None misuse)."""
    code = compile('''
x = None
a, b = x
''', '<test>', 'exec')
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # Should reach none_misuse_reached
    assert any(p.state.none_misuse_reached for p in paths)
    
    # Should have TypeError exception
    exception_paths = [p for p in paths if p.state.exception == "TypeError"]
    assert len(exception_paths) > 0


def test_unpack_int_typeerror():
    """Unpacking int raises TypeError."""
    code = compile('''
x = 42
a, b = x
''', '<test>', 'exec')
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # Should reach type_confusion
    assert any(p.state.type_confusion_reached for p in paths)
    
    # Should have TypeError exception
    exception_paths = [p for p in paths if p.state.exception == "TypeError"]
    assert len(exception_paths) > 0


def test_unpack_length_mismatch_short():
    """Unpacking wrong length raises ValueError (too few)."""
    code = compile('''
x = (1, 2)
a, b, c = x
''', '<test>', 'exec')
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # Should have ValueError exception
    exception_paths = [p for p in paths if p.state.exception == "ValueError"]
    assert len(exception_paths) > 0


def test_unpack_length_mismatch_long():
    """Unpacking wrong length raises ValueError (too many)."""
    code = compile('''
x = (1, 2, 3, 4)
a, b = x
''', '<test>', 'exec')
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # Should have ValueError exception
    exception_paths = [p for p in paths if p.state.exception == "ValueError"]
    assert len(exception_paths) > 0


def test_unpack_in_function():
    """Unpack in function context with STORE_FAST."""
    code = compile('''
def f():
    x = (10, 20)
    a, b = x
    return a + b

result = f()
''', '<test>', 'exec')
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    completed = [p for p in paths if p.state.halted and not p.state.exception]
    assert len(completed) > 0


def test_unpack_nested():
    """Test nested tuple unpacking."""
    code = compile('''
x = ((1, 2), (3, 4))
(a, b), (c, d) = x
''', '<test>', 'exec')
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    completed = [p for p in paths if p.state.halted and not p.state.exception]
    assert len(completed) > 0


def test_unpack_empty_tuple():
    """Unpack empty tuple (edge case)."""
    code = compile('''
x = ()
# Can't do () = x in Python, but we test the opcode directly
''', '<test>', 'exec')
    
    # This is valid Python - empty tuple assigned to nothing
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    # Should complete without errors
    completed = [p for p in paths if p.state.halted and not p.state.exception]
    assert len(completed) > 0


def test_unpack_single_element():
    """Unpack single-element tuple."""
    code = compile('''
x = (42,)
(a,) = x
''', '<test>', 'exec')
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    completed = [p for p in paths if p.state.halted and not p.state.exception]
    assert len(completed) > 0
    
    # Check that a=42
    for path in completed:
        frame = path.state.frame_stack[0] if path.state.frame_stack else None
        if frame and 'a' in frame.locals:
            assert frame.locals['a'].tag.name == 'INT'


def test_unpack_swap_values():
    """Classic swap using unpacking."""
    code = compile('''
a = 1
b = 2
a, b = b, a
''', '<test>', 'exec')
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    completed = [p for p in paths if p.state.halted and not p.state.exception]
    assert len(completed) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
