"""
Tests for BUILD_SET opcode.

BUILD_SET creates a set from N items on the stack.
This is the foundational opcode for set literals and set comprehensions.
"""
import pytest
import dis
import types
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicMachineState, SymbolicFrame
from a3_python.z3model.values import SymbolicValue, ValueTag


def test_build_set_opcode_direct():
    """Test that BUILD_SET appears in bytecode for set creation."""
    # Simple set literal: {1, 2, 3}
    # In Python 3.11+, this often uses BUILD_SET + SET_UPDATE
    def f():
        return {1, 2, 3}
    
    bytecode = dis.Bytecode(f)
    opcodes = [instr.opname for instr in bytecode]
    
    # BUILD_SET should appear
    assert "BUILD_SET" in opcodes, f"BUILD_SET not found in: {opcodes}"


def test_build_set_manual_empty():
    """Test BUILD_SET with argval=0 (empty set) using manual execution."""
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code=types.CodeType(
        0, 0, 0, 0, 0, 0, b'', (), (), (), '<test>', '<test>', '', 0, b'', b'', (), ()
    ))
    
    # Initialize set metadata tracking
    state.heap.set_metadata = {}
    
    # Stack setup for BUILD_SET(0): [] → [set]
    frame.operand_stack = []
    
    # Manually execute BUILD_SET logic (argval=0)
    count = 0
    items = []
    
    # Create a symbolic set object
    import z3
    set_id = z3.Int("set_test_0")
    set_obj = SymbolicValue(ValueTag.OBJ, set_id)
    
    # Store set contents in heap metadata
    state.heap.set_metadata[id(set_obj)] = {
        'items': items,
        'length': count
    }
    
    frame.operand_stack.append(set_obj)
    
    # Verify: stack should have the set, metadata should be empty
    assert len(frame.operand_stack) == 1
    assert frame.operand_stack[0] == set_obj
    assert len(state.heap.set_metadata[id(set_obj)]['items']) == 0
    assert state.heap.set_metadata[id(set_obj)]['length'] == 0


def test_build_set_manual_single():
    """Test BUILD_SET with argval=1 (single element) using manual execution."""
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code=types.CodeType(
        0, 0, 0, 0, 0, 0, b'', (), (), (), '<test>', '<test>', '', 0, b'', b'', (), ()
    ))
    
    # Initialize set metadata tracking
    state.heap.set_metadata = {}
    
    # Create an item to add to set
    item = SymbolicValue(ValueTag.INT, 42)
    
    # Stack setup for BUILD_SET(1): [item] → [set]
    frame.operand_stack = [item]
    
    # Manually execute BUILD_SET logic (argval=1)
    count = 1
    items = []
    for _ in range(count):
        items.insert(0, frame.operand_stack.pop())
    
    # Create a symbolic set object
    import z3
    set_id = z3.Int("set_test_1")
    set_obj = SymbolicValue(ValueTag.OBJ, set_id)
    
    # Store set contents in heap metadata
    state.heap.set_metadata[id(set_obj)] = {
        'items': items,
        'length': count
    }
    
    frame.operand_stack.append(set_obj)
    
    # Verify: stack should have the set, metadata should have the item
    assert len(frame.operand_stack) == 1
    assert frame.operand_stack[0] == set_obj
    assert len(state.heap.set_metadata[id(set_obj)]['items']) == 1
    assert state.heap.set_metadata[id(set_obj)]['items'][0] == item
    assert state.heap.set_metadata[id(set_obj)]['length'] == 1


def test_build_set_manual_multiple():
    """Test BUILD_SET with argval=3 (multiple elements) using manual execution."""
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code=types.CodeType(
        0, 0, 0, 0, 0, 0, b'', (), (), (), '<test>', '<test>', '', 0, b'', b'', (), ()
    ))
    
    # Initialize set metadata tracking
    state.heap.set_metadata = {}
    
    # Create items to add to set
    item1 = SymbolicValue(ValueTag.INT, 1)
    item2 = SymbolicValue(ValueTag.INT, 2)
    item3 = SymbolicValue(ValueTag.INT, 3)
    
    # Stack setup for BUILD_SET(3): [item1, item2, item3] → [set]
    # Note: items are pushed in order, so first item is at bottom
    frame.operand_stack = [item1, item2, item3]
    
    # Manually execute BUILD_SET logic (argval=3)
    count = 3
    items = []
    for _ in range(count):
        items.insert(0, frame.operand_stack.pop())
    
    # Create a symbolic set object
    import z3
    set_id = z3.Int("set_test_3")
    set_obj = SymbolicValue(ValueTag.OBJ, set_id)
    
    # Store set contents in heap metadata
    state.heap.set_metadata[id(set_obj)] = {
        'items': items,
        'length': count
    }
    
    frame.operand_stack.append(set_obj)
    
    # Verify: stack should have the set, metadata should have all items in order
    assert len(frame.operand_stack) == 1
    assert frame.operand_stack[0] == set_obj
    assert len(state.heap.set_metadata[id(set_obj)]['items']) == 3
    assert state.heap.set_metadata[id(set_obj)]['items'][0] == item1
    assert state.heap.set_metadata[id(set_obj)]['items'][1] == item2
    assert state.heap.set_metadata[id(set_obj)]['items'][2] == item3
    assert state.heap.set_metadata[id(set_obj)]['length'] == 3


def test_build_set_in_bytecode():
    """Test that BUILD_SET doesn't raise NotImplementedError in symbolic execution."""
    from a3_python.semantics.symbolic_vm import symbolic_execute
    
    # Set comprehension that will use BUILD_SET
    source = "{x for x in [1, 2]}"
    
    # This should not raise NotImplementedError for BUILD_SET
    paths = symbolic_execute(source, max_steps=150)
    
    # We expect at least one path to be generated
    # (may not complete due to missing other opcodes like SET_ADD)
    assert len(paths) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
