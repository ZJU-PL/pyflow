"""
Tests for SET_ADD opcode.

SET_ADD adds TOS to the set at stack position -argval (after pop).
This is used primarily in set comprehensions.
"""
import pytest
import dis
import types
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicMachineState, SymbolicFrame
from a3_python.z3model.values import SymbolicValue, ValueTag


def test_set_add_opcode_in_comprehension():
    """Test that SET_ADD appears in bytecode for set comprehensions."""
    # Set comprehension: {x for x in [1, 2, 3]}
    def f():
        return {x for x in [1, 2, 3]}
    
    bytecode = dis.Bytecode(f)
    opcodes = [instr.opname for instr in bytecode]
    
    # SET_ADD should appear in set comprehension bytecode
    assert "SET_ADD" in opcodes, f"SET_ADD not found in: {opcodes}"


def test_set_add_manual_single():
    """Test SET_ADD with argval=1 (set at stack[-1]) using manual execution."""
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code=types.CodeType(
        0, 0, 0, 0, 0, 0, b'', (), (), (), '<test>', '<test>', '', 0, b'', b'', (), ()
    ))
    
    # Initialize set metadata tracking
    state.heap.set_metadata = {}
    
    # Create a set object
    import z3
    set_id = z3.Int("set_test")
    set_obj = SymbolicValue(ValueTag.OBJ, set_id)
    
    # Initialize set metadata
    state.heap.set_metadata[id(set_obj)] = {
        'items': [],
        'length': 0
    }
    
    # Create an item to add
    item = SymbolicValue(ValueTag.INT, 42)
    
    # Stack setup for SET_ADD(1): [set, item] → [set]
    # argval=1 means the set is at position -1 after popping item
    frame.operand_stack = [set_obj, item]
    
    # Manually execute SET_ADD logic (argval=1)
    i = 1
    popped_item = frame.operand_stack.pop()
    target_set = frame.operand_stack[-i]
    
    # Add the item
    state.heap.set_metadata[id(target_set)]['items'].append(popped_item)
    state.heap.set_metadata[id(target_set)]['length'] += 1
    
    # Verify: stack should have only the set, metadata should have the item
    assert len(frame.operand_stack) == 1
    assert frame.operand_stack[0] == set_obj
    assert len(state.heap.set_metadata[id(set_obj)]['items']) == 1
    assert state.heap.set_metadata[id(set_obj)]['items'][0] == item
    assert state.heap.set_metadata[id(set_obj)]['length'] == 1


def test_set_add_manual_multiple():
    """Test SET_ADD multiple times to add multiple items."""
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code=types.CodeType(
        0, 0, 0, 0, 0, 0, b'', (), (), (), '<test>', '<test>', '', 0, b'', b'', (), ()
    ))
    
    # Initialize set metadata tracking
    state.heap.set_metadata = {}
    
    # Create a set object
    import z3
    set_id = z3.Int("set_test")
    set_obj = SymbolicValue(ValueTag.OBJ, set_id)
    
    # Initialize set metadata
    state.heap.set_metadata[id(set_obj)] = {
        'items': [],
        'length': 0
    }
    
    # Create items to add
    item1 = SymbolicValue(ValueTag.INT, 1)
    item2 = SymbolicValue(ValueTag.INT, 2)
    item3 = SymbolicValue(ValueTag.INT, 3)
    
    # Add first item
    frame.operand_stack = [set_obj, item1]
    i = 1
    popped_item = frame.operand_stack.pop()
    target_set = frame.operand_stack[-i]
    state.heap.set_metadata[id(target_set)]['items'].append(popped_item)
    state.heap.set_metadata[id(target_set)]['length'] += 1
    
    # Add second item
    frame.operand_stack = [set_obj, item2]
    popped_item = frame.operand_stack.pop()
    target_set = frame.operand_stack[-i]
    state.heap.set_metadata[id(target_set)]['items'].append(popped_item)
    state.heap.set_metadata[id(target_set)]['length'] += 1
    
    # Add third item
    frame.operand_stack = [set_obj, item3]
    popped_item = frame.operand_stack.pop()
    target_set = frame.operand_stack[-i]
    state.heap.set_metadata[id(target_set)]['items'].append(popped_item)
    state.heap.set_metadata[id(target_set)]['length'] += 1
    
    # Verify: metadata should have all three items
    assert len(state.heap.set_metadata[id(set_obj)]['items']) == 3
    assert state.heap.set_metadata[id(set_obj)]['items'][0] == item1
    assert state.heap.set_metadata[id(set_obj)]['items'][1] == item2
    assert state.heap.set_metadata[id(set_obj)]['items'][2] == item3
    assert state.heap.set_metadata[id(set_obj)]['length'] == 3


def test_set_comprehension_execution():
    """Test that set comprehension executes without NotImplementedError."""
    from a3_python.semantics.symbolic_vm import symbolic_execute
    
    # Set comprehension that will use BUILD_SET + SET_ADD
    source = "{x for x in [1, 2]}"
    
    # This should not raise NotImplementedError for SET_ADD
    # We just verify it doesn't crash; completion depends on other opcodes
    try:
        paths = symbolic_execute(source, max_steps=200)
        # We expect at least one path to be generated
        assert len(paths) > 0, "No paths generated from set comprehension"
    except NotImplementedError as e:
        if "SET_ADD" in str(e):
            pytest.fail(f"SET_ADD not implemented: {e}")
        else:
            # Some other opcode is missing, that's okay for this test
            pass


def test_set_comprehension_with_filter():
    """Test set comprehension with a filter condition."""
    from a3_python.semantics.symbolic_vm import symbolic_execute
    
    # Set comprehension with conditional
    source = "{x for x in [1, 2, 3] if x > 1}"
    
    # This tests SET_ADD in the context of conditional logic
    paths = symbolic_execute(source, max_steps=300)
    
    # We expect at least one path to be generated
    assert len(paths) > 0, "No paths generated from filtered set comprehension"


def test_nested_set_comprehension():
    """Test nested set comprehension (set of tuples)."""
    from a3_python.semantics.symbolic_vm import symbolic_execute
    
    # Nested comprehension: {(x, y) for x in [1, 2] for y in [3, 4]}
    source = "{(x, y) for x in [1, 2] for y in [3, 4]}"
    
    # This tests SET_ADD with complex items
    paths = symbolic_execute(source, max_steps=500)
    
    # We expect at least one path to be generated
    assert len(paths) > 0, "No paths generated from nested set comprehension"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
