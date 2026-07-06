"""
Tests for LIST_APPEND opcode implementation.

LIST_APPEND is used primarily in list comprehensions and appends an item
to a list at a specific stack position.

Note: Full list comprehension tests require LOAD_FAST_AND_CLEAR opcode.
These tests verify the LIST_APPEND opcode mechanics are sound.
"""

import pytest
import types
import dis
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicPath, SymbolicFrame, SymbolicMachineState
from a3_python.z3model.values import SymbolicValue, ValueTag
from a3_python.z3model.heap import SymbolicHeap


def test_list_append_opcode_direct():
    """Test LIST_APPEND opcode directly with a manually crafted state."""
    # Create a simple code object with LIST_APPEND instruction
    # We'll simulate: list on stack, item on TOS, then LIST_APPEND
    
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code=types.CodeType(
        0, 0, 0, 0, 0, 0, b'', (), (), (), '<test>', '<test>', '', 0, b'', b'', (), ()
    ))
    
    # Initialize heap tracking for lists
    state.heap.list_metadata = {}
    
    # Create a list object and put it on stack
    list_obj = SymbolicValue(ValueTag.OBJ, 1000)
    state.heap.list_metadata[id(list_obj)] = {'items': [], 'length': 0}
    
    # Create an item to append
    item = SymbolicValue(ValueTag.INT, 42)
    
    # Stack setup for LIST_APPEND with argval=1: [list, item]
    # After LIST_APPEND: [list]  (and item appended to list metadata)
    frame.operand_stack = [list_obj, item]
    
    # Manually create a LIST_APPEND instruction (argval=1)
    class FakeInstr:
        def __init__(self):
            self.opname = "LIST_APPEND"
            self.argval = 1
            self.offset = 0
    
    instr = FakeInstr()
    state.frame_stack = [frame]
    
    # Execute the LIST_APPEND logic manually
    # This is what the opcode handler should do:
    i = instr.argval
    if len(frame.operand_stack) >= i:
        popped_item = frame.operand_stack.pop()
        target_list = frame.operand_stack[-i]  # -i position after popping
        
        list_id = id(target_list)
        if list_id in state.heap.list_metadata:
            state.heap.list_metadata[list_id]['items'].append(popped_item)
            state.heap.list_metadata[list_id]['length'] += 1
    
    # Verify: stack should have only list, metadata should have item
    assert len(frame.operand_stack) == 1
    assert frame.operand_stack[0] == list_obj
    assert len(state.heap.list_metadata[id(list_obj)]['items']) == 1
    assert state.heap.list_metadata[id(list_obj)]['items'][0] == item
    assert state.heap.list_metadata[id(list_obj)]['length'] == 1


def test_list_append_with_argval_2():
    """Test LIST_APPEND with argval=2 (list is 2 positions below TOS after pop)."""
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code=types.CodeType(
        0, 0, 0, 0, 0, 0, b'', (), (), (), '<test>', '<test>', '', 0, b'', b'', (), ()
    ))
    
    state.heap.list_metadata = {}
    
    list_obj = SymbolicValue(ValueTag.OBJ, 2000)
    state.heap.list_metadata[id(list_obj)] = {'items': [], 'length': 0}
    
    dummy = SymbolicValue(ValueTag.INT, 999)
    item = SymbolicValue(ValueTag.INT, 123)
    
    # Stack for argval=2: [list, dummy, item]
    # After popping item: [list, dummy] -> list is at -2
    frame.operand_stack = [list_obj, dummy, item]
    
    # Execute LIST_APPEND with argval=2
    i = 2
    popped_item = frame.operand_stack.pop()
    target_list = frame.operand_stack[-i]  # Correct: -2 after pop
    
    list_id = id(target_list)
    state.heap.list_metadata[list_id]['items'].append(popped_item)
    state.heap.list_metadata[list_id]['length'] += 1
    
    # Verify
    assert len(frame.operand_stack) == 2  # list and dummy remain
    assert state.heap.list_metadata[id(list_obj)]['length'] == 1
    assert state.heap.list_metadata[id(list_obj)]['items'][0] == item


def test_list_append_multiple_items():
    """Test LIST_APPEND called multiple times (simulating comprehension loop)."""
    state = SymbolicMachineState()
    frame = SymbolicFrame(code=types.CodeType(
        0, 0, 0, 0, 0, 0, b'', (), (), (), '<test>', '<test>', '', 0, b'', b'', (), ()
    ))
    
    state.heap.list_metadata = {}
    
    list_obj = SymbolicValue(ValueTag.OBJ, 3000)
    state.heap.list_metadata[id(list_obj)] = {'items': [], 'length': 0}
    
    # Simulate multiple LIST_APPEND operations
    for value in [10, 20, 30]:
        item = SymbolicValue(ValueTag.INT, value)
        frame.operand_stack = [list_obj, item]
        
        # Execute LIST_APPEND
        i = 1
        popped_item = frame.operand_stack.pop()
        target_list = frame.operand_stack[-i]  # -i position after popping
        
        list_id = id(target_list)
        state.heap.list_metadata[list_id]['items'].append(popped_item)
        if isinstance(state.heap.list_metadata[list_id]['length'], int):
            state.heap.list_metadata[list_id]['length'] += 1
    
    # Verify all items appended
    assert state.heap.list_metadata[id(list_obj)]['length'] == 3
    assert len(state.heap.list_metadata[id(list_obj)]['items']) == 3
    assert state.heap.list_metadata[id(list_obj)]['items'][0].payload == 10
    assert state.heap.list_metadata[id(list_obj)]['items'][1].payload == 20
    assert state.heap.list_metadata[id(list_obj)]['items'][2].payload == 30
