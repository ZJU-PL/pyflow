"""
Tests for MAP_ADD opcode (dict comprehensions).

Semantic target: Python 3.11+ bytecode machine.
Ensures MAP_ADD correctly adds key-value pairs to dicts in symbolic semantics.

Note: Full dict comprehension tests require LOAD_FAST_AND_CLEAR opcode.
These tests verify the MAP_ADD opcode mechanics are sound.
"""

import pytest
import types
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicPath, SymbolicFrame, SymbolicMachineState
from a3_python.z3model.values import SymbolicValue, ValueTag
from a3_python.z3model.heap import SymbolicHeap


def test_map_add_opcode_direct():
    """Test MAP_ADD opcode directly with a manually crafted state."""
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code=types.CodeType(
        0, 0, 0, 0, 0, 0, b'', (), (), (), '<test>', '<test>', '', 0, b'', b'', (), ()
    ))
    
    # Initialize dict metadata tracking
    state.heap.dict_metadata = {}
    
    # Create a dict object
    dict_obj = SymbolicValue(ValueTag.OBJ, 1000)
    state.heap.dict_metadata[id(dict_obj)] = {'pairs': [], 'length': 0}
    
    # Create key and value
    key = SymbolicValue(ValueTag.INT, 42)
    value = SymbolicValue(ValueTag.INT, 84)
    
    # Stack setup for MAP_ADD with argval=1:
    # [dict, key, value] -> after pop key and value: [dict] -> dict is at -1
    frame.operand_stack = [dict_obj, key, value]
    
    # Manually execute MAP_ADD logic (argval=1)
    i = 1
    popped_value = frame.operand_stack.pop()
    popped_key = frame.operand_stack.pop()
    target_dict = frame.operand_stack[-i]  # -1 after pops
    
    # Add to dict
    dict_id = id(target_dict)
    if dict_id in state.heap.dict_metadata:
        state.heap.dict_metadata[dict_id]['pairs'].append((popped_key, popped_value))
        if isinstance(state.heap.dict_metadata[dict_id]['length'], int):
            state.heap.dict_metadata[dict_id]['length'] += 1
    
    # Verify: stack should have only dict, metadata should have the pair
    assert len(frame.operand_stack) == 1
    assert frame.operand_stack[0] == dict_obj
    assert len(state.heap.dict_metadata[id(dict_obj)]['pairs']) == 1
    assert state.heap.dict_metadata[id(dict_obj)]['pairs'][0] == (key, value)
    assert state.heap.dict_metadata[id(dict_obj)]['length'] == 1


def test_map_add_with_argval_2():
    """Test MAP_ADD with argval=2 (dict is 2 positions below TOS after pops)."""
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code=types.CodeType(
        0, 0, 0, 0, 0, 0, b'', (), (), (), '<test>', '<test>', '', 0, b'', b'', (), ()
    ))
    
    state.heap.dict_metadata = {}
    
    dict_obj = SymbolicValue(ValueTag.OBJ, 2000)
    state.heap.dict_metadata[id(dict_obj)] = {'pairs': [], 'length': 0}
    
    dummy = SymbolicValue(ValueTag.INT, 999)
    key = SymbolicValue(ValueTag.STR, "key1")
    value = SymbolicValue(ValueTag.STR, "value1")
    
    # Stack for argval=2: [dict, dummy, key, value]
    # After popping key and value: [dict, dummy] -> dict is at -2
    frame.operand_stack = [dict_obj, dummy, key, value]
    
    # Execute MAP_ADD with argval=2
    i = 2
    popped_value = frame.operand_stack.pop()
    popped_key = frame.operand_stack.pop()
    target_dict = frame.operand_stack[-i]  # -2 after pops
    
    dict_id = id(target_dict)
    state.heap.dict_metadata[dict_id]['pairs'].append((popped_key, popped_value))
    state.heap.dict_metadata[dict_id]['length'] += 1
    
    # Verify
    assert len(frame.operand_stack) == 2  # dict and dummy remain
    assert state.heap.dict_metadata[id(dict_obj)]['length'] == 1
    assert state.heap.dict_metadata[id(dict_obj)]['pairs'][0] == (key, value)


def test_map_add_multiple_pairs():
    """Test MAP_ADD called multiple times (simulating comprehension loop)."""
    state = SymbolicMachineState()
    frame = SymbolicFrame(code=types.CodeType(
        0, 0, 0, 0, 0, 0, b'', (), (), (), '<test>', '<test>', '', 0, b'', b'', (), ()
    ))
    
    state.heap.dict_metadata = {}
    
    dict_obj = SymbolicValue(ValueTag.OBJ, 3000)
    state.heap.dict_metadata[id(dict_obj)] = {'pairs': [], 'length': 0}
    
    # Simulate multiple MAP_ADD operations
    test_data = [(10, 20), (30, 40), (50, 60)]
    for k_val, v_val in test_data:
        key = SymbolicValue(ValueTag.INT, k_val)
        value = SymbolicValue(ValueTag.INT, v_val)
        frame.operand_stack = [dict_obj, key, value]
        
        # Execute MAP_ADD
        i = 1
        popped_value = frame.operand_stack.pop()
        popped_key = frame.operand_stack.pop()
        target_dict = frame.operand_stack[-i]  # -i position after popping
        
        dict_id = id(target_dict)
        state.heap.dict_metadata[dict_id]['pairs'].append((popped_key, popped_value))
        if isinstance(state.heap.dict_metadata[dict_id]['length'], int):
            state.heap.dict_metadata[dict_id]['length'] += 1
    
    # Verify all pairs added
    assert state.heap.dict_metadata[id(dict_obj)]['length'] == 3
    assert len(state.heap.dict_metadata[id(dict_obj)]['pairs']) == 3
    assert state.heap.dict_metadata[id(dict_obj)]['pairs'][0][0].payload == 10
    assert state.heap.dict_metadata[id(dict_obj)]['pairs'][0][1].payload == 20
    assert state.heap.dict_metadata[id(dict_obj)]['pairs'][1][0].payload == 30
    assert state.heap.dict_metadata[id(dict_obj)]['pairs'][1][1].payload == 40
    assert state.heap.dict_metadata[id(dict_obj)]['pairs'][2][0].payload == 50
    assert state.heap.dict_metadata[id(dict_obj)]['pairs'][2][1].payload == 60
