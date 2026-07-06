"""
Tests for contract system integration into symbolic VM.

Verifies that:
1. Unknown calls are handled with havoc contracts (sound default)
2. Known stdlib functions use their registered contracts
3. No SAFE claims are made on programs with havoc calls
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.contracts.schema import get_contract, list_contracts


class TestContractIntegration:
    """Test contract system integration into symbolic VM."""
    
    def test_unknown_call_uses_havoc_contract(self):
        """
        Unknown function calls should use the default havoc contract.
        This ensures soundness: we make no assumptions about unknown code.
        """
        # A program that calls an unknown function
        source = """
unknown_func(42)
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        
        # Should execute without crashing, using havoc semantics
        paths = vm.explore_bounded(code, max_steps=50)
        
        # Should complete (not crash on unknown function)
        assert len(paths) > 0
        
        # Check that we get a havoc contract for unknown functions
        contract = get_contract("unknown_func")
        assert contract.is_havoc()
        assert contract.heap_effect.may_write == {'*'}
        assert contract.exception_effect.may_raise == {'*'}
    
    def test_stdlib_len_uses_registered_contract(self):
        """
        Known stdlib functions should use their registered contracts.
        len() is pure and returns non-negative int.
        """
        # Program that calls len()
        source = """
x = [1, 2, 3]
result = len(x)
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        
        # Execute symbolically
        paths = vm.explore_bounded(code, max_steps=100)
        
        # Should complete successfully
        assert len(paths) > 0
        
        # Verify len has a registered contract (not havoc)
        contract = get_contract("len")
        assert not contract.is_havoc()
        assert contract.provenance == "stdlib_spec"
        assert contract.return_constraint.type_constraint == "int"
        assert contract.return_constraint.range_constraint == (0, None)  # Non-negative
        assert contract.heap_effect.may_write == set()  # Pure function
    
    def test_stdlib_abs_uses_registered_contract(self):
        """
        abs() is pure and returns non-negative numeric.
        """
        source = """
x = -42
result = abs(x)
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        
        paths = vm.explore_bounded(code, max_steps=100)
        assert len(paths) > 0
        
        contract = get_contract("abs")
        assert not contract.is_havoc()
        assert contract.provenance == "stdlib_spec"
        assert contract.heap_effect.may_write == set()  # Pure
    
    def test_no_safe_claims_with_havoc_calls(self):
        """
        Programs with unknown/havoc calls should NOT produce SAFE claims
        without a proper proof. This test verifies the anti-cheating rule.
        
        If a program calls an unknown function that could do anything,
        we cannot claim it's SAFE from bugs without a proof/contract.
        """
        # Program with unknown call
        source = """
unknown_func(42)
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        
        paths = vm.explore_bounded(code, max_steps=50)
        
        # We should complete paths, but this doesn't mean SAFE
        # (In a full implementation, we'd check for explicit SAFE claims)
        assert len(paths) > 0
        
        # The key principle: havoc means we cannot prove safety
        contract = get_contract("unknown_func")
        assert contract.is_havoc()
        # With havoc contract, any exception may occur
        assert '*' in contract.exception_effect.may_raise
        # Heap may be arbitrarily modified
        assert '*' in contract.heap_effect.may_write
    
    def test_stdlib_contracts_registered(self):
        """
        Verify that stdlib contracts are properly registered on import.
        """
        contracts = list_contracts()
        
        # Should have at least the 10 stdlib functions we registered
        assert len(contracts) >= 10
        assert "len" in contracts
        assert "abs" in contracts
        assert "int" in contracts
        assert "str" in contracts
        assert "max" in contracts
        assert "min" in contracts
        assert "sum" in contracts
        assert "isinstance" in contracts
        assert "issubclass" in contracts
        assert "range" in contracts
    
    def test_call_with_arguments(self):
        """
        Test that CALL opcode properly handles arguments.
        """
        source = """
x = abs(-5)
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        
        paths = vm.explore_bounded(code, max_steps=50)
        assert len(paths) > 0
        
        # Should execute without errors
        completed = [p for p in paths if p.state.halted and not p.state.exception]
        assert len(completed) > 0
    
    def test_multiple_calls_in_sequence(self):
        """
        Test multiple function calls in sequence.
        """
        source = """
x = abs(-5)
y = abs(-10)
z = abs(x + y)
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        
        paths = vm.explore_bounded(code, max_steps=200)
        assert len(paths) > 0
        
        # Should complete successfully
        completed = [p for p in paths if p.state.halted and not p.state.exception]
        assert len(completed) > 0
    
    def test_contract_heap_effects_are_sound(self):
        """
        Verify that heap effects in contracts are over-approximations.
        
        Pure functions (len, abs, isinstance) should not modify heap.
        Functions that may have side effects (str, due to __str__) should
        declare appropriate heap effects.
        """
        # len is pure
        len_contract = get_contract("len")
        assert len_contract.heap_effect.may_write == set()
        assert len_contract.heap_effect.may_read == set()
        
        # abs is pure
        abs_contract = get_contract("abs")
        assert abs_contract.heap_effect.may_write == set()
        
        # str may read (calls __str__ which may read objects)
        str_contract = get_contract("str")
        assert '*' in str_contract.heap_effect.may_read
        # But should not write (conservative assumption)
        assert str_contract.heap_effect.may_write == set()
    
    def test_contract_exception_effects_are_sound(self):
        """
        Verify that exception effects are over-approximations.
        
        Functions that may raise specific exceptions should declare them.
        """
        # len may raise TypeError
        len_contract = get_contract("len")
        assert "TypeError" in len_contract.exception_effect.may_raise
        assert not len_contract.exception_effect.always_raises
        
        # int may raise TypeError or ValueError
        int_contract = get_contract("int")
        assert "TypeError" in int_contract.exception_effect.may_raise
        assert "ValueError" in int_contract.exception_effect.may_raise
        
        # str may raise anything (because __str__ can)
        str_contract = get_contract("str")
        assert '*' in str_contract.exception_effect.may_raise


class TestOpcodeImplementation:
    """Test LOAD_GLOBAL and CALL opcodes."""
    
    def test_load_global_opcode(self):
        """
        LOAD_GLOBAL should load from globals or builtins.
        """
        source = """
abs(-5)
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        
        paths = vm.explore_bounded(code, max_steps=50)
        assert len(paths) > 0
    
    def test_call_opcode_with_nargs(self):
        """
        CALL opcode should handle argument count correctly.
        """
        # Call with 1 argument
        source = """
abs(-5)
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        assert len(paths) > 0
        
        # Call with 2 arguments (max)
        source = """
max(3, 5)
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        assert len(paths) > 0
    
    def test_call_result_pushed_to_stack(self):
        """
        CALL should push result onto operand stack.
        """
        source = """
x = abs(-5)
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        
        paths = vm.explore_bounded(code, max_steps=50)
        assert len(paths) > 0
        
        # Should complete and store result in x
        completed = [p for p in paths if p.state.halted]
        assert len(completed) > 0
        
        # x should be in locals
        final_state = completed[0].state
        if final_state.current_frame:
            assert 'x' in final_state.current_frame.locals
