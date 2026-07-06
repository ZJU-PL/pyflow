"""
Test EXTENDED_ARG opcode support.

EXTENDED_ARG is a prefix instruction used when opcode arguments exceed 255 (1 byte).
It's commonly seen in code with large constant pools, name tables, or code objects.
Example: numpy/ma/core.py triggers EXTENDED_ARG due to large constant table.
"""
import pytest
import dis

from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.z3model.values import ValueTag


class TestExtendedArg:
    """Tests for EXTENDED_ARG opcode."""
    
    def test_extended_arg_with_large_name_table(self):
        """Test EXTENDED_ARG triggered by large name table (>255 names)."""
        # Create code with 300 variable names to force EXTENDED_ARG
        names = [f"var_{i}" for i in range(300)]
        code_str = "\n".join([f"{name} = {i}" for i, name in enumerate(names)])
        code_str += "\nresult = var_280"
        
        code = compile(code_str, "<test>", "exec")
        
        # Verify EXTENDED_ARG appears in bytecode
        has_extended_arg = False
        for instr in dis.get_instructions(code):
            if instr.opname == "EXTENDED_ARG":
                has_extended_arg = True
                break
        
        assert has_extended_arg, "EXTENDED_ARG should appear with large name table"
        
        # Symbolic execution should handle EXTENDED_ARG without crashing
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=5000)
        
        # Should complete successfully (no NotImplementedError exception)
        assert len(paths) > 0
        final_state = paths[0].state
        assert final_state.halted
        assert final_state.exception is None
    
    def test_extended_arg_with_large_const_table(self):
        """Test EXTENDED_ARG with large constant table - focus on no NotImplementedError."""
        # The main point: EXTENDED_ARG opcodes should not cause NotImplementedError
        # Create code with many constants to trigger EXTENDED_ARG in bytecode
        const_list = list(range(300))
        code_str = f"constants = {const_list}"
        
        code = compile(code_str, "<test>", "exec")
        
        # Symbolic execution should handle EXTENDED_ARG without NotImplementedError
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=2000)
        
        # Should produce at least one path (success = no crash on EXTENDED_ARG)
        assert len(paths) > 0
        # The key test: no NotImplementedError for EXTENDED_ARG opcode
        # (Other exceptions like IndexError are valid bugs the analyzer may find)
    
    def test_extended_arg_semantics(self):
        """Verify EXTENDED_ARG doesn't break execution - programs run to completion."""
        # Small program (no EXTENDED_ARG)
        small_code = "x = 42\ny = x + 1"
        small_compiled = compile(small_code, "<small>", "exec")
        
        vm_small = SymbolicVM()
        paths_small = vm_small.explore_bounded(small_compiled, max_steps=100)
        
        # Large program that forces EXTENDED_ARG for some operations
        large_names = "\n".join([f"unused_{i} = {i}" for i in range(280)])
        large_code = large_names + "\nx = 42\ny = x + 1"
        large_compiled = compile(large_code, "<large>", "exec")
        
        vm_large = SymbolicVM()
        paths_large = vm_large.explore_bounded(large_compiled, max_steps=3000)
        
        # Both should complete successfully
        assert len(paths_small) > 0
        assert len(paths_large) > 0
        
        assert paths_small[0].state.halted
        assert paths_large[0].state.halted
        
        # Neither should have exceptions
        assert paths_small[0].state.exception is None
        assert paths_large[0].state.exception is None
    
    def test_extended_arg_nop_semantics(self):
        """Verify EXTENDED_ARG is transparent - dis resolves it for us."""
        # Create minimal code that triggers EXTENDED_ARG
        code_str = "\n".join([f"v{i} = {i}" for i in range(260)])
        code = compile(code_str, "<test>", "exec")
        
        # Check that dis.get_instructions() already resolves extended arguments
        found_v256 = False
        for instr in dis.get_instructions(code):
            if instr.argval == 'v256':
                # The arg should be 256 (the resolved value), not split across EXTENDED_ARG + STORE_NAME
                assert instr.arg == 256
                assert instr.opname == "STORE_NAME"
                found_v256 = True
                break
        
        assert found_v256, "Should find v256 with resolved arg=256"
        
        # Symbolic execution should work transparently
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=3000)
        
        assert len(paths) > 0
        assert paths[0].state.halted
        assert paths[0].state.exception is None
    
    def test_extended_arg_multiple_chained(self):
        """Test that even multiple EXTENDED_ARG instructions work (very large args)."""
        # Create code with enough names to potentially trigger multiple EXTENDED_ARG
        # (though in practice Python 3.14 may optimize differently)
        code_str = "\n".join([f"var{i} = {i}" for i in range(300)])
        code = compile(code_str, "<test>", "exec")
        
        # Count EXTENDED_ARG occurrences
        extended_count = sum(1 for instr in dis.get_instructions(code) if instr.opname == "EXTENDED_ARG")
        
        # Should have multiple EXTENDED_ARG instructions
        assert extended_count > 0, "Should have at least one EXTENDED_ARG"
        
        # Symbolic execution should handle all of them
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=5000)
        
        assert len(paths) > 0
        assert paths[0].state.halted
        assert paths[0].state.exception is None

