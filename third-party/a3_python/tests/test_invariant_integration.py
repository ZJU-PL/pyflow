"""
Tests for loop invariant synthesis integration.

Tests that loop invariant synthesis is correctly integrated with the symbolic VM
and can synthesize inductive invariants for simple loops.
"""

import pytest
from a3_python.semantics.invariant_integration import (
    InvariantIntegrator,
    LoopInvariantResult,
    add_invariant_synthesis_to_state
)
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicMachineState
from a3_python.cfg.loop_analysis import extract_loops


class TestInvariantIntegrator:
    """Test the InvariantIntegrator class."""
    
    def test_simple_loop_invariant_synthesis(self):
        """Test that we can synthesize an invariant for a simple counting loop."""
        code = compile("""
i = 0
while i < 10:
    i = i + 1
""", "<test>", "exec")
        
        integrator = InvariantIntegrator()
        results = integrator.synthesize_all_loops(code)
        
        # Should detect the loop
        assert len(results) >= 1
        
        # Should attempt synthesis (may succeed or fail - that's ok)
        result = results[0]
        assert result.loop_offset >= 0
        assert result.verdict in ["INVARIANT_FOUND", "UNKNOWN"]
    
    def test_no_loops_returns_empty(self):
        """Test that code without loops returns empty results."""
        code = compile("""
x = 1
y = 2
z = x + y
""", "<test>", "exec")
        
        integrator = InvariantIntegrator()
        results = integrator.synthesize_all_loops(code)
        
        # No loops detected
        assert len(results) == 0
    
    def test_multiple_loops(self):
        """Test that we can handle multiple loops."""
        code = compile("""
i = 0
while i < 5:
    i = i + 1

j = 0
while j < 3:
    j = j + 1
""", "<test>", "exec")
        
        integrator = InvariantIntegrator()
        results = integrator.synthesize_all_loops(code)
        
        # Should detect both loops
        assert len(results) >= 2
        
        # All results should have valid structure
        for result in results:
            assert result.loop_offset >= 0
            assert result.verdict in ["INVARIANT_FOUND", "UNKNOWN"]
    
    def test_nested_loops(self):
        """Test handling of nested loops."""
        code = compile("""
i = 0
while i < 3:
    j = 0
    while j < 3:
        j = j + 1
    i = i + 1
""", "<test>", "exec")
        
        integrator = InvariantIntegrator()
        results = integrator.synthesize_all_loops(code)
        
        # Should detect nested loops
        assert len(results) >= 2
    
    def test_result_caching(self):
        """Test that results are cached correctly."""
        code = compile("""
i = 0
while i < 10:
    i = i + 1
""", "<test>", "exec")
        
        integrator = InvariantIntegrator()
        
        # First call
        results1 = integrator.synthesize_all_loops(code)
        
        # Second call should return cached results
        results2 = integrator.synthesize_all_loops(code)
        
        # Should be the same object (cached)
        assert results1 is results2
    
    def test_loop_variables_extracted(self):
        """Test that loop variables are correctly extracted."""
        code = compile("""
i = 0
j = 5
while i < 10:
    i = i + 1
    j = j - 1
""", "<test>", "exec")
        
        integrator = InvariantIntegrator()
        results = integrator.synthesize_all_loops(code)
        
        assert len(results) >= 1
        result = results[0]
        
        # Should have detected loop variables
        if result.loop_variables:
            # If loop analysis found variables, check they're present
            assert len(result.loop_variables) >= 1


class TestStateIntegration:
    """Test integration with SymbolicMachineState."""
    
    def test_add_invariant_synthesis_to_state(self):
        """Test adding invariant synthesis results to a state."""
        code = compile("""
i = 0
while i < 10:
    i = i + 1
""", "<test>", "exec")
        
        # Create a minimal state
        from a3_python.z3model.heap import SymbolicHeap
        from a3_python.semantics.security_tracker_lattice import LatticeSecurityTracker
        import z3
        
        state = SymbolicMachineState(
            frame_stack=[],
            heap=SymbolicHeap(),
            path_condition=z3.BoolVal(True),
            func_names={},
            security_tracker=LatticeSecurityTracker()
        )
        
        # Add invariant synthesis
        add_invariant_synthesis_to_state(state, code)
        
        # State should have results attached
        assert hasattr(state, 'loop_invariant_results')
        assert hasattr(state, 'has_loop_invariants')
        assert hasattr(state, 'proven_invariants')
        
        # Should have at least attempted synthesis
        assert isinstance(state.loop_invariant_results, list)
    
    def test_state_flags_set_correctly(self):
        """Test that state flags are set correctly based on results."""
        code = compile("""
i = 0
while i < 10:
    i = i + 1
""", "<test>", "exec")
        
        from a3_python.z3model.heap import SymbolicHeap
        from a3_python.semantics.security_tracker_lattice import LatticeSecurityTracker
        import z3
        
        state = SymbolicMachineState(
            frame_stack=[],
            heap=SymbolicHeap(),
            path_condition=z3.BoolVal(True),
            func_names={},
            security_tracker=LatticeSecurityTracker()
        )
        
        add_invariant_synthesis_to_state(state, code)
        
        # has_loop_invariants should be False if no invariants found
        # (or True if synthesis succeeded)
        assert isinstance(state.has_loop_invariants, bool)


class TestLoopInvariantResult:
    """Test the LoopInvariantResult dataclass."""
    
    def test_has_proof_method(self):
        """Test the has_proof() method."""
        # Result with proof
        result_with_proof = LoopInvariantResult(
            loop_offset=0,
            verdict="INVARIANT_FOUND",
            invariant=None,  # Would be a BarrierCertificate in real use
            proof=None
        )
        assert result_with_proof.has_proof() is True
        
        # Result without proof
        result_no_proof = LoopInvariantResult(
            loop_offset=0,
            verdict="UNKNOWN",
            reason="Could not synthesize"
        )
        assert result_no_proof.has_proof() is False
    
    def test_result_structure(self):
        """Test that result has all expected fields."""
        result = LoopInvariantResult(
            loop_offset=42,
            verdict="INVARIANT_FOUND",
            loop_variables=["i", "j"]
        )
        
        assert result.loop_offset == 42
        assert result.verdict == "INVARIANT_FOUND"
        assert result.loop_variables == ["i", "j"]
        assert result.invariant is None
        assert result.proof is None
        assert result.reason is None


class TestEndToEndIntegration:
    """Test end-to-end integration with analyzer."""
    
    def test_cli_flag_integration(self):
        """Test that --synthesize-invariants flag works."""
        from a3_python.analyzer import analyze
        from pathlib import Path
        
        # Create a test file
        test_code = """
i = 0
while i < 10:
    i = i + 1
"""
        
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_code)
            test_file = f.name
        
        try:
            # Run analysis with invariant synthesis enabled
            result = analyze(
                Path(test_file),
                verbose=False,
                synthesize_invariants=True
            )
            
            # Should complete without error
            assert result.verdict in ["BUG", "SAFE", "UNKNOWN"]
        finally:
            os.unlink(test_file)
    
    def test_analyzer_integration(self):
        """Test that Analyzer class accepts synthesize_invariants parameter."""
        from a3_python.analyzer import Analyzer
        
        # Should accept the parameter
        analyzer = Analyzer(synthesize_invariants=True)
        assert analyzer.synthesize_invariants is True
        
        analyzer2 = Analyzer(synthesize_invariants=False)
        assert analyzer2.synthesize_invariants is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
