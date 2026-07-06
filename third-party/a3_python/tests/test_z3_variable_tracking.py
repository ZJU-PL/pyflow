"""
Tests for Z3 variable tracking in SymbolicMachineState.

This feature improves counterexample extraction by maintaining
a mapping from program variable names to their Z3 symbolic expressions.
"""

import z3
import pytest
from a3_python.semantics.symbolic_vm import SymbolicMachineState
from a3_python.z3model.values import SymbolicValue, ValueTag
from a3_python.barriers.cegis import CEGISBarrierSynthesizer, CEGISConfig, Counterexample
from a3_python.barriers.invariants import BarrierCertificate, InductivenessChecker


class TestZ3VariableMapping:
    """Test basic Z3 variable registration and retrieval."""
    
    def test_register_z3_variable(self):
        """Test registering a Z3 variable in the state."""
        state = SymbolicMachineState()
        
        # Create a Z3 variable
        x = z3.Int('x')
        
        # Register it
        state.register_z3_variable('x', x)
        
        # Retrieve it
        retrieved = state.get_z3_variable('x')
        assert retrieved is not None
        assert z3.eq(retrieved, x)
    
    def test_register_multiple_variables(self):
        """Test registering multiple Z3 variables."""
        state = SymbolicMachineState()
        
        x = z3.Int('x')
        y = z3.Real('y')
        z_var = z3.Bool('z')
        
        state.register_z3_variable('x', x)
        state.register_z3_variable('y', y)
        state.register_z3_variable('z', z_var)
        
        assert state.get_z3_variable('x') is not None
        assert state.get_z3_variable('y') is not None
        assert state.get_z3_variable('z') is not None
    
    def test_get_nonexistent_variable(self):
        """Test getting a variable that wasn't registered."""
        state = SymbolicMachineState()
        
        result = state.get_z3_variable('nonexistent')
        assert result is None
    
    def test_variable_map_copied(self):
        """Test that z3_variable_map is copied in state.copy()."""
        state = SymbolicMachineState()
        
        x = z3.Int('x')
        state.register_z3_variable('x', x)
        
        # Copy the state
        state_copy = state.copy()
        
        # The copied state should have the variable
        retrieved = state_copy.get_z3_variable('x')
        assert retrieved is not None
        assert z3.eq(retrieved, x)
        
        # Modifying copy shouldn't affect original
        y = z3.Int('y')
        state_copy.register_z3_variable('y', y)
        
        assert state_copy.get_z3_variable('y') is not None
        assert state.get_z3_variable('y') is None


class TestCounterexampleExtraction:
    """Test improved counterexample extraction using Z3 variable map."""
    
    def test_extract_variable_value_from_model(self):
        """Test extracting variable value from Z3 model."""
        # Create a simple Z3 problem
        solver = z3.Solver()
        x = z3.Int('x')
        solver.add(x > 5)
        solver.add(x < 10)
        
        assert solver.check() == z3.sat
        model = solver.model()
        
        # Create a state with the tracked variable
        state = SymbolicMachineState()
        state.register_z3_variable('x', x)
        
        # Create CEGIS synthesizer to test extraction
        synthesizer = CEGISBarrierSynthesizer()
        
        # Extract value
        def var_extractor(s):
            return s.get_z3_variable('x')
        
        value = synthesizer._extract_variable_value(model, var_extractor, state)
        
        # Should get a concrete integer between 6 and 9
        assert value is not None
        assert isinstance(value, (int, float))
        assert 5 < value < 10
    
    def test_extract_barrier_value_from_model(self):
        """Test extracting barrier value from Z3 model."""
        # Create a Z3 problem
        solver = z3.Solver()
        x = z3.Int('x')
        solver.add(x == 7)
        
        assert solver.check() == z3.sat
        model = solver.model()
        
        # Create state
        state = SymbolicMachineState()
        state.register_z3_variable('x', x)
        
        # Create a simple barrier: B(x) = 10 - x
        def barrier_fn(s):
            x_var = s.get_z3_variable('x')
            if x_var is None:
                return z3.RealVal(0)
            return z3.ToReal(z3.IntVal(10)) - z3.ToReal(x_var)
        
        barrier = BarrierCertificate(
            name="test_barrier",
            barrier_fn=barrier_fn,
            epsilon=0.5
        )
        
        # Extract barrier value
        synthesizer = CEGISBarrierSynthesizer()
        barrier_value = synthesizer._extract_barrier_value(model, barrier, state)
        
        # At x=7, B = 10 - 7 = 3
        assert barrier_value is not None
        assert abs(barrier_value - 3.0) < 0.01
    
    def test_counterexample_with_state(self):
        """Test that counterexamples include state information."""
        # Create a simple Init check that will fail
        checker = InductivenessChecker(timeout_ms=1000)
        
        def barrier_fn(s):
            x = s.get_z3_variable('x')
            if x is None:
                return z3.RealVal(-10)  # Will fail init
            return z3.ToReal(x)
        
        barrier = BarrierCertificate(
            name="test_barrier",
            barrier_fn=barrier_fn,
            epsilon=5.0  # Require B(s0) >= 5
        )
        
        def initial_state():
            s = SymbolicMachineState()
            x = z3.Int('x')
            s.register_z3_variable('x', x)
            # Constrain x to be small, so B(x) = x < 5
            s.path_condition = z3.And(x >= 0, x < 3)
            return s
        
        # Check init - should fail
        holds, cex, state = checker._check_init(barrier, initial_state)
        
        assert not holds
        assert cex is not None
        assert state is not None
        assert state.get_z3_variable('x') is not None


class TestCEGISWithVariableTracking:
    """Test CEGIS synthesis with improved variable tracking."""
    
    def test_cegis_tracks_variables_in_counterexamples(self):
        """Test that CEGIS properly uses variable tracking in CEs."""
        config = CEGISConfig(
            max_iterations=5,
            max_counterexamples=5,
            timeout_per_check_ms=1000,
            timeout_total_ms=5000,
        )
        
        synthesizer = CEGISBarrierSynthesizer(config)
        
        # Create a simple synthesis problem
        def initial_state_builder():
            s = SymbolicMachineState()
            n = z3.Int('n')
            s.register_z3_variable('n', n)
            s.path_condition = z3.And(n >= 0, n <= 5)
            return s
        
        def unsafe_predicate(s):
            n = s.get_z3_variable('n')
            if n is None:
                return z3.BoolVal(False)
            # Unsafe when n > 10
            return n > 10
        
        def step_relation(s, s_prime):
            n = s.get_z3_variable('n')
            n_prime = s_prime.get_z3_variable('n')
            if n is None or n_prime is None:
                return z3.BoolVal(False)
            # n' = n + 1
            return n_prime == n + 1
        
        def variable_extractor(s):
            return s.get_z3_variable('n')
        
        # Try to synthesize (may not succeed, but should not crash)
        result = synthesizer.synthesize(
            template_family="linear",
            initial_state_builder=initial_state_builder,
            unsafe_predicate=unsafe_predicate,
            step_relation=step_relation,
            variable_name="n",
            variable_extractor=variable_extractor,
        )
        
        # Should complete without error
        assert result is not None
        assert result.iterations > 0
        
        # If we got counterexamples, they should have state_values
        if result.counterexamples:
            for ce in result.counterexamples:
                assert ce.state_values is not None
                assert isinstance(ce.state_values, dict)


class TestInductivenessResultWithStates:
    """Test that InductivenessResult stores counterexample states."""
    
    def test_inductiveness_result_stores_states(self):
        """Test that check_inductiveness returns states in result."""
        checker = InductivenessChecker(timeout_ms=1000)
        
        # Create a barrier that will fail init
        def barrier_fn(s):
            return z3.RealVal(-1.0)  # Always negative
        
        barrier = BarrierCertificate(
            name="failing_barrier",
            barrier_fn=barrier_fn,
            epsilon=0.5
        )
        
        def initial_state_builder():
            s = SymbolicMachineState()
            x = z3.Int('x')
            s.register_z3_variable('x', x)
            s.path_condition = x >= 0
            return s
        
        def unsafe_predicate(s):
            return z3.BoolVal(False)
        
        def step_relation(s, s_prime):
            return z3.BoolVal(True)
        
        # Check inductiveness
        result = checker.check_inductiveness(
            barrier,
            initial_state_builder,
            unsafe_predicate,
            step_relation
        )
        
        # Should fail init
        assert not result.is_inductive
        assert not result.init_holds
        
        # Should have counterexample model
        assert result.init_counterexample is not None
        
        # Should have counterexample state (new feature!)
        assert result.init_counterexample_state is not None
        
        # The state should have our tracked variable
        state = result.init_counterexample_state
        assert state.get_z3_variable('x') is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
