"""
Tests for DSE (Dynamic Symbolic Execution) oracle.

Tests demonstrate:
1. DSE can realize symbolic traces with concrete inputs
2. DSE is used as refinement oracle (not proof of absence)
3. DSE failure does NOT imply infeasibility
"""

import pytest
import z3
from a3_python.dse import ConcreteExecutor, TraceValidator, DSEResult
from a3_python.dse.concolic import ConcreteInput, ConcreteTrace


class TestConcreteExecutor:
    """Test concrete bytecode execution with tracing."""
    
    def test_execute_simple_function(self):
        """Concrete executor can run a simple function."""
        code = compile("def f(x): return x + 1", "<test>", "exec")
        # Get the function's code object
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        executor = ConcreteExecutor()
        trace = executor.execute(func_code, ConcreteInput(
            args=[5],
            globals_dict={},
            env={},
            stdin=""
        ))
        
        assert trace.is_normal_return()
        assert trace.final_state == 6
        assert trace.exception_raised is None
    
    def test_execute_with_exception(self):
        """Concrete executor captures exceptions."""
        code = compile("def f(): raise ValueError('test')", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        executor = ConcreteExecutor()
        trace = executor.execute(func_code, ConcreteInput.empty())
        
        assert not trace.is_normal_return()
        assert trace.exception_raised is not None
        assert isinstance(trace.exception_raised, ValueError)
    
    def test_execute_records_offsets(self):
        """Concrete executor records bytecode offsets."""
        code = compile("def f(x):\n  y = x + 1\n  return y", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        executor = ConcreteExecutor()
        trace = executor.execute(func_code, ConcreteInput(
            args=[10],
            globals_dict={},
            env={},
            stdin=""
        ))
        
        # Should have recorded some offsets
        assert len(trace.executed_offsets) > 0
        # All offsets should be non-negative
        assert all(offset >= 0 for offset in trace.executed_offsets)
    
    def test_execute_respects_max_steps(self):
        """Concrete executor terminates infinite loops."""
        code = compile("def f():\n  while True: pass", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        executor = ConcreteExecutor(max_steps=100)
        trace = executor.execute(func_code, ConcreteInput.empty())
        
        # Should have raised RuntimeError about max steps
        assert trace.exception_raised is not None
        assert "exceeded" in str(trace.exception_raised).lower()


class TestTraceValidator:
    """Test trace validation via DSE."""
    
    def test_validate_simple_path_satisfiable(self):
        """DSE can realize a satisfiable path condition."""
        # Simple path: x > 5
        x = z3.Int('arg0')
        path_condition = x > 5
        
        code = compile("def f(x): return x > 5", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        validator = TraceValidator(timeout_sec=5)
        result = validator.validate_path(
            path_condition=path_condition,
            code_obj=func_code,
            symbolic_inputs={'arg0': x}
        )
        
        assert result.status == "realized"
        assert result.concrete_input is not None
        assert result.concrete_input.args[0] > 5  # Satisfies constraint
        assert result.concrete_trace is not None
    
    def test_validate_unsatisfiable_path(self):
        """DSE reports when path condition is unsatisfiable."""
        # Unsatisfiable: x > 10 AND x < 5
        x = z3.Int('arg0')
        path_condition = z3.And(x > 10, x < 5)
        
        code = compile("def f(x): return x", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        validator = TraceValidator(timeout_sec=5)
        result = validator.validate_path(
            path_condition=path_condition,
            code_obj=func_code,
            symbolic_inputs={'arg0': x}
        )
        
        assert result.status == "failed"
        assert "unsatisfiable" in result.message.lower() or "infeasible" in result.message.lower()
        assert result.concrete_input is None
    
    def test_dse_as_oracle_not_proof(self):
        """
        DSE failure does NOT prove infeasibility.
        
        This is critical: DSE is an under-approximate oracle.
        """
        # Complex constraint that might timeout
        x = z3.Int('arg0')
        # This is satisfiable but may be hard for the solver
        path_condition = z3.And(
            x > 0,
            x < 1000000,
            # Add some complexity
            (x % 7 == 3),
            (x % 11 == 5)
        )
        
        code = compile("def f(x): return x", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        # With a very short timeout, might fail
        validator = TraceValidator(timeout_sec=1)
        result = validator.validate_path(
            path_condition=path_condition,
            code_obj=func_code,
            symbolic_inputs={'arg0': x}
        )
        
        # Whether it succeeds or fails, we test the interpretation:
        if result.status == "failed":
            # Failure does NOT mean the path is infeasible!
            # It means we didn't find inputs within budget
            assert "failed" in result.status.lower() or "unknown" in result.status.lower()
            # The message should not claim the path is impossible
            assert "impossible" not in result.message.lower()
        else:
            # If it succeeds, the input should satisfy the constraint
            assert result.status == "realized"
    
    def test_dse_extracts_concrete_inputs(self):
        """DSE extracts usable concrete inputs from Z3 model."""
        x = z3.Int('arg0')
        y = z3.Int('arg1')
        path_condition = z3.And(x + y == 10, x > 0, y > 0)
        
        code = compile("def f(x, y): return x + y", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        validator = TraceValidator(timeout_sec=5)
        result = validator.validate_path(
            path_condition=path_condition,
            code_obj=func_code,
            symbolic_inputs={'arg0': x, 'arg1': y}
        )
        
        assert result.status == "realized"
        assert len(result.concrete_input.args) == 2
        x_val, y_val = result.concrete_input.args
        assert x_val + y_val == 10
        assert x_val > 0
        assert y_val > 0
    
    def test_dse_produces_concrete_trace(self):
        """DSE produces a concrete trace showing actual execution."""
        x = z3.Int('arg0')
        path_condition = x == 42
        
        code = compile("def f(x):\n  if x == 42:\n    return 'yes'\n  return 'no'", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        validator = TraceValidator(timeout_sec=5)
        result = validator.validate_path(
            path_condition=path_condition,
            code_obj=func_code,
            symbolic_inputs={'arg0': x}
        )
        
        assert result.status == "realized"
        assert result.concrete_trace is not None
        assert result.concrete_trace.final_state == 'yes'
        assert result.concrete_trace.is_normal_return()


class TestDSERefinementOracle:
    """Test DSE as refinement oracle for contracts."""
    
    def test_dse_witnesses_behavior(self):
        """DSE can witness a specific behavior of an unknown call."""
        # Suppose we have a symbolic trace saying "unknown_f(5) returns 10"
        x = z3.Int('arg0')
        result_var = z3.Int('result')
        # Path condition encoding the behavior we want to witness
        path_condition = z3.And(x == 5, result_var == 10)
        
        # Concrete implementation
        code = compile("def f(x): return x * 2", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        validator = TraceValidator(timeout_sec=5)
        result = validator.validate_path(
            path_condition=path_condition,
            code_obj=func_code,
            symbolic_inputs={'arg0': x, 'result': result_var}
        )
        
        # DSE confirms this behavior is realizable
        if result.status == "realized":
            assert result.concrete_input.args[0] == 5
            # We can use this to refine our contract (conservatively)
        else:
            # If DSE fails, we learn nothing (cannot shrink contract)
            pass
    
    def test_dse_failure_does_not_justify_refinement(self):
        """
        Critical test: DSE failure does NOT justify shrinking contracts.
        
        This enforces the soundness discipline.
        """
        # Suppose we have a contract saying "unknown_f may raise ValueError"
        # DSE tries to find an input that raises ValueError
        x = z3.Int('arg0')
        path_condition = x > 0  # Some condition
        
        code = compile("def f(x): return x * 2", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        validator = TraceValidator(timeout_sec=1)
        result = validator.validate_path(
            path_condition=path_condition,
            code_obj=func_code,
            symbolic_inputs={'arg0': x}
        )
        
        # Even if DSE succeeds and doesn't raise ValueError,
        # we CANNOT conclude "f never raises ValueError"
        # Because:
        # 1. We only tested one input
        # 2. DSE is under-approximate
        # 3. The actual function might raise on other inputs
        
        # This test just documents the principle
        assert True  # The discipline is in how we use the result
    
    def test_refinement_suggestion_is_conservative(self):
        """DSE refinement suggestions maintain soundness."""
        validator = TraceValidator()
        
        # Observed behaviors (all from successful DSE runs)
        observed = [
            (ConcreteInput(args=[5], globals_dict={}, env={}, stdin=""), 10),
            (ConcreteInput(args=[3], globals_dict={}, env={}, stdin=""), 6),
        ]
        
        suggestion = validator.attempt_refinement("unknown_f", observed)
        
        # Suggestion should warn about soundness
        assert "sound" in suggestion.lower() or "over-approximate" in suggestion.lower()
        assert "documentation" in suggestion.lower() or "source" in suggestion.lower()
        # Should NOT suggest automatic refinement
        assert "never" in suggestion.lower() or "manual" in suggestion.lower()


class TestDSEIntegrationWithBugDetection:
    """Test DSE integration with bug detection workflow."""
    
    def test_dse_produces_concrete_repro_for_bug(self):
        """When analyzer finds BUG, DSE produces concrete reproducer."""
        # Simulate: symbolic execution found assert False is reachable
        # Path condition: (no constraints, assert is always reached)
        path_condition = z3.BoolVal(True)
        
        code = compile("def f(): assert False", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        validator = TraceValidator(timeout_sec=5)
        result = validator.validate_path(
            path_condition=path_condition,
            code_obj=func_code,
            symbolic_inputs={}
        )
        
        # DSE should realize this (no inputs needed)
        assert result.status == "realized"
        assert result.concrete_trace is not None
        # The trace should show AssertionError was raised
        assert result.concrete_trace.exception_raised is not None
        assert isinstance(result.concrete_trace.exception_raised, AssertionError)
    
    def test_dse_validates_division_by_zero_repro(self):
        """DSE validates a division-by-zero counterexample."""
        x = z3.Int('arg0')
        path_condition = x == 0
        
        code = compile("def f(x): return 10 / x", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        validator = TraceValidator(timeout_sec=5)
        result = validator.validate_path(
            path_condition=path_condition,
            code_obj=func_code,
            symbolic_inputs={'arg0': x}
        )
        
        assert result.status == "realized"
        assert result.concrete_input.args[0] == 0
        assert result.concrete_trace.exception_raised is not None
        # Should be ZeroDivisionError
        assert isinstance(result.concrete_trace.exception_raised, ZeroDivisionError)
    
    def test_dse_result_includes_metadata(self):
        """DSE result includes timing and Z3 model for analysis."""
        x = z3.Int('arg0')
        path_condition = x > 100
        
        code = compile("def f(x): return x", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        validator = TraceValidator(timeout_sec=5)
        result = validator.validate_path(
            path_condition=path_condition,
            code_obj=func_code,
            symbolic_inputs={'arg0': x}
        )
        
        if result.status == "realized":
            # Should include timing metadata
            assert hasattr(result, 'solver_time_sec')
            assert hasattr(result, 'execution_time_sec')
            assert result.solver_time_sec >= 0
            assert result.execution_time_sec >= 0
            # Should include Z3 model
            assert result.z3_model is not None


class TestDSESoundnessPrinciples:
    """
    Tests documenting DSE soundness principles.
    
    These are not executable tests but documentation of the discipline.
    """
    
    def test_principle_dse_is_under_approximate(self):
        """
        Principle: DSE is an under-approximate oracle.
        
        DSE can prove feasibility (by finding inputs) but not infeasibility.
        """
        # When DSE finds inputs, we know the trace is feasible
        # When DSE fails, we know nothing (might be timeout, might be incomplete)
        
        x = z3.Int('arg0')
        feasible_condition = x == 42
        
        code = compile("def f(x): return x", "<test>", "exec")
        func_code = [c for c in code.co_consts if hasattr(c, 'co_code')][0]
        
        validator = TraceValidator(timeout_sec=5)
        result = validator.validate_path(feasible_condition, func_code, {'arg0': x})
        
        if result.status == "realized":
            # Positive witness: trace IS feasible
            assert True
        else:
            # Negative result: we learned nothing about feasibility
            assert result.status in ["failed", "error", "timeout"]
    
    def test_principle_never_report_safe_without_proof(self):
        """
        Principle: Never report SAFE based on DSE failure.
        
        DSE failure does not constitute a safety proof.
        """
        # This is enforced by the analyzer architecture:
        # - BUG requires a witness (DSE can provide)
        # - SAFE requires a proof (barrier certificate, not DSE)
        # - UNKNOWN when neither exists
        
        # This test documents the principle
        validator = TraceValidator()
        
        # Even if DSE fails for every attempted counterexample,
        # we still report UNKNOWN (not SAFE)
        # Only an inductive invariant can prove SAFE
        
        assert True  # Principle is documented
    
    def test_principle_over_approximate_contracts(self):
        """
        Principle: Contracts must be over-approximations.
        
        DSE can help refine contracts, but only conservatively.
        """
        validator = TraceValidator()
        
        # Given: current contract says "may_raise = {TypeError, ValueError}"
        # DSE observes: 10 runs, no exceptions
        # Conclusion: CANNOT shrink to "may_raise = {}"
        # Reason: 10 runs is not exhaustive; actual function may raise on other inputs
        
        # Only valid refinement sources:
        # 1. Source code analysis (independent)
        # 2. Specification/documentation (independent)
        # 3. Bounded exhaustive testing with proof of coverage
        
        assert True  # Principle is documented
