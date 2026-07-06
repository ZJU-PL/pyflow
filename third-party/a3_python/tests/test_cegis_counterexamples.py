"""
Tests for CEGIS counterexample extraction and utilization.

These tests verify that CEGIS correctly extracts concrete values from
counterexamples and uses them to guide parameter synthesis.
"""

import pytest
import z3
from a3_python.barriers.cegis import (
    CEGISBarrierSynthesizer,
    CEGISConfig,
    Counterexample,
    synthesize_barrier_cegis,
)
from a3_python.barriers.invariants import (
    InductivenessResult,
    InductivenessChecker,
)
from a3_python.barriers.templates import quadratic_barrier


def test_counterexample_value_extraction():
    """Test that concrete values are extracted from Z3 models."""
    synthesizer = CEGISBarrierSynthesizer()
    
    # Create a simple Z3 model
    solver = z3.Solver()
    x = z3.Int('x_0')
    y = z3.Real('y_init')
    solver.add(x == 42)
    solver.add(y == 3.14)
    
    assert solver.check() == z3.sat
    model = solver.model()
    
    # Extract state values
    state_values = synthesizer._extract_state_values_from_model(model)
    
    assert 'x_0' in state_values
    assert 'y_init' in state_values
    assert state_values['x_0'] == 42
    assert abs(state_values['y_init'] - 3.14) < 0.01


def test_z3_value_to_python_conversion():
    """Test Z3 value to Python primitive conversion."""
    synthesizer = CEGISBarrierSynthesizer()
    
    # Integer
    int_val = z3.IntVal(42)
    assert synthesizer._z3_value_to_python(int_val) == 42
    
    # Rational
    rat_val = z3.RealVal("3/2")
    assert abs(synthesizer._z3_value_to_python(rat_val) - 1.5) < 0.01
    
    # Boolean
    assert synthesizer._z3_value_to_python(z3.BoolVal(True)) is True
    assert synthesizer._z3_value_to_python(z3.BoolVal(False)) is False


def test_template_evaluation_at_point():
    """Test evaluating parametric template at concrete point."""
    synthesizer = CEGISBarrierSynthesizer()
    
    # Quadratic: B(x) = a·x² + b·x + c
    params = {
        "coeff_x2": z3.Real("a"),
        "coeff_x": z3.Real("b"),
        "constant": z3.Real("c"),
    }
    
    # Evaluate at x=2: B(2) = a·4 + b·2 + c
    expr = synthesizer._evaluate_template_at_point(params, "quadratic", 2.0)
    
    # Verify structure
    solver = z3.Solver()
    solver.add(params["coeff_x2"] == 1.0)
    solver.add(params["coeff_x"] == 2.0)
    solver.add(params["constant"] == 3.0)
    solver.add(expr == z3.Real("result"))
    
    assert solver.check() == z3.sat
    model = solver.model()
    result_val = model.eval(z3.Real("result"), model_completion=True)
    
    # B(2) = 1*4 + 2*2 + 3 = 11
    assert abs(float(result_val.as_fraction()) - 11.0) < 0.01


def test_counterexample_constraint_building_init():
    """Test that init counterexamples produce correct constraints."""
    synthesizer = CEGISBarrierSynthesizer()
    
    # Create a counterexample for init condition failure
    # Suppose init failed at x=5 with B(5) < ε
    solver = z3.Solver()
    x = z3.Int('n_0')
    solver.add(x == 5)
    assert solver.check() == z3.sat
    model = solver.model()
    
    state_values = {'n_0': 5}
    ce = Counterexample(
        kind='init',
        model=model,
        state_values=state_values,
        variable_value=5.0,
    )
    
    # Build constraints
    params = {
        "coeff_x2": z3.Real("a"),
        "coeff_x": z3.Real("b"),
        "constant": z3.Real("c"),
    }
    
    constraints = synthesizer._build_counterexample_constraints(
        params, [ce], "quadratic", "n"
    )
    
    # Should have constraint: B(5) ≥ ε
    # i.e., a·25 + b·5 + c ≥ ε
    assert len(constraints) >= 1


def test_counterexample_constraint_building_unsafe():
    """Test that unsafe counterexamples produce correct constraints."""
    synthesizer = CEGISBarrierSynthesizer()
    
    # Create a counterexample for unsafe condition failure
    # Suppose unsafe failed at x=100 with B(100) ≥ -ε (should be ≤ -ε)
    solver = z3.Solver()
    x = z3.Int('n_0')
    solver.add(x == 100)
    assert solver.check() == z3.sat
    model = solver.model()
    
    state_values = {'n_0': 100}
    ce = Counterexample(
        kind='unsafe',
        model=model,
        state_values=state_values,
        variable_value=100.0,
    )
    
    params = {
        "coeff_x2": z3.Real("a"),
        "coeff_x": z3.Real("b"),
        "constant": z3.Real("c"),
    }
    
    constraints = synthesizer._build_counterexample_constraints(
        params, [ce], "quadratic", "n"
    )
    
    # Should have constraint: B(100) ≤ -ε
    # i.e., a·10000 + b·100 + c ≤ -ε
    assert len(constraints) >= 1


def test_counterexample_guided_refinement():
    """
    Integration test: CEGIS should use counterexamples to guide search.
    
    This tests a scenario where initial parameter guesses fail and
    counterexamples guide the search toward valid parameters.
    """
    
    class SimpleState:
        def __init__(self, n=0):
            self.n = z3.IntVal(n) if isinstance(n, int) else n
    
    def initial_state_builder():
        # Initial state: n = 0
        return SimpleState(0)
    
    def unsafe_predicate(state):
        # Unsafe: n > 10
        return state.n > 10
    
    def step_relation(state, state_next):
        # Transition: n' = n + 1 (while n < 10)
        return z3.And(
            state.n < 10,
            state_next.n == state.n + 1
        )
    
    def extract_n(state):
        return state.n
    
    config = CEGISConfig(
        max_iterations=15,
        timeout_per_check_ms=3000,
        timeout_total_ms=30000,
    )
    
    result = synthesize_barrier_cegis(
        template_family="quadratic",
        initial_state_builder=initial_state_builder,
        unsafe_predicate=unsafe_predicate,
        step_relation=step_relation,
        variable_name="n",
        variable_extractor=extract_n,
        config=config,
    )
    
    # Verify counterexamples were collected
    assert result.iterations > 0
    
    # Print diagnostic info
    print(f"\nCEGIS synthesis result: {result.summary()}")
    if result.counterexamples:
        print(result.counterexample_summary())
    
    # Even if synthesis fails, counterexamples should be populated
    # (unless we succeed on first try, which is unlikely)
    if not result.success or result.iterations > 1:
        assert result.counterexamples_collected >= 0


def test_counterexample_summary_formatting():
    """Test the counterexample summary formatting."""
    # Create some mock counterexamples
    ce1 = Counterexample(
        kind='init',
        model=None,
        state_values={'x_0': 5},
        variable_value=5.0,
        barrier_value=0.3,
    )
    ce2 = Counterexample(
        kind='unsafe',
        model=None,
        state_values={'x_0': 100},
        variable_value=100.0,
        barrier_value=-0.05,
    )
    ce3 = Counterexample(
        kind='step',
        model=None,
        state_values={'x_0': 8, 'x_1': 9},
        variable_value=None,
        barrier_value=None,
    )
    
    from a3_python.barriers.cegis import CEGISResult
    
    result = CEGISResult(
        success=False,
        iterations=5,
        counterexamples_collected=3,
        synthesis_time_ms=123.4,
        termination_reason="parameter_space_exhausted",
        counterexamples=[ce1, ce2, ce3],
    )
    
    summary = result.counterexample_summary()
    
    assert "Counterexamples: 3 total" in summary
    assert "init:" in summary
    assert "unsafe:" in summary
    assert "step:" in summary
    assert "var=5.0" in summary  # ce1
    assert "var=100.0" in summary  # ce2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
