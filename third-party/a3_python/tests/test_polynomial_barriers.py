"""
Tests for polynomial and advanced barrier templates.

Validates:
1. Quadratic barriers (single variable)
2. Bivariate quadratic barriers
3. General polynomial barriers
4. Piecewise linear barriers
5. Enhanced disjunctive and conjunctive barriers
"""

import pytest
import z3

from a3_python.barriers.templates import (
    quadratic_barrier,
    polynomial_barrier,
    bivariate_quadratic_barrier,
    piecewise_linear_barrier,
    disjunctive_region_barrier,
    conjunctive_region_barrier,
    variable_upper_bound_barrier,
    variable_lower_bound_barrier,
)
from a3_python.semantics.symbolic_vm import SymbolicMachineState
from a3_python.z3model.values import SymbolicValue


def make_test_state(var_values: dict[str, int]) -> SymbolicMachineState:
    """Create a test state with given variable values."""
    from a3_python.semantics.symbolic_vm import SymbolicFrame
    import types
    
    # Create a dummy code object
    code = (lambda: None).__code__
    
    # Create frame with locals
    frame = SymbolicFrame(code=code)
    for name, val in var_values.items():
        frame.locals[name] = SymbolicValue.int(val)
    
    return SymbolicMachineState(
        frame_stack=[frame],
        heap={},
        path_condition=z3.BoolVal(True)
    )


def extract_var(var_name: str):
    """Create a variable extractor for testing."""
    def extractor(state: SymbolicMachineState):
        if not state.frame_stack:
            return z3.IntVal(0)
        frame = state.current_frame
        if var_name in frame.locals:
            return frame.locals[var_name].payload
        return z3.IntVal(0)
    return extractor


class TestQuadraticBarriers:
    """Test quadratic barrier templates."""
    
    def test_downward_parabola(self):
        """Test B(x) = 100 - x² proves |x| ≤ 10."""
        barrier = quadratic_barrier(
            "x", extract_var("x"),
            coeff_x2=-1.0, coeff_x=0.0, constant=100.0
        )
        
        # At x=0: B = 100 (safe)
        state = make_test_state({"x": 0})
        solver = z3.Solver()
        result = barrier.evaluate(state)
        solver.add(result >= 0)
        assert solver.check() == z3.sat
        
        # At x=10: B = 100 - 100 = 0 (boundary)
        state = make_test_state({"x": 10})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 0)
        assert solver.check() == z3.sat
        
        # At x=11: B = 100 - 121 = -21 (unsafe)
        state = make_test_state({"x": 11})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result < 0)
        assert solver.check() == z3.sat
    
    def test_shifted_parabola(self):
        """Test B(x) = -(x-5)² + 25 = -x² + 10x."""
        barrier = quadratic_barrier(
            "x", extract_var("x"),
            coeff_x2=-1.0, coeff_x=10.0, constant=0.0
        )
        
        # At x=5: B = -25 + 50 = 25 (maximum, safe)
        state = make_test_state({"x": 5})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 25)
        assert solver.check() == z3.sat
        
        # At x=0: B = 0 (boundary)
        state = make_test_state({"x": 0})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 0)
        assert solver.check() == z3.sat
        
        # At x=10: B = -100 + 100 = 0 (boundary)
        state = make_test_state({"x": 10})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 0)
        assert solver.check() == z3.sat
    
    def test_upward_parabola_with_negative_linear(self):
        """Test B(x) = x² - 10x + 20."""
        barrier = quadratic_barrier(
            "n", extract_var("n"),
            coeff_x2=1.0, coeff_x=-10.0, constant=20.0
        )
        
        # At n=5: B = 25 - 50 + 20 = -5 (unsafe, inside parabola)
        state = make_test_state({"n": 5})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == -5)
        assert solver.check() == z3.sat
        
        # At n=2: B = 4 - 20 + 20 = 4 (safe)
        state = make_test_state({"n": 2})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 4)
        assert solver.check() == z3.sat


class TestPolynomialBarriers:
    """Test general polynomial barrier templates."""
    
    def test_cubic_polynomial(self):
        """Test B(x) = 10 - 5x + 0.01x³."""
        barrier = polynomial_barrier(
            "x", extract_var("x"),
            coefficients=[10.0, -5.0, 0.0, 0.01]
        )
        
        # At x=0: B = 10 (safe)
        state = make_test_state({"x": 0})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 10)
        assert solver.check() == z3.sat
        
        # At x=10: B = 10 - 50 + 10 = -30 (unsafe)
        state = make_test_state({"x": 10})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == -30)
        assert solver.check() == z3.sat
    
    def test_quartic_polynomial(self):
        """Test B(x) = 100 - x² - 0.01x⁴."""
        barrier = polynomial_barrier(
            "x", extract_var("x"),
            coefficients=[100.0, 0.0, -1.0, 0.0, -0.01]
        )
        
        # At x=0: B = 100 (safe)
        state = make_test_state({"x": 0})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 100)
        assert solver.check() == z3.sat
        
        # At x=5: B = 100 - 25 - 6.25 = 68.75 (safe)
        state = make_test_state({"x": 5})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result > 68)
        solver.add(result < 69)
        assert solver.check() == z3.sat
    
    def test_linear_as_polynomial(self):
        """Test that linear case works: B(x) = 20 - 2x."""
        barrier = polynomial_barrier(
            "x", extract_var("x"),
            coefficients=[20.0, -2.0]
        )
        
        # At x=0: B = 20
        state = make_test_state({"x": 0})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 20)
        assert solver.check() == z3.sat
        
        # At x=10: B = 20 - 20 = 0 (boundary)
        state = make_test_state({"x": 10})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 0)
        assert solver.check() == z3.sat


class TestBivariateQuadraticBarriers:
    """Test bivariate quadratic barriers."""
    
    def test_circular_bound(self):
        """Test B(x,y) = 100 - x² - y² (circle of radius 10)."""
        barrier = bivariate_quadratic_barrier(
            "x", "y", extract_var("x"), extract_var("y"),
            coeff_x2=-1.0, coeff_y2=-1.0, coeff_xy=0.0,
            coeff_x=0.0, coeff_y=0.0, constant=100.0
        )
        
        # At origin: B = 100 (safe)
        state = make_test_state({"x": 0, "y": 0})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 100)
        assert solver.check() == z3.sat
        
        # At (6, 8): B = 100 - 36 - 64 = 0 (on circle boundary)
        state = make_test_state({"x": 6, "y": 8})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 0)
        assert solver.check() == z3.sat
        
        # At (10, 0): B = 100 - 100 = 0 (on circle boundary)
        state = make_test_state({"x": 10, "y": 0})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 0)
        assert solver.check() == z3.sat
        
        # At (7, 8): B = 100 - 49 - 64 = -13 (outside circle, unsafe)
        state = make_test_state({"x": 7, "y": 8})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result < 0)
        assert solver.check() == z3.sat
    
    def test_elliptical_bound(self):
        """Test ellipse with different x and y coefficients."""
        barrier = bivariate_quadratic_barrier(
            "x", "y", extract_var("x"), extract_var("y"),
            coeff_x2=-1.0, coeff_y2=-4.0, coeff_xy=0.0,
            coeff_x=0.0, coeff_y=0.0, constant=100.0
        )
        
        # At (10, 0): B = 100 - 100 = 0 (on boundary)
        state = make_test_state({"x": 10, "y": 0})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 0)
        assert solver.check() == z3.sat
        
        # At (0, 5): B = 100 - 100 = 0 (on boundary)
        state = make_test_state({"x": 0, "y": 5})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 0)
        assert solver.check() == z3.sat
    
    def test_hyperbolic_bound(self):
        """Test B(x,y) = x² - y² + C (hyperbola)."""
        barrier = bivariate_quadratic_barrier(
            "x", "y", extract_var("x"), extract_var("y"),
            coeff_x2=1.0, coeff_y2=-1.0, coeff_xy=0.0,
            coeff_x=0.0, coeff_y=0.0, constant=50.0
        )
        
        # At (10, 5): B = 100 - 25 + 50 = 125 (safe)
        state = make_test_state({"x": 10, "y": 5})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 125)
        assert solver.check() == z3.sat


class TestPiecewiseLinearBarriers:
    """Test piecewise linear barriers."""
    
    def test_three_phase_barrier(self):
        """Test piecewise barrier with 3 phases."""
        breakpoints = [
            (10.0, -1.0, 20.0),   # x < 10: B = 20 - x
            (100.0, -0.1, 11.0),  # 10 ≤ x < 100: B = 11 - 0.1x
            (1000.0, -0.01, 10.0) # x ≥ 100: B = 10 - 0.01x
        ]
        barrier = piecewise_linear_barrier("x", extract_var("x"), breakpoints)
        
        # Phase 1: x=5 → B = 20 - 5 = 15
        state = make_test_state({"x": 5})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 15)
        assert solver.check() == z3.sat
        
        # Phase 2: x=50 → B = 11 - 5 = 6
        state = make_test_state({"x": 50})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 6)
        assert solver.check() == z3.sat
        
        # Phase 3: x=500 → B = 10 - 5 = 5
        state = make_test_state({"x": 500})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 5)
        assert solver.check() == z3.sat


class TestDisjunctiveBarriers:
    """Test enhanced disjunctive region barriers."""
    
    def test_disjunction_of_two_bounds(self):
        """Test B(σ) = max(100-x, 50-y)."""
        b1 = variable_upper_bound_barrier("x", 100.0, extract_var("x"))
        b2 = variable_upper_bound_barrier("y", 50.0, extract_var("y"))
        
        barrier = disjunctive_region_barrier([b1, b2])
        
        # When x=90, y=40: max(10, 10) = 10 (both hold)
        state = make_test_state({"x": 90, "y": 40})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 10)
        assert solver.check() == z3.sat
        
        # When x=95, y=45: max(5, 5) = 5
        state = make_test_state({"x": 95, "y": 45})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 5)
        assert solver.check() == z3.sat
        
        # When x=105, y=45: max(-5, 5) = 5 (b2 saves us)
        state = make_test_state({"x": 105, "y": 45})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 5)
        assert solver.check() == z3.sat
        
        # When x=105, y=55: max(-5, -5) = -5 (both fail)
        state = make_test_state({"x": 105, "y": 55})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == -5)
        assert solver.check() == z3.sat
    
    def test_disjunction_of_three_barriers(self):
        """Test N-way disjunction."""
        b1 = variable_upper_bound_barrier("x", 100.0, extract_var("x"))
        b2 = variable_upper_bound_barrier("y", 50.0, extract_var("y"))
        b3 = variable_upper_bound_barrier("z", 25.0, extract_var("z"))
        
        barrier = disjunctive_region_barrier([b1, b2, b3])
        
        # When all variables at half their bounds: all positive
        state = make_test_state({"x": 50, "y": 25, "z": 12})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result >= 13)  # max(50, 25, 13) = 50
        assert solver.check() == z3.sat
        
        # When x,y exceed but z is OK: z saves us
        state = make_test_state({"x": 105, "y": 55, "z": 20})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 5)  # max(-5, -5, 5) = 5
        assert solver.check() == z3.sat


class TestConjunctiveBarriers:
    """Test enhanced conjunctive region barriers."""
    
    def test_conjunction_of_two_bounds(self):
        """Test B(σ) = min(100-x, 50-y)."""
        b1 = variable_upper_bound_barrier("x", 100.0, extract_var("x"))
        b2 = variable_upper_bound_barrier("y", 50.0, extract_var("y"))
        
        barrier = conjunctive_region_barrier([b1, b2])
        
        # When x=90, y=40: min(10, 10) = 10 (both hold)
        state = make_test_state({"x": 90, "y": 40})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 10)
        assert solver.check() == z3.sat
        
        # When x=95, y=45: min(5, 5) = 5
        state = make_test_state({"x": 95, "y": 45})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 5)
        assert solver.check() == z3.sat
        
        # When x=95, y=48: min(5, 2) = 2 (y is the limiting factor)
        state = make_test_state({"x": 95, "y": 48})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 2)
        assert solver.check() == z3.sat
        
        # When x=105, y=45: min(-5, 5) = -5 (x violates, conjunction fails)
        state = make_test_state({"x": 105, "y": 45})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == -5)
        assert solver.check() == z3.sat
    
    def test_conjunction_of_three_barriers(self):
        """Test N-way conjunction."""
        b1 = variable_upper_bound_barrier("x", 100.0, extract_var("x"))
        b2 = variable_upper_bound_barrier("y", 50.0, extract_var("y"))
        b3 = variable_upper_bound_barrier("z", 25.0, extract_var("z"))
        
        barrier = conjunctive_region_barrier([b1, b2, b3])
        
        # When all OK: min of all
        state = make_test_state({"x": 50, "y": 25, "z": 12})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 13)  # min(50, 25, 13) = 13
        assert solver.check() == z3.sat
        
        # When one violates: that one determines result
        state = make_test_state({"x": 50, "y": 25, "z": 30})
        result = barrier.evaluate(state)
        solver = z3.Solver()
        solver.add(result == -5)  # min(50, 25, -5) = -5
        assert solver.check() == z3.sat


class TestBarrierCombinations:
    """Test combinations of different barrier types."""
    
    def test_disjunction_of_quadratic_and_linear(self):
        """Test combining quadratic and linear barriers."""
        quad = quadratic_barrier(
            "x", extract_var("x"),
            coeff_x2=-1.0, coeff_x=0.0, constant=100.0
        )
        linear = variable_upper_bound_barrier("y", 50.0, extract_var("y"))
        
        combined = disjunctive_region_barrier([quad, linear])
        
        # When both hold
        state = make_test_state({"x": 5, "y": 25})
        result = combined.evaluate(state)
        solver = z3.Solver()
        solver.add(result > 0)
        assert solver.check() == z3.sat
    
    def test_conjunction_of_quadratic_barriers(self):
        """Test conjunction of two quadratic barriers."""
        q1 = quadratic_barrier(
            "x", extract_var("x"),
            coeff_x2=-1.0, coeff_x=0.0, constant=100.0
        )
        q2 = quadratic_barrier(
            "y", extract_var("y"),
            coeff_x2=-1.0, coeff_x=0.0, constant=100.0
        )
        
        combined = conjunctive_region_barrier([q1, q2])
        
        # Both safe: x=5, y=5 → B1=75, B2=75 → min=75
        state = make_test_state({"x": 5, "y": 5})
        result = combined.evaluate(state)
        solver = z3.Solver()
        solver.add(result == 75)
        assert solver.check() == z3.sat


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
