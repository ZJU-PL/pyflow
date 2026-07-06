"""
Tests for path constraint extraction and solving.

Validates that we can:
1. Extract Z3 constraints from symbolic paths
2. Solve constraints to generate concrete inputs
3. Map Z3 models back to Python values
"""

import pytest
import z3

from a3_python.dse.constraint_solver import (
    ConstraintExtractor, ConstraintSolver, PathConstraints,
    extract_and_solve_path, validate_path_with_input
)
from a3_python.semantics.symbolic_vm import (
    SymbolicVM, SymbolicMachineState, SymbolicPath, SymbolicFrame
)
from a3_python.z3model.values import SymbolicValue, ValueTag
from a3_python.dse.concolic import ConcreteInput, ConcreteExecutor
import types


def make_simple_code(source: str, name: str = "<test>") -> types.CodeType:
    """Compile Python source to code object."""
    return compile(source, name, "exec")


class TestConstraintExtractor:
    """Test extraction of constraints from symbolic paths."""
    
    def test_extract_trivial_path(self):
        """Test extracting constraints from a path with no conditions."""
        vm = SymbolicVM()
        code = make_simple_code("x = 1")
        path = vm.load_code(code)
        
        extractor = ConstraintExtractor()
        constraints = extractor.extract_from_path(path)
        
        assert constraints is not None
        assert constraints.path_condition is not None
        # Trivial path should have True as path condition
        assert z3.simplify(constraints.path_condition) == True
    
    def test_extract_symbolic_inputs_from_locals(self):
        """Test extracting symbolic input variables from locals."""
        vm = SymbolicVM()
        code = make_simple_code("x = 1")
        path = vm.load_code(code)
        
        # Add a symbolic local variable
        sym_int = z3.Int('input_x')
        sym_value = SymbolicValue(ValueTag.INT, sym_int)
        path.state.frame_stack[0].locals['x'] = sym_value
        
        extractor = ConstraintExtractor()
        constraints = extractor.extract_from_path(path)
        
        assert 'local_x' in constraints.symbolic_inputs
        assert constraints.symbolic_inputs['local_x'].tag == ValueTag.INT
    
    def test_extract_path_with_condition(self):
        """Test extracting constraints from a path with branch condition."""
        vm = SymbolicVM()
        code = make_simple_code("""
if x > 0:
    y = 1
else:
    y = 2
""")
        path = vm.load_code(code)
        
        # Manually add a path condition (simulating a branch taken)
        x_sym = z3.Int('x')
        path.state.path_condition = z3.And(path.state.path_condition, x_sym > 0)
        
        extractor = ConstraintExtractor()
        constraints = extractor.extract_from_path(path)
        
        # The path condition should include x > 0
        assert constraints.path_condition is not None
        # Simplify and check that it's not trivially true
        simplified = z3.simplify(constraints.path_condition)
        # Check it's not the constant True
        assert not z3.is_true(simplified)


class TestConstraintSolver:
    """Test solving constraints to generate concrete inputs."""
    
    def test_solve_trivial_constraint(self):
        """Test solving a trivially satisfiable constraint."""
        # Create a simple constraint: x > 0
        x = z3.Int('x')
        solver = z3.Solver()
        solver.add(x > 0)
        
        sym_value = SymbolicValue(ValueTag.INT, x)
        constraints = PathConstraints(
            path_condition=x > 0,
            symbolic_inputs={'local_x': sym_value},
            z3_solver=solver
        )
        
        cs = ConstraintSolver()
        result = cs.solve(constraints)
        
        assert result is not None
        assert len(result.args) == 1
        assert result.args[0] > 0
    
    def test_solve_unsatisfiable_constraint(self):
        """Test that unsatisfiable constraints return None."""
        # Create an unsatisfiable constraint: x > 0 AND x < 0
        x = z3.Int('x')
        solver = z3.Solver()
        solver.add(z3.And(x > 0, x < 0))
        
        sym_value = SymbolicValue(ValueTag.INT, x)
        constraints = PathConstraints(
            path_condition=z3.And(x > 0, x < 0),
            symbolic_inputs={'local_x': sym_value},
            z3_solver=solver
        )
        
        cs = ConstraintSolver()
        result = cs.solve(constraints)
        
        assert result is None
    
    def test_solve_multiple_variables(self):
        """Test solving constraints with multiple variables."""
        # Constraint: x + y == 10 AND x > y
        x = z3.Int('x')
        y = z3.Int('y')
        solver = z3.Solver()
        solver.add(x + y == 10)
        solver.add(x > y)
        
        constraints = PathConstraints(
            path_condition=z3.And(x + y == 10, x > y),
            symbolic_inputs={
                'local_x': SymbolicValue(ValueTag.INT, x),
                'local_y': SymbolicValue(ValueTag.INT, y)
            },
            z3_solver=solver
        )
        
        cs = ConstraintSolver()
        result = cs.solve(constraints)
        
        assert result is not None
        assert len(result.args) >= 2
        # Verify the solution satisfies the constraints
        assert result.args[0] + result.args[1] == 10
        assert result.args[0] > result.args[1]
    
    def test_solve_boolean_constraint(self):
        """Test solving constraints with boolean variables."""
        b = z3.Bool('flag')
        solver = z3.Solver()
        solver.add(b == True)
        
        sym_value = SymbolicValue(ValueTag.BOOL, b)
        constraints = PathConstraints(
            path_condition=b == True,
            symbolic_inputs={'local_flag': sym_value},
            z3_solver=solver
        )
        
        cs = ConstraintSolver()
        result = cs.solve(constraints)
        
        assert result is not None
        assert len(result.args) == 1
        assert result.args[0] == True


class TestEndToEndIntegration:
    """End-to-end tests combining symbolic execution, constraint extraction, and solving."""
    
    def test_simple_conditional_path(self):
        """Test extracting and solving constraints from a simple conditional."""
        # Simple code: if x > 5 then divide by x
        code = make_simple_code("""
x = 10
if x > 5:
    y = 100 // x
""")
        
        vm = SymbolicVM()
        path = vm.load_code(code)
        
        # Add symbolic input
        x_sym = z3.Int('x')
        path.state.frame_stack[0].locals['x'] = SymbolicValue(ValueTag.INT, x_sym)
        # Simulate taking the true branch
        path.state.path_condition = z3.And(path.state.path_condition, x_sym > 5)
        
        # Extract and solve
        concrete_input = extract_and_solve_path(path)
        
        assert concrete_input is not None
        assert len(concrete_input.args) >= 1
        # The generated x should be > 5
        assert concrete_input.args[0] > 5
    
    def test_div_zero_avoidance_constraint(self):
        """Test that constraints prevent division by zero."""
        code = make_simple_code("""
result = 100 // x
""")
        
        vm = SymbolicVM()
        path = vm.load_code(code)
        
        # Add symbolic input
        x_sym = z3.Int('x')
        path.state.frame_stack[0].locals['x'] = SymbolicValue(ValueTag.INT, x_sym)
        # Add constraint that x != 0 (to avoid division by zero)
        path.state.path_condition = z3.And(path.state.path_condition, x_sym != 0)
        
        # Extract and solve
        concrete_input = extract_and_solve_path(path)
        
        assert concrete_input is not None
        assert len(concrete_input.args) >= 1
        assert concrete_input.args[0] != 0
    
    def test_bounds_check_constraint(self):
        """Test constraints for array bounds checking."""
        code = make_simple_code("""
arr = [1, 2, 3, 4, 5]
val = arr[i]
""")
        
        vm = SymbolicVM()
        path = vm.load_code(code)
        
        # Add symbolic index
        i_sym = z3.Int('i')
        path.state.frame_stack[0].locals['i'] = SymbolicValue(ValueTag.INT, i_sym)
        # Add bounds constraint: 0 <= i < 5
        path.state.path_condition = z3.And(
            path.state.path_condition,
            i_sym >= 0,
            i_sym < 5
        )
        
        # Extract and solve
        concrete_input = extract_and_solve_path(path)
        
        assert concrete_input is not None
        assert len(concrete_input.args) >= 1
        assert 0 <= concrete_input.args[0] < 5


class TestModelExtraction:
    """Test extracting concrete values from Z3 models."""
    
    def test_extract_integer_from_model(self):
        """Test extracting integer value from Z3 model."""
        x = z3.Int('x')
        solver = z3.Solver()
        solver.add(x == 42)
        
        assert solver.check() == z3.sat
        model = solver.model()
        
        cs = ConstraintSolver()
        sym_value = SymbolicValue(ValueTag.INT, x)
        value = cs._extract_value_from_model(model, sym_value)
        
        assert value == 42
    
    def test_extract_boolean_from_model(self):
        """Test extracting boolean value from Z3 model."""
        b = z3.Bool('b')
        solver = z3.Solver()
        solver.add(b == True)
        
        assert solver.check() == z3.sat
        model = solver.model()
        
        cs = ConstraintSolver()
        sym_value = SymbolicValue(ValueTag.BOOL, b)
        value = cs._extract_value_from_model(model, sym_value)
        
        assert value == True
    
    def test_extract_concrete_value_unchanged(self):
        """Test that concrete values are extracted unchanged."""
        cs = ConstraintSolver()
        
        # Concrete integer
        concrete_int = SymbolicValue(ValueTag.INT, 123)
        assert cs._extract_value_from_model(None, concrete_int) == 123
        
        # Concrete boolean
        concrete_bool = SymbolicValue(ValueTag.BOOL, False)
        assert cs._extract_value_from_model(None, concrete_bool) == False
        
        # None
        concrete_none = SymbolicValue(ValueTag.NONE, None)
        assert cs._extract_value_from_model(None, concrete_none) is None


class TestPathValidation:
    """Test validating concrete inputs against path constraints."""
    
    def test_validate_satisfying_input(self):
        """Test that valid inputs pass validation."""
        vm = SymbolicVM()
        code = make_simple_code("x = 1")
        path = vm.load_code(code)
        
        # Add a constraint: x > 0
        x_sym = z3.Int('x')
        path.state.path_condition = x_sym > 0
        
        # This input satisfies x > 0
        concrete_input = ConcreteInput(args=[5], globals_dict={}, env={}, stdin="")
        
        # Validation should succeed (path is satisfiable)
        result = validate_path_with_input(path, concrete_input)
        assert result == True
    
    def test_validate_unsatisfiable_path(self):
        """Test that unsatisfiable paths fail validation."""
        vm = SymbolicVM()
        code = make_simple_code("x = 1")
        path = vm.load_code(code)
        
        # Add an unsatisfiable constraint
        x_sym = z3.Int('x')
        path.state.path_condition = z3.And(x_sym > 10, x_sym < 5)
        
        # Any input should fail validation (path is unsatisfiable)
        concrete_input = ConcreteInput(args=[7], globals_dict={}, env={}, stdin="")
        
        result = validate_path_with_input(path, concrete_input)
        assert result == False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
