"""
Tests for stdlib module relational summaries (math, os, sys, etc.).

Verifies that relational summaries correctly model stdlib module behaviors:
- Valid domain → correct return types and constraints
- Invalid domain → FP_DOMAIN detection (ValueError)
- Type errors → TYPE_CONFUSION detection (TypeError)
"""

import pytest
from a3_python.contracts.relations import get_relational_summary, has_relational_summary
from a3_python.contracts.stdlib_module_relations import init_stdlib_module_relations
from a3_python.z3model.values import SymbolicValue, ValueTag
import z3


class TestMathSqrtRelationalSummary:
    """Tests for math.sqrt relational summary."""
    
    def test_sqrt_summary_registered(self):
        """Verify math.sqrt relational summary is registered."""
        assert has_relational_summary("math.sqrt")
        summary = get_relational_summary("math.sqrt")
        assert summary is not None
        assert summary.function_id == "math.sqrt"
        assert len(summary.cases) == 3  # valid domain, invalid domain, type error
    
    def test_sqrt_valid_domain_guard(self):
        """Test sqrt guard for valid domain (x >= 0)."""
        summary = get_relational_summary("math.sqrt")
        
        # Case 1: x = 4 (valid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(4))]
        guard_result = summary.cases[0].guard(None, args)
        assert z3.is_true(guard_result)
        
        # Case 2: x = 0 (valid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(0))]
        guard_result = summary.cases[0].guard(None, args)
        assert z3.is_true(guard_result)
        
        # Case 3: x = -1 (invalid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(-1))]
        guard_result = summary.cases[0].guard(None, args)
        assert z3.is_false(guard_result)
    
    def test_sqrt_invalid_domain_guard(self):
        """Test sqrt guard for invalid domain (x < 0 → FP_DOMAIN)."""
        summary = get_relational_summary("math.sqrt")
        
        # Case: x = -5 (invalid → ValueError)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(-5))]
        guard_result = summary.cases[1].guard(None, args)
        assert z3.is_true(guard_result)
        
        # Case: x = 10 (valid, not this guard)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(10))]
        guard_result = summary.cases[1].guard(None, args)
        assert z3.is_false(guard_result)
    
    def test_sqrt_type_error_guard(self):
        """Test sqrt guard for type errors (non-numeric → TypeError)."""
        summary = get_relational_summary("math.sqrt")
        
        # Case: x = "hello" (type error)
        args = [SymbolicValue(ValueTag.STR, z3.StringVal("hello"))]
        guard_result = summary.cases[2].guard(None, args)
        assert z3.is_true(guard_result)
        
        # Case: x = [1, 2, 3] (type error)
        args = [SymbolicValue(ValueTag.LIST, z3.Int("list_obj"))]
        guard_result = summary.cases[2].guard(None, args)
        assert z3.is_true(guard_result)
    
    def test_sqrt_valid_postcondition(self):
        """Test sqrt postcondition for valid domain."""
        summary = get_relational_summary("math.sqrt")
        
        # Apply postcondition for x = 9
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(9))]
        post = summary.cases[0].post(None, args, 1)
        
        # Return value should be FLOAT
        assert post.return_value.tag == ValueTag.FLOAT
        
        # Should have constraint: result >= 0 and result^2 == 9
        assert len(post.path_constraints) >= 1
        
        # Check constraint satisfaction
        solver = z3.Solver()
        for constraint in post.path_constraints:
            solver.add(constraint)
        
        # Should be satisfiable
        assert solver.check() == z3.sat
        
        # Get model and verify result
        model = solver.model()
        result = model.eval(post.return_value.payload)
        # sqrt(9) = 3.0, so result should be approximately 3.0
        # Z3 should give us exactly 3.0 due to the constraint result^2 == 9
        assert float(result.as_fraction()) == 3.0
    
    def test_sqrt_invalid_postcondition_raises(self):
        """Test sqrt postcondition for invalid domain raises ValueError."""
        summary = get_relational_summary("math.sqrt")
        
        # Apply postcondition for x = -4 (should raise ValueError)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(-4))]
        post = summary.cases[1].post(None, args, 1)
        
        # Return value should be None (exception raised)
        assert post.return_value is None
        
        # Should have exception_raised observer update
        assert 'exception_raised' in post.observer_updates
        exc_type, exc_msg = post.observer_updates['exception_raised']
        assert exc_type == 'ValueError'
        assert 'domain' in exc_msg.lower()


class TestMathLogRelationalSummary:
    """Tests for math.log relational summary."""
    
    def test_log_summary_registered(self):
        """Verify math.log relational summary is registered."""
        assert has_relational_summary("math.log")
        summary = get_relational_summary("math.log")
        assert summary is not None
        assert summary.function_id == "math.log"
        assert len(summary.cases) == 3  # valid, invalid, type error
    
    def test_log_valid_domain_guard(self):
        """Test log guard for valid domain (x > 0)."""
        summary = get_relational_summary("math.log")
        
        # Case: x = 10 (valid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(10))]
        guard_result = summary.cases[0].guard(None, args)
        assert z3.is_true(guard_result)
        
        # Case: x = 0 (invalid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(0))]
        guard_result = summary.cases[0].guard(None, args)
        assert z3.is_false(guard_result)
        
        # Case: x = -5 (invalid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(-5))]
        guard_result = summary.cases[0].guard(None, args)
        assert z3.is_false(guard_result)
    
    def test_log_invalid_domain_guard(self):
        """Test log guard for invalid domain (x <= 0 → FP_DOMAIN)."""
        summary = get_relational_summary("math.log")
        
        # Case: x = 0 (invalid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(0))]
        guard_result = summary.cases[1].guard(None, args)
        assert z3.is_true(guard_result)
        
        # Case: x = -10 (invalid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(-10))]
        guard_result = summary.cases[1].guard(None, args)
        assert z3.is_true(guard_result)
    
    def test_log_invalid_postcondition_raises(self):
        """Test log postcondition for invalid domain raises ValueError."""
        summary = get_relational_summary("math.log")
        
        # Apply postcondition for x = -1 (should raise ValueError)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(-1))]
        post = summary.cases[1].post(None, args, 1)
        
        # Should signal exception
        assert post.return_value is None
        assert 'exception_raised' in post.observer_updates
        exc_type, _ = post.observer_updates['exception_raised']
        assert exc_type == 'ValueError'


class TestMathAsinRelationalSummary:
    """Tests for math.asin relational summary."""
    
    def test_asin_summary_registered(self):
        """Verify math.asin relational summary is registered."""
        assert has_relational_summary("math.asin")
        summary = get_relational_summary("math.asin")
        assert summary is not None
        assert len(summary.cases) == 3
    
    def test_asin_valid_domain_guard(self):
        """Test asin guard for valid domain (-1 <= x <= 1)."""
        summary = get_relational_summary("math.asin")
        
        # Case: x = 0.5 (valid)
        args = [SymbolicValue(ValueTag.FLOAT, z3.RealVal(0.5))]
        guard_result = summary.cases[0].guard(None, args)
        assert z3.is_true(guard_result)
        
        # Case: x = -1 (valid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(-1))]
        guard_result = summary.cases[0].guard(None, args)
        assert z3.is_true(guard_result)
        
        # Case: x = 1 (valid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(1))]
        guard_result = summary.cases[0].guard(None, args)
        assert z3.is_true(guard_result)
        
        # Case: x = 2 (invalid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(2))]
        guard_result = summary.cases[0].guard(None, args)
        assert z3.is_false(guard_result)
    
    def test_asin_invalid_domain_guard(self):
        """Test asin guard for invalid domain (x < -1 or x > 1 → FP_DOMAIN)."""
        summary = get_relational_summary("math.asin")
        
        # Case: x = 2 (invalid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(2))]
        guard_result = summary.cases[1].guard(None, args)
        assert z3.is_true(guard_result)
        
        # Case: x = -2 (invalid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(-2))]
        guard_result = summary.cases[1].guard(None, args)
        assert z3.is_true(guard_result)
    
    def test_asin_valid_postcondition_range(self):
        """Test asin postcondition constrains result to [-π/2, π/2]."""
        summary = get_relational_summary("math.asin")
        
        # Apply postcondition for x = 0
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(0))]
        post = summary.cases[0].post(None, args, 1)
        
        # Return value should be FLOAT
        assert post.return_value.tag == ValueTag.FLOAT
        
        # Should have range constraint [-π/2, π/2]
        solver = z3.Solver()
        for constraint in post.path_constraints:
            solver.add(constraint)
        
        # Should be satisfiable
        assert solver.check() == z3.sat
        
        # Result should be in range [-1.5708, 1.5708]
        model = solver.model()
        result = model.eval(post.return_value.payload)
        result_float = float(result.as_fraction())
        assert -1.5708 <= result_float <= 1.5708


class TestMathAcosRelationalSummary:
    """Tests for math.acos relational summary."""
    
    def test_acos_summary_registered(self):
        """Verify math.acos relational summary is registered."""
        assert has_relational_summary("math.acos")
        summary = get_relational_summary("math.acos")
        assert summary is not None
        assert len(summary.cases) == 3
    
    def test_acos_valid_domain_guard(self):
        """Test acos guard for valid domain (-1 <= x <= 1)."""
        summary = get_relational_summary("math.acos")
        
        # Case: x = 0.5 (valid)
        args = [SymbolicValue(ValueTag.FLOAT, z3.RealVal(0.5))]
        guard_result = summary.cases[0].guard(None, args)
        assert z3.is_true(guard_result)
        
        # Case: x = 3 (invalid)
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(3))]
        guard_result = summary.cases[0].guard(None, args)
        assert z3.is_false(guard_result)
    
    def test_acos_valid_postcondition_range(self):
        """Test acos postcondition constrains result to [0, π]."""
        summary = get_relational_summary("math.acos")
        
        # Apply postcondition for x = 0
        args = [SymbolicValue(ValueTag.INT, z3.IntVal(0))]
        post = summary.cases[0].post(None, args, 1)
        
        # Return value should be FLOAT
        assert post.return_value.tag == ValueTag.FLOAT
        
        # Should have range constraint [0, π]
        solver = z3.Solver()
        for constraint in post.path_constraints:
            solver.add(constraint)
        
        # Should be satisfiable
        assert solver.check() == z3.sat
        
        # Result should be in range [0, 3.1416]
        model = solver.model()
        result = model.eval(post.return_value.payload)
        result_float = float(result.as_fraction())
        assert 0.0 <= result_float <= 3.1416


class TestStdlibModuleRelationsSoundness:
    """Test soundness properties of stdlib module relational summaries."""
    
    def test_all_summaries_have_havoc_fallback(self):
        """Verify all summaries have required havoc fallback."""
        function_ids = ["math.sqrt", "math.log", "math.asin", "math.acos"]
        
        for func_id in function_ids:
            summary = get_relational_summary(func_id)
            assert summary is not None, f"{func_id} not registered"
            
            # Must have havoc fallback
            assert summary.havoc is not None
            assert summary.havoc.applies()
    
    def test_exception_cases_marked_correctly(self):
        """Verify exception cases properly mark may_raise."""
        # math.sqrt domain error case should raise ValueError
        summary = get_relational_summary("math.sqrt")
        domain_error_case = summary.cases[1]  # x < 0 case
        assert "ValueError" in domain_error_case.may_raise
        
        # math.log domain error case should raise ValueError
        summary = get_relational_summary("math.log")
        domain_error_case = summary.cases[1]  # x <= 0 case
        assert "ValueError" in domain_error_case.may_raise
    
    def test_provenance_documented(self):
        """Verify all summaries have documented provenance."""
        function_ids = ["math.sqrt", "math.log", "math.asin", "math.acos"]
        
        for func_id in function_ids:
            summary = get_relational_summary(func_id)
            assert summary.provenance is not None
            assert summary.provenance != ""
            # Should reference Python stdlib docs
            assert "python" in summary.provenance.lower() or "stdlib" in summary.provenance.lower()
