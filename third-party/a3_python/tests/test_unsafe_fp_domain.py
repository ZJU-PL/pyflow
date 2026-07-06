"""
Tests for FP_DOMAIN unsafe region.

Testing the semantic predicate for floating-point domain errors (math domain errors).
Both BUG (reachable domain error) and NON-BUG (provably no domain error) cases.

NOTE: Current implementation marks these as SKIP because full math.sqrt/log/asin
semantic handling requires import and module namespace tracking, which is not yet
implemented. These tests document the intended behavior for FP_DOMAIN.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


# ============================================================================
# BUG cases: Math domain error is reachable
# ============================================================================

def test_fpdomain_bug_sqrt_negative():
    """BUG: math.sqrt with negative argument."""
    code = compile("import math\nx = -1.0\nresult = math.sqrt(x)", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # Should find at least one path with FP_DOMAIN error
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'FP_DOMAIN']
    
    assert len(bugs) > 0, "Should detect FP_DOMAIN for sqrt(-1.0)"
    assert bugs[0]['bug_type'] == 'FP_DOMAIN'


# Skip removed - import handling implemented
def test_fpdomain_bug_log_negative():
    """BUG: math.log with negative argument."""
    code = compile("import math\nx = -5.0\nresult = math.log(x)", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'FP_DOMAIN']
    
    assert len(bugs) > 0, "Should detect FP_DOMAIN for log(-5.0)"


# Skip removed - import handling implemented
def test_fpdomain_bug_log_zero():
    """BUG: math.log with zero argument."""
    code = compile("import math\nx = 0.0\nresult = math.log(x)", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'FP_DOMAIN']
    
    assert len(bugs) > 0, "Should detect FP_DOMAIN for log(0.0)"


# Skip removed - import handling implemented
def test_fpdomain_bug_asin_out_of_range():
    """BUG: math.asin with argument > 1."""
    code = compile("import math\nx = 2.0\nresult = math.asin(x)", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'FP_DOMAIN']
    
    assert len(bugs) > 0, "Should detect FP_DOMAIN for asin(2.0)"


# Skip removed - import handling implemented
def test_fpdomain_bug_acos_out_of_range():
    """BUG: math.acos with argument < -1."""
    code = compile("import math\nx = -1.5\nresult = math.acos(x)", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'FP_DOMAIN']
    
    assert len(bugs) > 0, "Should detect FP_DOMAIN for acos(-1.5)"


# ============================================================================
# NON-BUG cases: No domain error reachable
# ============================================================================

# Skip removed - import handling implemented
def test_fpdomain_safe_sqrt_positive():
    """NON-BUG: math.sqrt with positive argument is valid."""
    code = compile("import math\nx = 4.0\nresult = math.sqrt(x)", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # Should complete without FP_DOMAIN error
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'FP_DOMAIN']
    
    assert len(bugs) == 0, "Should not detect FP_DOMAIN for sqrt(4.0)"


# Skip removed - import handling implemented
def test_fpdomain_safe_sqrt_zero():
    """NON-BUG: math.sqrt(0.0) is valid (edge case)."""
    code = compile("import math\nx = 0.0\nresult = math.sqrt(x)", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'FP_DOMAIN']
    
    assert len(bugs) == 0, "Should not detect FP_DOMAIN for sqrt(0.0)"


# Skip removed - import handling implemented
def test_fpdomain_safe_log_positive():
    """NON-BUG: math.log with positive argument is valid."""
    code = compile("import math\nx = 2.718\nresult = math.log(x)", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'FP_DOMAIN']
    
    assert len(bugs) == 0, "Should not detect FP_DOMAIN for log(2.718)"


# Skip removed - import handling implemented
def test_fpdomain_safe_asin_valid():
    """NON-BUG: math.asin with valid argument in [-1, 1]."""
    code = compile("import math\nx = 0.5\nresult = math.asin(x)", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'FP_DOMAIN']
    
    assert len(bugs) == 0, "Should not detect FP_DOMAIN for asin(0.5)"


# Skip removed - import handling implemented
def test_fpdomain_safe_guarded():
    """NON-BUG: math.sqrt guarded by condition checking x >= 0."""
    code = compile("""
import math
x = -4.0
if x >= 0:
    result = math.sqrt(x)
else:
    result = 0.0
""", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    # The sqrt call is never reached on the negative path
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'FP_DOMAIN']
    
    assert len(bugs) == 0, "Should not detect FP_DOMAIN when sqrt is guarded"


# ============================================================================
# Smoke tests (no skip): basic registration and predicate structure
# ============================================================================

def test_fpdomain_registered():
    """Smoke test: FP_DOMAIN is registered in unsafe predicates."""
    from a3_python.unsafe.registry import list_implemented_bug_types
    
    bug_types = list_implemented_bug_types()
    assert "FP_DOMAIN" in bug_types, "FP_DOMAIN should be registered"


def test_fpdomain_predicate_callable():
    """Smoke test: FP_DOMAIN predicate is callable."""
    from a3_python.unsafe.fp_domain import is_unsafe_fp_domain
    from a3_python.semantics.symbolic_vm import SymbolicMachineState
    
    # Create minimal state
    state = SymbolicMachineState()
    
    # Should not crash
    result = is_unsafe_fp_domain(state)
    assert result is False, "Empty state should not be FP_DOMAIN unsafe"


def test_fpdomain_extractor_callable():
    """Smoke test: FP_DOMAIN counterexample extractor is callable."""
    from a3_python.unsafe.fp_domain import extract_counterexample
    from a3_python.semantics.symbolic_vm import SymbolicMachineState
    
    state = SymbolicMachineState()
    state.fp_domain_error_reached = True
    state.domain_error_context = "sqrt(-1)"
    
    trace = ["step1", "step2"]
    cex = extract_counterexample(state, trace)
    
    assert cex['bug_type'] == 'FP_DOMAIN'
    assert cex['trace'] == trace
    assert 'final_state' in cex
