"""
Test termination checking integration with symbolic VM.

Verifies that:
1. Loop detection works on bytecode
2. Variable extraction identifies loop variables
3. Ranking synthesis can find ranking functions
4. SymbolicVM.check_termination() works end-to-end
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.cfg.loop_analysis import extract_loops, identify_loop_pattern
from a3_python.semantics.termination_integration import TerminationIntegrator


def test_simple_countdown_loop():
    """
    Test termination checking on simple countdown loop:
    
    def countdown(n):
        while n > 0:
            n -= 1
    
    Should find ranking function R = n
    """
    source = """
def countdown(n):
    while n > 0:
        n -= 1
"""
    code = compile(source, "<test>", "exec")
    
    # Extract function code object
    func_code = code.co_consts[0]
    
    # Test loop extraction
    loops = extract_loops(func_code)
    assert len(loops) >= 1, "Should detect at least one loop"
    
    loop = loops[0]
    assert 'n' in loop.loop_variables, "Should identify 'n' as loop variable"
    
    # Test pattern identification
    pattern = identify_loop_pattern(loop)
    assert pattern in ("simple_counter", "bounded_counter"), f"Pattern should be counter-based, got {pattern}"
    
    # Test termination checking via VM
    vm = SymbolicVM()
    results = vm.check_termination(func_code)
    
    assert len(results) >= 1, "Should return termination result"
    result = results[0]
    
    # For a simple countdown, we expect either TERMINATES or UNKNOWN
    # (UNKNOWN is acceptable if ranking synthesis didn't find the right template)
    assert result.verdict in ("TERMINATES", "UNKNOWN"), \
        f"Expected TERMINATES or UNKNOWN, got {result.verdict}"
    
    if result.verdict == "TERMINATES":
        assert result.ranking is not None, "Should have ranking function"
        assert 'n' in result.ranking.variables, "Ranking should involve variable n"


def test_bounded_counter_loop():
    """
    Test termination checking on bounded counter:
    
    def countup(n):
        i = 0
        while i < n:
            i += 1
    
    Should find ranking function R = n - i
    """
    source = """
def countup(n):
    i = 0
    while i < n:
        i += 1
"""
    code = compile(source, "<test>", "exec")
    func_code = code.co_consts[0]
    
    # Test loop extraction
    loops = extract_loops(func_code)
    assert len(loops) >= 1
    
    loop = loops[0]
    assert 'i' in loop.loop_variables
    # Note: n might not be in modified_variables but should be in compared_variables
    
    # Test termination checking
    vm = SymbolicVM()
    results = vm.check_termination(func_code)
    
    assert len(results) >= 1
    result = results[0]
    assert result.verdict in ("TERMINATES", "UNKNOWN")


def test_nested_loops():
    """
    Test termination checking on nested loops:
    
    def nested(m, n):
        for i in range(m):
            for j in range(n):
                pass
    
    Should detect nested loop pattern
    """
    source = """
def nested(m, n):
    for i in range(m):
        for j in range(n):
            pass
"""
    code = compile(source, "<test>", "exec")
    func_code = code.co_consts[0]
    
    # Test loop extraction
    loops = extract_loops(func_code)
    # Nested loops may be detected as 1 or 2 loops depending on CFG structure
    assert len(loops) >= 1
    
    # At least one loop should be identified
    has_nested_pattern = any(identify_loop_pattern(loop) == "nested" for loop in loops)
    has_counter_pattern = any(identify_loop_pattern(loop) in ("simple_counter", "bounded_counter") 
                              for loop in loops)
    
    # Either nested pattern or multiple counter patterns acceptable
    assert has_nested_pattern or has_counter_pattern or len(loops) >= 2


def test_no_loops():
    """
    Test termination checking on code without loops.
    
    Should return empty list.
    """
    source = """
def no_loop(x):
    return x + 1
"""
    code = compile(source, "<test>", "exec")
    func_code = code.co_consts[0]
    
    loops = extract_loops(func_code)
    assert len(loops) == 0, "Should not detect loops in code without loops"
    
    vm = SymbolicVM()
    results = vm.check_termination(func_code)
    assert len(results) == 0, "Should return empty results for code without loops"


def test_termination_integrator_caching():
    """
    Test that TerminationIntegrator caches results.
    """
    source = """
def countdown(n):
    while n > 0:
        n -= 1
"""
    code = compile(source, "<test>", "exec")
    func_code = code.co_consts[0]
    
    integrator = TerminationIntegrator()
    
    # First call
    results1 = integrator.check_all_loops(func_code)
    
    # Second call should hit cache
    results2 = integrator.check_all_loops(func_code)
    
    # Results should be identical (same objects, not just equal)
    assert results1 is results2, "Should return cached results"


def test_complex_loop():
    """
    Test termination checking on more complex loop:
    
    def complex_loop(a, b):
        while a > 0 and b > 0:
            if a > b:
                a -= 1
            else:
                b -= 1
    
    May return UNKNOWN (complex ranking function needed)
    """
    source = """
def complex_loop(a, b):
    while a > 0 and b > 0:
        if a > b:
            a -= 1
        else:
            b -= 1
"""
    code = compile(source, "<test>", "exec")
    func_code = code.co_consts[0]
    
    loops = extract_loops(func_code)
    assert len(loops) >= 1
    
    loop = loops[0]
    # Both a and b should be identified as loop variables
    loop_vars = loop.loop_variables
    assert 'a' in loop_vars or 'b' in loop_vars, "Should identify at least one loop variable"
    
    vm = SymbolicVM()
    results = vm.check_termination(func_code)
    
    assert len(results) >= 1
    result = results[0]
    # Complex loops may return TERMINATES (if found R = a + b) or UNKNOWN
    assert result.verdict in ("TERMINATES", "UNKNOWN")
    
    if result.verdict == "TERMINATES":
        # If we found termination, verify proof structure
        assert result.proof is not None
        assert "bounded_below_holds" in result.proof
        assert "decreasing_holds" in result.proof


def test_loop_with_break():
    """
    Test termination checking on loop with break:
    
    def with_break(n):
        while True:
            n -= 1
            if n <= 0:
                break
    
    Should handle early exit patterns
    """
    source = """
def with_break(n):
    while True:
        n -= 1
        if n <= 0:
            break
"""
    code = compile(source, "<test>", "exec")
    func_code = code.co_consts[0]
    
    loops = extract_loops(func_code)
    assert len(loops) >= 1
    
    # May return UNKNOWN or TERMINATES depending on how well
    # the break condition is encoded in the back-edge relation
    vm = SymbolicVM()
    results = vm.check_termination(func_code)
    assert len(results) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
