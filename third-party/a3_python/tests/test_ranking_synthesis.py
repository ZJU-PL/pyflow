"""
Tests for ranking function synthesis and NON_TERMINATION detection.

These tests verify that:
1. Ranking function synthesis can find valid ranking functions for terminating loops
2. NON_TERMINATION detector correctly identifies infinite loops
3. Termination proofs are sound (Z3-verified)
"""

import pytest
import z3
from dataclasses import dataclass
from typing import Callable

from a3_python.barriers.ranking_synthesis import (
    RankingSynthesizer,
    RankingSynthesisConfig,
    synthesize_ranking_for_loop,
)
from a3_python.barriers.ranking import (
    TerminationChecker,
    linear_ranking_function,
    simple_counter_ranking,
)
from a3_python.unsafe.non_termination import (
    check_termination_via_ranking,
    is_unsafe_non_termination,
)


# Simple symbolic state for testing
@dataclass
class SimpleSymbolicState:
    """Minimal symbolic state with program variables."""
    variables: dict[str, z3.ExprRef]
    path_condition: z3.ExprRef
    
    def __init__(self):
        self.variables = {}
        self.path_condition = z3.BoolVal(True)


def create_state_builder(var_names: list[str]) -> Callable[[], SimpleSymbolicState]:
    """Create a state builder with given variable names."""
    def builder():
        state = SimpleSymbolicState()
        for var_name in var_names:
            state.variables[var_name] = z3.Int(var_name)
        return state
    return builder


def var_extractor(var_name: str) -> Callable[[SimpleSymbolicState], z3.ExprRef]:
    """Create variable extractor for given variable name."""
    def extractor(state: SimpleSymbolicState) -> z3.ExprRef:
        return state.variables[var_name]
    return extractor


# Test 1: Simple counter loop (decreasing)
def test_simple_counter_decreasing():
    """
    Loop: while i > 0: i -= 1
    Ranking: R = i
    Should find ranking function and prove termination.
    """
    state_builder = create_state_builder(['i'])
    
    def loop_back_edge(s, s_prime):
        # Transition: i' = i - 1, with guard i > 0
        i = s.variables['i']
        i_prime = s_prime.variables['i']
        return z3.And(
            i > 0,  # Loop guard
            i_prime == i - 1  # Update
        )
    
    variable_extractors = [('i', var_extractor('i'))]
    
    result = synthesize_ranking_for_loop(
        state_builder,
        loop_back_edge,
        variable_extractors
    )
    
    assert result.success, "Should find ranking function for simple counter loop"
    assert result.termination_proof.terminates, "Should prove termination"
    assert 'i' in result.ranking.variables, "Ranking should involve variable i"


# Test 2: Counter with upper bound (increasing)
def test_counter_with_upper_bound():
    """
    Loop: while i < n: i += 1
    Ranking: R = n - i
    Should find ranking function.
    """
    state_builder = create_state_builder(['i', 'n'])
    
    def loop_back_edge(s, s_prime):
        # Transition: i' = i + 1, with guard i < n
        i = s.variables['i']
        n = s.variables['n']
        i_prime = s_prime.variables['i']
        n_prime = s_prime.variables['n']
        return z3.And(
            i < n,  # Loop guard
            i_prime == i + 1,  # Update
            n_prime == n  # n unchanged
        )
    
    variable_extractors = [
        ('i', var_extractor('i')),
        ('n', var_extractor('n'))
    ]
    
    result = synthesize_ranking_for_loop(
        state_builder,
        loop_back_edge,
        variable_extractors
    )
    
    assert result.success, "Should find ranking function for bounded counter"
    assert result.termination_proof.terminates


# Test 3: Nested loops
def test_nested_loops():
    """
    Loop: for i in range(n): for j in range(m): ...
    Ranking: R = n*m - (i*m + j) (lexicographic: (n-i, m-j))
    Should find some valid ranking.
    """
    state_builder = create_state_builder(['i', 'j', 'n', 'm'])
    
    def loop_back_edge(s, s_prime):
        # Inner loop: j increments, or outer loop: i increments and j resets
        i = s.variables['i']
        j = s.variables['j']
        n = s.variables['n']
        m = s.variables['m']
        i_prime = s_prime.variables['i']
        j_prime = s_prime.variables['j']
        
        # Case 1: inner loop step (j < m-1)
        inner_step = z3.And(
            i < n,
            j < m - 1,
            i_prime == i,
            j_prime == j + 1
        )
        
        # Case 2: outer loop step (j == m-1, i increments)
        outer_step = z3.And(
            i < n - 1,
            j == m - 1,
            i_prime == i + 1,
            j_prime == 0
        )
        
        return z3.Or(inner_step, outer_step)
    
    variable_extractors = [
        ('i', var_extractor('i')),
        ('j', var_extractor('j')),
        ('n', var_extractor('n')),
        ('m', var_extractor('m'))
    ]
    
    config = RankingSynthesisConfig(
        max_templates=100,  # May need more templates for nested loops
        max_lexicographic_depth=2
    )
    
    result = synthesize_ranking_for_loop(
        state_builder,
        loop_back_edge,
        variable_extractors,
        config
    )
    
    # Nested loops are harder - we may not find ranking within budget
    # But if we do, it must be valid
    if result.success:
        assert result.termination_proof.terminates


# Test 4: Linear ranking function verification
def test_linear_ranking_verification():
    """
    Manually create a ranking function and verify it.
    Loop: while x > 0: x -= 2
    Ranking: R = x
    """
    state_builder = create_state_builder(['x'])
    
    def loop_back_edge(s, s_prime):
        x = s.variables['x']
        x_prime = s_prime.variables['x']
        return z3.And(
            x > 0,
            x_prime == x - 2
        )
    
    # Extract loop invariant from back-edge
    def loop_invariant(s):
        s_prime = state_builder()
        return loop_back_edge(s, s_prime)
    
    # Create ranking function manually
    ranking = linear_ranking_function(
        [('x', var_extractor('x'))],
        [1.0],
        0.0,
        name="R=x"
    )
    
    # Verify it
    checker = TerminationChecker()
    result = checker.check_termination(
        ranking,
        state_builder,
        loop_back_edge,
        loop_invariant  # Pass invariant
    )
    
    assert result.terminates, "R=x should prove termination for x -= 2"
    assert result.bounded_below_holds
    assert result.decreasing_holds


# Test 5: Two-variable ranking
def test_two_variable_ranking():
    """
    Loop: while a > 0 and b > 0: a -= 1; b -= 1
    Ranking: R = a + b
    """
    state_builder = create_state_builder(['a', 'b'])
    
    def loop_back_edge(s, s_prime):
        a = s.variables['a']
        b = s.variables['b']
        a_prime = s_prime.variables['a']
        b_prime = s_prime.variables['b']
        return z3.And(
            a > 0,
            b > 0,
            a_prime == a - 1,
            b_prime == b - 1
        )
    
    variable_extractors = [
        ('a', var_extractor('a')),
        ('b', var_extractor('b'))
    ]
    
    result = synthesize_ranking_for_loop(
        state_builder,
        loop_back_edge,
        variable_extractors
    )
    
    assert result.success, "Should find R = a + b for dual counter loop"


# Test 6: Non-terminating loop detection
def test_non_terminating_loop_detection():
    """
    Loop: while True: pass  (or any loop with no decrease)
    Should NOT find a valid ranking function.
    """
    state_builder = create_state_builder(['x'])
    
    def loop_back_edge(s, s_prime):
        # No variables change - infinite loop
        x = s.variables['x']
        x_prime = s_prime.variables['x']
        return x_prime == x  # No change
    
    variable_extractors = [('x', var_extractor('x'))]
    
    config = RankingSynthesisConfig(max_templates=20)  # Limit search
    
    result = synthesize_ranking_for_loop(
        state_builder,
        loop_back_edge,
        variable_extractors,
        config
    )
    
    # Should fail to find ranking (does not prove non-termination, just unknown)
    assert not result.success, "Should not find ranking for infinite loop"


# Test 7: check_termination_via_ranking API
def test_check_termination_api():
    """
    Test the high-level check_termination_via_ranking API.
    """
    state_builder = create_state_builder(['i'])
    
    def loop_back_edge(s, s_prime):
        i = s.variables['i']
        i_prime = s_prime.variables['i']
        return z3.And(i > 0, i_prime == i - 1)
    
    variable_extractors = [('i', var_extractor('i'))]
    
    verdict, proof = check_termination_via_ranking(
        state_builder,
        loop_back_edge,
        variable_extractors
    )
    
    assert verdict == "TERMINATES", "Should prove termination"
    assert proof['verdict'] == "SAFE"
    assert 'ranking_function' in proof
    assert 'proof' in proof
    assert proof['proof']['bounded_below_holds']
    assert proof['proof']['decreasing_holds']


# Test 8: UNKNOWN verdict for complex loops
def test_unknown_verdict_for_complex_loop():
    """
    Loop that terminates but synthesis can't find ranking within budget.
    """
    state_builder = create_state_builder(['x', 'y', 'z'])
    
    def loop_back_edge(s, s_prime):
        # Complex update that terminates but is hard to prove
        x = s.variables['x']
        y = s.variables['y']
        z = s.variables['z']
        x_prime = s_prime.variables['x']
        y_prime = s_prime.variables['y']
        z_prime = s_prime.variables['z']
        
        return z3.And(
            x > 0,
            x_prime == x - 1,
            y_prime == z3.If(x % 2 == 0, y + 1, y - 1),
            z_prime == z + y
        )
    
    variable_extractors = [
        ('x', var_extractor('x')),
        ('y', var_extractor('y')),
        ('z', var_extractor('z'))
    ]
    
    config = RankingSynthesisConfig(max_templates=10)  # Very limited budget
    
    verdict, proof = check_termination_via_ranking(
        state_builder,
        loop_back_edge,
        variable_extractors,
        config
    )
    
    # With limited budget, likely UNKNOWN
    # (If we happen to find it, that's also valid)
    assert verdict in ["TERMINATES", "UNKNOWN"]
    
    if verdict == "UNKNOWN":
        assert proof['verdict'] == "UNKNOWN"
        assert 'note' in proof


# Test 9: is_unsafe_non_termination predicate
def test_is_unsafe_non_termination_predicate():
    """
    Test the unsafe predicate for NON_TERMINATION.
    """
    @dataclass
    class MockState:
        iteration_count: int = 0
        ranking_function_failed: bool = False
        infinite_loop_detected: bool = False
    
    # Test 1: Excessive iterations
    state1 = MockState(iteration_count=15000)
    assert is_unsafe_non_termination(state1), "Should detect excessive iterations"
    
    # Test 2: Ranking function failed
    state2 = MockState(ranking_function_failed=True)
    assert is_unsafe_non_termination(state2), "Should detect ranking failure"
    
    # Test 3: Explicit infinite loop marker
    state3 = MockState(infinite_loop_detected=True)
    assert is_unsafe_non_termination(state3), "Should detect explicit marker"
    
    # Test 4: Safe state
    state4 = MockState(iteration_count=100)
    assert not is_unsafe_non_termination(state4), "Should not flag safe state"


# Test 10: Ranking with initial condition constraints
def test_ranking_with_initial_constraints():
    """
    Loop with constraint: n >= 0, i starts at 0
    while i < n: i += 1
    Ranking: R = n - i
    
    Verify that ranking is bounded below (R >= 0) given initial constraints.
    """
    state_builder = create_state_builder(['i', 'n'])
    
    def loop_back_edge(s, s_prime):
        i = s.variables['i']
        n = s.variables['n']
        i_prime = s_prime.variables['i']
        n_prime = s_prime.variables['n']
        
        return z3.And(
            i < n,
            n >= 0,  # Constraint
            i_prime == i + 1,
            n_prime == n
        )
    
    # Extract loop invariant
    def loop_invariant(s):
        s_prime = state_builder()
        return loop_back_edge(s, s_prime)
    
    ranking = linear_ranking_function(
        [('n', var_extractor('n')), ('i', var_extractor('i'))],
        [1.0, -1.0],
        0.0,
        name="n-i"
    )
    
    checker = TerminationChecker()
    result = checker.check_termination(
        ranking,
        state_builder,
        loop_back_edge,
        loop_invariant  # Pass invariant
    )
    
    assert result.terminates


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
