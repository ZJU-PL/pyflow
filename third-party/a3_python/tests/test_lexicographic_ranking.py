"""
Tests for lexicographic ranking templates for nested loops.

Lexicographic ranking (R1, R2, ..., Rn) decreases iff:
- R1(s') < R1(s), OR
- R1(s') = R1(s) AND R2(s') < R2(s), OR
- R1(s') = R1(s) AND R2(s') = R2(s) AND R3(s') < R3(s), etc.

This is the proper formulation for nested loops where outer loop variables
may stay constant while inner loops run.
"""

import pytest
import z3
import threading

from a3_python.barriers.ranking import (
    RankingFunctionCertificate,
    TerminationProofResult,
    simple_counter_ranking,
    linear_ranking_function,
    create_lexicographic_ranking,
)
from a3_python.semantics.symbolic_vm import SymbolicMachineState, SymbolicValue


# Global counter for unique variable names (thread-safe)
_var_counter = threading.local()

def _get_next_id():
    """Get next unique ID for variable naming."""
    if not hasattr(_var_counter, 'value'):
        _var_counter.value = 0
    _var_counter.value += 1
    return _var_counter.value


def make_state_with_vars(**kwargs):
    """Helper to create a symbolic state with specified local variables."""
    state = SymbolicMachineState()
    state.locals = {}
    for name, value in kwargs.items():
        if isinstance(value, int):
            state.locals[name] = SymbolicValue.int(z3.IntVal(value))
        elif isinstance(value, z3.ExprRef):
            state.locals[name] = SymbolicValue.int(value)
        else:
            state.locals[name] = value
    return state


def extract_var(var_name: str):
    """Create a variable extractor function."""
    def extractor(state: SymbolicMachineState) -> z3.ExprRef:
        if var_name in state.locals:
            val = state.locals[var_name]
            if isinstance(val, SymbolicValue):
                # SymbolicValue stores the Z3 expression in payload
                return val.payload
            return val
        # Return symbolic variable with unique name based on state id
        # Use id(state) to ensure each state gets unique variables
        return z3.Int(f"state_{id(state)}_{var_name}")
    return extractor


def make_unique_state_builder(*var_names):
    """
    Create a state builder that generates unique Z3 variables for each call.
    
    Args:
        *var_names: Names of variables to create
    
    Returns:
        A state_builder function that creates fresh variables
    
    Example:
        state_builder = make_unique_state_builder('n', 'i', 'm', 'j')
        s1 = state_builder()  # Creates n_1, i_1, m_1, j_1
        s2 = state_builder()  # Creates n_2, i_2, m_2, j_2
    """
    def state_builder():
        suffix = f"_{_get_next_id()}"
        vars_dict = {}
        for var_name in var_names:
            vars_dict[var_name] = z3.Int(var_name + suffix)
        return make_state_with_vars(**vars_dict)
    return state_builder


def test_lexicographic_two_component_basic():
    """
    Test basic 2-component lexicographic ranking: (R1, R2)
    
    Nested loop pattern:
        for i in range(n):  # i from 0 to n-1
            for j in range(m):  # j from 0 to m-1
                pass
    
    Ranking: (n-i, m-j)
    - Outer loop: n-i decreases from n to 1
    - Inner loop: when i is constant, m-j decreases from m to 1
    """
    # Create component rankings
    # R1 = n - i (outer loop)
    # R2 = m - j (inner loop)
    R1 = linear_ranking_function(
        [("n", extract_var("n")), ("i", extract_var("i"))],
        [1.0, -1.0],
        0.0,
        name="R1_n_minus_i"
    )
    
    R2 = linear_ranking_function(
        [("m", extract_var("m")), ("j", extract_var("j"))],
        [1.0, -1.0],
        0.0,
        name="R2_m_minus_j"
    )
    
    lex_rank = create_lexicographic_ranking([R1, R2], name="nested_loops")
    
    assert len(lex_rank.components) == 2
    assert lex_rank.name == "nested_loops"
    
    # Test evaluation
    state = make_state_with_vars(
        n=z3.IntVal(10),
        i=z3.IntVal(3),
        m=z3.IntVal(5),
        j=z3.IntVal(2)
    )
    
    R1_val = R1.evaluate(state)
    R2_val = R2.evaluate(state)
    
    # R1 = 10 - 3 = 7
    # R2 = 5 - 2 = 3
    solver = z3.Solver()
    solver.add(R1_val == 7.0)
    solver.add(R2_val == 3.0)
    assert solver.check() == z3.sat


def test_lexicographic_decrease_inner_loop():
    """
    Test lexicographic decrease when only inner loop executes.
    
    Scenario: i is constant, j increments
    Before: (n-i, m-j) = (7, 3)
    After:  (n-i, m-j) = (7, 2)  [j incremented]
    
    This should satisfy lexicographic decrease:
    R1' = R1 AND R2' < R2
    """
    R1 = linear_ranking_function(
        [("n", extract_var("n")), ("i", extract_var("i"))],
        [1.0, -1.0],
        0.0
    )
    
    R2 = linear_ranking_function(
        [("m", extract_var("m")), ("j", extract_var("j"))],
        [1.0, -1.0],
        0.0
    )
    
    lex_rank = create_lexicographic_ranking([R1, R2])
    
    # Use helper to create unique states
    state_builder = make_unique_state_builder('n', 'i', 'm', 'j')
    
    # Define inner loop back-edge: i' = i, j' = j + 1
    def inner_loop_edge(s, s_prime):
        i = extract_var("i")(s)
        i_prime = extract_var("i")(s_prime)
        j = extract_var("j")(s)
        j_prime = extract_var("j")(s_prime)
        m = extract_var("m")(s)
        m_prime = extract_var("m")(s_prime)
        n = extract_var("n")(s)
        n_prime = extract_var("n")(s_prime)
        
        # Inner loop: i stays same, j increments, guards
        # Crucially: bound variables n, m must be unchanged
        return z3.And(
            i_prime == i,  # i unchanged
            j_prime == j + 1,  # j increments
            n_prime == n,  # bounds unchanged
            m_prime == m,
            j >= 0,  # j is non-negative
            j < m,  # j < m (loop guard)
            i >= 0,
            i < n,
            m > 0,
            n > 0
        )
    
    # Check lexicographic decrease
    decreasing_holds, cex = lex_rank.check_lexicographic_decrease(
        state_builder,
        inner_loop_edge,
        timeout_ms=5000
    )
    
    assert decreasing_holds, f"Inner loop should satisfy lexicographic decrease, but got counterexample: {cex}"


def test_lexicographic_decrease_outer_loop():
    """
    Test lexicographic decrease when outer loop executes.
    
    Scenario: i increments, j resets to 0
    Before: (n-i, m-j) = (7, 0)   [inner loop finished]
    After:  (n-i, m-j) = (6, m)   [i incremented, j reset]
    
    This should satisfy lexicographic decrease:
    R1' < R1  (doesn't matter what R2 does)
    """
    R1 = linear_ranking_function(
        [("n", extract_var("n")), ("i", extract_var("i"))],
        [1.0, -1.0],
        0.0
    )
    
    R2 = linear_ranking_function(
        [("m", extract_var("m")), ("j", extract_var("j"))],
        [1.0, -1.0],
        0.0
    )
    
    lex_rank = create_lexicographic_ranking([R1, R2])
    
    state_builder = make_unique_state_builder('n', 'i', 'm', 'j')
    
    # Outer loop edge: i increments, j resets to 0
    def outer_loop_edge(s, s_prime):
        i = extract_var("i")(s)
        i_prime = extract_var("i")(s_prime)
        j_prime = extract_var("j")(s_prime)
        m = extract_var("m")(s)
        m_prime = extract_var("m")(s_prime)
        n = extract_var("n")(s)
        n_prime = extract_var("n")(s_prime)
        
        return z3.And(
            i_prime == i + 1,  # i increments
            j_prime == 0,  # j resets
            n_prime == n,  # bounds unchanged
            m_prime == m,
            i >= 0,
            i < n,
            m > 0,
            n > 0
        )
    
    decreasing_holds, cex = lex_rank.check_lexicographic_decrease(
        state_builder,
        outer_loop_edge,
        timeout_ms=5000
    )
    
    assert decreasing_holds, f"Outer loop should satisfy lexicographic decrease, but got counterexample: {cex}"


def test_lexicographic_not_decreasing():
    """
    Test that lexicographic ranking correctly detects non-terminating loops.
    
    Scenario: both i and j stay constant (infinite loop)
    Before: (n-i, m-j) = (7, 3)
    After:  (n-i, m-j) = (7, 3)  [no change]
    
    This should NOT satisfy lexicographic decrease.
    """
    R1 = linear_ranking_function(
        [("n", extract_var("n")), ("i", extract_var("i"))],
        [1.0, -1.0],
        0.0
    )
    
    R2 = linear_ranking_function(
        [("m", extract_var("m")), ("j", extract_var("j"))],
        [1.0, -1.0],
        0.0
    )
    
    lex_rank = create_lexicographic_ranking([R1, R2])
    
    state_builder = make_unique_state_builder('n', 'i', 'm', 'j')
    
    # Infinite loop: nothing changes
    def infinite_loop_edge(s, s_prime):
        i = extract_var("i")(s)
        i_prime = extract_var("i")(s_prime)
        j = extract_var("j")(s)
        j_prime = extract_var("j")(s_prime)
        
        return z3.And(
            i_prime == i,  # i unchanged
            j_prime == j,  # j unchanged
            i >= 0,
            j >= 0
        )
    
    decreasing_holds, cex = lex_rank.check_lexicographic_decrease(
        state_builder,
        infinite_loop_edge,
        timeout_ms=5000
    )
    
    assert not decreasing_holds, "Infinite loop should NOT satisfy lexicographic decrease"
    assert cex is not None, "Should have counterexample for non-decreasing case"


def test_lexicographic_three_components():
    """
    Test 3-component lexicographic ranking for triple-nested loops.
    
    Nested loop pattern:
        for i in range(n):
            for j in range(m):
                for k in range(p):
                    pass
    
    Ranking: (n-i, m-j, p-k)
    """
    R1 = linear_ranking_function(
        [("n", extract_var("n")), ("i", extract_var("i"))],
        [1.0, -1.0],
        0.0
    )
    
    R2 = linear_ranking_function(
        [("m", extract_var("m")), ("j", extract_var("j"))],
        [1.0, -1.0],
        0.0
    )
    
    R3 = linear_ranking_function(
        [("p", extract_var("p")), ("k", extract_var("k"))],
        [1.0, -1.0],
        0.0
    )
    
    lex_rank = create_lexicographic_ranking([R1, R2, R3], name="triple_nested")
    
    assert len(lex_rank.components) == 3
    assert lex_rank.name == "triple_nested"
    
    state_builder = make_unique_state_builder('n', 'i', 'm', 'j', 'p', 'k')
    
    # Innermost loop: only k changes
    def innermost_loop_edge(s, s_prime):
        i = extract_var("i")(s)
        i_prime = extract_var("i")(s_prime)
        j = extract_var("j")(s)
        j_prime = extract_var("j")(s_prime)
        k = extract_var("k")(s)
        k_prime = extract_var("k")(s_prime)
        p = extract_var("p")(s)
        p_prime = extract_var("p")(s_prime)
        n = extract_var("n")(s)
        n_prime = extract_var("n")(s_prime)
        m = extract_var("m")(s)
        m_prime = extract_var("m")(s_prime)
        
        return z3.And(
            i_prime == i,  # i unchanged
            j_prime == j,  # j unchanged
            k_prime == k + 1,  # k increments
            n_prime == n,  # bounds unchanged
            m_prime == m,
            p_prime == p,
            k >= 0,
            k < p,
            p > 0
        )
    
    decreasing_holds, cex = lex_rank.check_lexicographic_decrease(
        state_builder,
        innermost_loop_edge,
        timeout_ms=5000
    )
    
    assert decreasing_holds, f"Innermost loop should satisfy 3-component lexicographic decrease, got: {cex}"


def test_lexicographic_bounded_below():
    """
    Test bounded-below check for lexicographic ranking.
    
    All components must be non-negative.
    """
    R1 = linear_ranking_function(
        [("n", extract_var("n")), ("i", extract_var("i"))],
        [1.0, -1.0],
        0.0
    )
    
    R2 = linear_ranking_function(
        [("m", extract_var("m")), ("j", extract_var("j"))],
        [1.0, -1.0],
        0.0
    )
    
    lex_rank = create_lexicographic_ranking([R1, R2])
    
    state_builder = make_unique_state_builder('n', 'i', 'm', 'j')
    
    # Loop invariant: valid loop indices
    def loop_invariant(s):
        i = extract_var("i")(s)
        j = extract_var("j")(s)
        n = extract_var("n")(s)
        m = extract_var("m")(s)
        return z3.And(
            0 <= i, i < n,
            0 <= j, j < m,
            n > 0,
            m > 0
        )
    
    bounded_holds, cex = lex_rank.check_bounded_below(
        state_builder,
        loop_invariant,
        timeout_ms=5000
    )
    
    assert bounded_holds, f"Ranking should be bounded below in loop invariant, got: {cex}"


def test_lexicographic_full_termination_proof():
    """
    Test full termination proof using lexicographic ranking.
    
    Verifies both bounded-below and lexicographic decrease.
    """
    R1 = linear_ranking_function(
        [("n", extract_var("n")), ("i", extract_var("i"))],
        [1.0, -1.0],
        0.0
    )
    
    R2 = linear_ranking_function(
        [("m", extract_var("m")), ("j", extract_var("j"))],
        [1.0, -1.0],
        0.0
    )
    
    lex_rank = create_lexicographic_ranking([R1, R2])
    
    state_builder = make_unique_state_builder('n', 'i', 'm', 'j')
    
    # Combined loop edge (inner or outer)
    def loop_edge(s, s_prime):
        i = extract_var("i")(s)
        i_prime = extract_var("i")(s_prime)
        j = extract_var("j")(s)
        j_prime = extract_var("j")(s_prime)
        n = extract_var("n")(s)
        n_prime = extract_var("n")(s_prime)
        m = extract_var("m")(s)
        m_prime = extract_var("m")(s_prime)
        
        # Inner loop step OR outer loop step
        inner_step = z3.And(
            i_prime == i,
            j_prime == j + 1,
            j >= 0, j < m
        )
        
        outer_step = z3.And(
            i_prime == i + 1,
            j_prime == 0,
            i >= 0, i < n
        )
        
        return z3.And(
            z3.Or(inner_step, outer_step),
            n_prime == n,  # bounds unchanged
            m_prime == m,
            n > 0,
            m > 0
        )
    
    def loop_invariant(s):
        i = extract_var("i")(s)
        j = extract_var("j")(s)
        n = extract_var("n")(s)
        m = extract_var("m")(s)
        return z3.And(
            0 <= i, i < n,
            0 <= j, j < m,
            n > 0,
            m > 0
        )
    
    result = lex_rank.verify_termination(
        state_builder,
        loop_edge,
        loop_invariant,
        timeout_ms=10000
    )
    
    assert result.terminates, f"Nested loop should terminate: {result.summary()}"
    assert result.bounded_below_holds
    assert result.decreasing_holds


def test_lexicographic_vs_weighted_sum():
    """
    Test case demonstrating lexicographic behavior with component priority.
    
    Scenario: R1 increases but R2 strongly decreases
    For lexicographic ordering to work, R1 MUST NOT increase.
    
    If both change on same transition, lexicographic check looks at R1 first.
    If R1 increases, the tuple does NOT decrease lexicographically.
    """
    # Use i directly (increases) and m-j (decreases)
    R1 = simple_counter_ranking("i", extract_var("i"))
    R2 = linear_ranking_function(
        [("m", extract_var("m")), ("j", extract_var("j"))],
        [1.0, -1.0],
        0.0
    )
    
    lex_rank = create_lexicographic_ranking([R1, R2])
    
    state_builder = make_unique_state_builder('i', 'm', 'j', 'n')
    
    # Loop where i increases (violates R1 decrease)
    def loop_edge(s, s_prime):
        i = extract_var("i")(s)
        i_prime = extract_var("i")(s_prime)
        j = extract_var("j")(s)
        j_prime = extract_var("j")(s_prime)
        m = extract_var("m")(s)
        n = extract_var("n")(s)
        
        # i increases, j stays same or decreases
        # This violates lexicographic decrease because R1 increases
        return z3.And(
            i_prime == i + 1,  # i INCREASES
            j_prime == j,  # j stays same (to isolate R1 effect)
            j >= 0,
            i >= 0,
            i < n,
            m > 0,
            n > 0
        )
    
    # Lexicographic check should detect this is NOT decreasing
    # because R1 increases (R1 = i, so if i increases, R1 increases)
    decreasing_holds, cex = lex_rank.check_lexicographic_decrease(
        state_builder,
        loop_edge,
        timeout_ms=5000
    )
    
    # This should fail because R1 (i) increases
    assert not decreasing_holds, "Loop where R1 increases should NOT satisfy lexicographic decrease"


def test_lexicographic_with_counter_rankings():
    """
    Test lexicographic ranking with simple counter components.
    
    This is the most common pattern for nested loops with range().
    """
    i_rank = simple_counter_ranking("i", extract_var("i"))
    j_rank = simple_counter_ranking("j", extract_var("j"))
    
    lex_rank = create_lexicographic_ranking([i_rank, j_rank])
    
    # For range-based loops, counters are typically decreasing
    # (or we model them as max - counter)
    
    state_builder = make_unique_state_builder('i', 'j')
    
    # Simple pattern: both decrease (sequential execution)
    def loop_edge(s, s_prime):
        i = extract_var("i")(s)
        i_prime = extract_var("i")(s_prime)
        j = extract_var("j")(s)
        j_prime = extract_var("j")(s_prime)
        
        return z3.And(
            i_prime <= i,  # i stays same or decreases
            z3.Or(
                z3.And(i_prime == i, j_prime == j - 1, j > 0),  # inner loop
                z3.And(i_prime == i - 1, i > 0)  # outer loop
            ),
            i >= 0,
            j >= 0
        )
    
    decreasing_holds, cex = lex_rank.check_lexicographic_decrease(
        state_builder,
        loop_edge,
        timeout_ms=5000
    )
    
    assert decreasing_holds, "Nested counter loops should satisfy lexicographic decrease"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
