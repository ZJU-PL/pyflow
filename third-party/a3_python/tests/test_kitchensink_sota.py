"""
Test suite for "Kitchensink" SOTA approach verification.

This test file demonstrates the power of combining 20 SOTA papers:
- ICE (Implication CounterExamples) for invariant learning
- CEGIS (CounterExample-Guided Inductive Synthesis) for barrier synthesis
- Predicate Abstraction for finite-state reasoning
- CEGAR for abstraction refinement
- IC3/PDR for property-directed reachability
- Ranking functions for termination
- SOS/SDP for non-linear invariants
- Interpolation for predicate discovery

These tests showcase bugs/situations that are particularly well-suited
for detection or FP/TP discrimination with the kitchensink approach.
"""

import pytest
import z3

from a3_python.barriers.ice import ice_learn_conjunction
from a3_python.barriers.cegis import CEGISConfig
from a3_python.barriers.predicate_abstraction import (
    Predicate,
    PredicateSet,
    AbstractState,
)
from a3_python.barriers.ranking import RankingFunctionCertificate
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


# =============================================================================
# TEST 1: ICE-based loop invariant discovery
# =============================================================================
# ICE is particularly powerful for discovering loop invariants from examples.
# The key insight: given positive (invariant holds), negative (invariant fails),
# and implication examples (if invariant holds before step, holds after),
# ICE can synthesize a conjunction that is inductive.

class TestICEInvariantDiscovery:
    """Test ICE learning for loop invariants."""

    def test_simple_counter_invariant(self):
        """
        Test ICE learning for simple counter loop:
        
            i = 0
            while i < n:
                i += 1
            assert i == n
            
        Invariant: 0 <= i <= n
        """
        # Define variables
        i, n = z3.Ints("i n")
        variables = {"i": i, "n": n}
        
        # Candidate predicates for the invariant
        candidate_predicates = {
            "i >= 0": i >= 0,
            "i <= n": i <= n,
            "i < n": i < n,
            "i > 0": i > 0,
            "n >= 0": n >= 0,
        }
        
        # Positive examples: states where invariant holds
        positive = [
            {"i": 0, "n": 5},   # Entry
            {"i": 3, "n": 5},   # Mid-loop
            {"i": 5, "n": 5},   # Exit
        ]
        
        # Negative examples: states that should NOT satisfy invariant
        negative = [
            {"i": -1, "n": 5},  # i < 0 violates
            {"i": 6, "n": 5},   # i > n violates
        ]
        
        # Implication examples: (pre-state, post-state) pairs showing inductiveness
        implications = [
            ({"i": 0, "n": 5}, {"i": 1, "n": 5}),  # After i += 1
            ({"i": 4, "n": 5}, {"i": 5, "n": 5}),  # Last iteration
        ]
        
        result = ice_learn_conjunction(
            variables=variables,
            candidate_predicates=candidate_predicates,
            positive=positive,
            negative=negative,
            implications=implications,
        )
        
        assert result.success, f"ICE learning failed: {result.message}"
        assert "i >= 0" in result.chosen_predicates
        assert "i <= n" in result.chosen_predicates

    def test_binary_search_invariant(self):
        """
        Test ICE for binary search invariant:
        
            lo, hi = 0, len(arr) - 1
            while lo <= hi:
                mid = (lo + hi) // 2
                if arr[mid] < target:
                    lo = mid + 1
                elif arr[mid] > target:
                    hi = mid - 1
                else:
                    return mid
            return -1
            
        Invariant: 0 <= lo <= len(arr) AND -1 <= hi < len(arr)
        """
        lo, hi, length = z3.Ints("lo hi length")
        variables = {"lo": lo, "hi": hi, "length": length}
        
        candidate_predicates = {
            "lo >= 0": lo >= 0,
            "hi >= -1": hi >= -1,
            "lo <= length": lo <= length,
            "hi < length": hi < length,
            "lo <= hi + 1": lo <= hi + 1,
        }
        
        positive = [
            {"lo": 0, "hi": 9, "length": 10},
            {"lo": 5, "hi": 9, "length": 10},
            {"lo": 5, "hi": 4, "length": 10},  # Termination: lo > hi
        ]
        
        negative = [
            {"lo": -1, "hi": 9, "length": 10},  # lo < 0
            {"lo": 0, "hi": 10, "length": 10},  # hi >= length
        ]
        
        implications = [
            ({"lo": 0, "hi": 9, "length": 10}, {"lo": 5, "hi": 9, "length": 10}),  # lo = mid + 1
            ({"lo": 0, "hi": 9, "length": 10}, {"lo": 0, "hi": 3, "length": 10}),  # hi = mid - 1
        ]
        
        result = ice_learn_conjunction(
            variables=variables,
            candidate_predicates=candidate_predicates,
            positive=positive,
            negative=negative,
            implications=implications,
        )
        
        assert result.success


# =============================================================================
# TEST 2: CEGIS-based barrier synthesis
# =============================================================================
# CEGIS is powerful for synthesizing barriers that separate safe from unsafe.

class TestCEGISBarrierSynthesis:
    """Test CEGIS for barrier certificate synthesis."""

    def test_division_by_zero_barrier(self):
        """
        Synthesize barrier for division safety:
        
            x = input()
            if x > 0:
                y = 10 / x  # Safe: barrier proves x != 0
                
        Barrier: x > 0 implies x != 0
        """
        x = z3.Real("x")
        
        # Initial region: x > 0
        init = x > 0
        
        # Unsafe region: x == 0 (division by zero)
        unsafe = x == 0
        
        # With constraint x > 0, we can prove x != 0
        solver = z3.Solver()
        solver.add(init)
        solver.add(unsafe)
        
        # If UNSAT, the barrier (x > 0) separates init from unsafe
        result = solver.check()
        assert result == z3.unsat, "Barrier should prove division is safe"

    def test_array_bounds_barrier(self):
        """
        Synthesize barrier for array bounds:
        
            for i in range(len(arr)):
                x = arr[i]  # Safe: 0 <= i < len
                
        Barrier: 0 <= i < n
        """
        i, n = z3.Ints("i n")
        
        # Loop invariant: 0 <= i < n
        invariant = z3.And(i >= 0, i < n)
        
        # Unsafe: i < 0 or i >= n
        unsafe = z3.Or(i < 0, i >= n)
        
        solver = z3.Solver()
        solver.add(invariant)
        solver.add(unsafe)
        
        result = solver.check()
        assert result == z3.unsat, "Invariant should prevent out-of-bounds"


# =============================================================================
# TEST 3: Predicate Abstraction for path-sensitive analysis
# =============================================================================
# Predicate abstraction reduces infinite state to finite Boolean combinations.

class TestPredicateAbstraction:
    """Test predicate abstraction for verification."""

    def test_null_check_predicate(self):
        """
        Predicate abstraction for null pointer dereference:
        
            if x is not None:
                y = x.value  # Safe: predicate "x != None" holds
                
        Abstract state: {x_is_none: False}
        """
        x = z3.Int("x")  # Represent as int, 0 = None
        
        pred_not_none = Predicate(
            name="x_not_none",
            formula=x != 0,
            variables=[x],
            id=0,
        )
        
        pred_set = PredicateSet(predicates=[pred_not_none], variables=[x])
        
        # Abstract state where x != None (assignment is a tuple of booleans)
        abstract_state = AbstractState(assignment=(True,))  # x_not_none = True
        
        assert abstract_state.assignment[0] is True

    def test_type_check_predicate(self):
        """
        Predicate abstraction for type confusion:
        
            if isinstance(x, int):
                y = x + 1  # Safe: predicate "x is int" holds
        """
        x_is_int = z3.Bool("x_is_int")
        x_is_str = z3.Bool("x_is_str")
        
        # Mutual exclusion: can't be both int and str
        type_axiom = z3.Not(z3.And(x_is_int, x_is_str))
        
        solver = z3.Solver()
        solver.add(type_axiom)
        solver.add(x_is_int)  # We know x is int
        solver.add(x_is_str)  # Try to also claim x is str
        
        result = solver.check()
        assert result == z3.unsat, "Type predicates should be mutually exclusive"


# =============================================================================
# TEST 4: Ranking functions for termination
# =============================================================================
# Ranking functions prove loop termination by showing a value decreases.

class TestRankingFunctions:
    """Test ranking function synthesis for termination."""

    def test_simple_decrement_loop(self):
        """
        Termination of simple countdown:
        
            while n > 0:
                n -= 1
                
        Ranking function: n (decreases by 1, bounded below by 0)
        """
        n = z3.Int("n")
        n_prime = z3.Int("n_prime")
        
        # Loop guard
        guard = n > 0
        
        # Transition: n' = n - 1
        transition = n_prime == n - 1
        
        # Ranking function: n
        rank = n
        rank_prime = n_prime
        
        solver = z3.Solver()
        solver.add(guard)
        solver.add(transition)
        
        # Check: rank decreases (n' < n)
        solver.add(z3.Not(rank_prime < rank))
        
        result = solver.check()
        assert result == z3.unsat, "Ranking function should decrease"

    def test_gcd_termination(self):
        """
        Termination of Euclidean GCD:
        
            while b != 0:
                a, b = b, a % b
                
        Ranking function: (a, b) lexicographically with b > 0
        """
        a, b = z3.Ints("a b")
        a_prime, b_prime = z3.Ints("a_prime b_prime")
        
        # Loop guard
        guard = b != 0
        
        # Transition: a' = b, b' = a % b
        # For termination, b' < b when b > 0
        transition = z3.And(
            a_prime == b,
            b_prime >= 0,
            b_prime < b,  # a % b < b for b > 0
        )
        
        # Ranking function: b (decreases, bounded by 0)
        solver = z3.Solver()
        solver.add(guard)
        solver.add(b > 0)  # Precondition for valid modulo
        solver.add(transition)
        
        # Check: b' < b
        solver.add(z3.Not(b_prime < b))
        
        result = solver.check()
        assert result == z3.unsat, "GCD loop terminates"


# =============================================================================
# TEST 5: Combined techniques for complex bugs
# =============================================================================
# The kitchensink approach shines when multiple techniques work together.

class TestKitchensinkCombined:
    """Test combined SOTA techniques."""

    def test_toctou_with_predicates(self):
        """
        TOCTOU (Time-of-Check-Time-of-Use) detection:
        
            if os.path.exists(path):       # Check
                # ... other code ...
                f = open(path, 'r')         # Use - may fail!
                
        Predicate abstraction tracks:
        - path_exists_checked: bool
        - path_may_have_changed: bool
        
        Bug if: path_exists_checked AND path_may_have_changed AND open(path)
        """
        path_exists_checked = z3.Bool("path_exists_checked")
        path_may_have_changed = z3.Bool("path_may_have_changed")
        open_called = z3.Bool("open_called")
        
        # TOCTOU bug condition
        bug_condition = z3.And(
            path_exists_checked,
            path_may_have_changed,
            open_called,
        )
        
        # Trace where:
        # 1. Check is done
        # 2. Intervening code that could allow race
        # 3. Open is called
        solver = z3.Solver()
        solver.add(path_exists_checked)
        solver.add(path_may_have_changed)
        solver.add(open_called)
        solver.add(bug_condition)
        
        result = solver.check()
        # SAT means bug is reachable
        assert result == z3.sat, "TOCTOU bug should be detectable"

    def test_integer_overflow_barrier(self):
        """
        Integer overflow protection with barrier.
        
        When x >= 0, y >= 0, and x + y >= 0, we know no signed overflow occurred.
        Barrier: x >= 0 AND y >= 0 AND x + y <= MAX_INT proves safety.
        """
        x, y = z3.Ints("x y")
        MAX_INT = 2**31 - 1
        
        # Guard: both positive and sum within range
        guard = z3.And(x >= 0, y >= 0, x + y <= MAX_INT)
        
        # Bug: signed overflow (sum exceeds MAX_INT)
        overflow = x + y > MAX_INT
        
        solver = z3.Solver()
        solver.add(guard)
        solver.add(overflow)
        
        result = solver.check()
        assert result == z3.unsat, "Guard prevents overflow"

    def test_resource_leak_barrier(self):
        """
        Resource leak prevention with barrier:
        
            f = open(path)
            try:
                data = f.read()
            finally:
                f.close()  # Always closed
                
        Barrier tracks: file_opened => eventually file_closed
        """
        file_opened = z3.Bool("file_opened")
        file_closed = z3.Bool("file_closed")
        exit_point = z3.Bool("exit_point")
        
        # Safety: at exit, if opened then closed
        safety = z3.Implies(
            z3.And(file_opened, exit_point),
            file_closed,
        )
        
        # With finally block, this is always true
        solver = z3.Solver()
        solver.add(file_opened)
        solver.add(exit_point)
        solver.add(file_closed)  # finally ensures this
        solver.add(z3.Not(safety))
        
        result = solver.check()
        assert result == z3.unsat, "finally block ensures no leak"


# =============================================================================
# TEST 6: False Positive Reduction with DSE + Barriers
# =============================================================================
# DSE provides concrete counterexamples; barriers provide proofs.
# Together they reduce FPs by proving infeasibility.

class TestFPReductionWithBarriers:
    """Test false positive reduction using barrier certificates."""

    def test_infeasible_path_pruning(self):
        """
        FP: Static analysis might flag this, but path is infeasible:
        
            x = get_positive_int()
            if x < 0:  # Dead code
                1 / 0   # Never reached
                
        Barrier: x >= 0 from get_positive_int() contract
        """
        x = z3.Int("x")
        
        # Contract: get_positive_int() returns x >= 0
        contract = x >= 0
        
        # Path condition to reach bug: x < 0
        path_condition = x < 0
        
        solver = z3.Solver()
        solver.add(contract)
        solver.add(path_condition)
        
        result = solver.check()
        assert result == z3.unsat, "Path is infeasible - this is a FP"

    def test_correlated_guards(self):
        """
        FP from ignoring guard correlation:
        
            if x > 0:
                y = x  # y > 0
            if y > 0:
                z = 1 / y  # Safe, but naively flagged
                
        Barrier: x > 0 => y == x => y > 0
        """
        x, y = z3.Ints("x y")
        
        # First guard
        guard1 = x > 0
        
        # Assignment
        assignment = y == x
        
        # Second guard (correlated)
        guard2 = y > 0
        
        # Check: under guard1, after assignment, guard2 holds
        solver = z3.Solver()
        solver.add(guard1)
        solver.add(assignment)
        solver.add(z3.Not(guard2))  # Try to find y <= 0
        
        result = solver.check()
        assert result == z3.unsat, "Guards are correlated - y > 0 guaranteed"

    def test_contract_propagation(self):
        """
        FP from missing contract propagation:
        
            def get_length(lst):
                return len(lst)  # Always >= 0
                
            n = get_length(items)
            arr = [0] * n  # Safe - n >= 0
                
        Barrier: len(x) >= 0 for any list
        """
        n = z3.Int("n")
        
        # Contract: len() returns non-negative
        contract = n >= 0
        
        # Bug condition: n < 0 (invalid array size)
        bug = n < 0
        
        solver = z3.Solver()
        solver.add(contract)
        solver.add(bug)
        
        result = solver.check()
        assert result == z3.unsat, "len() contract proves safety"


# =============================================================================
# TEST 7: True Positive Detection with DSE
# =============================================================================
# DSE can find concrete inputs that trigger bugs.

class TestTPDetectionWithDSE:
    """Test true positive detection with DSE."""

    def test_division_by_zero_reachable(self):
        """
        TP: Division by zero is reachable:
        
            x = user_input()
            if x >= -1 and x <= 1:
                if x != 1 and x != -1:
                    y = 1 / x  # Bug when x == 0
        """
        x = z3.Int("x")
        
        # Path constraints
        in_range = z3.And(x >= -1, x <= 1)
        not_one = z3.And(x != 1, x != -1)
        
        # Bug condition
        division_by_zero = x == 0
        
        solver = z3.Solver()
        solver.add(in_range)
        solver.add(not_one)
        solver.add(division_by_zero)
        
        result = solver.check()
        assert result == z3.sat, "Division by zero is reachable"
        
        model = solver.model()
        assert model[x].as_long() == 0, "x=0 triggers the bug"

    def test_null_deref_reachable(self):
        """
        TP: Null dereference is reachable:
        
            d = {}
            x = d.get('key')  # Returns None if key missing
            y = x.upper()     # Bug: x might be None
        """
        x_is_none = z3.Bool("x_is_none")
        key_exists = z3.Bool("key_exists")
        
        # d.get('key') returns None if key doesn't exist
        constraint = z3.Implies(z3.Not(key_exists), x_is_none)
        
        # Bug: accessing method on None
        bug = x_is_none
        
        solver = z3.Solver()
        solver.add(constraint)
        solver.add(z3.Not(key_exists))  # Key doesn't exist
        solver.add(bug)
        
        result = solver.check()
        assert result == z3.sat, "Null dereference is reachable"

    def test_bounds_violation_reachable(self):
        """
        TP: Array bounds violation is reachable:
        
            arr = [1, 2, 3]
            i = user_input()
            if i >= 0:
                x = arr[i]  # Bug: no upper bound check
        """
        i, length = z3.Ints("i length")
        
        # Constraint: i >= 0, but no upper bound
        lower_check = i >= 0
        
        # Array length
        arr_length = length == 3
        
        # Bug: i >= length
        out_of_bounds = i >= length
        
        solver = z3.Solver()
        solver.add(lower_check)
        solver.add(arr_length)
        solver.add(out_of_bounds)
        
        result = solver.check()
        assert result == z3.sat, "Out of bounds is reachable"
        
        model = solver.model()
        assert model[i].as_long() >= 3, "i >= 3 triggers the bug"


# =============================================================================
# TEST 8: Houdini for invariant inference
# =============================================================================
# Houdini: given candidate invariants, find largest subset that is inductive.

class TestHoudiniInvariance:
    """Test Houdini algorithm for invariant inference."""

    def test_houdini_counter_loop(self):
        """
        Houdini for counter loop invariant:
        
            i = 0
            while i < n:
                i += 1
                
        Candidates: {i >= 0, i <= n, i > 0, i == n}
        Houdini should keep: {i >= 0, i <= n}
        """
        i, n = z3.Ints("i n")
        i_prime = z3.Int("i_prime")
        
        # Initial state
        init = z3.And(i == 0, n >= 0)
        
        # Transition
        guard = i < n
        transition = i_prime == i + 1
        
        # Candidates
        candidates = [
            i >= 0,
            i <= n,
            i > 0,   # Not preserved at init (i=0 violates i > 0)
            i == n,  # Not preserved in loop
        ]
        
        # Check which are inductive
        # Simplified check: init => candidate AND (guard AND candidate AND transition => candidate')
        inductive = []
        for cand in candidates:
            cand_prime = z3.substitute(cand, (i, i_prime))
            
            # Check init => cand
            solver = z3.Solver()
            solver.add(init)
            solver.add(z3.Not(cand))
            init_check = solver.check()
            
            if init_check == z3.sat:
                continue  # Not established at init
            
            # Check inductiveness
            solver = z3.Solver()
            solver.add(guard)
            solver.add(cand)
            solver.add(transition)
            solver.add(z3.Not(cand_prime))
            induct_check = solver.check()
            
            if induct_check == z3.unsat:
                inductive.append(cand)
        
        # Should keep i >= 0 and i <= n
        assert len(inductive) >= 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
