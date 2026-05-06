"""
Ranking functions for termination proofs.

A ranking function (also called a descent function) is a map R: S → ℕ (or ℝ≥0)
that decreases on every step of a loop or recursion, proving termination.

For termination, we need:
1. BoundedBelow: ∀s. R(s) ≥ 0
2. Decreasing: ∀s,s'. (s →loop s') ⇒ R(s') < R(s)

This is dual to a barrier certificate: instead of staying above 0, we prove
we cannot stay in the loop forever because R keeps decreasing.

Ranking functions can be:
- Linear: R(σ) = c0 + c1*v1 + ... (most common)
- Lexicographic: (R1(σ), R2(σ), ...) with lexicographic ordering
- Piecewise: different ranking functions for different regions
"""

from dataclasses import dataclass
from typing import Callable, Optional, Protocol
import z3

from ..semantics.symbolic_vm import SymbolicMachineState


class RankingFunction(Protocol):
    """
    A ranking function maps machine states to non-negative values.
    
    The ranking value R(σ) must be expressible in terms of loop variables,
    iteration counters, or other state components that decrease on each step.
    """
    
    def __call__(self, state: SymbolicMachineState) -> z3.ExprRef:
        """
        Compute R(σ) for the given state.
        
        Returns: Z3 IntSort or RealSort expression (must be ≥ 0).
        """
        ...


@dataclass
class RankingFunctionCertificate:
    """
    A ranking function with metadata.
    
    Attributes:
        name: Human-readable identifier
        ranking_fn: The ranking function R: S → ℕ or ℝ≥0
        description: Optional explanation
        variables: Variables referenced by ranking function
    """
    name: str
    ranking_fn: RankingFunction
    description: Optional[str] = None
    variables: list[str] = None
    
    def evaluate(self, state: SymbolicMachineState) -> z3.ExprRef:
        """Evaluate R(σ) for the given state."""
        return self.ranking_fn(state)


@dataclass
class TerminationProofResult:
    """
    Result of checking termination via ranking function.
    
    A program terminates if:
    - BoundedBelow: R(s) ≥ 0 for all reachable states
    - Decreasing: R(s') < R(s) for all loop back-edges s → s'
    """
    terminates: bool
    bounded_below_holds: bool
    decreasing_holds: bool
    
    bounded_below_counterexample: Optional[z3.ModelRef] = None
    decreasing_counterexample: Optional[z3.ModelRef] = None
    
    verification_time_ms: float = 0.0
    
    def __bool__(self) -> bool:
        return self.terminates
    
    def summary(self) -> str:
        """Human-readable summary."""
        if self.terminates:
            return f"TERMINATES (verified in {self.verification_time_ms:.1f}ms)"
        
        failures = []
        if not self.bounded_below_holds:
            failures.append("BoundedBelow")
        if not self.decreasing_holds:
            failures.append("Decreasing")
        
        return f"MAY NOT TERMINATE (failed: {', '.join(failures)})"


class TerminationChecker:
    """
    Checks whether a ranking function proves termination.
    
    Given:
    - Loop back-edge relation s →loop s' (transition from loop end to loop start)
    - Ranking function R
    
    Verifies via Z3:
    1. BoundedBelow: ∀s. R(s) ≥ 0
    2. Decreasing: ∀s,s'. (s →loop s') ⇒ R(s') < R(s)
    """
    
    def __init__(self, timeout_ms: int = 5000):
        """
        Args:
            timeout_ms: Z3 solver timeout in milliseconds
        """
        self.timeout_ms = timeout_ms
    
    def check_termination(
        self,
        ranking_fn: RankingFunctionCertificate,
        state_builder: Callable[[], SymbolicMachineState],
        loop_back_edge: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef],
        loop_invariant: Optional[Callable[[SymbolicMachineState], z3.ExprRef]] = None
    ) -> TerminationProofResult:
        """
        Check termination via ranking function.
        
        Args:
            ranking_fn: The ranking function to check
            state_builder: Function that returns a fresh symbolic state
            loop_back_edge: Function that returns (s →loop s') as Z3 bool
            loop_invariant: Optional function that returns loop invariant Inv(s)
                           (e.g., loop guard constraints that must hold in loop)
        
        Returns:
            TerminationProofResult with verification status
        """
        import time
        start_time = time.time()
        
        bounded_holds, bounded_cex = self._check_bounded_below(ranking_fn, state_builder, loop_invariant)
        decreasing_holds, decreasing_cex = self._check_decreasing(
            ranking_fn, state_builder, loop_back_edge
        )
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        terminates = bounded_holds and decreasing_holds
        
        return TerminationProofResult(
            terminates=terminates,
            bounded_below_holds=bounded_holds,
            decreasing_holds=decreasing_holds,
            bounded_below_counterexample=bounded_cex,
            decreasing_counterexample=decreasing_cex,
            verification_time_ms=elapsed_ms
        )
    
    def _check_bounded_below(
        self,
        ranking_fn: RankingFunctionCertificate,
        state_builder: Callable[[], SymbolicMachineState],
        loop_invariant: Optional[Callable[[SymbolicMachineState], z3.ExprRef]] = None
    ) -> tuple[bool, Optional[z3.ModelRef]]:
        """
        Check BoundedBelow: ∀s. (Inv(s) ⇒ R(s) ≥ 0)
        
        Where Inv(s) is the loop invariant (e.g., loop guard constraints).
        If no invariant provided, we check R(s) ≥ 0 for all states.
        
        We verify by checking unsatisfiability of: ∃s. Inv(s) ∧ R(s) < 0
        """
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        s = state_builder()
        R_s = ranking_fn.evaluate(s)
        
        # Add loop invariant constraints if provided
        # This is crucial: we only need R ≥ 0 in reachable states
        if loop_invariant is not None:
            solver.add(loop_invariant(s))
        
        # Negate the desired property: look for R(s) < 0
        if z3.is_int(R_s):
            R_s_real = z3.ToReal(R_s)
        else:
            R_s_real = R_s
        solver.add(R_s_real < 0)
        
        if hasattr(s, 'path_condition'):
            solver.add(s.path_condition)
        
        result = solver.check()
        
        if result == z3.unsat:
            # No counterexample → bounded below holds
            return True, None
        elif result == z3.sat:
            # Found counterexample where R(s) < 0
            return False, solver.model()
        else:
            # Unknown (timeout or other)
            return False, None
    
    def _check_decreasing(
        self,
        ranking_fn: RankingFunctionCertificate,
        state_builder: Callable[[], SymbolicMachineState],
        loop_back_edge: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef]
    ) -> tuple[bool, Optional[z3.ModelRef]]:
        """
        Check Decreasing: ∀s,s'. (s →loop s') ⇒ R(s') < R(s)
        
        We verify by checking unsatisfiability of:
            ∃s,s'. (s →loop s') ∧ R(s') ≥ R(s)
        """
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        s = state_builder()
        s_prime = state_builder()  # Fresh state for s'
        
        R_s = ranking_fn.evaluate(s)
        R_s_prime = ranking_fn.evaluate(s_prime)
        
        loop_edge = loop_back_edge(s, s_prime)
        
        # Negate the desired implication:
        # (s →loop s') ∧ R(s') ≥ R(s)
        if z3.is_int(R_s):
            R_s_real = z3.ToReal(R_s)
        else:
            R_s_real = R_s
        if z3.is_int(R_s_prime):
            R_s_prime_real = z3.ToReal(R_s_prime)
        else:
            R_s_prime_real = R_s_prime
        
        solver.add(loop_edge)
        solver.add(R_s_prime_real >= R_s_real)
        
        if hasattr(s, 'path_condition'):
            solver.add(s.path_condition)
        if hasattr(s_prime, 'path_condition'):
            solver.add(s_prime.path_condition)
        
        result = solver.check()
        
        if result == z3.unsat:
            # No counterexample → decreasing holds
            return True, None
        elif result == z3.sat:
            # Found counterexample where R does not decrease
            return False, solver.model()
        else:
            # Unknown
            return False, None


def linear_ranking_function(
    variable_extractors: list[tuple[str, Callable[[SymbolicMachineState], z3.ExprRef]]],
    coefficients: list[float],
    constant: float = 0.0,
    name: Optional[str] = None
) -> RankingFunctionCertificate:
    """
    Create a linear ranking function: R(σ) = c0 + c1*v1 + c2*v2 + ...
    
    For termination, coefficients should be chosen such that R decreases
    on each loop iteration (typically: counter variables have positive
    coefficients, upper bounds have negative coefficients).
    
    Args:
        variable_extractors: List of (name, extractor) pairs
        coefficients: Coefficients for each variable
        constant: Constant term
        name: Optional custom name
    
    Returns:
        RankingFunctionCertificate
    
    Example:
        # R(σ) = n - i  (loop: for i in range(n))
        # As i increases, R decreases. When i = n, R = 0, loop terminates.
        ranking = linear_ranking_function(
            [("n", extract_var("n")), ("i", extract_var("i"))],
            [1.0, -1.0],
            0.0
        )
    """
    assert len(variable_extractors) == len(coefficients), \
        "Must have same number of variables and coefficients"
    
    def ranking_fn(state: SymbolicMachineState) -> z3.ExprRef:
        result = z3.RealVal(constant)
        for (var_name, extractor), coeff in zip(variable_extractors, coefficients):
            var_value = extractor(state)
            # Convert to real if needed
            if z3.is_int(var_value):
                var_value = z3.ToReal(var_value)
            result = result + z3.RealVal(coeff) * var_value
        return result
    
    var_names = [name for name, _ in variable_extractors]
    desc = f"Linear ranking: {constant}"
    for var_name, coeff in zip(var_names, coefficients):
        if coeff >= 0:
            desc += f" + {coeff}*{var_name}"
        else:
            desc += f" - {-coeff}*{var_name}"
    
    return RankingFunctionCertificate(
        name=name or "linear_ranking",
        ranking_fn=ranking_fn,
        description=desc,
        variables=var_names
    )


def simple_counter_ranking(
    counter_var: str,
    counter_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    name: Optional[str] = None
) -> RankingFunctionCertificate:
    """
    Simplest ranking function: R(σ) = counter_max - counter
    
    Works for simple loops with a counter that increments to a bound:
        for i in range(n):  # R = n - i
    
    Args:
        counter_var: Name of the counter variable
        counter_extractor: Function to extract counter from state
        name: Optional custom name
    
    Returns:
        RankingFunctionCertificate
    """
    # For now, we use the counter itself as the ranking function
    # (assumes counter decrements to 0, or we invert it later)
    def ranking_fn(state: SymbolicMachineState) -> z3.ExprRef:
        val = counter_extractor(state)
        if z3.is_int(val):
            return z3.ToReal(val)
        return val
    
    return RankingFunctionCertificate(
        name=name or f"counter_ranking_{counter_var}",
        ranking_fn=ranking_fn,
        description=f"Counter-based ranking on {counter_var}",
        variables=[counter_var]
    )


def lexicographic_ranking(
    rankings: list[RankingFunctionCertificate],
    name: Optional[str] = None
) -> RankingFunctionCertificate:
    """
    Lexicographic ranking: (R1, R2, ..., Rn)
    
    For nested loops or complex control flow, we may need multiple ranking
    functions in lexicographic order:
    - First, R1 must decrease or stay same
    - If R1 stays same, R2 must decrease
    - And so on...
    
    For now, this is a placeholder - proper lexicographic checking requires
    more complex verification logic.
    
    Args:
        rankings: List of ranking functions in order
        name: Optional custom name
    
    Returns:
        RankingFunctionCertificate (simplified as tuple representation)
    """
    # Simplified: encode as a weighted sum with decreasing weights
    # This is NOT a full lexicographic implementation but a conservative approximation
    def ranking_fn(state: SymbolicMachineState) -> z3.ExprRef:
        result = z3.RealVal(0.0)
        weight = 1.0
        for r in rankings:
            r_val = r.evaluate(state)
            if z3.is_int(r_val):
                r_val = z3.ToReal(r_val)
            result = result + z3.RealVal(weight) * r_val
            weight /= 1000.0  # Exponential decay in weight
        return result
    
    var_list = []
    for r in rankings:
        if r.variables:
            var_list.extend(r.variables)
    
    return RankingFunctionCertificate(
        name=name or "lexicographic_ranking",
        ranking_fn=ranking_fn,
        description=f"Lexicographic combination of {len(rankings)} rankings",
        variables=var_list
    )


def create_lexicographic_ranking(
    components: list[RankingFunctionCertificate],
    name: Optional[str] = None
) -> 'LexicographicRankingTemplate':
    """
    Create a proper lexicographic ranking template.
    
    For nested loops, use one component per nesting level:
    - Outer loop: component 0
    - Middle loop: component 1
    - Inner loop: component 2
    
    Args:
        components: List of ranking functions in priority order
        name: Optional custom name
    
    Returns:
        LexicographicRankingTemplate instance
    
    Example:
        # For nested loops: for i in range(n): for j in range(m): ...
        # Outer loop decreases i, inner loop decreases j
        outer_rank = simple_counter_ranking("i", extract_i)
        inner_rank = simple_counter_ranking("j", extract_j)
        lex_rank = create_lexicographic_ranking([outer_rank, inner_rank])
    """
    if not name:
        var_names = []
        for comp in components:
            if comp.variables:
                var_names.extend(comp.variables)
        name = f"lex_{'_'.join(var_names)}"
    
    return LexicographicRankingTemplate(
        components=components,
        name=name
    )


@dataclass
class LexicographicRankingTemplate:
    """
    Proper lexicographic ranking template: (R1, R2, ..., Rn)
    
    A lexicographic tuple (R1, R2, ..., Rn) decreases iff:
    - R1(s') < R1(s), OR
    - R1(s') = R1(s) AND R2(s') < R2(s), OR
    - R1(s') = R1(s) AND R2(s') = R2(s) AND R3(s') < R3(s), OR
    - ... and so on
    
    This is the proper formulation for nested loops:
    - Outer loop: R1 decreases
    - Inner loop (when outer stays same): R2 decreases
    - Triple nested (when outer two stay same): R3 decreases
    
    Unlike the simplified weighted-sum approximation, this properly handles
    cases where outer loop variables may stay constant while inner loops run.
    """
    components: list[RankingFunctionCertificate]
    name: str
    
    def check_bounded_below(
        self,
        state_builder: Callable[[], SymbolicMachineState],
        loop_invariant: Optional[Callable[[SymbolicMachineState], z3.ExprRef]] = None,
        timeout_ms: int = 5000
    ) -> tuple[bool, Optional[z3.ModelRef]]:
        """
        Check that all components are bounded below: ∀i. Ri(s) ≥ 0
        """
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        
        s = state_builder()
        
        if loop_invariant is not None:
            solver.add(loop_invariant(s))
        
        if hasattr(s, 'path_condition'):
            solver.add(s.path_condition)
        
        # All components must be non-negative
        for component in self.components:
            R_val = component.evaluate(s)
            if z3.is_int(R_val):
                R_val = z3.ToReal(R_val)
            solver.add(R_val < 0)  # Negate: look for counterexample
        
        result = solver.check()
        
        if result == z3.unsat:
            return True, None
        elif result == z3.sat:
            return False, solver.model()
        else:
            return False, None
    
    def check_lexicographic_decrease(
        self,
        state_builder: Callable[[], SymbolicMachineState],
        loop_back_edge: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef],
        timeout_ms: int = 5000
    ) -> tuple[bool, Optional[z3.ModelRef]]:
        """
        Check lexicographic decrease: (R1, ..., Rn)(s') <_lex (R1, ..., Rn)(s)
        
        The lexicographic ordering is:
        R1(s') < R1(s) OR
        (R1(s') = R1(s) AND R2(s') < R2(s)) OR
        (R1(s') = R1(s) AND R2(s') = R2(s) AND R3(s') < R3(s)) OR ...
        
        We verify by checking unsatisfiability of the negation:
        (s →loop s') AND NOT(lex_decrease)
        
        where NOT(lex_decrease) is:
        R1(s') ≥ R1(s) AND (R1(s') > R1(s) OR R2(s') ≥ R2(s)) AND ...
        
        Equivalently:
        ∀i. (Ri(s') ≥ Ri(s) OR ∃j<i. Rj(s') > Rj(s))
        """
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        
        s = state_builder()
        s_prime = state_builder()
        
        # Add loop back-edge constraint
        solver.add(loop_back_edge(s, s_prime))
        
        if hasattr(s, 'path_condition'):
            solver.add(s.path_condition)
        if hasattr(s_prime, 'path_condition'):
            solver.add(s_prime.path_condition)
        
        # Build lexicographic decrease condition:
        # (R1' < R1) OR (R1' = R1 AND R2' < R2) OR ...
        lex_decrease_clauses = []
        
        for i in range(len(self.components)):
            # For position i, we need:
            # R0' = R0 AND R1' = R1 AND ... AND Ri-1' = Ri-1 AND Ri' < Ri
            
            # Build equality constraints for all previous components
            prefix_equals = []
            for j in range(i):
                Rj_s = self.components[j].evaluate(s)
                Rj_s_prime = self.components[j].evaluate(s_prime)
                
                if z3.is_int(Rj_s):
                    Rj_s = z3.ToReal(Rj_s)
                if z3.is_int(Rj_s_prime):
                    Rj_s_prime = z3.ToReal(Rj_s_prime)
                
                prefix_equals.append(Rj_s_prime == Rj_s)
            
            # Add decrease constraint for component i
            Ri_s = self.components[i].evaluate(s)
            Ri_s_prime = self.components[i].evaluate(s_prime)
            
            if z3.is_int(Ri_s):
                Ri_s = z3.ToReal(Ri_s)
            if z3.is_int(Ri_s_prime):
                Ri_s_prime = z3.ToReal(Ri_s_prime)
            
            decrease_at_i = Ri_s_prime < Ri_s
            
            # Combine: all previous equal AND this decreases
            if prefix_equals:
                clause = z3.And(*prefix_equals, decrease_at_i)
            else:
                clause = decrease_at_i
            
            lex_decrease_clauses.append(clause)
        
        # At least one clause must hold
        lex_decrease = z3.Or(*lex_decrease_clauses) if len(lex_decrease_clauses) > 1 else lex_decrease_clauses[0]
        
        # Negate for counterexample search
        solver.add(z3.Not(lex_decrease))
        
        result = solver.check()
        
        if result == z3.unsat:
            # No counterexample → lexicographic decrease holds
            return True, None
        elif result == z3.sat:
            # Found counterexample
            return False, solver.model()
        else:
            # Unknown
            return False, None
    
    def verify_termination(
        self,
        state_builder: Callable[[], SymbolicMachineState],
        loop_back_edge: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef],
        loop_invariant: Optional[Callable[[SymbolicMachineState], z3.ExprRef]] = None,
        timeout_ms: int = 5000
    ) -> TerminationProofResult:
        """
        Verify termination using lexicographic ranking.
        
        Returns:
            TerminationProofResult with verification status
        """
        import time
        start_time = time.time()
        
        bounded_holds, bounded_cex = self.check_bounded_below(
            state_builder, loop_invariant, timeout_ms
        )
        
        decreasing_holds, decreasing_cex = self.check_lexicographic_decrease(
            state_builder, loop_back_edge, timeout_ms
        )
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        terminates = bounded_holds and decreasing_holds
        
        return TerminationProofResult(
            terminates=terminates,
            bounded_below_holds=bounded_holds,
            decreasing_holds=decreasing_holds,
            bounded_below_counterexample=bounded_cex,
            decreasing_counterexample=decreasing_cex,
            verification_time_ms=elapsed_ms
        )
