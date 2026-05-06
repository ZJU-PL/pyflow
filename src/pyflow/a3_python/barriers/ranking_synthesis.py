"""
Ranking function synthesis for termination proofs.

This module implements automatic synthesis of ranking functions via:
1. Template enumeration (linear, lexicographic)
2. Z3-based validation of decreasing property
3. Loop back-edge identification from CFG

Ranking function R: S → ℝ≥0 must satisfy:
- BoundedBelow: ∀s. R(s) ≥ 0
- Decreasing: ∀s,s'. (s →loop s') ⇒ R(s') < R(s)

This proves termination: the ranking value strictly decreases on each
loop iteration, so infinite loops are impossible.
"""

from dataclasses import dataclass
from typing import Callable, Optional, Iterator, Union
import z3
import itertools

from .ranking import (
    RankingFunctionCertificate,
    TerminationChecker,
    TerminationProofResult,
    linear_ranking_function,
    simple_counter_ranking,
    lexicographic_ranking,
    LexicographicRankingTemplate,
)
from ..semantics.symbolic_vm import SymbolicMachineState


@dataclass
class RankingSynthesisConfig:
    """
    Configuration for ranking function synthesis.
    
    Attributes:
        max_templates: Maximum number of ranking templates to try
        timeout_per_template_ms: Z3 timeout for each template check
        coefficient_range: Range of coefficients to try (start, stop, step)
        max_lexicographic_depth: Maximum number of components in lexicographic ranking
    """
    max_templates: int = 50
    timeout_per_template_ms: int = 5000
    coefficient_range: tuple[float, float, float] = (-5.0, 5.5, 1.0)
    max_lexicographic_depth: int = 3


@dataclass
class RankingSynthesisResult:
    """
    Result of ranking function synthesis.
    
    Attributes:
        success: Whether a valid ranking function was found
        ranking: The synthesized ranking (RankingFunctionCertificate or LexicographicRankingTemplate)
        termination_proof: Termination verification result (if success)
        templates_tried: Number of templates attempted
        synthesis_time_ms: Total synthesis time
    """
    success: bool
    ranking: Optional[Union[RankingFunctionCertificate, LexicographicRankingTemplate]] = None
    termination_proof: Optional[TerminationProofResult] = None
    templates_tried: int = 0
    synthesis_time_ms: float = 0.0
    
    def summary(self) -> str:
        """Human-readable summary."""
        if self.success:
            name = self.ranking.name if hasattr(self.ranking, 'name') else str(self.ranking)
            return (
                f"TERMINATES: synthesized {name} "
                f"(tried {self.templates_tried} templates in {self.synthesis_time_ms:.1f}ms)"
            )
        else:
            return (
                f"NON_TERMINATION or UNKNOWN "
                f"(tried {self.templates_tried} templates in {self.synthesis_time_ms:.1f}ms)"
            )


class RankingSynthesizer:
    """
    Synthesizes ranking functions via template enumeration.
    
    Strategy:
    1. Identify loop variables from bytecode/CFG
    2. Enumerate ranking templates:
       - Single counter: R = counter
       - Linear: R = c0 + c1*v1 + c2*v2 + ...
       - Lexicographic: (R1, R2, ...) for nested loops
    3. For each template, verify via Z3:
       - BoundedBelow: R(s) ≥ 0
       - Decreasing: R(s') < R(s) on loop back-edges
    4. Return first valid ranking function
    """
    
    def __init__(self, config: Optional[RankingSynthesisConfig] = None):
        """
        Args:
            config: Synthesis configuration (uses defaults if None)
        """
        self.config = config or RankingSynthesisConfig()
        self.checker = TerminationChecker(
            timeout_ms=self.config.timeout_per_template_ms
        )
    
    def synthesize(
        self,
        state_builder: Callable[[], SymbolicMachineState],
        loop_back_edge: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef],
        variable_extractors: list[tuple[str, Callable[[SymbolicMachineState], z3.ExprRef]]],
        loop_type_hint: Optional[str] = None
    ) -> RankingSynthesisResult:
        """
        Synthesize a ranking function for the given loop.
        
        Args:
            state_builder: Function that returns a fresh symbolic state
            loop_back_edge: Function encoding s →loop s' as Z3 bool
            variable_extractors: List of (name, extractor) for loop variables
            loop_type_hint: Optional hint about loop structure ("simple_counter", "nested", etc.)
        
        Returns:
            RankingSynthesisResult with synthesized ranking (if found)
        """
        import time
        start_time = time.time()
        
        templates_tried = 0
        
        # Extract loop invariant from back-edge
        # The back-edge encodes: guard(s) ∧ update(s, s')
        # We approximate the invariant as: ∃s'. back_edge(s, s')
        def loop_invariant(s):
            s_prime = state_builder()
            return loop_back_edge(s, s_prime)
        
        # Generate candidate ranking templates
        template_generator = self._generate_ranking_templates(
            variable_extractors,
            loop_type_hint
        )
        
        for ranking in template_generator:
            if templates_tried >= self.config.max_templates:
                break
            
            templates_tried += 1
            
            # Check termination via this ranking function
            # Handle both RankingFunctionCertificate and LexicographicRankingTemplate
            if isinstance(ranking, LexicographicRankingTemplate):
                # Use native lexicographic verification
                result = ranking.verify_termination(
                    state_builder,
                    loop_back_edge,
                    loop_invariant,
                    self.config.timeout_per_template_ms
                )
            else:
                # Use standard TerminationChecker for single ranking functions
                result = self.checker.check_termination(
                    ranking,
                    state_builder,
                    loop_back_edge,
                    loop_invariant  # Pass the extracted invariant
                )
            
            if result.terminates:
                # Found a valid ranking function!
                elapsed_ms = (time.time() - start_time) * 1000
                return RankingSynthesisResult(
                    success=True,
                    ranking=ranking,
                    termination_proof=result,
                    templates_tried=templates_tried,
                    synthesis_time_ms=elapsed_ms
                )
        
        # No valid ranking function found
        elapsed_ms = (time.time() - start_time) * 1000
        return RankingSynthesisResult(
            success=False,
            templates_tried=templates_tried,
            synthesis_time_ms=elapsed_ms
        )
    
    def _generate_ranking_templates(
        self,
        variable_extractors: list[tuple[str, Callable[[SymbolicMachineState], z3.ExprRef]]],
        loop_type_hint: Optional[str] = None
    ) -> Iterator[RankingFunctionCertificate]:
        """
        Generate candidate ranking function templates.
        
        Ordering strategy (simplest first):
        1. Single counter variables (most common case)
        2. Simple linear combinations (sum/difference of 2 vars)
        3. Multi-variable linear rankings
        4. Lexicographic rankings (for nested loops)
        """
        if not variable_extractors:
            return
        
        # Phase 1: Try each variable as a simple counter
        # R = var (assumes var is decreasing counter)
        # Common pattern: while i > 0: ... i -= 1
        for var_name, var_extractor in variable_extractors:
            yield simple_counter_ranking(
                var_name,
                var_extractor,
                name=f"counter_{var_name}"
            )
        
        # Phase 2: Try inverted counters for increasing loops
        # R = max_bound - var (for: i = 0; while i < n: ... i += 1)
        # Common loop counter patterns:
        if len(variable_extractors) >= 2:
            for (counter_name, counter_ext), (bound_name, bound_ext) in itertools.combinations(variable_extractors, 2):
                # Try R = bound - counter
                yield linear_ranking_function(
                    [(bound_name, bound_ext), (counter_name, counter_ext)],
                    [1.0, -1.0],
                    0.0,
                    name=f"{bound_name}-{counter_name}"
                )
                # Try R = counter - bound (if counter is large and decreasing)
                yield linear_ranking_function(
                    [(counter_name, counter_ext), (bound_name, bound_ext)],
                    [1.0, -1.0],
                    0.0,
                    name=f"{counter_name}-{bound_name}"
                )
        
        # Phase 3: Try single-variable linear rankings with constants
        # R = c0 + c1*var
        for var_name, var_extractor in variable_extractors:
            for coeff in self._float_range(*self.config.coefficient_range):
                if abs(coeff) < 0.1:  # Skip near-zero
                    continue
                
                # Try different constant offsets
                for const in [0.0, 10.0, 100.0]:
                    yield linear_ranking_function(
                        [(var_name, var_extractor)],
                        [coeff],
                        const,
                        name=f"{const:+.1f}{coeff:+.1f}*{var_name}"
                    )
        
        # Phase 4: Try two-variable linear rankings
        # R = c0 + c1*v1 + c2*v2
        # Common for loops like: while i < n and j > 0: ...
        if len(variable_extractors) >= 2:
            for (v1_name, v1_ext), (v2_name, v2_ext) in itertools.combinations(variable_extractors, 2):
                # Try common coefficient patterns
                coefficient_patterns = [
                    ([1.0, -1.0], 0.0),   # v1 - v2
                    ([-1.0, 1.0], 0.0),   # v2 - v1
                    ([1.0, 1.0], 0.0),    # v1 + v2 (both decreasing)
                    ([2.0, -1.0], 0.0),   # 2*v1 - v2
                    ([1.0, -2.0], 0.0),   # v1 - 2*v2
                ]
                
                for coeffs, const in coefficient_patterns:
                    yield linear_ranking_function(
                        [(v1_name, v1_ext), (v2_name, v2_ext)],
                        coeffs,
                        const,
                        name=f"{const:+.1f}{coeffs[0]:+.1f}*{v1_name}{coeffs[1]:+.1f}*{v2_name}"
                    )
        
        # Phase 5: Try three-variable linear rankings
        # R = c0 + c1*v1 + c2*v2 + c3*v3
        if len(variable_extractors) >= 3:
            for vars_combo in itertools.combinations(variable_extractors, 3):
                # Just try a few simple patterns to avoid explosion
                yield linear_ranking_function(
                    [(name, ext) for name, ext in vars_combo],
                    [1.0, 1.0, 1.0],
                    0.0,
                    name=f"sum_{'_'.join(name for name, _ in vars_combo)}"
                )
                yield linear_ranking_function(
                    [(name, ext) for name, ext in vars_combo],
                    [1.0, -1.0, 1.0],
                    0.0,
                    name=f"mixed_{'_'.join(name for name, _ in vars_combo)}"
                )
        
        # Phase 6: Try proper lexicographic rankings for nested loops
        # Use LexicographicRankingTemplate for true lexicographic decrease checking
        # Hint: if loop_type_hint == "nested", prioritize these
        if len(variable_extractors) >= 2 and self.config.max_lexicographic_depth >= 2:
            # Create component rankings for lexicographic combination
            component_rankings = []
            for var_name, var_extractor in variable_extractors[:self.config.max_lexicographic_depth]:
                component_rankings.append(
                    simple_counter_ranking(var_name, var_extractor)
                )
            
            # Try lexicographic combinations using proper LexicographicRankingTemplate
            # This replaces the weighted-sum approximation with true lexicographic checking
            if len(component_rankings) >= 2:
                # Two-component lexicographic ranking
                yield LexicographicRankingTemplate(
                    components=component_rankings[:2],
                    name=f"lex_{'_'.join(r.variables[0] for r in component_rankings[:2])}"
                )
            
            if len(component_rankings) >= 3:
                # Three-component lexicographic ranking (for triple-nested loops)
                yield LexicographicRankingTemplate(
                    components=component_rankings[:3],
                    name=f"lex_{'_'.join(r.variables[0] for r in component_rankings[:3])}"
                )
            
            # Also try mixed lexicographic combinations with linear rankings
            # For nested loops with complex inner loop behavior
            if len(variable_extractors) >= 2:
                for i in range(min(len(variable_extractors) - 1, self.config.max_lexicographic_depth - 1)):
                    # First component: simple counter
                    first = simple_counter_ranking(
                        variable_extractors[i][0], 
                        variable_extractors[i][1]
                    )
                    # Second component: difference of next two variables
                    if i + 2 < len(variable_extractors):
                        (v1_name, v1_ext) = variable_extractors[i + 1]
                        (v2_name, v2_ext) = variable_extractors[i + 2]
                        second = linear_ranking_function(
                            [(v1_name, v1_ext), (v2_name, v2_ext)],
                            [1.0, -1.0],
                            0.0,
                            name=f"{v1_name}-{v2_name}"
                        )
                        
                        yield LexicographicRankingTemplate(
                            components=[first, second],
                            name=f"lex_{variable_extractors[i][0]}_then_{v1_name}-{v2_name}"
                        )
        
        # Phase 7: Try quadratic rankings for polynomial decrease
        # R = c0 + c1*var + c2*var²
        # Less common but useful for complex decrease patterns
        if len(variable_extractors) >= 1:
            for var_name, var_extractor in variable_extractors:
                # Try a few quadratic patterns
                # Downward parabola: 100 - var²
                yield self._create_quadratic_ranking(
                    var_name, var_extractor,
                    coeff_x2=-1.0, coeff_x=0.0, const=100.0
                )
                # Mixed: 50 + 10*var - var²
                yield self._create_quadratic_ranking(
                    var_name, var_extractor,
                    coeff_x2=-1.0, coeff_x=10.0, const=50.0
                )
    
    def _create_quadratic_ranking(
        self,
        var_name: str,
        var_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
        coeff_x2: float,
        coeff_x: float,
        const: float
    ) -> RankingFunctionCertificate:
        """Create a quadratic ranking function: R = const + coeff_x*var + coeff_x2*var²"""
        def ranking_fn(state: SymbolicMachineState) -> z3.ExprRef:
            var_val = var_extractor(state)
            if z3.is_int(var_val):
                var_val = z3.ToReal(var_val)
            
            result = z3.RealVal(const)
            if abs(coeff_x) > 0.01:
                result = result + z3.RealVal(coeff_x) * var_val
            if abs(coeff_x2) > 0.01:
                result = result + z3.RealVal(coeff_x2) * (var_val * var_val)
            
            return result
        
        return RankingFunctionCertificate(
            name=f"quad_{var_name}_{coeff_x2}_{coeff_x}_{const}",
            ranking_fn=ranking_fn,
            description=f"Quadratic ranking: {const}{coeff_x:+.1f}*{var_name}{coeff_x2:+.1f}*{var_name}²",
            variables=[var_name]
        )
    
    def _float_range(self, start: float, stop: float, step: float) -> Iterator[float]:
        """Generate floating-point range."""
        current = start
        while current < stop:
            yield current
            current += step


def synthesize_ranking_for_loop(
    state_builder: Callable[[], SymbolicMachineState],
    loop_back_edge: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef],
    variable_extractors: list[tuple[str, Callable[[SymbolicMachineState], z3.ExprRef]]],
    config: Optional[RankingSynthesisConfig] = None
) -> RankingSynthesisResult:
    """
    High-level convenience function: synthesize ranking for a specific loop.
    
    Args:
        state_builder: State builder for symbolic states
        loop_back_edge: Transition relation for loop back-edge
        variable_extractors: Loop variables
        config: Optional synthesis config
    
    Returns:
        RankingSynthesisResult
    """
    synthesizer = RankingSynthesizer(config)
    return synthesizer.synthesize(
        state_builder,
        loop_back_edge,
        variable_extractors
    )
