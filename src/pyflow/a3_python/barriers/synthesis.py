"""
Barrier certificate synthesis.

This module implements automatic synthesis of barrier certificates
using template enumeration + Z3 validation.

Synthesis strategy (start simple):
1. Enumerate candidate barrier templates (linear combinations)
2. For each template, check inductiveness via Z3
3. Return first valid certificate found

This is NOT a complete CEGIS loop - we enumerate templates deterministically
and check them. Future work can add counterexample-guided refinement.
"""

from dataclasses import dataclass
from typing import Callable, Optional, Iterator
import z3
import itertools

from .invariants import (
    BarrierCertificate,
    InductivenessChecker,
    InductivenessResult,
    linear_combination_barrier,
)
from .templates import (
    stack_depth_barrier,
    variable_upper_bound_barrier,
    variable_lower_bound_barrier,
    constant_barrier,
    loop_range_barrier,
    collection_size_barrier,
    disjunction_barrier,
    progress_measure_barrier,
    quadratic_barrier,
    polynomial_barrier,
    bivariate_quadratic_barrier,
    disjunctive_region_barrier,
    conjunctive_region_barrier,
    piecewise_linear_barrier,
)
from ..semantics.symbolic_vm import SymbolicMachineState


@dataclass
class SynthesisConfig:
    """
    Configuration for barrier synthesis.
    
    Attributes:
        max_templates: Maximum number of templates to try
        timeout_per_template_ms: Z3 timeout for each template check
        coefficient_range: Range of coefficients to try (start, stop, step)
        constant_range: Range of constant terms to try
        epsilon: Safety margin for barriers
    """
    max_templates: int = 100
    timeout_per_template_ms: int = 5000
    coefficient_range: tuple[float, float, float] = (-10.0, 10.5, 1.0)
    constant_range: tuple[float, float, float] = (0.0, 20.5, 5.0)
    epsilon: float = 0.5


@dataclass
class SynthesisResult:
    """
    Result of barrier synthesis attempt.
    
    Attributes:
        success: Whether a valid barrier was found
        barrier: The synthesized barrier (if success)
        inductiveness: Inductiveness check result (if success)
        templates_tried: Number of templates attempted
        synthesis_time_ms: Total synthesis time
    """
    success: bool
    barrier: Optional[BarrierCertificate] = None
    inductiveness: Optional[InductivenessResult] = None
    templates_tried: int = 0
    synthesis_time_ms: float = 0.0
    
    def summary(self) -> str:
        """Human-readable summary."""
        if self.success:
            return (
                f"SYNTHESIZED {self.barrier.name} "
                f"(tried {self.templates_tried} templates in {self.synthesis_time_ms:.1f}ms)"
            )
        else:
            return (
                f"SYNTHESIS FAILED "
                f"(tried {self.templates_tried} templates in {self.synthesis_time_ms:.1f}ms)"
            )


class BarrierSynthesizer:
    """
    Synthesizes barrier certificates via template enumeration.
    
    The synthesizer tries templates in order of increasing complexity:
    1. Constants (trivial)
    2. Single-variable linear barriers
    3. Multi-variable linear combinations
    
    For each template, it checks inductiveness using Z3.
    """
    
    def __init__(self, config: Optional[SynthesisConfig] = None):
        """
        Args:
            config: Synthesis configuration (uses defaults if None)
        """
        self.config = config or SynthesisConfig()
        self.checker = InductivenessChecker(
            timeout_ms=self.config.timeout_per_template_ms
        )
    
    def synthesize(
        self,
        initial_state_builder: Callable[[], SymbolicMachineState],
        unsafe_predicate: Callable[[SymbolicMachineState], z3.ExprRef],
        step_relation: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef],
        variable_extractors: list[tuple[str, Callable[[SymbolicMachineState], z3.ExprRef]]] = None,
    ) -> SynthesisResult:
        """
        Synthesize a barrier certificate for the given system.
        
        Args:
            initial_state_builder: Function that returns a symbolic initial state
            unsafe_predicate: Function that returns U(σ) as Z3 bool
            step_relation: Function that returns (s → s') as Z3 bool
            variable_extractors: Optional list of (name, extractor) for program variables
        
        Returns:
            SynthesisResult with the synthesized barrier (if found)
        """
        import time
        start_time = time.time()
        
        templates_tried = 0
        
        # Generate candidate templates
        template_generator = self._generate_templates(variable_extractors or [])
        
        for barrier in template_generator:
            if templates_tried >= self.config.max_templates:
                break
            
            templates_tried += 1
            
            # Check inductiveness
            result = self.checker.check_inductiveness(
                barrier,
                initial_state_builder,
                unsafe_predicate,
                step_relation
            )
            
            if result.is_inductive:
                # Found a valid barrier!
                elapsed_ms = (time.time() - start_time) * 1000
                return SynthesisResult(
                    success=True,
                    barrier=barrier,
                    inductiveness=result,
                    templates_tried=templates_tried,
                    synthesis_time_ms=elapsed_ms
                )
        
        # No valid barrier found
        elapsed_ms = (time.time() - start_time) * 1000
        return SynthesisResult(
            success=False,
            templates_tried=templates_tried,
            synthesis_time_ms=elapsed_ms
        )
    
    def _generate_templates(
        self,
        variable_extractors: list[tuple[str, Callable[[SymbolicMachineState], z3.ExprRef]]]
    ) -> Iterator[BarrierCertificate]:
        """
        Generate candidate barrier templates in order of increasing complexity.
        
        Yields barrier certificates to try.
        """
        # Phase 1: Try some simple constant barriers
        # These can only work if the unsafe region is unreachable from init
        # (i.e., separated by topology alone)
        for const in self._float_range(*self.config.constant_range):
            yield constant_barrier(const, name=f"const_{const}")
        
        # Phase 2: Try single-variable linear barriers
        # For each variable v: B(σ) = c0 + c1*v
        if variable_extractors:
            for var_name, var_extractor in variable_extractors:
                for c1 in self._float_range(*self.config.coefficient_range):
                    if abs(c1) < 0.1:  # Skip near-zero coefficients
                        continue
                    
                    for c0 in self._float_range(*self.config.constant_range):
                        barrier_fn = linear_combination_barrier(
                            [(var_name, var_extractor)],
                            [c1],
                            c0
                        )
                        yield BarrierCertificate(
                            name=f"{c0:+.1f}{c1:+.1f}*{var_name}",
                            barrier_fn=barrier_fn,
                            epsilon=self.config.epsilon,
                            variables=[var_name]
                        )
        
        # Phase 3: Try stack depth barriers specifically
        # These are common for STACK_OVERFLOW bugs
        for max_depth in range(5, 25, 5):
            yield stack_depth_barrier(max_depth)
        
        # Phase 3.5: Try loop range barriers for common iteration patterns
        # Try bounded loops with common limits
        if variable_extractors:
            for var_name, var_extractor in variable_extractors:
                # Check if this looks like a loop counter (heuristic: name contains 'i', 'iter', 'count')
                if any(hint in var_name.lower() for hint in ['i', 'iter', 'count', 'n', 'idx']):
                    for max_iter in [10, 100, 1000]:
                        yield loop_range_barrier(var_extractor, max_iter, name=f"loop_{var_name}≤{max_iter}")
        
        # Phase 3.6: Try collection size barriers
        # For variables that might be collections
        if variable_extractors:
            for var_name, var_extractor in variable_extractors:
                if any(hint in var_name.lower() for hint in ['list', 'dict', 'set', 'collection', 'len']):
                    for max_size in [10, 100, 1000]:
                        yield collection_size_barrier(var_extractor, max_size, name=f"{var_name}_size≤{max_size}")
        
        # Phase 3.7: Try progress measure barriers for termination
        # These are particularly useful for NON_TERMINATION proofs
        if variable_extractors:
            for var_name, var_extractor in variable_extractors:
                # Progress measures: strictly decreasing quantities
                # Try: B(σ) = var (assuming var decreases)
                yield progress_measure_barrier(var_extractor, name=f"progress_{var_name}")
        
        # Phase 4: Try two-variable linear combinations
        # B(σ) = c0 + c1*v1 + c2*v2
        if len(variable_extractors) >= 2:
            # Only try a subset to avoid combinatorial explosion
            for (v1_name, v1_ext), (v2_name, v2_ext) in itertools.combinations(variable_extractors, 2):
                for c1 in [-1.0, 1.0]:  # Keep it simple
                    for c2 in [-1.0, 1.0]:
                        for c0 in [0.0, 10.0]:
                            barrier_fn = linear_combination_barrier(
                                [(v1_name, v1_ext), (v2_name, v2_ext)],
                                [c1, c2],
                                c0
                            )
                            yield BarrierCertificate(
                                name=f"{c0}{c1:+.1f}*{v1_name}{c2:+.1f}*{v2_name}",
                                barrier_fn=barrier_fn,
                                epsilon=self.config.epsilon,
                                variables=[v1_name, v2_name]
                            )
        
        # Phase 5: Try quadratic barriers for single variables
        # B(σ) = a·x² + b·x + c
        # Useful for proving bounded growth with non-linear patterns
        if variable_extractors:
            for var_name, var_extractor in variable_extractors:
                # Try common quadratic patterns
                quadratic_configs = [
                    # Downward parabola: B = c - x² (proves |x| bounded)
                    (-1.0, 0.0, 100.0),
                    (-1.0, 0.0, 25.0),
                    # Upward parabola with negative linear: B = x² - 10x + 20
                    (1.0, -10.0, 20.0),
                    # Shifted parabola: B = -(x-5)² + 25 = -x² + 10x
                    (-1.0, 10.0, 0.0),
                ]
                for coeff_x2, coeff_x, constant in quadratic_configs:
                    yield quadratic_barrier(
                        var_name, var_extractor,
                        coeff_x2, coeff_x, constant,
                        name=f"quad_{var_name}_{coeff_x2}_{coeff_x}_{constant}"
                    )
        
        # Phase 6: Try bivariate quadratic barriers
        # B(σ) = a·x² + b·y² + c·xy + d·x + e·y + f
        # Useful for coupled variables (e.g., x² + y² ≤ R²)
        if len(variable_extractors) >= 2:
            for (v1_name, v1_ext), (v2_name, v2_ext) in itertools.combinations(variable_extractors, 2):
                # Try elliptical bounds: 100 - x² - y² (circle/ellipse)
                yield bivariate_quadratic_barrier(
                    v1_name, v2_name, v1_ext, v2_ext,
                    coeff_x2=-1.0, coeff_y2=-1.0, coeff_xy=0.0,
                    coeff_x=0.0, coeff_y=0.0, constant=100.0,
                    name=f"ellipse_{v1_name}_{v2_name}"
                )
                # Try hyperbolic bounds: x² - y² ≤ C
                yield bivariate_quadratic_barrier(
                    v1_name, v2_name, v1_ext, v2_ext,
                    coeff_x2=1.0, coeff_y2=-1.0, coeff_xy=0.0,
                    coeff_x=0.0, coeff_y=0.0, constant=50.0,
                    name=f"hyperbola_{v1_name}_{v2_name}"
                )
        
        # Phase 7: Try cubic polynomials for more complex bounds
        # B(σ) = c₀ + c₁·x + c₂·x² + c₃·x³
        if variable_extractors:
            for var_name, var_extractor in variable_extractors:
                # Cubic with positive leading coefficient (bounded below)
                yield polynomial_barrier(
                    var_name, var_extractor,
                    coefficients=[10.0, -5.0, 0.0, 0.01],  # 10 - 5x + 0.01x³
                    name=f"cubic_{var_name}_bounded"
                )
        
        # Phase 8: Try piecewise linear barriers (phase-dependent invariants)
        # Useful when different program phases have different bounds
        if variable_extractors:
            for var_name, var_extractor in variable_extractors:
                # Example: initialization phase (x < 10), main phase (10 ≤ x < 100), cleanup (x ≥ 100)
                # Different slopes for each phase
                breakpoints = [
                    (10.0, -1.0, 20.0),   # x < 10: B = 20 - x
                    (100.0, -0.1, 11.0),  # 10 ≤ x < 100: B = 11 - 0.1x
                    (1000.0, -0.01, 10.0) # x ≥ 100: B = 10 - 0.01x
                ]
                yield piecewise_linear_barrier(
                    var_name, var_extractor, breakpoints,
                    name=f"piecewise_{var_name}"
                )
        
        # Phase 9: Try disjunctions of simple barriers
        # B(σ) = max(B₁(σ), B₂(σ), ...)
        # Useful for control-flow dependent safety
        if len(variable_extractors) >= 2:
            # Create simple component barriers
            simple_barriers = []
            for var_name, var_extractor in variable_extractors[:3]:  # Limit to first 3 vars
                # Upper bound barrier: 100 - x
                simple_barriers.append(
                    variable_upper_bound_barrier(var_name, 100.0, var_extractor)
                )
            
            if len(simple_barriers) >= 2:
                # Try disjunction of 2 barriers
                yield disjunctive_region_barrier(
                    simple_barriers[:2],
                    name="disj_2_bounds"
                )
                
                # Try disjunction of all (up to 3)
                if len(simple_barriers) >= 3:
                    yield disjunctive_region_barrier(
                        simple_barriers,
                        name="disj_3_bounds"
                    )
        
        # Phase 10: Try conjunctions for multi-variable bounds
        # B(σ) = min(B₁(σ), B₂(σ), ...)
        # All conditions must hold simultaneously
        if len(variable_extractors) >= 2:
            simple_barriers = []
            for var_name, var_extractor in variable_extractors[:3]:
                # Each variable bounded independently
                simple_barriers.append(
                    variable_upper_bound_barrier(var_name, 50.0, var_extractor)
                )
            
            if len(simple_barriers) >= 2:
                yield conjunctive_region_barrier(
                    simple_barriers[:2],
                    name="conj_2_bounds"
                )
                
                if len(simple_barriers) >= 3:
                    yield conjunctive_region_barrier(
                        simple_barriers,
                        name="conj_3_bounds"
                    )
        
        # Phase 11: Try higher-degree polynomial barriers (quartic, quintic)
        # Only for variables where we suspect complex growth patterns
        if variable_extractors:
            for var_name, var_extractor in variable_extractors[:2]:  # Limit to avoid explosion
                # Quartic: c₀ + c₁x + c₂x² + c₃x³ + c₄x⁴
                yield polynomial_barrier(
                    var_name, var_extractor,
                    coefficients=[100.0, 0.0, -1.0, 0.0, -0.01],  # 100 - x² - 0.01x⁴
                    name=f"quartic_{var_name}"
                )
    
    def _float_range(self, start: float, stop: float, step: float) -> Iterator[float]:
        """
        Generate floating-point range (like range() but for floats).
        """
        current = start
        while current < stop:
            yield current
            current += step


def synthesize_barrier_for_bug_type(
    bug_type: str,
    initial_state_builder: Callable[[], SymbolicMachineState],
    unsafe_predicate: Callable[[SymbolicMachineState], z3.ExprRef],
    step_relation: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef],
    config: Optional[SynthesisConfig] = None
) -> SynthesisResult:
    """
    High-level convenience function: synthesize a barrier for a specific bug type.
    
    This function provides bug-type-specific hints to guide synthesis:
    - STACK_OVERFLOW: prioritize stack depth barriers
    - DIV_ZERO, BOUNDS, etc.: prioritize variable range barriers
    
    Args:
        bug_type: Bug type name (e.g., "STACK_OVERFLOW", "DIV_ZERO")
        initial_state_builder: Initial state builder
        unsafe_predicate: Unsafe predicate
        step_relation: Step relation
        config: Optional synthesis config
    
    Returns:
        SynthesisResult
    """
    synthesizer = BarrierSynthesizer(config)
    
    # Bug-type-specific variable extractors
    # (In a full implementation, these would be inferred from the program)
    variable_extractors = []
    
    # For now, just use the generic synthesis
    # Future: add bug-type-specific heuristics
    return synthesizer.synthesize(
        initial_state_builder,
        unsafe_predicate,
        step_relation,
        variable_extractors
    )
