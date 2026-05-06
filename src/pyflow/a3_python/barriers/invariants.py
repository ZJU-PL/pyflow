"""
Barrier certificates and inductive invariants.

A barrier certificate B: S → ℝ separates initial states from unsafe states:
- Init: ∀s∈S0. B(s) ≥ ε
- Unsafe: ∀s∈U. B(s) ≤ -ε  
- Step: ∀s,s'. (B(s) ≥ 0 ∧ s → s') ⇒ B(s') ≥ 0

This module provides:
1. Data structures for barrier certificates
2. Inductiveness checking via Z3
3. Integration with the symbolic semantics
"""

from dataclasses import dataclass
from typing import Callable, Optional, Protocol
import z3

from ..semantics.symbolic_vm import SymbolicMachineState


class BarrierFunction(Protocol):
    """
    A barrier function maps machine states to Z3 real expressions.
    
    The barrier value B(σ) must be expressible in terms of:
    - Frame-local variables
    - Heap properties
    - Stack depth
    - Path condition constraints
    """
    
    def __call__(self, state: SymbolicMachineState) -> z3.ExprRef:
        """
        Compute B(σ) for the given state.
        
        Returns: Z3 RealSort or IntSort expression (coercible to Real).
        """
        ...


@dataclass
class BarrierCertificate:
    """
    A barrier certificate with metadata.
    
    Attributes:
        name: Human-readable identifier
        barrier_fn: The barrier function B: S → ℝ
        epsilon: Safety margin (default 0.01)
        description: Optional explanation
        variables: Variables referenced by barrier (for debugging)
    """
    name: str
    barrier_fn: BarrierFunction
    epsilon: float = 0.01
    description: Optional[str] = None
    variables: list[str] = None
    
    @property
    def barrier_function(self) -> BarrierFunction:
        """Alias for barrier_fn for compatibility."""
        return self.barrier_fn
    
    def evaluate(self, state: SymbolicMachineState) -> z3.ExprRef:
        """Evaluate B(σ) for the given state."""
        return self.barrier_fn(state)


@dataclass
class InductivenessResult:
    """
    Result of checking barrier inductiveness.
    
    A barrier is inductive if Init, Unsafe, and Step conditions all hold.
    """
    is_inductive: bool
    init_holds: bool
    unsafe_holds: bool
    step_holds: bool
    
    init_counterexample: Optional[z3.ModelRef] = None
    unsafe_counterexample: Optional[z3.ModelRef] = None
    step_counterexample: Optional[z3.ModelRef] = None
    
    # Store states for better counterexample extraction
    init_counterexample_state: Optional[SymbolicMachineState] = None
    unsafe_counterexample_state: Optional[SymbolicMachineState] = None
    step_counterexample_state: Optional[SymbolicMachineState] = None
    
    verification_time_ms: float = 0.0
    
    def __bool__(self) -> bool:
        return self.is_inductive
    
    def summary(self) -> str:
        """Human-readable summary."""
        if self.is_inductive:
            return f"INDUCTIVE (verified in {self.verification_time_ms:.1f}ms)"
        
        failures = []
        if not self.init_holds:
            failures.append("Init")
        if not self.unsafe_holds:
            failures.append("Unsafe")
        if not self.step_holds:
            failures.append("Step")
        
        return f"NOT INDUCTIVE (failed: {', '.join(failures)})"


class InductivenessChecker:
    """
    Checks whether a barrier certificate is inductive.
    
    Given:
    - Initial states S0
    - Unsafe region predicate U(σ)
    - Transition relation s → s'
    - Barrier function B
    - Epsilon margin ε
    
    Verifies via Z3:
    1. Init: ∀s∈S0. B(s) ≥ ε
    2. Unsafe: ∀s∈U. B(s) ≤ -ε
    3. Step: ∀s,s'. (B(s) ≥ 0 ∧ s → s') ⇒ B(s') ≥ 0
    """
    
    def __init__(self, timeout_ms: int = 5000):
        """
        Args:
            timeout_ms: Z3 solver timeout in milliseconds
        """
        self.timeout_ms = timeout_ms
    
    def check_inductiveness(
        self,
        barrier: BarrierCertificate,
        initial_state_builder: Callable[[], SymbolicMachineState],
        unsafe_predicate: Callable[[SymbolicMachineState], z3.ExprRef],
        step_relation: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef]
    ) -> InductivenessResult:
        """
        Check all three inductiveness conditions.
        
        Args:
            barrier: The barrier certificate to check
            initial_state_builder: Function that returns a symbolic initial state
            unsafe_predicate: Function that returns U(σ) as Z3 bool
            step_relation: Function that returns (s → s') as Z3 bool
        
        Returns:
            InductivenessResult with verification status
        """
        import time
        start_time = time.time()
        
        init_holds, init_cex, init_state = self._check_init(barrier, initial_state_builder)
        unsafe_holds, unsafe_cex, unsafe_state = self._check_unsafe(barrier, unsafe_predicate, initial_state_builder)
        step_holds, step_cex, step_state = self._check_step(barrier, step_relation, initial_state_builder)
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        is_inductive = init_holds and unsafe_holds and step_holds
        
        return InductivenessResult(
            is_inductive=is_inductive,
            init_holds=init_holds,
            unsafe_holds=unsafe_holds,
            step_holds=step_holds,
            init_counterexample=init_cex,
            unsafe_counterexample=unsafe_cex,
            step_counterexample=step_cex,
            init_counterexample_state=init_state,
            unsafe_counterexample_state=unsafe_state,
            step_counterexample_state=step_state,
            verification_time_ms=elapsed_ms
        )
    
    def _check_init(
        self,
        barrier: BarrierCertificate,
        initial_state_builder: Callable[[], SymbolicMachineState]
    ) -> tuple[bool, Optional[z3.ModelRef], Optional[SymbolicMachineState]]:
        """
        Check Init condition: ∀s∈S0. B(s) ≥ ε
        
        We verify by checking unsatisfiability of: ∃s∈S0. B(s) < ε
        
        Returns:
            Tuple of (holds, counterexample_model, counterexample_state)
        """
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        s0 = initial_state_builder()
        B_s0 = barrier.evaluate(s0)
        
        # Negate the desired property: look for B(s0) < ε
        # Convert to real if needed
        if z3.is_int(B_s0):
            B_s0_real = z3.ToReal(B_s0)
        else:
            B_s0_real = B_s0
        solver.add(B_s0_real < barrier.epsilon)
        
        # Add any constraints from the initial state
        if hasattr(s0, 'path_condition'):
            solver.add(s0.path_condition)
        
        result = solver.check()
        
        if result == z3.unsat:
            # No counterexample found → Init holds
            return True, None, None
        elif result == z3.sat:
            # Found counterexample where B(s0) < ε
            return False, solver.model(), s0
        else:
            # Unknown (timeout or other)
            return False, None, None
    
    def _check_unsafe(
        self,
        barrier: BarrierCertificate,
        unsafe_predicate: Callable[[SymbolicMachineState], z3.ExprRef],
        initial_state_builder: Callable[[], SymbolicMachineState]
    ) -> tuple[bool, Optional[z3.ModelRef], Optional[SymbolicMachineState]]:
        """
        Check Unsafe condition: ∀s∈U. B(s) ≤ -ε
        
        We verify by checking unsatisfiability of: ∃s. U(s) ∧ B(s) > -ε
        
        Returns:
            Tuple of (holds, counterexample_model, counterexample_state)
        """
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        s = initial_state_builder()
        U_s = unsafe_predicate(s)
        B_s = barrier.evaluate(s)
        
        # Negate the desired property: look for U(s) ∧ B(s) > -ε
        if z3.is_int(B_s):
            B_s_real = z3.ToReal(B_s)
        else:
            B_s_real = B_s
        solver.add(U_s)
        solver.add(B_s_real > -barrier.epsilon)
        
        if hasattr(s, 'path_condition'):
            solver.add(s.path_condition)
        
        result = solver.check()
        
        if result == z3.unsat:
            return True, None, None
        elif result == z3.sat:
            return False, solver.model(), s
        else:
            return False, None, None
    
    def _check_step(
        self,
        barrier: BarrierCertificate,
        step_relation: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef],
        initial_state_builder: Callable[[], SymbolicMachineState]
    ) -> tuple[bool, Optional[z3.ModelRef], Optional[SymbolicMachineState]]:
        """
        Check Step condition: ∀s,s'. (B(s) ≥ 0 ∧ s → s') ⇒ B(s') ≥ 0
        
        We verify by checking unsatisfiability of:
            ∃s,s'. B(s) ≥ 0 ∧ (s → s') ∧ B(s') < 0
        
        Returns:
            Tuple of (holds, counterexample_model, counterexample_state)
        """
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        s = initial_state_builder()
        s_prime = initial_state_builder()  # Fresh state for s'
        
        B_s = barrier.evaluate(s)
        B_s_prime = barrier.evaluate(s_prime)
        
        step = step_relation(s, s_prime)
        
        # Negate the desired implication:
        # B(s) ≥ 0 ∧ (s → s') ∧ B(s') < 0
        if z3.is_int(B_s):
            B_s_real = z3.ToReal(B_s)
        else:
            B_s_real = B_s
        if z3.is_int(B_s_prime):
            B_s_prime_real = z3.ToReal(B_s_prime)
        else:
            B_s_prime_real = B_s_prime
        
        solver.add(B_s_real >= 0)
        solver.add(step)
        solver.add(B_s_prime_real < 0)
        
        if hasattr(s, 'path_condition'):
            solver.add(s.path_condition)
        if hasattr(s_prime, 'path_condition'):
            solver.add(s_prime.path_condition)
        
        result = solver.check()
        
        if result == z3.unsat:
            return True, None, None
        elif result == z3.sat:
            return False, solver.model(), s
        else:
            return False, None, None


def linear_combination_barrier(
    variable_extractors: list[tuple[str, Callable[[SymbolicMachineState], z3.ExprRef]]],
    coefficients: list[float],
    constant: float = 0.0
) -> BarrierFunction:
    """
    Create a linear barrier function: B(σ) = c0 + c1*v1 + c2*v2 + ...
    
    Args:
        variable_extractors: List of (name, extractor) pairs
        coefficients: Coefficients for each variable
        constant: Constant term
    
    Returns:
        A barrier function
    
    Example:
        # B(σ) = 10 - stack_depth(σ)
        barrier = linear_combination_barrier(
            [("stack_depth", lambda s: len(s.frame_stack))],
            [-1.0],
            10.0
        )
    """
    assert len(variable_extractors) == len(coefficients), \
        "Must have same number of variables and coefficients"
    
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        result = z3.RealVal(constant)
        for (name, extractor), coeff in zip(variable_extractors, coefficients):
            var_value = extractor(state)
            # Convert to real if needed
            if z3.is_int(var_value):
                var_value = z3.ToReal(var_value)
            result = result + z3.RealVal(coeff) * var_value
        return result
    
    return barrier_fn
