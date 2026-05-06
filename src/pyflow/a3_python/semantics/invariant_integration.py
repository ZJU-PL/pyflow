"""
Integration of loop invariant synthesis with symbolic VM.

This module provides automatic loop invariant synthesis during symbolic execution
by discovering inductive invariants for detected loops.

The integration follows these steps:
1. Detect loops in the bytecode (via CFG analysis)
2. Extract loop variables (modified within loop body)
3. Build symbolic state for invariant synthesis
4. Encode loop transition relation
5. Synthesize inductive invariant via template enumeration
6. Record invariant proof or UNKNOWN result in machine state

This complements termination_integration.py and implements the SAFE proofs
for loops beyond termination (e.g., bounds checking, overflow prevention).
"""

from dataclasses import dataclass
from typing import Optional, Dict, Callable, List
import itertools
import z3

from ..cfg.loop_analysis import extract_loops, LoopInfo, identify_loop_pattern
from ..cfg.affine_loop_model import (
    extract_affine_loop_model,
    AffineUpdate,
    ConstantUpdate,
)
from ..barriers.synthesis import BarrierSynthesizer, SynthesisConfig, SynthesisResult
from ..barriers.invariants import BarrierCertificate, InductivenessResult
from .symbolic_vm import SymbolicMachineState


@dataclass
class LoopInvariantResult:
    """
    Result of loop invariant synthesis for a specific loop.
    
    Attributes:
        loop_offset: Bytecode offset of loop header
        verdict: "INVARIANT_FOUND", "UNKNOWN"
        invariant: Synthesized inductive invariant (if verdict is INVARIANT_FOUND)
        proof: Inductiveness proof details (if verdict is INVARIANT_FOUND)
        reason: Explanation (if verdict is UNKNOWN)
    """
    loop_offset: int
    verdict: str  # "INVARIANT_FOUND", "UNKNOWN"
    invariant: Optional[BarrierCertificate] = None
    proof: Optional[InductivenessResult] = None
    reason: Optional[str] = None
    loop_variables: List[str] = None
    
    def has_proof(self) -> bool:
        """Returns True if loop invariant was synthesized."""
        return self.verdict == "INVARIANT_FOUND"


class InvariantIntegrator:
    """
    Integrates loop invariant synthesis with symbolic VM.
    
    Responsibilities:
    - Extract loops from code object
    - Build symbolic states for invariant synthesis
    - Encode loop transitions
    - Call barrier synthesizer with loop-specific templates
    - Cache invariant results
    """
    
    def __init__(self, config: Optional[SynthesisConfig] = None):
        """
        Args:
            config: Configuration for invariant synthesis (uses defaults if None)
        """
        self.config = config or SynthesisConfig(
            max_templates=100,
            timeout_per_template_ms=1000,
            constant_range=(0.0, 20.5, 5.0),
            coefficient_range=(-10.0, 10.5, 1.0),
            epsilon=0.5
        )
        self.synthesizer = BarrierSynthesizer(self.config)
        
        # Cache: code_obj -> list of LoopInvariantResult
        self._invariant_cache: Dict[int, List[LoopInvariantResult]] = {}
    
    def synthesize_all_loops(self, code_obj) -> List[LoopInvariantResult]:
        """
        Synthesize inductive invariants for all loops in a code object.
        
        Args:
            code_obj: Python code object containing loops
        
        Returns:
            List of LoopInvariantResult, one per loop
        """
        # Check cache
        code_id = id(code_obj)
        if code_id in self._invariant_cache:
            return self._invariant_cache[code_id]
        
        # Extract loops from bytecode
        loops = extract_loops(code_obj)
        
        results = []
        for loop in loops:
            result = self._synthesize_single_loop(code_obj, loop)
            results.append(result)
        
        # Cache results
        self._invariant_cache[code_id] = results
        
        return results
    
    def _synthesize_single_loop(
        self,
        code_obj,
        loop: LoopInfo
    ) -> LoopInvariantResult:
        """
        Synthesize inductive invariant for a single loop.
        
        Args:
            code_obj: Code object
            loop: Loop information
        
        Returns:
            LoopInvariantResult
        """
        # If no loop variables found, cannot synthesize invariant
        if not loop.loop_variables:
            return LoopInvariantResult(
                loop_offset=loop.header_offset,
                verdict="UNKNOWN",
                reason="No loop variables identified for invariant synthesis",
                loop_variables=[]
            )
        
        # Build variable extractors for loop variables
        variable_extractors = []
        for var_name in loop.loop_variables:
            extractor = self._create_variable_extractor(var_name)
            variable_extractors.append((var_name, extractor))
        
        # Build state builder
        state_builder = self._create_state_builder(code_obj, loop.loop_variables)
        
        # Build unsafe predicate (for now, use trivial: never unsafe)
        # This is because we're synthesizing general invariants, not safety properties
        # The invariant should separate loop states from error states
        def unsafe_predicate(state: SymbolicMachineState) -> z3.ExprRef:
            # For general invariants, we use a placeholder unsafe region
            # In practice, this would be combined with specific bug predicates
            return z3.BoolVal(False)
        
        # Build loop transition encoder
        loop_transition = self._create_transition_encoder(code_obj, loop)
        
        # Synthesize inductive invariant (barrier certificate for loop)
        synthesis_result = self.synthesizer.synthesize(
            state_builder,
            unsafe_predicate,
            loop_transition,
            variable_extractors
        )
        
        if synthesis_result.success:
            # Found inductive invariant
            return LoopInvariantResult(
                loop_offset=loop.header_offset,
                verdict="INVARIANT_FOUND",
                invariant=synthesis_result.barrier,
                proof=synthesis_result.inductiveness,
                loop_variables=list(loop.loop_variables)
            )
        else:
            # Could not find invariant → UNKNOWN
            return LoopInvariantResult(
                loop_offset=loop.header_offset,
                verdict="UNKNOWN",
                reason=f"No invariant found (tried {synthesis_result.templates_tried} templates)",
                loop_variables=list(loop.loop_variables)
            )
    
    def _create_variable_extractor(
        self,
        var_name: str
    ) -> Callable[[SymbolicMachineState], z3.ExprRef]:
        """
        Create a function that extracts a variable from symbolic state.
        
        Args:
            var_name: Variable name to extract
        
        Returns:
            Function that extracts z3.ExprRef for the variable
        """
        def extractor(state: SymbolicMachineState) -> z3.ExprRef:
            # Try to get variable from current frame locals
            if state.frame_stack:
                frame = state.frame_stack[-1]
                if var_name in frame.locals:
                    value = frame.locals[var_name]
                    # Extract numeric payload from SymbolicValue
                    if hasattr(value, 'payload'):
                        payload = value.payload
                        if isinstance(payload, z3.ExprRef):
                            return payload
                        elif isinstance(payload, (int, float)):
                            return z3.IntVal(int(payload))
            
            # Fallback: create fresh symbolic variable
            return z3.Int(f"{var_name}_inv")
        
        return extractor
    
    def _create_state_builder(
        self,
        code_obj,
        loop_variables: set[str]
    ) -> Callable[[], SymbolicMachineState]:
        """
        Create a state builder that produces fresh symbolic states.
        
        Args:
            code_obj: Code object
            loop_variables: Set of loop variable names
        
        Returns:
            Function that creates fresh symbolic state
        """
        counter = itertools.count()

        def builder() -> SymbolicMachineState:
            state_id = next(counter)
            # Create minimal symbolic state with loop variables
            from ..z3model.heap import SymbolicHeap
            from ..z3model.values import SymbolicValue, ValueTag
            from .security_tracker_lattice import LatticeSecurityTracker
            from .symbolic_vm import SymbolicFrame
            
            # Create symbolic frame with loop variables as symbolic integers
            frame_locals = {}
            for var_name in loop_variables:
                # Each variable gets a fresh symbolic integer
                sym_val = z3.Int(f"{var_name}_{state_id}")
                frame_locals[var_name] = SymbolicValue(ValueTag.INT, sym_val)
            
            frame = SymbolicFrame(
                code=code_obj,
                instruction_offset=0,
                locals=frame_locals,
                globals={},
                builtins={},
                operand_stack=[]
            )
            
            state = SymbolicMachineState(
                frame_stack=[frame],
                heap=SymbolicHeap(),
                path_condition=z3.BoolVal(True),
                func_names={},
                security_tracker=LatticeSecurityTracker()
            )
            
            return state
        
        return builder
    
    def _create_transition_encoder(
        self,
        code_obj,
        loop: LoopInfo
    ) -> Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef]:
        """
        Create an encoder for the loop transition relation.
        
        The transition encodes: guard(s) ∧ update(s, s')
        where guard is the loop condition and update is the variable updates.
        
        Args:
            code_obj: Code object
            loop: Loop information
        
        Returns:
            Function that encodes s →loop s' as Z3 boolean
        """
        # Try to extract an affine loop model; if this fails, fall back to havoc.
        model = extract_affine_loop_model(
            code_obj,
            header_offset=loop.header_offset,
            body_offsets=loop.body_offsets,
            modified_variables=loop.modified_variables,
        )

        var_extractors = {name: self._create_variable_extractor(name) for name in loop.loop_variables}

        def _operand_to_int(op, st: SymbolicMachineState) -> Optional[z3.ArithRef]:
            if op.kind == "const":
                return z3.IntVal(int(op.value))
            if op.kind == "var":
                name = str(op.value)
                extractor = var_extractors.get(name) or self._create_variable_extractor(name)
                v = extractor(st)
                return v if z3.is_int(v) else z3.ToInt(v)
            return None

        def _guard_formula(st: SymbolicMachineState) -> z3.BoolRef:
            if not model or not model.guard:
                return z3.BoolVal(True)
            lhs = _operand_to_int(model.guard.lhs, st)
            rhs = _operand_to_int(model.guard.rhs, st)
            if lhs is None or rhs is None:
                return z3.BoolVal(True)
            op = model.guard.op
            if op == "<":
                return lhs < rhs
            if op == "<=":
                return lhs <= rhs
            if op == ">":
                return lhs > rhs
            if op == ">=":
                return lhs >= rhs
            if op == "==":
                return lhs == rhs
            if op == "!=":
                return lhs != rhs
            return z3.BoolVal(True)

        def encoder(s: SymbolicMachineState, s_prime: SymbolicMachineState) -> z3.ExprRef:
            if not model:
                return z3.BoolVal(True)

            constraints: list[z3.BoolRef] = [_guard_formula(s)]

            for var_name in loop.loop_variables:
                extractor = var_extractors.get(var_name) or self._create_variable_extractor(var_name)
                pre = extractor(s)
                post = extractor(s_prime)

                upd = model.updates.get(var_name)
                if isinstance(upd, AffineUpdate):
                    constraints.append(post == pre + int(upd.delta))
                elif isinstance(upd, ConstantUpdate):
                    constraints.append(post == int(upd.value))
                else:
                    if var_name not in loop.modified_variables:
                        constraints.append(post == pre)

            return z3.And(*constraints)
        
        return encoder


def add_invariant_synthesis_to_state(
    state: SymbolicMachineState,
    code_obj,
    integrator: Optional[InvariantIntegrator] = None
) -> None:
    """
    Add loop invariant synthesis results to a symbolic machine state.
    
    This function:
    1. Synthesizes inductive invariants for all loops in the code object
    2. Stores results in state.loop_invariant_results
    3. Sets state.has_loop_invariants if any invariant was found
    
    Args:
        state: Symbolic machine state to annotate
        code_obj: Code object being analyzed
        integrator: Optional invariant integrator (creates one if None)
    """
    if integrator is None:
        integrator = InvariantIntegrator()
    
    # Synthesize invariants for all loops
    results = integrator.synthesize_all_loops(code_obj)
    
    # Store results in state
    if not hasattr(state, 'loop_invariant_results'):
        state.loop_invariant_results = []
    state.loop_invariant_results = results
    
    # Track if any invariants were found
    state.has_loop_invariants = any(r.has_proof() for r in results)
    
    # Store proven invariants (for reporting)
    if not hasattr(state, 'proven_invariants'):
        state.proven_invariants = []
    state.proven_invariants = [r for r in results if r.has_proof()]
