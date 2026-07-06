"""
Integration of termination checking with symbolic VM.

This module provides automatic termination checking during symbolic execution
by synthesizing ranking functions for detected loops.

The integration follows these steps:
1. Detect loops in the bytecode (via CFG analysis)
2. Extract loop variables (modified within loop body)
3. Build symbolic state for ranking synthesis
4. Encode loop back-edge transition relation
5. Synthesize ranking function via template enumeration
6. Record termination proof or UNKNOWN result in machine state

This implements barrier-certificate-theory.tex §8 (Ranking Functions).
"""

from dataclasses import dataclass
from typing import Optional, Dict, Callable
import itertools
import z3

from ..cfg.loop_analysis import extract_loops, LoopInfo, identify_loop_pattern
from ..cfg.affine_loop_model import (
    extract_affine_loop_model,
    AffineUpdate,
    ConstantUpdate,
)
from ..barriers.ranking_synthesis import (
    RankingSynthesizer,
    RankingSynthesisConfig,
    RankingSynthesisResult
)
from ..barriers.ranking import RankingFunctionCertificate
from .symbolic_vm import SymbolicMachineState


@dataclass
class TerminationCheckResult:
    """
    Result of termination checking for a specific loop.
    
    Attributes:
        loop_offset: Bytecode offset of loop header
        verdict: "TERMINATES", "NON_TERMINATION", or "UNKNOWN"
        ranking: Synthesized ranking function (if verdict is TERMINATES)
        proof: Termination proof details (if verdict is TERMINATES)
        reason: Explanation (if verdict is UNKNOWN or NON_TERMINATION)
    """
    loop_offset: int
    verdict: str  # "TERMINATES", "NON_TERMINATION", "UNKNOWN"
    ranking: Optional[RankingFunctionCertificate] = None
    proof: Optional[dict] = None
    reason: Optional[str] = None
    
    def is_safe(self) -> bool:
        """Returns True if loop provably terminates."""
        return self.verdict == "TERMINATES"
    
    def is_bug(self) -> bool:
        """Returns True if non-termination detected."""
        return self.verdict == "NON_TERMINATION"


class TerminationIntegrator:
    """
    Integrates ranking function synthesis with symbolic VM.
    
    Responsibilities:
    - Extract loops from code object
    - Build symbolic states for ranking synthesis
    - Encode loop transitions
    - Call ranking synthesizer
    - Cache termination results
    """
    
    def __init__(self, config: Optional[RankingSynthesisConfig] = None):
        """
        Args:
            config: Configuration for ranking synthesis (uses defaults if None)
        """
        self.config = config or RankingSynthesisConfig()
        self.synthesizer = RankingSynthesizer(self.config)
        
        # Cache: code_obj -> list of TerminationCheckResult
        self._termination_cache: Dict[int, list[TerminationCheckResult]] = {}
    
    def check_all_loops(self, code_obj) -> list[TerminationCheckResult]:
        """
        Check termination for all loops in a code object.
        
        Args:
            code_obj: Python code object containing loops
        
        Returns:
            List of TerminationCheckResult, one per loop
        """
        # Check cache
        code_id = id(code_obj)
        if code_id in self._termination_cache:
            return self._termination_cache[code_id]
        
        # Extract loops from bytecode
        loops = extract_loops(code_obj)
        
        results = []
        for loop in loops:
            result = self._check_single_loop(code_obj, loop)
            results.append(result)
        
        # Cache results
        self._termination_cache[code_id] = results
        
        return results
    
    def _check_single_loop(
        self,
        code_obj,
        loop: LoopInfo
    ) -> TerminationCheckResult:
        """
        Check termination for a single loop.
        
        Args:
            code_obj: Code object
            loop: Loop information
        
        Returns:
            TerminationCheckResult
        """
        # If no loop variables found, cannot synthesize ranking function
        if not loop.loop_variables:
            return TerminationCheckResult(
                loop_offset=loop.header_offset,
                verdict="UNKNOWN",
                reason="No loop variables identified for ranking synthesis"
            )
        
        # Build variable extractors for loop variables
        variable_extractors = []
        for var_name in loop.loop_variables:
            extractor = self._create_variable_extractor(var_name)
            variable_extractors.append((var_name, extractor))
        
        # Build state builder
        state_builder = self._create_state_builder(code_obj, loop.loop_variables)
        
        # Build loop back-edge transition encoder
        loop_back_edge = self._create_back_edge_encoder(code_obj, loop)
        
        # Identify loop pattern for synthesis hints
        loop_pattern = identify_loop_pattern(loop)
        
        # Synthesize ranking function
        synthesis_result = self.synthesizer.synthesize(
            state_builder,
            loop_back_edge,
            variable_extractors,
            loop_type_hint=loop_pattern
        )
        
        if synthesis_result.success:
            # Found ranking function → loop terminates
            return TerminationCheckResult(
                loop_offset=loop.header_offset,
                verdict="TERMINATES",
                ranking=synthesis_result.ranking,
                proof={
                    "bounded_below_holds": synthesis_result.termination_proof.bounded_below_holds,
                    "decreasing_holds": synthesis_result.termination_proof.decreasing_holds,
                    "verification_time_ms": synthesis_result.termination_proof.verification_time_ms,
                    "templates_tried": synthesis_result.templates_tried,
                    "synthesis_time_ms": synthesis_result.synthesis_time_ms,
                }
            )
        else:
            # Could not find ranking function → UNKNOWN
            # NOTE: This does NOT prove non-termination
            return TerminationCheckResult(
                loop_offset=loop.header_offset,
                verdict="UNKNOWN",
                reason=f"No ranking function found (tried {synthesis_result.templates_tried} templates)"
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
            return z3.Int(f"{var_name}_symbolic")
        
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
            
            # Create symbolic frame with loop variables as symbolic integers
            from .symbolic_vm import SymbolicFrame
            
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
    
    def _create_back_edge_encoder(
        self,
        code_obj,
        loop: LoopInfo
    ) -> Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef]:
        """
        Create an encoder for the loop back-edge transition.
        
        The back-edge encodes: guard(s) ∧ update(s, s')
        where guard is the loop condition and update is the variable updates.
        
        Args:
            code_obj: Code object
            loop: Loop information
        
        Returns:
            Function that encodes s →loop s' as Z3 boolean
        """
        # Try to extract a precise affine loop model for this back-edge.
        model = extract_affine_loop_model(
            code_obj,
            header_offset=loop.header_offset,
            body_offsets=loop.body_offsets,
            modified_variables=loop.modified_variables,
        )

        # Pre-create extractors so we don't reallocate on every call.
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
            # If we cannot extract a precise model, fall back to the previous
            # conservative semantics (at least one modified var changes).
            if not model:
                constraints = []
                for var_name in loop.modified_variables:
                    extractor = self._create_variable_extractor(var_name)
                    var_s = extractor(s)
                    var_s_prime = extractor(s_prime)
                    constraints.append(var_s != var_s_prime)
                return z3.Or(*constraints) if constraints else z3.BoolVal(True)

            constraints: list[z3.BoolRef] = [_guard_formula(s)]

            # Apply updates for vars we can model; keep other loop vars unchanged.
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
                    # If we couldn't model the update for a modified var, we must
                    # conservatively allow it to change arbitrarily (havoc).
                    if var_name not in loop.modified_variables:
                        constraints.append(post == pre)

            return z3.And(*constraints)
        
        return encoder


def add_termination_checks_to_state(
    state: SymbolicMachineState,
    code_obj,
    integrator: Optional[TerminationIntegrator] = None
) -> None:
    """
    Add termination checking results to a symbolic machine state.
    
    This function:
    1. Checks all loops in the code object for termination
    2. Stores results in state.termination_results
    3. Sets state.has_non_termination_bug if any loop is non-terminating
    
    Args:
        state: Symbolic machine state to annotate
        code_obj: Code object being analyzed
        integrator: Optional termination integrator (creates one if None)
    """
    if integrator is None:
        integrator = TerminationIntegrator()
    
    # Check all loops
    results = integrator.check_all_loops(code_obj)
    
    # Store results in state
    state.termination_results = results
    
    # Check for non-termination bugs
    state.has_non_termination_bug = any(r.is_bug() for r in results)
    
    # Store terminating loops (for reporting)
    state.terminating_loops = [r for r in results if r.is_safe()]
    
    # Store unknown loops
    state.unknown_termination_loops = [r for r in results if r.verdict == "UNKNOWN"]
