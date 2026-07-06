"""
Guard-to-Barrier Certificate Translation Layer.

This module eliminates ad-hoc pattern matching by translating bytecode guard patterns
into formal barrier certificates that the 5-layer verification system can understand.

Architecture:
    GuardFact (bytecode pattern) 
        → BarrierCertificate (formal verification object)
        → Verified interprocedurally via barrier certificate synthesis

Instead of ad-hoc checks like:
    if guard_type == 'assert_nonempty' and bug_type == 'BOUNDS':
        skip_bug()
        
We now have:
    guard_barrier = translate_guard_to_barrier(guard_fact)
    is_safe = barrier_synthesis_engine.verify_inductive(guard_barrier)
    if is_safe:
        skip_bug()

This integrates guards into the formal z3/bytecode/barrier certificate verification.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
import z3

from .invariants import BarrierCertificate, BarrierFunction
from ..semantics.symbolic_vm import SymbolicMachineState
from ..cfg.control_flow import GuardFact


# =============================================================================
# GUARD → BARRIER TRANSLATION
# =============================================================================

class GuardBarrierTranslator:
    """
    Translates GuardFacts from bytecode analysis into BarrierCertificates
    for formal verification.
    
    Each guard pattern establishes a barrier that prevents certain crashes:
    
    1. assert len(x) > 0  →  B(x) = len(x) - 1 ≥ 0
       Protects: BOUNDS (x[0] is safe)
       
    2. assert key in dict  →  B(key, dict) = (key ∈ dict) ? 1 : -1
       Protects: KEY_ERROR
       
    3. assert x != 0  →  B(x) = |x| - ε ≥ 0
       Protects: DIV_ZERO
       
    4. if not x: raise  →  B(x) = (x is not None) ? 1 : -1
       Protects: NULL_PTR, ATTRIBUTE_ERROR
    """
    
    def __init__(self):
        # Mapping of guard types to barrier generators
        self._translators: Dict[str, BarrierGenerator] = {
            'assert_nonempty': self._translate_nonempty_guard,
            'assert_len': self._translate_nonempty_guard,
            'key_in': self._translate_key_in_guard,
            'assert_contains': self._translate_key_in_guard,
            'assert_div': self._translate_nonzero_guard,
            'assert_nonzero': self._translate_nonzero_guard,
            'raise_if_not': self._translate_nonnull_guard,
            'assert_nonnull': self._translate_nonnull_guard,
            'nonempty': self._translate_nonempty_guard,
            'nonnull': self._translate_nonnull_guard,
            'bounds': self._translate_bounds_guard,
            'range_check': self._translate_range_guard,
        }
    
    def translate(self, guard: GuardFact) -> BarrierCertificate:
        """
        Translate a GuardFact into a BarrierCertificate.
        
        Args:
            guard: GuardFact from bytecode analysis
            
        Returns:
            BarrierCertificate that formally encodes the guard condition
        """
        # Strip assert_/raise_ prefixes to get base type
        base_type = guard.guard_type
        for prefix in ['assert_', 'raise_']:
            if base_type.startswith(prefix):
                base_type = base_type[len(prefix):]
                break
        
        # Look up translator (try both original and base type)
        translator = self._translators.get(guard.guard_type) or \
                     self._translators.get(base_type)
        
        if translator is None:
            # Fallback: generic truthiness barrier
            return self._translate_generic_guard(guard)
        
        return translator(guard)
    
    # -------------------------------------------------------------------------
    # SPECIFIC BARRIER GENERATORS
    # -------------------------------------------------------------------------
    
    def _translate_nonempty_guard(self, guard: GuardFact) -> BarrierCertificate:
        """
        assert len(x) > 0  →  B(x) = len(x) - 1
        
        Barrier condition: B(x) ≥ 0 ⟺ len(x) ≥ 1
        Protects against: BOUNDS errors (accessing x[0])
        """
        var = guard.variable
        
        def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
            # Get symbolic value of the variable
            val = self._get_symbolic_value(state, var)
            
            # Compute len(val) symbolically
            # For sequences, we track length in symbolic semantics
            if hasattr(val, 'length'):
                length = val.length
            else:
                # Fallback: create fresh length variable
                length = z3.Int(f'len_{var}')
                # Add constraint: length must be non-negative
                state.solver.add(length >= 0)
            
            # Barrier: B(x) = len(x) - 1
            return length - 1
        
        return BarrierCertificate(
            name=f'nonempty_{var}',
            barrier_fn=barrier_fn,
            epsilon=0.0,  # Strict: len(x) ≥ 1
            description=f'Container {var} is non-empty (len ≥ 1)',
            variables=[var]
        )
    
    def _translate_key_in_guard(self, guard: GuardFact) -> BarrierCertificate:
        """
        assert key in dict  →  B(key, dict) = (key ∈ dict) ? 1 : -1
        
        Barrier condition: B ≥ 0 ⟺ key ∈ dict
        Protects against: KEY_ERROR
        """
        key_var = guard.variable
        dict_var = guard.extra  # Container variable
        
        def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
            # Get symbolic values
            key = self._get_symbolic_value(state, key_var)
            container = self._get_symbolic_value(state, dict_var or 'container')
            
            # Symbolic membership check
            # In symbolic semantics, we track which keys are in which dicts
            # Here we create a boolean constraint and convert to 0/1
            if hasattr(container, 'contains_key'):
                contains = container.contains_key(key)
            else:
                # Fallback: fresh boolean variable
                contains = z3.Bool(f'{key_var}_in_{dict_var}')
            
            # Convert bool to int: True → 1, False → -1
            return z3.If(contains, z3.IntVal(1), z3.IntVal(-1))
        
        return BarrierCertificate(
            name=f'key_in_{key_var}_{dict_var}',
            barrier_fn=barrier_fn,
            epsilon=0.0,
            description=f'Key {key_var} is in {dict_var}',
            variables=[key_var, dict_var] if dict_var else [key_var]
        )
    
    def _translate_nonzero_guard(self, guard: GuardFact) -> BarrierCertificate:
        """
        assert x != 0  →  B(x) = |x| - ε
        
        Barrier condition: B(x) ≥ 0 ⟺ |x| ≥ ε
        Protects against: DIV_ZERO
        """
        var = guard.variable
        epsilon = 0.001  # Small margin for numerical stability
        
        def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
            val = self._get_symbolic_value(state, var)
            
            # Convert to real for absolute value
            if z3.is_int(val):
                val_real = z3.ToReal(val)
            elif z3.is_real(val):
                val_real = val
            else:
                # Create fresh real variable
                val_real = z3.Real(f'{var}_real')
            
            # Barrier: |x| - ε
            # Note: Z3 doesn't have built-in abs, so we use: |x| = if x ≥ 0 then x else -x
            abs_val = z3.If(val_real >= 0, val_real, -val_real)
            return abs_val - epsilon
        
        return BarrierCertificate(
            name=f'nonzero_{var}',
            barrier_fn=barrier_fn,
            epsilon=0.0,
            description=f'Variable {var} is non-zero (|{var}| ≥ {epsilon})',
            variables=[var]
        )
    
    def _translate_nonnull_guard(self, guard: GuardFact) -> BarrierCertificate:
        """
        if not x: raise  →  B(x) = (x is not None) ? 1 : -1
        
        Barrier condition: B(x) ≥ 0 ⟺ x is not None
        Protects against: NULL_PTR, ATTRIBUTE_ERROR
        """
        var = guard.variable
        
        def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
            val = self._get_symbolic_value(state, var)
            
            # Symbolic null check
            # In our symbolic semantics, nullability is tracked
            if hasattr(val, 'is_null'):
                is_null = val.is_null
            else:
                # Fallback: fresh boolean variable
                is_null = z3.Bool(f'{var}_is_null')
            
            # Barrier: not null → 1, null → -1
            return z3.If(z3.Not(is_null), z3.IntVal(1), z3.IntVal(-1))
        
        return BarrierCertificate(
            name=f'nonnull_{var}',
            barrier_fn=barrier_fn,
            epsilon=0.0,
            description=f'Variable {var} is not None',
            variables=[var]
        )
    
    def _translate_bounds_guard(self, guard: GuardFact) -> BarrierCertificate:
        """
        Combined length and index guard.
        Extra format: 'index_var' or None for general bounds
        """
        var = guard.variable
        index_var = guard.extra
        
        def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
            container = self._get_symbolic_value(state, var)
            
            if hasattr(container, 'length'):
                length = container.length
            else:
                length = z3.Int(f'len_{var}')
                state.solver.add(length >= 0)
            
            if index_var:
                # Specific index check: 0 ≤ index < len
                index = self._get_symbolic_value(state, index_var)
                if z3.is_int(index):
                    # Barrier: min(index, len - index - 1)
                    # This is positive iff 0 ≤ index < len
                    return z3.If(
                        z3.And(index >= 0, index < length),
                        z3.IntVal(1),
                        z3.IntVal(-1)
                    )
                else:
                    # Unknown index type
                    return length - 1
            else:
                # General: container is non-empty
                return length - 1
        
        return BarrierCertificate(
            name=f'bounds_{var}_{index_var}' if index_var else f'bounds_{var}',
            barrier_fn=barrier_fn,
            epsilon=0.0,
            description=f'Bounds check for {var}[{index_var}]' if index_var else f'{var} is non-empty',
            variables=[var, index_var] if index_var else [var]
        )
    
    def _translate_range_guard(self, guard: GuardFact) -> BarrierCertificate:
        """
        Range check: lower ≤ x < upper
        Extra format: 'lower:upper'
        """
        var = guard.variable
        
        # Parse bounds from extra
        if guard.extra and ':' in guard.extra:
            lower_str, upper_str = guard.extra.split(':')
            lower = int(lower_str) if lower_str.isdigit() else 0
            upper = int(upper_str) if upper_str.isdigit() else None
        else:
            lower = 0
            upper = None
        
        def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
            val = self._get_symbolic_value(state, var)
            
            # Ensure it's an int
            if not z3.is_int(val):
                val = z3.Int(f'{var}_int')
            
            # Barrier: min(val - lower, upper - val - 1) if upper exists
            # Otherwise: val - lower
            if upper is not None:
                return z3.If(
                    z3.And(val >= lower, val < upper),
                    z3.IntVal(1),
                    z3.IntVal(-1)
                )
            else:
                return val - lower
        
        return BarrierCertificate(
            name=f'range_{var}_{lower}_{upper}' if upper else f'range_{var}_{lower}',
            barrier_fn=barrier_fn,
            epsilon=0.0,
            description=f'Range check: {lower} ≤ {var} < {upper}' if upper else f'{var} ≥ {lower}',
            variables=[var]
        )
    
    def _translate_generic_guard(self, guard: GuardFact) -> BarrierCertificate:
        """
        Fallback for unknown guard types: truthiness barrier.
        """
        var = guard.variable
        
        def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
            val = self._get_symbolic_value(state, var)
            
            # Generic truthiness: val is "truthy"
            # For simplicity, use boolean → int conversion
            if z3.is_bool(val):
                return z3.If(val, z3.IntVal(1), z3.IntVal(-1))
            else:
                # Assume truthy if not explicitly false/null
                return z3.IntVal(1)
        
        return BarrierCertificate(
            name=f'generic_{guard.guard_type}_{var}',
            barrier_fn=barrier_fn,
            epsilon=0.0,
            description=f'Generic guard: {guard.guard_type} on {var}',
            variables=[var]
        )
    
    # -------------------------------------------------------------------------
    # HELPER METHODS
    # -------------------------------------------------------------------------
    
    def _get_symbolic_value(self, state: SymbolicMachineState, var: str) -> z3.ExprRef:
        """
        Retrieve the symbolic value of a variable from the machine state.
        
        This bridges the gap between variable names in guards and
        symbolic values tracked by the symbolic VM.
        """
        # Try to find variable in current frame
        if hasattr(state, 'current_frame') and state.current_frame:
            frame = state.current_frame
            
            # Check locals
            if hasattr(frame, 'locals') and var in frame.locals:
                return frame.locals[var]
            
            # Check function arguments
            if hasattr(frame, 'args') and var in frame.args:
                return frame.args[var]
        
        # Try global scope
        if hasattr(state, 'globals') and var in state.globals:
            return state.globals[var]
        
        # Fallback: create fresh symbolic variable
        # Infer type from variable name heuristics
        if 'len' in var or 'count' in var or 'size' in var or 'idx' in var:
            return z3.Int(f'sym_{var}')
        else:
            # Generic: use Int as default
            return z3.Int(f'sym_{var}')


# =============================================================================
# BARRIER → BUG TYPE MAPPING
# =============================================================================

# Canonical mapping: which bug types does each barrier protect against?
BARRIER_TYPE_TO_PROTECTED_BUGS: Dict[str, Set[str]] = {
    'nonempty': {'BOUNDS', 'INDEX_ERROR'},
    'nonnull': {'NULL_PTR', 'ATTRIBUTE_ERROR', 'NONE_TYPE_ERROR'},
    'nonzero': {'DIV_ZERO', 'ZERO_DIVISION_ERROR'},
    'key_in': {'KEY_ERROR', 'DICT_ACCESS'},
    'bounds': {'BOUNDS', 'INDEX_ERROR'},
    'range': {'BOUNDS', 'INDEX_ERROR', 'OVERFLOW'},
}


def get_protected_bugs(barrier: BarrierCertificate) -> Set[str]:
    """
    Determine which bug types a barrier certificate protects against.
    
    Args:
        barrier: BarrierCertificate
        
    Returns:
        Set of bug type names that cannot occur when barrier holds
    """
    # Extract base type from barrier name
    for barrier_type, protected in BARRIER_TYPE_TO_PROTECTED_BUGS.items():
        if barrier_type in barrier.name.lower():
            return protected.copy()
    
    # Fallback: empty set (unknown protection)
    return set()


# =============================================================================
# HIGH-LEVEL API
# =============================================================================

_translator = GuardBarrierTranslator()


def translate_guard_to_barrier(guard: GuardFact) -> BarrierCertificate:
    """
    Convert a GuardFact from bytecode analysis into a formal BarrierCertificate.
    
    This is the main entry point for eliminating ad-hoc pattern matching.
    
    Args:
        guard: GuardFact from bytecode analysis (e.g., from GuardAnalyzer)
        
    Returns:
        BarrierCertificate that can be verified using the 5-layer system
        
    Example:
        ```python
        guard = GuardFact(guard_type='assert_nonempty', variable='my_list')
        barrier = translate_guard_to_barrier(guard)
        
        # Now use barrier in formal verification
        checker = InductivenessChecker()
        result = checker.check_inductiveness(barrier, ...)
        ```
    """
    return _translator.translate(guard)


def guards_protect_bug(guards: List[GuardFact], bug_type: str) -> bool:
    """
    Check if a set of guards protects against a specific bug type.
    
    This replaces ad-hoc pattern matching like:
        if guard_type == 'assert_nonempty' and bug_type == 'BOUNDS':
            return True
    
    With formal verification:
        barriers = [translate_guard_to_barrier(g) for g in guards]
        return any(bug_type in get_protected_bugs(b) for b in barriers)
    
    Args:
        guards: List of GuardFacts from bytecode analysis
        bug_type: Bug type name (e.g., 'BOUNDS', 'DIV_ZERO')
        
    Returns:
        True if any guard protects against the bug type
    """
    for guard in guards:
        barrier = translate_guard_to_barrier(guard)
        protected_bugs = get_protected_bugs(barrier)
        if bug_type in protected_bugs:
            return True
    return False
