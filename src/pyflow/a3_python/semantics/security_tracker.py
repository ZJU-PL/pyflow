"""
Security taint tracking integration for the symbolic VM (barrier-certificate-theory.md §11).

This module provides hooks for the symbolic VM to:
1. Apply taint at source function calls
2. Check taint at sink function calls
3. Propagate taint through operations
4. Record security violations

Mode A (pure symbolic): Sound over-approximation using taint bits
Mode B (concolic): Optional concrete validation (does not affect verdicts)
"""

from typing import List, Optional, Dict, Set
from dataclasses import dataclass, field
import z3

from a3_python.z3model.taint import (
    TaintSource, SinkType, SanitizerType, TaintState, TaintLabel,
    SecurityViolation, create_violation,
    create_symbolic_taint, taint_propagate_binop
)
from a3_python.contracts.security import (
    get_source_contract, get_sink_contract, get_sanitizer_contract,
    is_taint_source, is_security_sink, is_sanitizer,
    apply_source_taint, check_sink_taint, apply_sanitizer,
    init_security_contracts
)
from a3_python.z3model.values import SymbolicValue


@dataclass
class SecurityTracker:
    """
    Security taint tracking state.
    
    Maintained by the symbolic VM to track taint flow through execution.
    """
    # Map from symbolic value ID to its taint state
    value_taints: Dict[int, TaintState] = field(default_factory=dict)
    
    # Map from symbolic value to its Z3 taint bits (for Mode A symbolic reasoning)
    symbolic_taints: Dict[int, tuple] = field(default_factory=dict)  # value_id -> (τ, σ)
    
    # List of detected security violations
    violations: List[SecurityViolation] = field(default_factory=list)
    
    # Current execution location (for error messages)
    current_location: str = "unknown"
    
    # Flag to enable/disable taint tracking
    enabled: bool = True
    
    # Mode A only: no concolic validation
    pure_symbolic: bool = True
    
    def set_taint(self, value: SymbolicValue, taint: TaintState):
        """Associate taint state with a symbolic value."""
        self.value_taints[id(value)] = taint
    
    def get_taint(self, value: SymbolicValue) -> TaintState:
        """Get taint state for a symbolic value."""
        return self.value_taints.get(id(value), TaintState.clean())
    
    def merge_taints(self, values: List[SymbolicValue]) -> TaintState:
        """Merge taints from multiple values (for operations)."""
        result = TaintState.clean()
        for v in values:
            result = result.merge(self.get_taint(v))
        return result
    
    def set_symbolic_taint(self, value: SymbolicValue, tau: z3.BoolRef, sigma: z3.BoolRef):
        """Set symbolic taint bits for a value (Mode A)."""
        self.symbolic_taints[id(value)] = (tau, sigma)
    
    def get_symbolic_taint(self, value: SymbolicValue) -> tuple:
        """Get symbolic taint bits (τ, σ) for a value."""
        if id(value) in self.symbolic_taints:
            return self.symbolic_taints[id(value)]
        # Default: untainted (τ=False, σ=False)
        return (z3.BoolVal(False), z3.BoolVal(False))
    
    def add_violation(self, violation: SecurityViolation):
        """Record a security violation."""
        self.violations.append(violation)
    
    def has_violations(self) -> bool:
        """Check if any violations have been detected."""
        return len(self.violations) > 0
    
    def copy(self) -> 'SecurityTracker':
        """Deep copy for path forking."""
        return SecurityTracker(
            value_taints=self.value_taints.copy(),
            symbolic_taints=self.symbolic_taints.copy(),
            violations=self.violations.copy(),
            current_location=self.current_location,
            enabled=self.enabled,
            pure_symbolic=self.pure_symbolic
        )


# Global initialization flag
_security_contracts_initialized = False


def ensure_security_contracts_initialized():
    """Initialize security contracts if not already done."""
    global _security_contracts_initialized
    if not _security_contracts_initialized:
        init_security_contracts()
        _security_contracts_initialized = True


def handle_call_pre(
    tracker: SecurityTracker,
    func_name: str,
    args: List[SymbolicValue],
    location: str,
    kwargs: dict = None
) -> Optional[SecurityViolation]:
    """
    Pre-call hook: check if calling a sink with tainted args.
    
    Called by the VM before executing a function call.
    Returns SecurityViolation if a security bug is detected.
    """
    if not tracker.enabled:
        return None
    
    ensure_security_contracts_initialized()
    tracker.current_location = location
    
    # Check if this is a security sink
    if is_security_sink(func_name):
        # Get taint state for each argument
        arg_taints = [tracker.get_taint(arg) for arg in args]
        
        # Check for violation
        violation = check_sink_taint(func_name, location, arg_taints, kwargs)
        if violation:
            tracker.add_violation(violation)
            return violation
    
    return None


def handle_call_post(
    tracker: SecurityTracker,
    func_name: str,
    args: List[SymbolicValue],
    result: SymbolicValue,
    location: str
) -> TaintState:
    """
    Post-call hook: apply taint to result if this is a source.
    
    Called by the VM after executing a function call.
    Returns the taint state to associate with the result.
    """
    if not tracker.enabled:
        return TaintState.clean()
    
    ensure_security_contracts_initialized()
    
    # Check if this is a taint source
    if is_taint_source(func_name):
        taint = apply_source_taint(func_name, location)
        tracker.set_taint(result, taint)
        return taint
    
    # Check if this is a sanitizer
    if is_sanitizer(func_name):
        if args:
            input_taint = tracker.get_taint(args[0])
            result_taint = apply_sanitizer(func_name, input_taint)
            tracker.set_taint(result, result_taint)
            return result_taint
    
    # Otherwise, propagate taint from arguments to result
    merged_taint = tracker.merge_taints(args)
    tracker.set_taint(result, merged_taint)
    return merged_taint


def handle_binop(
    tracker: SecurityTracker,
    left: SymbolicValue,
    right: SymbolicValue,
    result: SymbolicValue
) -> TaintState:
    """
    Handle taint propagation for binary operations.
    
    τ(result) = τ(left) ∨ τ(right)
    σ(result) = σ(left) ∨ σ(right)
    """
    if not tracker.enabled:
        return TaintState.clean()
    
    left_taint = tracker.get_taint(left)
    right_taint = tracker.get_taint(right)
    result_taint = left_taint.merge(right_taint)
    tracker.set_taint(result, result_taint)
    
    # Also propagate symbolic taint bits (Mode A)
    left_tau, left_sigma = tracker.get_symbolic_taint(left)
    right_tau, right_sigma = tracker.get_symbolic_taint(right)
    result_tau, result_sigma = taint_propagate_binop(left_tau, left_sigma, right_tau, right_sigma)
    tracker.set_symbolic_taint(result, result_tau, result_sigma)
    
    return result_taint


def handle_unop(
    tracker: SecurityTracker,
    operand: SymbolicValue,
    result: SymbolicValue
) -> TaintState:
    """
    Handle taint propagation for unary operations.
    
    Taint is preserved through unary operations.
    """
    if not tracker.enabled:
        return TaintState.clean()
    
    operand_taint = tracker.get_taint(operand)
    tracker.set_taint(result, operand_taint)
    
    # Also propagate symbolic taint bits (Mode A)
    tau, sigma = tracker.get_symbolic_taint(operand)
    tracker.set_symbolic_taint(result, tau, sigma)
    
    return operand_taint


def handle_subscript(
    tracker: SecurityTracker,
    container: SymbolicValue,
    index: SymbolicValue,
    result: SymbolicValue
) -> TaintState:
    """
    Handle taint propagation for subscript operations.
    
    Taint propagates from both container and index to result.
    """
    if not tracker.enabled:
        return TaintState.clean()
    
    container_taint = tracker.get_taint(container)
    index_taint = tracker.get_taint(index)
    result_taint = container_taint.merge(index_taint)
    tracker.set_taint(result, result_taint)
    
    # Symbolic propagation
    cont_tau, cont_sigma = tracker.get_symbolic_taint(container)
    idx_tau, idx_sigma = tracker.get_symbolic_taint(index)
    result_tau = z3.Or(cont_tau, idx_tau)
    result_sigma = z3.Or(cont_sigma, idx_sigma)
    tracker.set_symbolic_taint(result, result_tau, result_sigma)
    
    return result_taint


def handle_store(
    tracker: SecurityTracker,
    value: SymbolicValue,
    target: SymbolicValue
):
    """
    Handle taint propagation for store operations.
    
    Taint is transferred from value to target.
    """
    if not tracker.enabled:
        return
    
    value_taint = tracker.get_taint(value)
    tracker.set_taint(target, value_taint)
    
    # Symbolic propagation
    tau, sigma = tracker.get_symbolic_taint(value)
    tracker.set_symbolic_taint(target, tau, sigma)


def create_fresh_tainted_value(
    tracker: SecurityTracker,
    value: SymbolicValue,
    source_type: TaintSource,
    location: str,
    is_sensitive: bool = False
):
    """
    Create a fresh symbolic value with taint from a source.
    
    Used when modeling sources that return fresh values (e.g., input()).
    """
    if not tracker.enabled:
        return
    
    # Create concrete taint state
    taint = TaintState.from_source(source_type, location, is_sensitive)
    tracker.set_taint(value, taint)
    
    # Create symbolic taint bits (Mode A: over-approximate as tainted)
    name = f"taint_{id(value)}"
    tau, sigma = create_symbolic_taint(name)
    
    # For sound over-approximation, constrain taint bits based on source type
    if is_sensitive:
        # Sensitive source: σ=1
        tracker.set_symbolic_taint(value, z3.BoolVal(False), z3.BoolVal(True))
    else:
        # Untrusted source: τ=1
        tracker.set_symbolic_taint(value, z3.BoolVal(True), z3.BoolVal(False))


def get_security_violations_from_state(state) -> List[SecurityViolation]:
    """
    Extract security violations from a machine state.
    
    Called by the bug detection registry to check for security bugs.
    """
    if hasattr(state, 'security_tracker') and state.security_tracker:
        return state.security_tracker.violations
    return []


def update_state_security_flags(state, tracker: SecurityTracker):
    """
    Update state flags based on security tracker findings.
    
    Maps security violations to the state attributes checked by
    the unsafe region predicates in unsafe/security/*.py
    """
    for violation in tracker.violations:
        # Set the specific detection flag based on sink type
        if violation.sink_type == SinkType.SQL_EXECUTE:
            state.sql_injection_detected = True
        elif violation.sink_type == SinkType.COMMAND_SHELL:
            state.command_injection_detected = True
        elif violation.sink_type == SinkType.CODE_EVAL:
            state.code_injection_detected = True
        elif violation.sink_type == SinkType.FILE_PATH:
            state.path_injection_detected = True
        elif violation.sink_type == SinkType.HTML_OUTPUT:
            state.xss_detected = True
        elif violation.sink_type == SinkType.HTTP_REQUEST:
            state.ssrf_detected = True
        elif violation.sink_type == SinkType.DESERIALIZE:
            state.deserialization_detected = True
        elif violation.sink_type == SinkType.XML_PARSE:
            state.xxe_detected = True
        elif violation.sink_type == SinkType.LOG_OUTPUT:
            state.cleartext_logging_detected = True
        elif violation.sink_type == SinkType.FILE_WRITE:
            state.cleartext_storage_detected = True
    
    # Also store the full list for detailed reporting
    if not hasattr(state, 'security_violations'):
        state.security_violations = []
    state.security_violations.extend(tracker.violations)
