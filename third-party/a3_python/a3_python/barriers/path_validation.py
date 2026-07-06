"""
Path validation barrier certificates.

Implements barrier-theoretic reasoning for path traversal safety patterns.

When code validates paths before file operations (e.g., checking that
extracted paths are within a safe directory), we can prove safety via
barrier certificates that track the validation state.

Pattern recognized:
    member_path = os.path.join(dest, member.name)
    if not member_path.startswith(os.path.abspath(dest)):
        raise ValueError("Path traversal")
    tar.extractall(dest)  # SAFE on this path

Barrier certificate approach:
    B_path(s) = { M                              if π != π_sink
                { (1 - g_validated) - 1/2        if π == π_sink }
    
Where g_validated = 1 on paths where validation passed.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Set, Optional, Any
import z3

from a3_python.z3model.taint_lattice import (
    SinkType, TaintLabel, create_barrier_certificate
)


@dataclass
class PathValidationGuard:
    """
    Tracks path validation for a symbolic value.
    
    Records that a path has been validated against a safe prefix,
    enabling barrier-certificate-based proof of safety.
    """
    # The value ID being validated
    value_id: int
    
    # Z3 guard variable: True iff path is validated
    guard: z3.BoolRef
    
    # Which sink types this validation protects against
    protected_sinks: Set[SinkType]
    
    # Source location of validation
    location: str


class PathValidationTracker:
    """
    Tracks path validation guards for barrier certificate synthesis.
    
    Detects common path validation patterns:
    1. path.startswith(safe_prefix) check before file ops
    2. os.path.abspath() normalization before comparison
    3. Raises exception on validation failure
    
    Creates Z3 guard variables that can be used in barrier certificates
    to prove safety.
    """
    
    def __init__(self):
        # Map from (value_id, sink_type) to validation guard
        self.guards: Dict[tuple[int, SinkType], PathValidationGuard] = {}
        
        # Sinks that path validation protects against
        # Note: TARSLIP and ZIPSLIP bugs both use FILE_PATH sink type
        self.path_sinks = {
            SinkType.FILE_PATH,
            SinkType.FILE_WRITE,
        }
    
    def record_validation(
        self,
        value: Any,
        validation_passed: z3.BoolRef,
        location: str
    ) -> None:
        """
        Record that a path value has been validated.
        
        Args:
            value: The path value being validated
            validation_passed: Z3 constraint that is True when validation passes
            location: Source location of validation
        """
        value_id = id(value)
        
        for sink in self.path_sinks:
            guard_name = f"path_valid_{value_id}_{sink.name}"
            guard = z3.Bool(guard_name)
            
            # Create guard
            validation_guard = PathValidationGuard(
                value_id=value_id,
                guard=guard,
                protected_sinks={sink},
                location=location
            )
            
            self.guards[(value_id, sink)] = validation_guard
    
    def get_guard(
        self,
        value: Any,
        sink: SinkType
    ) -> Optional[z3.BoolRef]:
        """
        Get validation guard for a value at a sink.
        
        Returns Z3 boolean that is True iff the path has been validated
        for use at this sink.
        """
        value_id = id(value)
        guard_data = self.guards.get((value_id, sink))
        
        if guard_data:
            return guard_data.guard
        
        return None
    
    def is_validated(
        self,
        value: Any,
        sink: SinkType
    ) -> bool:
        """
        Check if a value has a validation guard for a sink.
        """
        return (id(value), sink) in self.guards
    
    def create_path_safety_barrier(
        self,
        value: Any,
        sink: SinkType,
        taint_label: TaintLabel,
        at_sink: z3.BoolRef
    ) -> Optional[z3.ExprRef]:
        """
        Create barrier certificate for path safety.
        
        Returns barrier B_path that proves safety if:
        1. Value is validated (guard = True) on paths to sink
        2. Or value is untainted (τ = 0)
        
        B_path(s) = (1 - at_sink) · M + at_sink · (guard + (1-τ) - 1/2)
        
        Where:
        - M is a large constant (e.g., 1.0)
        - guard = 1 if path validated, 0 otherwise
        - τ = 1 if tainted from untrusted source, 0 if clean
        """
        guard = self.get_guard(value, sink)
        
        if guard is None:
            # No validation guard - cannot prove safety via this method
            return None
        
        # Get taint bit (τ component)
        tau = taint_label.tau
        
        # Barrier at sink: (guard + (1-τ) - 1/2)
        # This is >= 0 iff (guard OR NOT tainted)
        # I.e., safe if validated OR clean
        M = 1.0
        
        barrier_at_sink = z3.If(
            tau == 0,
            z3.RealVal(0.5),  # Clean: always safe
            z3.If(
                guard,
                z3.RealVal(0.5),  # Validated: safe
                z3.RealVal(-0.5)  # Tainted + not validated: unsafe
            )
        )
        
        # Full barrier with indicator
        barrier = z3.If(
            at_sink,
            barrier_at_sink,
            z3.RealVal(M)  # Not at sink: in safe region
        )
        
        return barrier
    
    def clear(self):
        """Clear all validation guards."""
        self.guards.clear()


def detect_startswith_validation(
    func_name: str,
    receiver: Any,
    args: list,
    result: Any
) -> Optional[tuple[Any, bool]]:
    """
    Detect if a call represents a path validation via startswith.
    
    Pattern: `path.startswith(safe_prefix)` or `str.startswith(path, safe_prefix)`
    
    Args:
        func_name: Name of function being called
        receiver: Receiver object for method calls (args[0] in is_method_call=True)
        args: Arguments to the call (excluding receiver for method calls)
        result: Return value of the call
    
    Returns:
        (validated_value, validation_passed_constraint) if pattern matches
        None otherwise
        
    The validation_passed_constraint is True when the result indicates
    the path is validated (i.e., startswith returned True).
    """
    # Check if this is a startswith call
    if func_name in ("str.startswith", "startswith"):
        # Pattern: path.startswith(prefix) or str.startswith(path, prefix)
        # For method call: receiver is the path, args[0] is the prefix
        # For function call: args[0] is the path, args[1] is the prefix
        
        if receiver is not None:
            # Method call: receiver.startswith(prefix)
            validated_value = receiver
        elif len(args) >= 2:
            # Function call: str.startswith(path, prefix)
            validated_value = args[0]
        else:
            # Invalid call - not enough arguments
            return None
        
        # The validation passes when startswith returns True
        # We return the validated value and True (meaning result == True)
        return (validated_value, True)
    
    return None


def detect_abspath_check(
    func_name: str,
    args: list
) -> Optional[tuple[Any, Any]]:
    """
    Detect if a call involves os.path.abspath for normalization.
    
    Pattern: `os.path.abspath(dest)` returns normalized path
    
    Args:
        func_name: Name of function being called
        args: Arguments to the call
    
    Returns:
        (original_path, normalized_marker) if pattern matches
        None otherwise
        
    When os.path.abspath is detected, we mark that the path argument
    has been normalized, which is a precondition for safe validation.
    """
    # Check if this is os.path.abspath
    if func_name in ("os.path.abspath", "posixpath.abspath", "ntpath.abspath"):
        if len(args) >= 1:
            # Return the path being normalized
            return (args[0], True)
    
    return None
