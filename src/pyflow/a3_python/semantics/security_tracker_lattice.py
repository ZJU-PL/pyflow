"""
Security Tracker with Full Lattice Integration (leak_theory.md implementation).

This module provides the deep integration between the symbolic VM and the
taint product lattice L = P(T) × P(K) × P(T). It tracks:

1. Concrete taint labels (TaintLabel) for each symbolic value
2. Symbolic taint labels (SymbolicTaintLabel) for Z3 reasoning
3. PC taint for implicit flow tracking
4. Security violations detected during execution

The tracker provides hooks for:
- CALL opcode: source tainting, sink checking, sanitizer application
- BINARY_OP: taint propagation via lattice join
- STORE_*/LOAD_*: taint transfer
- POP_JUMP_IF_*: PC taint update for implicit flows
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
import z3
import os

# Debug flag for taint tracing
TAINT_DEBUG = os.environ.get('TAINT_DEBUG') == '1'

from a3_python.z3model.taint_lattice import (
    SourceType, SinkType, SanitizerType,
    TaintLabel, SymbolicTaintLabel,
    PCTaint, SymbolicPCTaint,
    SecurityViolation, SecurityBugType, CODEQL_BUG_TYPES,
    create_violation, create_unsafe_region_constraint, create_barrier_certificate,
    label_join, label_join_many,
    symbolic_label_join, symbolic_label_join_many,
    tau_zero, kappa_zero, kappa_full, sigma_zero,
    TAU_WIDTH, KAPPA_WIDTH, SIGMA_WIDTH,
)
from a3_python.contracts.security_lattice import (
    init_security_contracts,
    is_taint_source, is_security_sink, is_sanitizer,
    get_source_contract, get_sink_contract, get_sink_contracts, get_sanitizer_contract,
    apply_source_taint, apply_source_taint_symbolic,
    check_sink_taint, create_sink_unsafe_constraint,
    apply_sanitizer, apply_sanitizer_symbolic,
)
from a3_python.z3model.type_tracking import (
    ConcreteType, TypeLabel, TypeAwareTaintLabel,
    get_conversion_result_type, is_type_conversion
)
# NOTE: PathValidationTracker imported lazily to avoid circular import
# (barriers/__init__.py -> invariants -> symbolic_vm -> security_tracker_lattice)


# ============================================================================
# SYMBOLIC VALUE WRAPPER (for ID-based tracking)
# ============================================================================

def _value_id(value: Any) -> int:
    """Get stable ID for a symbolic value."""
    return id(value)


# ============================================================================
# SECURITY TRACKER
# ============================================================================

@dataclass
class LatticeSecurityTracker:
    """
    Security taint tracking with full product lattice.
    
    Tracks both concrete (TaintLabel) and symbolic (SymbolicTaintLabel)
    taint state for each value, enabling both precise analysis and
    Z3-based reasoning.
    """
    
    # ===== Concrete Taint State =====
    
    # Map from value ID to its concrete taint label
    value_labels: Dict[int, TaintLabel] = field(default_factory=dict)
    
    # Map from value ID to its type label (NEW: type tracking)
    type_labels: Dict[int, TypeLabel] = field(default_factory=dict)
    
    # Current PC taint (for implicit flow tracking)
    pc_taint: PCTaint = field(default_factory=PCTaint)
    
    # Stack of PC taint contexts (for nested branches)
    pc_taint_stack: List[PCTaint] = field(default_factory=list)
    
    # ===== Symbolic Taint State (Z3) =====
    
    # Map from value ID to its symbolic taint label
    symbolic_labels: Dict[int, SymbolicTaintLabel] = field(default_factory=dict)
    
    # Current symbolic PC taint
    symbolic_pc_taint: SymbolicPCTaint = field(default_factory=SymbolicPCTaint.clean)
    
    # Stack of symbolic PC taint contexts
    symbolic_pc_stack: List[SymbolicPCTaint] = field(default_factory=list)
    
    # ===== Taint Constraints (for Z3 path condition) =====
    
    # Constraints on taint labels (e.g., "this value came from HTTP source")
    taint_constraints: List[z3.BoolRef] = field(default_factory=list)
    
    # ===== Detection State =====
    
    # Detected security violations
    violations: List[SecurityViolation] = field(default_factory=list)
    
    # Guard variables for barrier certificates
    # Maps (value_id, sink_type) -> z3.Bool indicating sanitization
    sanitization_guards: Dict[Tuple[int, SinkType], z3.BoolRef] = field(default_factory=dict)
    
    # ===== Path Validation Tracking =====
    
    # Path validation tracker for tarslip/zipslip barrier certificates
    # Initialized lazily to avoid circular import
    path_validation_tracker: Optional[Any] = field(default=None)
    
    # ===== Configuration =====
    
    # Current execution location (for error messages)
    current_location: str = "unknown"
    
    # Enable/disable tracking
    enabled: bool = True
    
    # Enable implicit flow tracking (more precise but slower)
    track_implicit_flows: bool = True
    
    # Mode A only (no concolic validation)
    pure_symbolic: bool = True
    
    # ===== Initialization =====
    
    def __post_init__(self):
        """Initialize security contracts."""
        init_security_contracts()
    
    def _ensure_path_validation_tracker(self):
        """Lazy initialization of path validation tracker to avoid circular import."""
        if self.path_validation_tracker is None:
            from a3_python.barriers.path_validation import PathValidationTracker
            self.path_validation_tracker = PathValidationTracker()
        return self.path_validation_tracker
    
    def __deepcopy__(self, memo):
        """
        Custom deepcopy to properly copy violations list.
        
        Default deepcopy behavior with field(default_factory=list) creates
        new empty lists. We need to explicitly copy the violations list.
        
        ITERATION 590 FIX: Also copy any additional attributes from subclasses
        (e.g., InterproceduralTaintTracker.call_chain).
        """
        import copy
        
        # Create new instance without calling __init__
        cls = self.__class__
        new_tracker = cls.__new__(cls)
        memo[id(self)] = new_tracker
        
        # Copy all fields
        new_tracker.value_labels = copy.deepcopy(self.value_labels, memo)
        new_tracker.type_labels = copy.deepcopy(self.type_labels, memo)  # NEW: copy type labels
        new_tracker.pc_taint = copy.deepcopy(self.pc_taint, memo)
        new_tracker.pc_taint_stack = copy.deepcopy(self.pc_taint_stack, memo)
        new_tracker.symbolic_labels = copy.deepcopy(self.symbolic_labels, memo)
        new_tracker.symbolic_pc_taint = copy.deepcopy(self.symbolic_pc_taint, memo)
        new_tracker.symbolic_pc_stack = copy.deepcopy(self.symbolic_pc_stack, memo)
        new_tracker.taint_constraints = copy.deepcopy(self.taint_constraints, memo)
        new_tracker.violations = copy.deepcopy(self.violations, memo)  # Critical: copy violations
        new_tracker.sanitization_guards = copy.deepcopy(self.sanitization_guards, memo)
        new_tracker.path_validation_tracker = copy.deepcopy(self.path_validation_tracker, memo)
        new_tracker.current_location = self.current_location
        new_tracker.enabled = self.enabled
        new_tracker.track_implicit_flows = self.track_implicit_flows
        new_tracker.pure_symbolic = self.pure_symbolic
        
        # ITERATION 590 FIX: Copy additional attributes from subclasses
        # This handles InterproceduralTaintTracker.call_chain, context, summary_applications
        for attr_name in dir(self):
            if not attr_name.startswith('_') and attr_name not in [
                'value_labels', 'type_labels', 'pc_taint', 'pc_taint_stack',
                'symbolic_labels', 'symbolic_pc_taint', 'symbolic_pc_stack',
                'taint_constraints', 'violations', 'sanitization_guards',
                'path_validation_tracker', 'current_location', 'enabled',
                'track_implicit_flows', 'pure_symbolic'
            ]:
                attr_value = getattr(self, attr_name, None)
                # Only copy data attributes, not methods
                if attr_value is not None and not callable(attr_value):
                    try:
                        setattr(new_tracker, attr_name, copy.deepcopy(attr_value, memo))
                    except:
                        # If deepcopy fails, use shallow copy
                        setattr(new_tracker, attr_name, attr_value)
        
        if TAINT_DEBUG:
            print(f"[TAINT] __deepcopy__: copied {len(self.violations)} violations")
            print(f"        new tracker violations: {len(new_tracker.violations)}")
        
        return new_tracker
    
    # ===== Concrete Label Operations =====
    
    def set_label(self, value: Any, label: TaintLabel) -> None:
        """Set concrete taint label for a value."""
        self.value_labels[_value_id(value)] = label
    
    def get_label(self, value: Any) -> TaintLabel:
        """Get concrete taint label for a value (default: clean)."""
        return self.value_labels.get(_value_id(value), TaintLabel.clean())
    
    def merge_labels(self, *values: Any) -> TaintLabel:
        """Merge taint labels from multiple values."""
        labels = [self.get_label(v) for v in values]
        return label_join_many(labels)
    
    # ===== Type Label Operations (NEW) =====
    
    def set_type_label(self, value: Any, type_label: TypeLabel) -> None:
        """Set type label for a value."""
        self.type_labels[_value_id(value)] = type_label
    
    def get_type_label(self, value: Any) -> TypeLabel:
        """Get type label for a value (default: unknown)."""
        return self.type_labels.get(_value_id(value), TypeLabel.unknown())
    
    def get_type_aware_label(self, value: Any) -> TypeAwareTaintLabel:
        """Get combined type-aware taint label for a value."""
        return TypeAwareTaintLabel(
            taint_label=self.get_label(value),
            type_label=self.get_type_label(value)
        )
    
    def set_type_aware_label(self, value: Any, type_aware: TypeAwareTaintLabel) -> None:
        """Set both taint and type labels from a type-aware label."""
        self.set_label(value, type_aware.taint_label)
        self.set_type_label(value, type_aware.type_label)
    
    # ===== Symbolic Label Operations =====
    
    def set_symbolic_label(self, value: Any, label: SymbolicTaintLabel) -> None:
        """Set symbolic taint label for a value."""
        self.symbolic_labels[_value_id(value)] = label
    
    def get_symbolic_label(self, value: Any) -> SymbolicTaintLabel:
        """Get symbolic taint label for a value (default: clean)."""
        return self.symbolic_labels.get(_value_id(value), SymbolicTaintLabel.clean())
    
    def merge_symbolic_labels(self, *values: Any) -> SymbolicTaintLabel:
        """Merge symbolic taint labels from multiple values."""
        labels = [self.get_symbolic_label(v) for v in values]
        return symbolic_label_join_many(labels)
    
    # ===== Implicit Flow (PC Taint) Operations =====
    
    def enter_branch(self, condition_value: Any) -> None:
        """
        Enter a branch conditioned on a potentially tainted value.
        
        Saves current PC taint and merges condition's taint into PC taint.
        """
        if not self.track_implicit_flows:
            return
        
        # Push current PC taint
        self.pc_taint_stack.append(self.pc_taint)
        self.symbolic_pc_stack.append(self.symbolic_pc_taint)
        
        # Merge condition's taint into PC taint
        cond_label = self.get_label(condition_value)
        self.pc_taint = self.pc_taint.merge_from_condition(cond_label)
        
        cond_symbolic = self.get_symbolic_label(condition_value)
        self.symbolic_pc_taint = self.symbolic_pc_taint.merge_from_condition(cond_symbolic)
    
    def exit_branch(self) -> None:
        """
        Exit a branch, restoring previous PC taint.
        """
        if not self.track_implicit_flows:
            return
        
        if self.pc_taint_stack:
            self.pc_taint = self.pc_taint_stack.pop()
        if self.symbolic_pc_stack:
            self.symbolic_pc_taint = self.symbolic_pc_stack.pop()
    
    def apply_pc_taint(self, label: TaintLabel) -> TaintLabel:
        """Apply current PC taint to a label (for implicit flows)."""
        if self.track_implicit_flows and not self.pc_taint.is_clean():
            return self.pc_taint.apply_to_assignment(label)
        return label
    
    def apply_symbolic_pc_taint(self, label: SymbolicTaintLabel) -> SymbolicTaintLabel:
        """Apply symbolic PC taint to a label."""
        if self.track_implicit_flows:
            return self.symbolic_pc_taint.apply_to_assignment(label)
        return label
    
    # ===== Call Handling =====
    
    def handle_call_pre(
        self,
        func_name: str,
        args: List[Any],
        location: str,
        kwargs: Dict = None,
        is_method_call: bool = False
    ) -> Optional[SecurityViolation]:
        """
        Pre-call hook: check if calling a sink with tainted args.
        
        Called by the VM before executing a function call.
        
        Args:
            func_name: Name of the function being called
            args: Arguments to the call (for method calls, args[0] is the receiver/self)
            location: Source location
            kwargs: Keyword arguments
            is_method_call: If True, args[0] is the receiver object (self)
        
        Returns SecurityViolation if a security bug is detected.
        """
        if not self.enabled:
            return None
        
        self.current_location = location
        kwargs = kwargs or {}
        
        # ITERATION 286: Debug ALL calls, not just sinks
        if TAINT_DEBUG:
            print(f"[TAINT] handle_call_pre: func_name={repr(func_name)}")
            print(f"        is_method_call={is_method_call}, num_args={len(args)}")
            print(f"        is_sink? {is_security_sink(func_name)}")
            if func_name and 'request' in func_name.lower():
                print(f"        *** REQUEST-RELATED CALL DETECTED ***")
        
        # Check if this is a security sink
        if is_security_sink(func_name):
            if TAINT_DEBUG:
                print(f"[TAINT] handle_call_pre: SINK {func_name}({args})")
            
            # Get taint labels for arguments
            arg_labels = [self.get_label(arg) for arg in args]
            
            # ITERATION 544: Get type labels for type-aware checking
            type_labels = [self.get_type_label(arg) for arg in args]
            
            # ITERATION 526: For method calls, extract receiver label separately
            receiver_label = None
            receiver_type = None
            if is_method_call and len(args) > 0:
                receiver_label = arg_labels[0]
                receiver_type = type_labels[0]
                # Remove receiver from arg_labels since it will be checked separately
                arg_labels = arg_labels[1:]
                type_labels = type_labels[1:]
                
                if TAINT_DEBUG:
                    print(f"        RECEIVER (args[0]): {args[0]}")
                    print(f"          taint: {receiver_label}")
                    print(f"          type: {receiver_type.concrete_type.name}")
                    print(f"          τ (untrusted): {bin(receiver_label.tau)} = {receiver_label.tau}")
                    print(f"          has τ-taint? {receiver_label.has_untrusted_taint()}")
            
            if TAINT_DEBUG:
                for i, (arg, label, typ) in enumerate(zip(args[1:] if is_method_call else args, arg_labels, type_labels)):
                    print(f"        arg[{i}]: {arg}")
                    print(f"          taint: {label}")
                    print(f"          type: {typ.concrete_type.name}")
                    print(f"          τ (untrusted): {bin(label.tau)} = {label.tau}")
                    print(f"          σ (sensitive): {bin(label.sigma)} = {label.sigma}")
                    print(f"          κ (sanitized): {bin(label.kappa)} = {label.kappa}")
                    print(f"          has τ-taint? {label.has_untrusted_taint()}")
                    print(f"          has σ-taint? {label.has_sensitivity()}")
            
            # ITERATION 544: Use type-aware checking for improved precision
            # For each arg, enhance its taint label with type information
            # The enhanced check happens inside check_sink_taint via the lattice is_safe_for_sink
            # We store type information so it can be consulted if needed by other analyses
            # (The actual type-aware filtering is minimal here since TypeAwareTaintLabel
            #  already handles this correctly in is_safe_for_sink_considering_type)
            
            # ITERATION 559: Convert kwargs values to TaintLabels for kwarg checking
            kwargs_labels = {}
            for key, value in kwargs.items():
                kwargs_labels[key] = self.get_label(value)
            
            # ITERATION 586: Pass path validation tracker and original args for validation guard checking
            path_tracker = self._ensure_path_validation_tracker() if hasattr(self, '_ensure_path_validation_tracker') else None
            
            # Check for violations - may return multiple for multi-sink functions
            violations_found = check_sink_taint(
                func_name, 
                location, 
                arg_labels, 
                kwargs_labels, 
                receiver_label, 
                path_validation_tracker=path_tracker,
                args=args
            )
            
            if violations_found:
                if TAINT_DEBUG:
                    print(f"        *** {len(violations_found)} VIOLATION(S) DETECTED ***")
                    for v in violations_found:
                        print(f"            - {v.bug_type}")
                # Append all violations to tracker
                self.violations.extend(violations_found)
                # Return first one for backward compatibility
                return violations_found[0]
            elif TAINT_DEBUG:
                print(f"        No violation (args are safe)")
            
            # Also create symbolic constraint for Z3 reasoning
            symbolic_labels = [self.get_symbolic_label(arg) for arg in args]
            unsafe_constraint = create_sink_unsafe_constraint(func_name, symbolic_labels)
            if unsafe_constraint is not None:
                # This constraint is satisfiable iff a bug is possible
                # We'll add it to path condition for barrier synthesis
                self.taint_constraints.append(z3.Not(unsafe_constraint))
        
        # ================================================================
        # ITERATION 495: Configuration bug detection - INSECURE_COOKIE
        # ================================================================
        # Detect set_cookie calls without proper security flags
        # Pattern: response.set_cookie(..., secure=False/None) or missing secure/httponly
        if func_name:  # Added None check
            if TAINT_DEBUG:
                print(f"[TAINT] Checking func_name: {func_name}")
            
            if 'set_cookie' in func_name.lower():
                if TAINT_DEBUG:
                    print(f"[TAINT] Detected set_cookie call: {func_name}")
                    print(f"        kwargs: {kwargs}")
                
                # Check for security flags in kwargs
                has_secure = kwargs.get('secure') is True
                has_httponly = kwargs.get('httponly') is True
                has_samesite = kwargs.get('samesite') in ('Strict', 'Lax')
                
                # Also check for explicit insecure values
                secure_false = kwargs.get('secure') is False or kwargs.get('secure') is None
                httponly_false = kwargs.get('httponly') is False or kwargs.get('httponly') is None
                samesite_none = kwargs.get('samesite') is None
                
                # Flag as insecure if ANY security flag is missing or explicitly insecure
                is_insecure = (
                    not has_secure or  # Missing or False
                    not has_httponly or  # Missing or False
                    not has_samesite  # Missing, None, or invalid
                )
                
                if is_insecure:
                    # Create violation for INSECURE_COOKIE
                    missing_flags = []
                    if not has_secure:
                        missing_flags.append("secure=True")
                    if not has_httponly:
                        missing_flags.append("httponly=True")
                    if not has_samesite:
                        missing_flags.append("samesite='Strict'/'Lax'")
                    
                    violation = SecurityViolation(
                        bug_type="INSECURE_COOKIE",
                        cwe="CWE-614",
                        severity="medium",
                        location=location,
                        message=f"Cookie set without security flags: missing {', '.join(missing_flags)}",
                        taint_path=[f"{location}: {func_name}() call"],
                        barrier_info={
                            "unsafe_region": "U_cookie := { s | set_cookie ∧ ¬secure_flags }",
                            "missing_flags": missing_flags,
                            "kwargs_present": list(kwargs.keys()) if kwargs else []
                        }
                    )
                    
                    if TAINT_DEBUG:
                        print(f"        *** INSECURE_COOKIE VIOLATION DETECTED ***")
                        print(f"            Missing flags: {missing_flags}")
                    
                    self.violations.append(violation)
                    return violation
        
        return None
    
    def handle_call_post(
        self,
        func_name: str,
        func_ref: Any,
        args: List[Any],
        result: Any,
        location: str
    ) -> Tuple[TaintLabel, SymbolicTaintLabel]:
        """
        Post-call hook: apply taint to result.
        
        Called by the VM after executing a function call.
        Returns (concrete_label, symbolic_label) for the result.
        
        Args:
            func_name: The name of the called function
            func_ref: The callable object being called (for method taint propagation)
            args: The arguments passed to the call
            result: The result value to taint
            location: Source location string
        """
        if not self.enabled:
            return TaintLabel.clean(), SymbolicTaintLabel.clean()
        
        # Check if this is a taint source
        if is_taint_source(func_name):
            concrete = apply_source_taint(func_name, location)
            symbolic = apply_source_taint_symbolic(func_name)
            
            # ITERATION 529: For method calls on tainted objects, merge source taint with callable taint
            # Example: cursor.fetchone() should inherit taint from BOTH DATABASE_RESULT source AND cursor object
            if func_ref is not None:
                func_concrete = self.get_label(func_ref)
                func_symbolic = self.get_symbolic_label(func_ref)
                concrete = label_join(concrete, func_concrete)
                symbolic = symbolic_label_join(symbolic, func_symbolic)
            
            # Apply PC taint (implicit flow)
            concrete = self.apply_pc_taint(concrete)
            symbolic = self.apply_symbolic_pc_taint(symbolic)
            
            self.set_label(result, concrete)
            self.set_symbolic_label(result, symbolic)
            
            # Add constraint: source's taint bits are set
            contract = get_source_contract(func_name)
            if contract:
                source_bit = 1 << contract.source_type
                if contract.is_sensitive:
                    self.taint_constraints.append(
                        (symbolic.sigma & z3.BitVecVal(source_bit, SIGMA_WIDTH)) != sigma_zero()
                    )
                else:
                    self.taint_constraints.append(
                        (symbolic.tau & z3.BitVecVal(source_bit, TAU_WIDTH)) != tau_zero()
                    )
            
            return concrete, symbolic
        
        # Check if this is a sanitizer
        if is_sanitizer(func_name) and args:
            # ITERATION 523: Special handling for Django template rendering
            # Django's render()/render_to_string() take taint from ALL args (especially context dict)
            # but return sanitized HTML due to auto-escaping
            is_django_render = (
                'render_to_string' in func_name or
                ('render' in func_name and 'django' in func_name)
            )
            
            if is_django_render:
                # Merge taint from ALL arguments (context dict may be in args[1] or later)
                labels_to_merge = [self.get_label(arg) for arg in args]
                symbolic_labels_to_merge = [self.get_symbolic_label(arg) for arg in args]
                
                input_concrete = label_join_many(labels_to_merge) if labels_to_merge else TaintLabel.clean()
                input_symbolic = symbolic_label_join_many(symbolic_labels_to_merge) if symbolic_labels_to_merge else SymbolicTaintLabel.fresh("clean")
            else:
                # Standard sanitizer: sanitize first argument only
                input_concrete = self.get_label(args[0])
                input_symbolic = self.get_symbolic_label(args[0])
            
            result_concrete = apply_sanitizer(func_name, input_concrete)
            result_symbolic = apply_sanitizer_symbolic(func_name, input_symbolic)
            
            # Apply PC taint
            result_concrete = self.apply_pc_taint(result_concrete)
            result_symbolic = self.apply_symbolic_pc_taint(result_symbolic)
            
            self.set_label(result, result_concrete)
            self.set_symbolic_label(result, result_symbolic)
            
            # ITERATION 544: Track type after conversion for type-sensitive sanitizers
            result_type = get_conversion_result_type(func_name)
            if result_type is not None:
                type_label = TypeLabel.from_type(result_type, f"{func_name}()")
                self.set_type_label(result, type_label)
            
            # Create sanitization guard for barrier certificates
            contract = get_sanitizer_contract(func_name)
            if contract:
                for sink in contract.applicable_sinks:
                    guard_name = f"sanitized_{_value_id(result)}_{sink.name}"
                    guard = z3.Bool(guard_name)
                    self.sanitization_guards[(_value_id(result), sink)] = guard
                    # Add constraint: this guard is True
                    self.taint_constraints.append(guard)
            
            return result_concrete, result_symbolic
        
        # Otherwise, propagate taint from arguments AND callable to result
        # CRITICAL: For method calls (e.g., tainted_obj.method(arg)), the method itself is tainted
        labels_to_merge = [self.get_label(arg) for arg in args]
        symbolic_labels_to_merge = [self.get_symbolic_label(arg) for arg in args]
        
        # Also propagate taint from the callable (for method calls on tainted objects)
        if func_ref is not None:
            func_concrete = self.get_label(func_ref)
            func_symbolic = self.get_symbolic_label(func_ref)
            labels_to_merge.append(func_concrete)
            symbolic_labels_to_merge.append(func_symbolic)
            
            if TAINT_DEBUG:
                print(f"[TAINT] handle_call_post: {func_name}({args}) -> {result}")
                print(f"        func_ref: {func_ref}")
                print(f"        func_ref taint: {func_concrete}")
                print(f"        func_ref has taint? {func_concrete.has_untrusted_taint()}")
                print(f"        arg taints: {[self.get_label(arg) for arg in args]}")
        
        merged_concrete = label_join_many(labels_to_merge)
        merged_symbolic = symbolic_label_join_many(symbolic_labels_to_merge)
        
        # Apply PC taint
        merged_concrete = self.apply_pc_taint(merged_concrete)
        merged_symbolic = self.apply_symbolic_pc_taint(merged_symbolic)
        
        self.set_label(result, merged_concrete)
        self.set_symbolic_label(result, merged_symbolic)
        
        if TAINT_DEBUG and func_ref is not None:
            print(f"        result taint: {merged_concrete}")
            print(f"        result has taint? {merged_concrete.has_untrusted_taint()}")
        
        # ===== Path Validation Detection =====
        # Detect startswith() calls for path validation (tarslip/zipslip)
        # Pattern: member_path.startswith(safe_prefix) returns True on safe paths
        # Lazy import to avoid circular dependency
        from a3_python.barriers.path_validation import detect_startswith_validation, detect_abspath_check
        
        validation_detected = detect_startswith_validation(func_name, func_ref, args, result)
        if validation_detected:
            validated_value, validation_passes_when_true = validation_detected
            
            # Create Z3 guard: validation passes when result == True
            # In a conditional check like `if not path.startswith(...)`, the negation
            # is handled by POP_JUMP_IF_* bytecode, not here
            guard = z3.Bool(f"path_valid_{_value_id(validated_value)}_{location}")
            
            # Record the validation in the tracker
            tracker = self._ensure_path_validation_tracker()
            tracker.record_validation(
                validated_value,
                guard,
                location
            )
            
            if TAINT_DEBUG:
                print(f"[PATH VALIDATION] Detected startswith validation:")
                print(f"  Function: {func_name}")
                print(f"  Validated value: {validated_value}")
                print(f"  Location: {location}")
        
        # Detect os.path.abspath() calls for path normalization
        abspath_detected = detect_abspath_check(func_name, args)
        if abspath_detected:
            original_path, _ = abspath_detected
            
            # Mark the result as a normalized path
            # This can be used in combination with startswith validation
            if TAINT_DEBUG:
                print(f"[PATH VALIDATION] Detected abspath normalization:")
                print(f"  Function: {func_name}")
                print(f"  Original path: {original_path}")
                print(f"  Normalized result: {result}")
        
        return merged_concrete, merged_symbolic
    
    # ===== Binary Operation Handling =====
    
    def handle_binop(
        self,
        left: Any,
        right: Any,
        result: Any
    ) -> Tuple[TaintLabel, SymbolicTaintLabel]:
        """
        Handle taint propagation for binary operations.
        
        τ(result) = τ(left) ∪ τ(right)
        κ(result) = κ(left) ∩ κ(right)
        σ(result) = σ(left) ∪ σ(right)
        """
        if not self.enabled:
            return TaintLabel.clean(), SymbolicTaintLabel.clean()
        
        left_concrete = self.get_label(left)
        right_concrete = self.get_label(right)
        result_concrete = left_concrete.join(right_concrete)
        
        left_symbolic = self.get_symbolic_label(left)
        right_symbolic = self.get_symbolic_label(right)
        result_symbolic = left_symbolic.join(right_symbolic)
        
        # Apply PC taint
        result_concrete = self.apply_pc_taint(result_concrete)
        result_symbolic = self.apply_symbolic_pc_taint(result_symbolic)
        
        self.set_label(result, result_concrete)
        self.set_symbolic_label(result, result_symbolic)
        
        return result_concrete, result_symbolic
    
    # ===== Unary Operation Handling =====
    
    def handle_unop(
        self,
        operand: Any,
        result: Any
    ) -> Tuple[TaintLabel, SymbolicTaintLabel]:
        """
        Handle taint propagation for unary operations.
        
        Taint is preserved through unary operations.
        """
        if not self.enabled:
            return TaintLabel.clean(), SymbolicTaintLabel.clean()
        
        operand_concrete = self.get_label(operand)
        operand_symbolic = self.get_symbolic_label(operand)
        
        # Apply PC taint
        result_concrete = self.apply_pc_taint(operand_concrete)
        result_symbolic = self.apply_symbolic_pc_taint(operand_symbolic)
        
        self.set_label(result, result_concrete)
        self.set_symbolic_label(result, result_symbolic)
        
        return result_concrete, result_symbolic
    
    # ===== Subscript Handling =====
    
    def handle_subscript(
        self,
        container: Any,
        index: Any,
        result: Any
    ) -> Tuple[TaintLabel, SymbolicTaintLabel]:
        """
        Handle taint propagation for subscript operations.
        
        Taint propagates from both container and index to result.
        """
        if not self.enabled:
            return TaintLabel.clean(), SymbolicTaintLabel.clean()
        
        container_concrete = self.get_label(container)
        index_concrete = self.get_label(index)
        result_concrete = container_concrete.join(index_concrete)
        
        container_symbolic = self.get_symbolic_label(container)
        index_symbolic = self.get_symbolic_label(index)
        result_symbolic = container_symbolic.join(index_symbolic)
        
        # Apply PC taint
        result_concrete = self.apply_pc_taint(result_concrete)
        result_symbolic = self.apply_symbolic_pc_taint(result_symbolic)
        
        self.set_label(result, result_concrete)
        self.set_symbolic_label(result, result_symbolic)
        
        return result_concrete, result_symbolic
    
    # ===== Store Handling =====
    
    def handle_store(
        self,
        value: Any,
        target: Any
    ) -> None:
        """
        Handle taint propagation for store operations.
        
        Taint is transferred from value to target.
        """
        if not self.enabled:
            return
        
        value_concrete = self.get_label(value)
        value_symbolic = self.get_symbolic_label(value)
        
        # Apply PC taint
        result_concrete = self.apply_pc_taint(value_concrete)
        result_symbolic = self.apply_symbolic_pc_taint(value_symbolic)
        
        self.set_label(target, result_concrete)
        self.set_symbolic_label(target, result_symbolic)
    
    # ===== Attribute Access Handling =====
    
    def handle_getattr(
        self,
        obj: Any,
        attr_name: str,
        result: Any
    ) -> Tuple[TaintLabel, SymbolicTaintLabel]:
        """
        Handle taint propagation for attribute access.
        
        Taint propagates from object to attribute value.
        """
        if not self.enabled:
            return TaintLabel.clean(), SymbolicTaintLabel.clean()
        
        obj_concrete = self.get_label(obj)
        obj_symbolic = self.get_symbolic_label(obj)
        
        if TAINT_DEBUG:
            print(f"[TAINT] handle_getattr: {obj}.{attr_name} -> {result}")
            print(f"        obj taint: {obj_concrete}")
            print(f"        has taint? {obj_concrete.has_untrusted_taint()}")
        
        # Apply PC taint
        result_concrete = self.apply_pc_taint(obj_concrete)
        result_symbolic = self.apply_symbolic_pc_taint(obj_symbolic)
        
        self.set_label(result, result_concrete)
        self.set_symbolic_label(result, result_symbolic)
        
        if TAINT_DEBUG:
            print(f"        result taint: {result_concrete}")
            print(f"        result has taint? {result_concrete.has_untrusted_taint()}")
        
        return result_concrete, result_symbolic
    
    # ===== Violation Detection =====
    
    def has_violations(self) -> bool:
        """Check if any security violations were detected."""
        return len(self.violations) > 0
    
    def get_violations(self) -> List[SecurityViolation]:
        """Get all detected violations."""
        return self.violations.copy()
    
    def get_violations_by_type(self, bug_type: str) -> List[SecurityViolation]:
        """Get violations of a specific bug type."""
        return [v for v in self.violations if v.bug_type == bug_type]
    
    # ===== Barrier Certificate Generation =====
    
    def get_barrier_constraints(self) -> List[z3.BoolRef]:
        """
        Get Z3 constraints for barrier certificate synthesis.
        
        Returns constraints that must hold for the program to be safe.
        """
        return self.taint_constraints.copy()
    
    def get_sanitization_guard(self, value: Any, sink: SinkType) -> Optional[z3.BoolRef]:
        """Get sanitization guard variable for a value and sink."""
        return self.sanitization_guards.get((_value_id(value), sink))
    
    def create_barrier_for_sink(
        self,
        sink: SinkType,
        arg_value: Any,
        at_sink_location: z3.BoolRef = None
    ) -> z3.ArithRef:
        """
        Create barrier certificate for a specific sink.
        
        B(s) = g_sanitized + (1 - τ) - 0.5
        """
        bug_type = None
        for bt in CODEQL_BUG_TYPES.values():
            if bt.sink_type == sink:
                bug_type = bt
                break
        
        if bug_type is None:
            return z3.IntVal(1)  # Always safe
        
        label = self.get_symbolic_label(arg_value)
        guard = self.get_sanitization_guard(arg_value, sink)
        
        return create_barrier_certificate(bug_type, label, guard)
    
    # ===== State Management =====
    
    def copy(self) -> 'LatticeSecurityTracker':
        """Deep copy for path forking."""
        return LatticeSecurityTracker(
            value_labels=self.value_labels.copy(),
            pc_taint=self.pc_taint,
            pc_taint_stack=self.pc_taint_stack.copy(),
            symbolic_labels=self.symbolic_labels.copy(),
            symbolic_pc_taint=self.symbolic_pc_taint,
            symbolic_pc_stack=self.symbolic_pc_stack.copy(),
            taint_constraints=self.taint_constraints.copy(),
            violations=self.violations.copy(),
            sanitization_guards=self.sanitization_guards.copy(),
            current_location=self.current_location,
            enabled=self.enabled,
            track_implicit_flows=self.track_implicit_flows,
            pure_symbolic=self.pure_symbolic
        )
    
    def clear(self) -> None:
        """Clear all tracking state."""
        self.value_labels.clear()
        self.pc_taint = PCTaint()
        self.pc_taint_stack.clear()
        self.symbolic_labels.clear()
        self.symbolic_pc_taint = SymbolicPCTaint.clean()
        self.symbolic_pc_stack.clear()
        self.taint_constraints.clear()
        self.violations.clear()
        self.sanitization_guards.clear()


# ============================================================================
# NAME-BASED SENSITIVITY INFERENCE
# ============================================================================

def infer_sensitivity_from_name(var_name: str) -> Optional[SourceType]:
    """
    Infer sensitivity type from variable/parameter name using heuristic patterns.
    
    This provides pragmatic detection of sensitive data based on naming conventions,
    matching CodeQL's behavior for cleartext detection.
    
    Args:
        var_name: The variable or parameter name to analyze
        
    Returns:
        SourceType if name suggests sensitive data, None otherwise
        
    Example:
        >>> infer_sensitivity_from_name("password")
        SourceType.PASSWORD
        >>> infer_sensitivity_from_name("api_key")
        SourceType.API_KEY
        >>> infer_sensitivity_from_name("user_name")
        None
    """
    if not var_name or not isinstance(var_name, str):
        return None
    
    # Convert to lowercase for case-insensitive matching
    name_lower = var_name.lower()
    
    # PASSWORD patterns
    if any(pattern in name_lower for pattern in ['password', 'passwd', 'pwd']):
        return SourceType.PASSWORD
    
    # API_KEY patterns
    if any(pattern in name_lower for pattern in ['api_key', 'apikey', 'api-key', 'api.key']):
        return SourceType.API_KEY
    
    # CREDENTIALS patterns
    if any(pattern in name_lower for pattern in ['credential', 'secret', 'auth_token']):
        return SourceType.CREDENTIALS
    
    # SESSION_TOKEN patterns
    if any(pattern in name_lower for pattern in ['session_id', 'session_token', 'sessionid', 'csrf_token', 'auth_code']):
        return SourceType.SESSION_TOKEN
    
    # CRYPTO_KEY patterns
    if any(pattern in name_lower for pattern in ['private_key', 'privatekey', 'secret_key', 'secretkey', 'encryption_key']):
        return SourceType.CRYPTO_KEY
    
    # PII patterns
    if any(pattern in name_lower for pattern in ['ssn', 'social_security', 'credit_card', 'creditcard']):
        return SourceType.PII
    
    # PRIVATE_DATA patterns (fallback for generic sensitive terms)
    if any(pattern in name_lower for pattern in ['private', 'confidential', 'sensitive']):
        return SourceType.PRIVATE_DATA
    
    return None


# ============================================================================
# BACKWARD COMPATIBILITY
# ============================================================================

# Alias for backward compatibility with existing code
SecurityTracker = LatticeSecurityTracker


def handle_call_pre(
    tracker: LatticeSecurityTracker,
    func_name: str,
    args: List[Any],
    location: str,
    kwargs: Dict = None,
    is_method_call: bool = False
) -> Optional[SecurityViolation]:
    """Backward-compatible wrapper."""
    return tracker.handle_call_pre(func_name, args, location, kwargs, is_method_call)


def handle_call_post(
    tracker: LatticeSecurityTracker,
    func_name: str,
    func_ref: Any,
    args: List[Any],
    result: Any,
    location: str
) -> TaintLabel:
    """Backward-compatible wrapper."""
    import os
    import sys
    if os.environ.get('TAINT_DEBUG') == '1':
        print(f"[WRAPPER] handle_call_post called for {func_name}", file=sys.stderr)
        print(f"[WRAPPER]   tracker type: {type(tracker).__name__}", file=sys.stderr)
        print(f"[WRAPPER]   tracker.handle_call_post: {tracker.handle_call_post}", file=sys.stderr)
    concrete, _ = tracker.handle_call_post(func_name, func_ref, args, result, location)
    return concrete


def handle_binop(
    tracker: LatticeSecurityTracker,
    left: Any,
    right: Any,
    result: Any
) -> TaintLabel:
    """Backward-compatible wrapper."""
    concrete, _ = tracker.handle_binop(left, right, result)
    return concrete


def handle_unop(
    tracker: LatticeSecurityTracker,
    operand: Any,
    result: Any
) -> TaintLabel:
    """Backward-compatible wrapper."""
    concrete, _ = tracker.handle_unop(operand, result)
    return concrete


def handle_subscript(
    tracker: LatticeSecurityTracker,
    container: Any,
    index: Any,
    result: Any
) -> TaintLabel:
    """Backward-compatible wrapper."""
    concrete, _ = tracker.handle_subscript(container, index, result)
    return concrete


def handle_store(
    tracker: LatticeSecurityTracker,
    value: Any,
    target: Any
) -> None:
    """Backward-compatible wrapper."""
    tracker.handle_store(value, target)


def ensure_security_contracts_initialized():
    """Initialize security contracts."""
    init_security_contracts()


# ============================================================================
# STATE FLAG UPDATES
# ============================================================================

def update_state_security_flags(state: Any, tracker: LatticeSecurityTracker) -> None:
    """
    Update state flags based on security tracker findings.
    
    Maps security violations to state attributes for unsafe region predicates.
    """
    for violation in tracker.violations:
        sink = violation.sink_type
        
        # Set specific detection flags
        flag_mapping = {
            SinkType.SQL_EXECUTE: 'sql_injection_detected',
            SinkType.COMMAND_SHELL: 'command_injection_detected',
            SinkType.CODE_EVAL: 'code_injection_detected',
            SinkType.FILE_PATH: 'path_injection_detected',
            SinkType.HTML_OUTPUT: 'xss_detected',
            SinkType.TEMPLATE_RENDER: 'xss_detected',
            SinkType.HTTP_REQUEST: 'ssrf_detected',
            SinkType.DESERIALIZE: 'deserialization_detected',
            SinkType.XML_PARSE: 'xxe_detected',
            SinkType.LOG_OUTPUT: 'cleartext_logging_detected',
            SinkType.FILE_WRITE: 'cleartext_storage_detected',
            SinkType.LDAP_QUERY: 'ldap_injection_detected',
            SinkType.XPATH_QUERY: 'xpath_injection_detected',
            SinkType.NOSQL_QUERY: 'nosql_injection_detected',
            SinkType.REGEX_PATTERN: 'regex_injection_detected',
            SinkType.REDIRECT_URL: 'redirect_detected',
            SinkType.HEADER_SET: 'header_injection_detected',
            SinkType.LOG_FORGING: 'log_injection_detected',
            SinkType.CRYPTO_WEAK: 'weak_crypto_detected',
        }
        
        flag_name = flag_mapping.get(sink)
        if flag_name:
            setattr(state, flag_name, True)
    
    # Store full violations list
    if not hasattr(state, 'security_violations'):
        state.security_violations = []
    state.security_violations.extend(tracker.violations)


def get_security_violations_from_state(state: Any) -> List[SecurityViolation]:
    """Extract security violations from a machine state."""
    if hasattr(state, 'security_tracker') and state.security_tracker:
        return state.security_tracker.get_violations()
    if hasattr(state, 'security_violations'):
        return state.security_violations
    return []


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Main class
    'LatticeSecurityTracker',
    'SecurityTracker',  # Alias
    
    # Handlers
    'handle_call_pre', 'handle_call_post',
    'handle_binop', 'handle_unop', 'handle_subscript', 'handle_store',
    
    # State management
    'update_state_security_flags',
    'get_security_violations_from_state',
    'ensure_security_contracts_initialized',
]
