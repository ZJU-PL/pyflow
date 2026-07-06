"""
Interprocedural Taint Tracker with Function Summaries.

Extends LatticeSecurityTracker to use taint summaries for interprocedural dataflow.

This implements the interprocedural analysis from python-barrier-certificate-theory.md §9.5.10:

At call sites (applying summary Σ_g):
    ℓ_ret = Σ_g(ℓ_arg₁, ..., ℓ_arg_n)

For unknown functions (havoc with footprint):
    ℓ_ret = (⋃ᵢ τᵢ, ⋂ᵢ κᵢ, ⋃ᵢ σᵢ)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path
import sys

from .security_tracker_lattice import LatticeSecurityTracker
from .summaries import TaintSummary, SummaryComputer, compute_summaries_for_project
from ..cfg.call_graph import CallGraph, build_call_graph_from_directory
from ..frontend.entry_points import detect_entry_points_in_project, get_entry_point_functions
from ..z3model.taint_lattice import (
    TaintLabel, SymbolicTaintLabel,
    SourceType, SinkType, SanitizerType,
    label_join, label_join_many,
    SecurityViolation, CODEQL_BUG_TYPES,
)
from ..contracts.security_lattice import (
    is_taint_source, is_security_sink, is_sanitizer,
    get_source_contract, get_sink_contract, get_sanitizer_contract,
)


@dataclass
class InterproceduralContext:
    """
    Context for interprocedural analysis.
    
    Holds the call graph, computed summaries, and entry points.
    """
    call_graph: CallGraph
    summaries: Dict[str, TaintSummary]
    entry_points: Set[str]
    reachable_functions: Set[str]
    
    @classmethod
    def from_project(
        cls,
        root_path: Path,
        source_contracts: Dict[str, int] = None,
        sink_contracts: Dict[str, int] = None,
        sanitizer_contracts: Dict[str, Set[int]] = None,
    ) -> 'InterproceduralContext':
        """Build interprocedural context for an entire project."""
        # Build call graph
        call_graph = build_call_graph_from_directory(root_path)
        
        # Detect entry points
        entry_point_list = detect_entry_points_in_project(root_path)
        entry_points = get_entry_point_functions(entry_point_list)
        
        # Compute reachable functions
        reachable = call_graph.get_reachable_from(entry_points)
        
        # Compute summaries
        computer = SummaryComputer(
            call_graph,
            source_contracts=source_contracts,
            sink_contracts=sink_contracts,
            sanitizer_contracts=sanitizer_contracts,
        )
        summaries = computer.compute_all()
        
        return cls(
            call_graph=call_graph,
            summaries=summaries,
            entry_points=entry_points,
            reachable_functions=reachable,
        )
    
    @classmethod
    def from_file(
        cls,
        file_path: Path,
        source_contracts: Dict[str, int] = None,
        sink_contracts: Dict[str, int] = None,
        sanitizer_contracts: Dict[str, Set[int]] = None,
    ) -> 'InterproceduralContext':
        """Build interprocedural context for a single file."""
        from ..cfg.call_graph import build_call_graph_from_file
        
        # Build call graph for the file
        call_graph = build_call_graph_from_file(file_path)
        
        # For a single file, treat all functions as potential entry points
        entry_points = set(call_graph.functions.keys())
        
        # All functions are considered reachable
        reachable = entry_points.copy()
        
        # Compute summaries
        computer = SummaryComputer(
            call_graph,
            source_contracts=source_contracts,
            sink_contracts=sink_contracts,
            sanitizer_contracts=sanitizer_contracts,
        )
        summaries = computer.compute_all()
        
        return cls(
            call_graph=call_graph,
            summaries=summaries,
            entry_points=entry_points,
            reachable_functions=reachable,
        )
    
    def get_summary(self, func_name: str) -> Optional[TaintSummary]:
        """Get summary for a function, if available."""
        # Prefer exact match.
        summary = self.summaries.get(func_name)
        if summary is not None:
            return summary

        # Allow unqualified lookups (e.g., "foo") when summaries are qualified
        # (e.g., "module.foo"). Only return a suffix match if unambiguous.
        suffix = f".{func_name}"
        candidates = [s for k, s in self.summaries.items() if k.endswith(suffix)]
        if len(candidates) == 1:
            return candidates[0]

        return None
    
    def is_reachable(self, func_name: str) -> bool:
        """Check if a function is reachable from entry points."""
        return func_name in self.reachable_functions


class InterproceduralTaintTracker(LatticeSecurityTracker):
    """
    Taint tracker with interprocedural summary support.
    
    Extends LatticeSecurityTracker to apply function summaries at call sites,
    enabling cross-function and cross-file taint tracking.
    
    Phase 4B Extension: Call chain tracking for multi-level bug detection.
    """
    
    def __init__(
        self,
        context: Optional[InterproceduralContext] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.context = context
        
        # Track summary applications for debugging
        self.summary_applications: List[Tuple[str, str, TaintLabel]] = []
        
        # Phase 4B: Call chain tracking for cross-function bugs
        self.call_chain: List[str] = []  # Stack of function names
        self.call_chain_max_depth = 100  # Prevent infinite recursion in tracking
        
        # ITERATION 600: Object-sensitive heap tracking
        # Maps object value ID -> field name -> TaintLabel
        # This allows tracking taint through object fields for builder patterns
        self.heap: Dict[int, Dict[str, TaintLabel]] = {}
    
    def handle_call_pre(
        self,
        func_name: Optional[str],
        args: List[Any],
        location: str,
        kwargs: Dict = None,
        is_method_call: bool = False
    ) -> Optional[Any]:  # Returns SecurityViolation or None
        """
        Pre-call hook with call chain tracking.
        
        Phase 4B: Push function onto call chain before processing.
        Iteration 433: Check summaries FIRST before falling back to contracts.
        Iteration 575: Added is_method_call parameter to match LatticeSecurityTracker signature.
        Returns: SecurityViolation if a security bug is detected, None otherwise
        """
        # Push function onto call chain (with depth limit for safety)
        if func_name and len(self.call_chain) < self.call_chain_max_depth:
            self.call_chain.append(func_name)
        
        # Iteration 433: If we have a summary for this function, DON'T use contracts
        # The summary-based checking will happen in _apply_summary (called from handle_call_post)
        # This avoids double-checking with wrong sink types
        if func_name and self.context is not None:
            # Try exact match
            summary = self.context.get_summary(func_name)
            if summary is not None:
                # Have summary - skip contract-based checking
                # Sink checking will happen in _apply_summary
                return None
            
            # Try partial match
            for qname in self.context.summaries.keys():
                if qname.endswith(f'.{func_name}') or qname == func_name:
                    # Have summary - skip contract-based checking
                    return None
        
        # No summary - call parent implementation for contract-based sink checking
        result = super().handle_call_pre(func_name, args, location, kwargs)
        
        # If violation detected, include call chain in message
        if result is not None:
            # Violation detected - augment message with call chain
            chain_str = " → ".join(self.call_chain) if self.call_chain else func_name or "unknown"
            # Augment the violation message with call chain
            if hasattr(result, 'message'):
                result.message = f"{result.message} (call chain: {chain_str})"
        
        return result
    
    def handle_call_post(
        self,
        func_name: str,
        func_ref: Any,
        args: List[Any],
        result: Any,
        location: str
    ) -> Tuple[TaintLabel, SymbolicTaintLabel]:
        """
        Post-call hook with interprocedural summary support.
        
        Phase 4B: Pop function from call chain after processing.
        
        1. First check if we have a summary for this function
        2. If so, apply the summary to get return taint
        3. Otherwise, fall back to parent's contract-based handling
        """
        import os
        debug = os.environ.get('TAINT_DEBUG') == '1'
        
        if debug:
            print(f"[INTERPROC-HANDLER] handle_call_post called for {func_name}", file=sys.stderr)
            print(f"  Tracker type: {type(self).__name__}", file=sys.stderr)
            print(f"  Context: {self.context is not None}", file=sys.stderr)
        
        try:
            if not self.enabled:
                if debug:
                    print(f"  Tracker not enabled, returning clean", file=sys.stderr)
                return TaintLabel.clean(), SymbolicTaintLabel.clean()
            
            if debug:
                print(f"[INTERPROC] handle_call_post for {func_name}", file=sys.stderr)
                print(f"  Available summaries: {list(self.context.summaries.keys()) if self.context else 'None'}", file=sys.stderr)
            
            # Try to apply summary if we have interprocedural context
            if self.context is not None:
                summary = self.context.get_summary(func_name)
                if summary is not None:
                    if debug:
                        print(f"  -> Found exact match summary for {func_name}", file=sys.stderr)
                    # Compute arg labels HERE before passing to _apply_summary
                    arg_labels = [self.get_label(arg) for arg in args]
                    if debug:
                        print(f"  Computed arg labels before _apply_summary:", file=sys.stderr)
                        for i, lbl in enumerate(arg_labels):
                            print(f"    arg[{i}]: tau={bin(lbl.tau)}, tainted={lbl.has_untrusted_taint()}", file=sys.stderr)
                    return_labels = self._apply_summary(summary, args, arg_labels, location)
                    # Set labels on result
                    self.set_label(result, return_labels[0])
                    self.set_symbolic_label(result, return_labels[1])
                    return return_labels
            
            # Also try partial name matching (for qualified names)
            if self.context is not None:
                for qname, summary in self.context.summaries.items():
                    if qname.endswith(f'.{func_name}') or qname == func_name:
                        if debug:
                            print(f"  -> Found summary (partial match): {qname}", file=sys.stderr)
                        # Compute arg labels HERE before passing to _apply_summary
                        arg_labels = [self.get_label(arg) for arg in args]
                        if debug:
                            print(f"  Computed arg labels before _apply_summary:", file=sys.stderr)
                            for i, lbl in enumerate(arg_labels):
                                print(f"    arg[{i}]: tau={bin(lbl.tau)}, tainted={lbl.has_untrusted_taint()}", file=sys.stderr)
                        return_labels = self._apply_summary(summary, args, arg_labels, location)
                        # Set labels on result
                        self.set_label(result, return_labels[0])
                        self.set_symbolic_label(result, return_labels[1])
                        return return_labels
            
            # Fall back to parent implementation (contract-based)
            if func_name and self.context is not None and debug:
                print(f"  -> No summary found, falling back to parent", file=sys.stderr)
            return super().handle_call_post(func_name, func_ref, args, result, location)
        finally:
            # Phase 4B: Pop from call chain (ensuring balanced push/pop)
            if self.call_chain and self.call_chain[-1] == func_name:
                self.call_chain.pop()
    
    def _apply_summary(
        self,
        summary: TaintSummary,
        args: List[Any],
        arg_labels: List[TaintLabel],
        location: str
    ) -> Tuple[TaintLabel, SymbolicTaintLabel]:
        """
        Apply a taint summary to compute return value taint.
        
        Phase 4B Extension: Check if called function contains security sinks.
        
        Implements: ℓ_ret = Σ_f(ℓ_arg₁, ..., ℓ_arg_n)
        
        Args:
            summary: The taint summary to apply
            args: The symbolic values being passed as arguments
            arg_labels: The taint labels for the arguments (computed by caller)
            location: Source location for error reporting
        """
        import os
        debug = os.environ.get('TAINT_DEBUG') == '1'
        
        if debug:
            print(f"[APPLY_SUMMARY] Function: {summary.function_name}", file=sys.stderr)
            print(f"  is_sink: {summary.dependency.is_sink}", file=sys.stderr)
            print(f"  sink_types: {summary.dependency.sink_types}", file=sys.stderr)
            print(f"  params_to_sinks: {summary.dependency.params_to_sinks}", file=sys.stderr)
        
        # Use the arg_labels passed from caller (not get_label lookup)
        arg_tuples = [(l.tau, l.kappa, l.sigma) for l in arg_labels]
        
        if debug:
            for i, label in enumerate(arg_labels):
                print(f"  arg[{i}] label: tau={bin(label.tau)}, has_taint={label.has_untrusted_taint()}", file=sys.stderr)
        
        # Phase 4B: Check if this function is a sink and arguments are tainted
        if summary.dependency.is_sink and summary.dependency.sink_types:
            if debug:
                print(f"  Checking sinks...", file=sys.stderr)
            # Check each sink type in the function
            for sink_type_int in summary.dependency.sink_types:
                sink_type_enum = SinkType(sink_type_int)
                
                # Get which parameters flow to this sink (Iteration 416 fix)
                params_for_sink = summary.dependency.params_to_sinks.get(sink_type_int, set())
                
                # If no explicit mapping, conservatively check all parameters
                if not params_for_sink:
                    params_for_sink = set(range(len(args)))
                
                # Iteration 436: Check if this function sanitizes this sink
                # If it's a sanitizer for this sink type, don't report violation
                if summary.dependency.is_sanitizer and sink_type_int in summary.dependency.sinks_protected:
                    if debug:
                        print(f"    Sink {sink_type_enum} is sanitized by this function - skipping violation check", file=sys.stderr)
                    continue
                
                # Check each parameter that reaches the sink
                for i in params_for_sink:
                    # ITERATION 594: Handle external taint marker (index -1)
                    # If -1 is in params_to_sinks, it means the function internally
                    # creates tainted data (e.g., from sys.argv) that flows to a sink
                    if i == -1:
                        # Internal taint source -> sink flow
                        # This is always a bug regardless of caller's arguments
                        chain_str = " → ".join(self.call_chain) if self.call_chain else summary.function_name
                        violation_msg = f"Internal tainted data reaches {summary.function_name} sink (call chain: {chain_str})"
                        
                        if debug:
                            print(f"  [VIOLATION DETECTED] Internal taint to sink", file=sys.stderr)
                        
                        # Find the matching bug type
                        bug_type_name = None
                        cwe = "CWE-000"
                        for bug_name, bug_def in CODEQL_BUG_TYPES.items():
                            if sink_type_enum == bug_def.sink_type:
                                bug_type_name = bug_name
                                cwe = bug_def.cwe
                                break
                        
                        if not bug_type_name:
                            # Fallback: map sink type directly
                            bug_type_name = f"{sink_type_enum.name}_BUG"
                        
                        # Create a tainted label for reporting (internal provenance marker).
                        # NOTE: This is an over-approximate witness of internal taint reaching a sink.
                        internal_taint_label = TaintLabel.from_untrusted_source(
                            SourceType.ARGV, "internal_source_in_function"
                        )
                        
                        # Record violation as SecurityViolation object
                        violation = SecurityViolation(
                            bug_type=bug_type_name,
                            cwe=cwe,
                            sink_type=sink_type_enum,
                            sink_location=location,
                            taint_label=internal_taint_label,
                            message=violation_msg
                        )
                        self.violations.append(violation)
                        
                        if debug:
                            print(f"  Recorded violation: {violation}", file=sys.stderr)
                            print(f"  Total violations now: {len(self.violations)}", file=sys.stderr)
                    
                    elif i < len(arg_labels):
                        label = arg_labels[i]
                        if debug:
                            print(f"    Checking param {i}: is_safe={label.is_safe_for_sink(sink_type_enum)}", file=sys.stderr)
                        # Check if argument is unsafe for this sink
                        if not label.is_safe_for_sink(sink_type_enum):
                            # Create violation with call chain context
                            chain_str = " → ".join(self.call_chain) if self.call_chain else summary.function_name
                            violation_msg = f"Tainted value reaches {summary.function_name} sink (call chain: {chain_str})"
                            
                            if debug:
                                print(f"  [VIOLATION DETECTED] {violation_msg}", file=sys.stderr)
                            
                            # Find the matching bug type
                            bug_type_name = None
                            cwe = "CWE-000"
                            for bug_name, bug_def in CODEQL_BUG_TYPES.items():
                                if sink_type_enum == bug_def.sink_type:
                                    bug_type_name = bug_name
                                    cwe = bug_def.cwe
                                    break
                            
                            if not bug_type_name:
                                # Fallback: map sink type directly
                                bug_type_name = f"{sink_type_enum.name}_BUG"
                            
                            # Record violation as SecurityViolation object
                            violation = SecurityViolation(
                                bug_type=bug_type_name,
                                cwe=cwe,
                                sink_type=sink_type_enum,
                                sink_location=location,
                                taint_label=label,
                                message=violation_msg
                            )
                            self.violations.append(violation)
                            
                            if debug:
                                print(f"  Recorded violation: {violation}", file=sys.stderr)
                                print(f"  Total violations now: {len(self.violations)}", file=sys.stderr)
        
        # Apply summary to compute return taint
        tau_ret, kappa_ret, sigma_ret = summary.apply(arg_tuples)
        
        result_concrete = TaintLabel(tau=tau_ret, kappa=kappa_ret, sigma=sigma_ret)
        
        # ITERATION 600: Handle heap mutations and field reads for object-sensitive analysis
        # If the summary shows field mutations (params_to_fields), update heap
        if summary.dependency.params_to_fields and len(args) > 0:
            # First argument is typically 'self' for methods
            self_arg = args[0]
            self_id = id(self_arg)
            
            if self_id not in self.heap:
                self.heap[self_id] = {}
            
            # For each field that gets mutated
            for field_name, param_indices in summary.dependency.params_to_fields.items():
                # Join taint from all parameters that flow into this field
                field_labels = []
                for param_idx in param_indices:
                    if param_idx < len(arg_labels):
                        field_labels.append(arg_labels[param_idx])
                
                if field_labels:
                    # Compute joined taint for this field
                    from ..z3model.taint_lattice import label_join_many
                    new_field_taint = label_join_many(field_labels)
                    
                    # Update heap: join with existing taint (fields accumulate taint)
                    old_field_taint = self.heap[self_id].get(field_name, TaintLabel.clean())
                    from ..z3model.taint_lattice import label_join
                    self.heap[self_id][field_name] = label_join(old_field_taint, new_field_taint)
        
        # If the summary reads fields to compute return (fields_to_return), inherit taint from heap
        if summary.dependency.fields_to_return and len(args) > 0:
            # First argument is typically 'self' for methods
            self_arg = args[0]
            self_id = id(self_arg)
            
            if self_id in self.heap:
                # Join taint from all fields that are read
                field_taints = []
                for field_name in summary.dependency.fields_to_return:
                    if field_name in self.heap[self_id]:
                        field_taints.append(self.heap[self_id][field_name])
                
                if field_taints:
                    # Compute joined field taint
                    from ..z3model.taint_lattice import label_join_many
                    field_taint = label_join_many(field_taints)
                    
                    # Join with return taint from parameters
                    from ..z3model.taint_lattice import label_join
                    result_concrete = label_join(result_concrete, field_taint)
        
        # Apply PC taint for implicit flows
        result_concrete = self.apply_pc_taint(result_concrete)
        
        # Record application for debugging
        self.summary_applications.append((
            summary.function_name,
            location,
            result_concrete
        ))
        
        # Set labels (result parameter removed - will be set by caller)
        # self.set_label(result, result_concrete)  # REMOVED - handled externally
        
        # For symbolic, merge symbolic labels from args that flow to return
        symbolic_arg_labels = [self.get_symbolic_label(arg) for arg in args]
        flowing_labels = []
        for i in summary.dependency.param_to_return:
            if i < len(symbolic_arg_labels):
                flowing_labels.append(symbolic_arg_labels[i])
        
        if flowing_labels:
            from ..z3model.taint_lattice import symbolic_label_join_many
            result_symbolic = symbolic_label_join_many(flowing_labels)
        else:
            result_symbolic = SymbolicTaintLabel.clean()
        
        # Apply symbolic PC taint
        result_symbolic = self.apply_symbolic_pc_taint(result_symbolic)
        
        # self.set_symbolic_label(result, result_symbolic)  # REMOVED - handled externally
        
        return result_concrete, result_symbolic
    
    def analyze_function(
        self,
        func_name: str,
        initial_labels: Dict[str, TaintLabel] = None
    ) -> Dict[str, TaintLabel]:
        """
        Analyze a function with given initial parameter labels.
        
        Uses the function's summary if available, otherwise performs
        intraprocedural analysis.
        
        Returns:
            Map from variable names to their taint labels at function exit
        """
        if self.context is None:
            return {}
        
        summary = self.context.get_summary(func_name)
        if summary is None:
            return {}
        
        func_info = self.context.call_graph.functions.get(func_name)
        if func_info is None:
            return {}
        
        # Initialize labels for parameters
        param_labels: Dict[str, TaintLabel] = {}
        if initial_labels:
            param_labels.update(initial_labels)
        else:
            # Default: clean labels for all parameters
            for param in func_info.parameters:
                param_labels[param] = TaintLabel.clean()
        
        # Compute return label using summary
        arg_tuples = []
        for param in func_info.parameters:
            label = param_labels.get(param, TaintLabel.clean())
            arg_tuples.append((label.tau, label.kappa, label.sigma))
        
        tau_ret, kappa_ret, sigma_ret = summary.apply(arg_tuples)
        return_label = TaintLabel(tau=tau_ret, kappa=kappa_ret, sigma=sigma_ret)
        
        return {
            **param_labels,
            '__return__': return_label,
        }
    
    def get_taint_at_sink(
        self,
        func_name: str,
        sink_name: str,
    ) -> Optional[TaintLabel]:
        """
        Check taint at a sink within a function.
        
        Traces interprocedurally to determine if tainted data reaches the sink.
        """
        if self.context is None:
            return None
        
        # Get the function info
        func_info = self.context.call_graph.functions.get(func_name)
        if func_info is None:
            return None
        
        # Get call sites within this function
        call_sites = self.context.call_graph.call_sites_by_caller.get(func_name, [])
        
        # Find call sites to the sink
        for site in call_sites:
            if site.callee_name == sink_name or (site.callee_attribute and sink_name.endswith(site.callee_attribute)):
                # Found a call to sink - trace taint to this point
                # For now, return a conservative estimate
                summary = self.context.get_summary(func_name)
                if summary:
                    # If any parameter flows to the sink call, return joined taint
                    if summary.dependency.param_to_return:
                        # Conservative: assume all params are tainted
                        return TaintLabel.from_source(SourceType.HTTP_PARAM)
        
        return None


def create_interprocedural_tracker(
    project_path: Path,
    source_contracts: Dict[str, int] = None,
    sink_contracts: Dict[str, int] = None,
    sanitizer_contracts: Dict[str, Set[int]] = None,
) -> InterproceduralTaintTracker:
    """
    Create an interprocedural taint tracker for a project.
    
    This is the main entry point for interprocedural analysis.
    """
    context = InterproceduralContext.from_project(
        project_path,
        source_contracts=source_contracts,
        sink_contracts=sink_contracts,
        sanitizer_contracts=sanitizer_contracts,
    )
    
    return InterproceduralTaintTracker(context=context)


def analyze_project_for_security_bugs(
    project_path: Path,
    verbose: bool = False
) -> List[Dict]:
    """
    Perform full interprocedural security analysis on a project.
    
    Returns list of detected security violations.
    """
    from ..contracts.security_lattice import (
        SOURCE_CONTRACTS, SINK_CONTRACTS, SANITIZER_CONTRACTS,
        init_security_contracts,
    )
    
    init_security_contracts()
    
    # Build source/sink/sanitizer mappings
    source_contracts = {}
    for name, contract in SOURCE_CONTRACTS.items():
        source_contracts[name] = contract.source_type
    
    sink_contracts = {}
    for name, contract in SINK_CONTRACTS.items():
        sink_contracts[name] = contract.sink_type
    
    sanitizer_contracts = {}
    for name, contract in SANITIZER_CONTRACTS.items():
        sanitizer_contracts[name] = set(s for s in contract.applicable_sinks)
    
    # Create tracker with context
    tracker = create_interprocedural_tracker(
        project_path,
        source_contracts=source_contracts,
        sink_contracts=sink_contracts,
        sanitizer_contracts=sanitizer_contracts,
    )
    
    violations = []
    
    if verbose:
        print(f"Analyzing project: {project_path}")
        print(f"  Functions: {len(tracker.context.call_graph.functions)}")
        print(f"  Entry points: {len(tracker.context.entry_points)}")
        print(f"  Reachable: {len(tracker.context.reachable_functions)}")
        print(f"  Summaries: {len(tracker.context.summaries)}")
    
    # Analyze each reachable function
    for func_name in tracker.context.reachable_functions:
        func_info = tracker.context.call_graph.functions.get(func_name)
        if not func_info:
            continue
        
        summary = tracker.context.get_summary(func_name)
        if not summary:
            continue
        
        # Check for sinks in this function
        call_sites = tracker.context.call_graph.call_sites_by_caller.get(func_name, [])
        
        for site in call_sites:
            callee = site.callee_name or site.callee_attribute or ''
            
            # Check if this is a known sink
            if is_security_sink(callee):
                # Check if taint flows here
                if summary.dependency.param_to_return:
                    # Parameters flow through - potential vulnerability
                    violations.append({
                        'type': 'POTENTIAL_TAINT_FLOW',
                        'function': func_name,
                        'sink': callee,
                        'location': f"{site.file_path}:{site.line_number}",
                        'params_flowing': list(summary.dependency.param_to_return),
                    })
    
    return violations


__all__ = [
    'InterproceduralContext',
    'InterproceduralTaintTracker',
    'create_interprocedural_tracker',
    'analyze_project_for_security_bugs',
]
