"""
Taint Summary Computation for Interprocedural Analysis.

Implements function summaries as taint transformers (python-barrier-certificate-theory.md §9.5.3-9.5.5):

Definition (Taint Summary): For function f with parameters (p₁, ..., pₙ) and return r,
a taint summary is a transformer:
    Σ_f^τ : L^n → L
mapping input taint labels to output taint label.

The summary is computed bottom-up in the call graph using Kleene iteration for SCCs.

This module provides both:
1. AST-based summary analyzer (legacy, for compatibility)
2. Bytecode-level summary analyzer (preferred, integrates with barrier theory)

The bytecode-level analyzer uses abstract interpretation from bytecode_summaries.py
which integrates with the full barrier certificate infrastructure.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Callable, Any
from enum import IntEnum
import ast
import types
from pathlib import Path

from ..cfg.call_graph import CallGraph, FunctionInfo, CallSite, build_call_graph_from_file
from ..z3model.taint_lattice import SourceType


# ============================================================================
# TAINT SUMMARY REPRESENTATION
# ============================================================================

@dataclass
class TaintDependency:
    """
    Represents how return value depends on parameters.
    
    For each parameter index i, tracks whether it flows to return.
    
    ITERATION 600: Added heap mutation tracking for object-sensitive analysis.
    """
    # Set of parameter indices that flow to return
    param_to_return: Set[int] = field(default_factory=set)
    
    # Does this function introduce new taint (source)?
    introduces_taint: bool = False
    source_type: Optional[int] = None
    
    # Does this function sanitize (add to kappa)?
    is_sanitizer: bool = False
    sinks_protected: Set[int] = field(default_factory=set)
    
    # Does this function check at a sink?
    is_sink: bool = False
    sink_types: Set[int] = field(default_factory=set)  # Changed from Optional[int] to Set[int] for multi-sink support
    
    # NEW: Which parameters flow to sinks? (for interprocedural violation detection)
    # Maps sink_type (int) -> set of parameter indices that flow to it
    params_to_sinks: Dict[int, Set[int]] = field(default_factory=dict)
    
    # Is this a pure function (no side effects)?
    is_pure: bool = True
    
    # May raise exceptions?
    may_raise: bool = False
    
    # ITERATION 600: Object-sensitive heap tracking
    # Maps field name -> set of parameter indices that are stored into that field
    # E.g., if `self.parts.append(arg)` then params_to_fields["parts"] = {1}
    params_to_fields: Dict[str, Set[int]] = field(default_factory=dict)
    
    # Which fields are read to compute the return value?
    # E.g., if `return self.parts` then fields_to_return = {"parts"}
    fields_to_return: Set[str] = field(default_factory=set)


@dataclass
class TaintSummary:
    """
    Complete taint summary for a function.
    
    Σ_f : L^n → L where L = P(T) × P(K) × P(T) is the taint lattice.
    """
    function_name: str
    parameter_count: int
    
    # Core dependency information
    dependency: TaintDependency = field(default_factory=TaintDependency)
    
    # ITERATION 578: Track if sanitizer clears sensitivity (σ)
    clears_sensitivity: bool = False
    
    # For symbolic representation
    # Maps param index to symbolic contribution
    tau_contribution: Dict[int, bool] = field(default_factory=dict)  # param -> flows to tau
    kappa_contribution: Dict[int, bool] = field(default_factory=dict)  # param -> flows to kappa  
    sigma_contribution: Dict[int, bool] = field(default_factory=dict)  # param -> flows to sigma
    
    def apply(
        self,
        arg_labels: List[Tuple[int, int, int]]
    ) -> Tuple[int, int, int]:
        """
        Apply summary to concrete argument labels.
        
        ITERATION 450: Now tracks interprocedural σ (sensitivity) via sigma_contribution.
        If a parameter is inferred to be sensitive (e.g., named "password"), it contributes
        σ to the return even if the caller's argument doesn't have σ set.
        
        ITERATION 594: Handle varargs - when more arguments are passed than regular params,
        aggregate them into the vararg parameter index.
        
        Args:
            arg_labels: List of (tau, kappa, sigma) for each argument
        
        Returns:
            (tau_ret, kappa_ret, sigma_ret) for return value
        """
        if not arg_labels:
            # No arguments - return clean or source taint
            if self.dependency.introduces_taint:
                return (1 << self.dependency.source_type, 0, 0)
            return (0, 0xFFFFFFFF, 0)  # Full kappa = safe for all sinks
        
        # ITERATION 594: Build effective parameter labels including varargs aggregation
        # If function has varargs, aggregate extra arguments into the vararg index
        effective_labels: Dict[int, Tuple[int, int, int]] = {}
        
        # Regular parameters (indexed 0 to parameter_count-1)
        for i in range(min(self.parameter_count, len(arg_labels))):
            effective_labels[i] = arg_labels[i]
        
        # Varargs handling: if there are extra arguments beyond parameter_count,
        # aggregate them all into parameter index = parameter_count (the vararg index)
        if len(arg_labels) > self.parameter_count:
            vararg_tau = 0
            vararg_kappa = 0xFFFFFFFF
            vararg_sigma = 0
            
            for i in range(self.parameter_count, len(arg_labels)):
                tau, kappa, sigma = arg_labels[i]
                vararg_tau |= tau
                vararg_kappa &= kappa
                vararg_sigma |= sigma
            
            # Store aggregated label at vararg index
            effective_labels[self.parameter_count] = (vararg_tau, vararg_kappa, vararg_sigma)
        
        # Join labels of parameters that flow to return
        tau_ret = 0
        kappa_ret = 0xFFFFFFFF  # Start with full (intersection)
        sigma_ret = 0
        
        for i in self.dependency.param_to_return:
            if i in effective_labels:
                tau, kappa, sigma = effective_labels[i]
                tau_ret |= tau
                kappa_ret &= kappa
                sigma_ret |= sigma  # Propagate caller's σ
                
                # ITERATION 450: Add σ if parameter was inferred sensitive
                if self.sigma_contribution.get(i, False):
                    # This parameter is sensitive (e.g., named "password")
                    # Mark return as having sensitivity even if argument doesn't
                    from ..z3model.taint_lattice import SourceType
                    # Use a generic sensitivity marker (PASSWORD as default)
                    sigma_ret |= (1 << SourceType.PASSWORD.value)
        
        # Apply sanitizer effect
        if self.dependency.is_sanitizer:
            for sink in self.dependency.sinks_protected:
                kappa_ret |= (1 << sink)
            
            # ITERATION 578: Clear sensitivity if sanitizer declares it
            if self.clears_sensitivity:
                sigma_ret = 0
        
        return (tau_ret, kappa_ret, sigma_ret)
    
    def is_identity(self) -> bool:
        """Check if this is an identity summary (returns first arg unchanged)."""
        return (
            self.parameter_count >= 1 and
            self.dependency.param_to_return == {0} and
            not self.dependency.introduces_taint and
            not self.dependency.is_sanitizer
        )
    
    def is_source(self) -> bool:
        """Check if this function is a taint source."""
        return self.dependency.introduces_taint
    
    def is_sink(self) -> bool:
        """Check if this function is a security sink."""
        return self.dependency.is_sink


# ============================================================================
# INTRAPROCEDURAL SUMMARY ANALYZER
# ============================================================================

class SummaryAnalyzer(ast.NodeVisitor):
    """
    AST visitor that computes taint summary for a single function.
    
    Tracks dataflow from parameters to return statements.
    Phase 4B: Also tracks security sink calls to propagate sink information.
    """
    
    def __init__(self, func_info: FunctionInfo, existing_summaries: Dict[str, TaintSummary], 
                 source_contracts: Dict[str, int] = None, sink_contracts: Dict[str, Set[int]] = None,
                 sanitizer_contracts: Dict[str, Set[int]] = None):
        self.func_info = func_info
        self.summaries = existing_summaries
        self.source_contracts = source_contracts or {}
        self.sink_contracts = sink_contracts or {}
        self.sanitizer_contracts = sanitizer_contracts or {}
        
        # Extract module prefix from qualified name (e.g., "module.func" -> "module")
        # This is used to resolve local function calls
        parts = func_info.qualified_name.rsplit('.', 1)
        self.module_prefix = parts[0] if len(parts) > 1 else ""
        
        # Map variable names to parameter indices (or -1 for non-params)
        self.param_indices: Dict[str, int] = {}
        for i, param in enumerate(func_info.parameters):
            self.param_indices[param] = i
        
        # ITERATION 594: Handle varargs - assign virtual parameter indices
        # Varargs collect all arguments beyond the regular parameters
        # We use a special marker: if vararg is present, it has index = len(parameters)
        if func_info.has_varargs and func_info.vararg_name:
            self.vararg_index = len(func_info.parameters)
            self.param_indices[func_info.vararg_name] = self.vararg_index
        else:
            self.vararg_index = None
        
        # Track which params flow to each variable
        self.var_flows: Dict[str, Set[int]] = {}
        for param in func_info.parameters:
            self.var_flows[param] = {self.param_indices[param]}
        
        # ITERATION 594: Initialize vararg flow tracking
        # Vararg aggregates all args beyond regular params, so it initially flows from itself
        if self.vararg_index is not None and func_info.vararg_name:
            # Vararg receives taint from all extra arguments - we'll track this specially
            self.var_flows[func_info.vararg_name] = {self.vararg_index}
        
        # Params that flow to return
        self.return_flows: Set[int] = set()
        
        # Special flags
        self.may_raise = False
        
        # Phase 4B: Track if this function calls a security source/sink
        self.introduces_taint = False
        self.source_type = None  # SourceType value if this function calls a source
        self.is_sink = False
        self.sink_types = set()  # Set of SinkType values if this function contains sink calls
        
        # NEW (Iteration 416): Track which parameters flow to which sinks
        self.params_to_sinks: Dict[int, Set[int]] = {}  # sink_type -> set of param indices
        
        # NEW (Iteration 433): Track sanitizer behavior
        self.is_sanitizer = False
        self.sinks_protected = set()  # Set of sink type ints that are sanitized
        
        # NEW (Iteration 578): Track if sanitizer clears sensitivity
        self.clears_sensitivity = False
        
        # NEW (Iteration 450): Track sensitivity (σ) for parameters
        self.param_has_sigma: Set[int] = set()  # Parameters inferred to have sensitivity
        
        # ITERATION 600: Object-sensitive heap tracking
        # Maps field name -> set of parameter indices stored into that field
        # E.g., if `self.parts.append(arg)` then params_to_fields["parts"] = {1}
        self.params_to_fields: Dict[str, Set[int]] = {}
        
        # Which fields are read to compute the return value?
        # E.g., if `return self.parts` then fields_to_return = {"parts"}
        self.fields_to_return: Set[str] = set()
        
        # ITERATION 607: Track which variables are sanitized for which sinks
        # Maps variable name -> set of sink types it's sanitized for
        # E.g., if `hashed = hashlib.sha256(password)` then var_sanitized["hashed"] = {CLEARTEXT_STORAGE}
        self.var_sanitized: Dict[str, Set[int]] = {}
        
        # ITERATION 609: Track path validation (for tarslip/zipslip false positives)
        # Maps variable name -> set of sink types it's validated for
        # E.g., if `if not path.startswith(safe): raise` then var_validated["path"] = {FILE_PATH}
        self.var_validated: Dict[str, Set[int]] = {}
    
    def analyze(self) -> TaintSummary:
        """Analyze the function and return its summary."""
        # ITERATION 450: Infer sensitivity from parameter names
        from ..semantics.security_tracker_lattice import infer_sensitivity_from_name
        
        for i, param_name in enumerate(self.func_info.parameters):
            if infer_sensitivity_from_name(param_name) is not None:
                self.param_has_sigma.add(i)
        
        # Parse and visit the function
        try:
            with open(self.func_info.file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            tree = ast.parse(source)
            
            # Find the function node
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name == self.func_info.name and node.lineno == self.func_info.line_number:
                        self.visit(node)
                        break
        except Exception:
            # Default to conservative (all params flow to return)
            self.return_flows = set(range(len(self.func_info.parameters)))
        
        # Build summary with Phase 4B source/sink information
        dependency = TaintDependency(
            param_to_return=self.return_flows,
            may_raise=self.may_raise,
            introduces_taint=self.introduces_taint,  # Phase 4B: propagate source information
            source_type=self.source_type,  # Phase 4B: propagate source type
            is_sink=self.is_sink,  # Phase 4B: propagate sink information
            sink_types=self.sink_types,  # Phase 4B: propagate sink types (multi-sink support)
            params_to_sinks=self.params_to_sinks,  # Iteration 416: which params flow to sinks
            is_sanitizer=self.is_sanitizer,  # Iteration 433: sanitizer detection
            sinks_protected=self.sinks_protected,  # Iteration 433: which sinks are protected
            params_to_fields=self.params_to_fields,  # ITERATION 600: heap mutations
            fields_to_return=self.fields_to_return,  # ITERATION 600: heap reads in return
        )
        
        # ITERATION 450: Populate sigma_contribution
        # A parameter has σ if it's inferred to be sensitive (from its name)
        # This is independent of whether it flows to return or to sinks
        sigma_contribution: Dict[int, bool] = {}
        for i in range(len(self.func_info.parameters)):
            sigma_contribution[i] = (i in self.param_has_sigma)
        
        summary = TaintSummary(
            function_name=self.func_info.qualified_name,
            parameter_count=len(self.func_info.parameters),
            dependency=dependency,
            sigma_contribution=sigma_contribution,
            clears_sensitivity=self.clears_sensitivity,  # ITERATION 578
        )
        
        return summary
    
    def visit_Return(self, node: ast.Return) -> None:
        """
        Track which parameters flow to return value.
        
        ITERATION 600: Also track field reads in return statements.
        """
        if node.value:
            flows = self._get_flows(node.value)
            self.return_flows.update(flows)
            
            # ITERATION 600: Track field reads in return
            # If returning self.field, record that this field is read for return
            self._track_field_reads_in_expr(node.value)
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """
        Track assignments.
        
        ITERATION 594: Detect external sources (sys.argv, os.environ) and mark
        variables as tainted using a virtual "external taint" parameter index (-1).
        
        ITERATION 600: Track attribute assignments (heap mutations) for object-sensitive analysis.
        
        ITERATION 607: Track sanitization through assignments (e.g., hashed = hashlib.sha256(password)).
        """
        flows = self._get_flows(node.value)
        
        # ITERATION 594: Check if RHS is an external source (sys.argv[i], os.environ[k])
        is_external_source = self._is_external_source(node.value)
        if is_external_source:
            # Mark with virtual index -1 for "external taint" only when the value
            # does not depend on any parameters (otherwise we'd lose parameter flows,
            # e.g. request.args.get(...) depends on the `request` parameter).
            if not flows:
                flows = {-1}
        
        # ITERATION 607: Check if RHS is a sanitizer call
        sanitized_sinks = self._get_sanitized_sinks(node.value)
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.var_flows[target.id] = flows
                
                # ITERATION 607: Track sanitization for this variable
                if sanitized_sinks:
                    self.var_sanitized[target.id] = sanitized_sinks
            elif isinstance(target, ast.Subscript):
                # Handle subscript assignments: container[index] = value
                # The value flows into the container (e.g., users[username] = password)
                if isinstance(target.value, ast.Name):
                    container_name = target.value.id
                    # Union with existing flows (container may already have flows)
                    old_flows = self.var_flows.get(container_name, set())
                    self.var_flows[container_name] = old_flows | flows
                    
                    # ITERATION 607: Propagate sanitization to container
                    # If storing a sanitized value into a container, the container becomes sanitized
                    if sanitized_sinks:
                        old_sanitized = self.var_sanitized.get(container_name, set())
                        self.var_sanitized[container_name] = old_sanitized | sanitized_sinks
            elif isinstance(target, ast.Attribute):
                # ITERATION 600: Track heap mutations (self.field = value)
                # If assigning to self.field, record which params flow into that field
                if isinstance(target.value, ast.Name) and target.value.id == 'self':
                    field_name = target.attr
                    # Union with existing flows for this field
                    old_flows = self.params_to_fields.get(field_name, set())
                    self.params_to_fields[field_name] = old_flows | flows
        self.generic_visit(node)
    
    def _is_external_source(self, node: ast.expr) -> bool:
        """
        Check if an expression is an external source (sys.argv, os.environ, etc.).
        
        ITERATION 594: Used to detect assignments from untrusted sources.
        """
        # Check for sys.argv[...] or os.environ[...]
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
            attr_chain = self._build_attribute_chain(node.value)
            if attr_chain in ['sys.argv', 'os.environ']:
                return True

        # Treat calls to known source contracts (including sensitive sources like getpass.getpass)
        # as external sources for flow tracking (virtual index -1).
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = self._build_attribute_chain(node.func)

            if func_name:
                source_result = self._matches_contract(func_name, self.source_contracts)
                if source_result is not None and source_result != set():
                    return True

                resolved_name = self._resolve_callee_name(func_name)
                if resolved_name and resolved_name in self.summaries:
                    callee_summary = self.summaries[resolved_name]
                    if callee_summary.dependency.introduces_taint:
                        return True
        
        # Check for conditional expressions with external sources
        # e.g., sys.argv[1] if len(sys.argv) > 1 else "default"
        if isinstance(node, ast.IfExp):
            return self._is_external_source(node.body) or self._is_external_source(node.orelse)
        
        return False
    
    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Track augmented assignments."""
        if isinstance(node.target, ast.Name):
            old_flows = self.var_flows.get(node.target.id, set())
            new_flows = self._get_flows(node.value)
            self.var_flows[node.target.id] = old_flows | new_flows
        self.generic_visit(node)
    
    def visit_Raise(self, node: ast.Raise) -> None:
        """Track raise statements."""
        self.may_raise = True
        self.generic_visit(node)
    
    def visit_For(self, node: ast.For) -> None:
        """
        Track for loops - handle varargs iteration.
        
        ITERATION 594: When iterating over a vararg (e.g., 'for part in parts:'),
        the loop variable receives taint from the vararg parameter.
        """
        # Get flows from the iterable
        iter_flows = self._get_flows(node.iter)
        
        # Assign these flows to the loop target variable
        if isinstance(node.target, ast.Name):
            self.var_flows[node.target.id] = iter_flows
        elif isinstance(node.target, ast.Tuple):
            # For unpacking: for x, y in items:
            for elt in node.target.elts:
                if isinstance(elt, ast.Name):
                    self.var_flows[elt.id] = iter_flows
        
        self.generic_visit(node)
    
    def visit_Subscript(self, node: ast.Subscript) -> None:
        """
        Track subscript operations - detect sources like sys.argv[1].
        
        This is needed because sys.argv[1] is a subscript, not a call,
        so it won't be caught by visit_Call's source detection.
        """
        # Check if this is sys.argv access
        if isinstance(node.value, ast.Attribute):
            attr_chain = self._build_attribute_chain(node.value)
            # Check if it matches a known source pattern
            if attr_chain in ['sys.argv', 'os.environ']:
                # This function returns untrusted input
                from ..z3model.taint_lattice import SourceType
                self.introduces_taint = True
                if attr_chain == 'sys.argv':
                    self.source_type = SourceType.ARGV.value
                elif attr_chain == 'os.environ':
                    self.source_type = SourceType.ENVIRONMENT.value
        
        self.generic_visit(node)
    
    def _build_attribute_chain(self, node: ast.Attribute) -> str:
        """
        Recursively build the full attribute chain for a node.
        
        Examples:
        - request.GET.get -> "request.GET.get"
        - cursor.execute -> "cursor.execute"
        - obj.method -> "obj.method"
        """
        parts = [node.attr]
        current = node.value
        
        while current:
            if isinstance(current, ast.Name):
                parts.append(current.id)
                break
            elif isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            else:
                # Can't resolve further (e.g., function call result)
                break
        
        # Reverse to get the correct order
        return '.'.join(reversed(parts))
    
    def _matches_contract(self, func_name: str, contracts: Dict[str, Set[int]]) -> Set[int]:
        """
        Check if func_name matches any contract with flexible matching.
        
        Supports:
        - Exact match: 'input' matches 'input'
        - Suffix match: 'mymodule.requests.get' ends with '.requests.get' which matches 'requests.get'
        - Method name match: 'obj.extractall' matches known contracts for extractall methods
        
        Does NOT match:
        - 'tarfile.open' should NOT match 'builtins.open' (different modules, same method name)
        - 'request.GET.get' should NOT match bare 'get'
        
        ITERATION 610: Fixed false matching where tarfile.open matched builtins.open
        because both ended in 'open'. Now requires suffix match (ends with '.contract_key')
        or exact match. Also added method_contracts for known dangerous methods.
        
        Returns: Set of sink/source type integers (empty if no match)
        """
        # Try exact match first
        if func_name in contracts:
            return contracts[func_name]
        
        # If func_name is a bare name (no dots), only exact match (already checked above)
        if '.' not in func_name:
            return set()
        
        # Try suffix match with module separator
        # E.g., "mymodule.requests.get" should match contract "requests.get"
        # because it ends with ".requests.get"
        for contract_key, value in contracts.items():
            # Skip bare contract names to avoid ambiguity
            if '.' not in contract_key:
                continue
            
            # ITERATION 610: Use suffix matching only, not method-name-only matching
            # This prevents "tarfile.open" from matching "builtins.open"
            if func_name.endswith('.' + contract_key):
                return value
        
        # ITERATION 610: Method name matching for known dangerous methods
        # This handles cases like "tar.extractall" matching "tarfile.TarFile.extractall"
        # where we know the method name is dangerous regardless of the object type
        method_name = func_name.split('.')[-1]
        method_contracts = {
            'extractall': ['tarfile.TarFile.extractall', 'zipfile.ZipFile.extractall'],
            'extract': ['tarfile.TarFile.extract', 'zipfile.ZipFile.extract'],
            'execute': ['cursor.execute', 'sqlite3.Cursor.execute'],
            'executemany': ['cursor.executemany', 'sqlite3.Cursor.executemany'],
            'write': ['file.write', 'io.TextIOWrapper.write'],
        }
        if method_name in method_contracts:
            for canonical_name in method_contracts[method_name]:
                if canonical_name in contracts:
                    return contracts[canonical_name]
        
        return set()
    
    def visit_Call(self, node: ast.Call) -> None:
        """
        Handle function calls - track flows and detect sources/sinks.
        
        Phase 4B: Check if called function is a security source/sink and propagate
        information to this function's summary.
        
        Iteration 416: Track which parameters flow to sink arguments.
        """
        # Try to determine what function is being called
        func_name = None
        
        # Simple case: direct function call (e.g., execute_query(...) or input(...))
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        
        # Method call case: obj.method(...) (e.g., cursor.execute(...))
        elif isinstance(node.func, ast.Attribute):
            # Build full attribute chain (e.g., request.GET.get -> "request.GET.get")
            func_name = self._build_attribute_chain(node.func)
        
        # Phase 4B: Check if this is a source or sink call
        if func_name:
            # Check source contracts with flexible matching
            source_result = self._matches_contract(func_name, self.source_contracts)
            # source_contracts values are ints (including 0 for HTTP_PARAM), so check is not None and not empty set
            if source_result is not None and source_result != set():
                self.introduces_taint = True
                self.source_type = source_result
            
            # Check if we have a summary that indicates it's a source
            resolved_name = self._resolve_callee_name(func_name)
            if resolved_name and resolved_name in self.summaries:
                callee_summary = self.summaries[resolved_name]
                if callee_summary.dependency.introduces_taint:
                    self.introduces_taint = True
                    self.source_type = callee_summary.dependency.source_type
            
            # Check sink contracts with flexible matching
            sink_types = self._matches_contract(func_name, self.sink_contracts)
            if sink_types:
                # Iteration 433: Context-aware sink detection (parameterized queries)
                # SQL sinks with 2+ args are parameterized (safe)
                is_parameterized_sql = False
                if any('execute' in func_name.lower() for _ in sink_types):
                    # Check if this looks like cursor.execute(query, params)
                    if len(node.args) >= 2:
                        is_parameterized_sql = True
                
                if not is_parameterized_sql:
                    self.is_sink = True
                    self.sink_types.update(sink_types)
                    
                    # Iteration 416: Track which parameters flow to these sinks
                    # ITERATION 607: Only track unsanitized flows to sinks
                    # ITERATION 608: Check ONLY the tainted_arg_indices specified in the contract
                    
                    # Get the full sink contract to access tainted_arg_indices
                    from ..contracts.security_lattice import get_sink_contract
                    sink_contract = get_sink_contract(func_name)
                    
                    import os
                    if os.environ.get('SUMMARY_DEBUG') == '1':
                        print(f"[SUMMARY] Sink call: {func_name}")
                        print(f"  sink_contract found: {sink_contract is not None}")
                        if sink_contract:
                            print(f"  tainted_arg_indices: {sink_contract.tainted_arg_indices}")
                    
                    if sink_contract and sink_contract.tainted_arg_indices:
                        # Only check the specific arguments indicated by the contract
                        for arg_idx in sink_contract.tainted_arg_indices:
                            if arg_idx < len(node.args):
                                arg = node.args[arg_idx]
                                arg_flows = self._get_flows(arg)
                                
                                # ITERATION 607: Check if this argument is sanitized
                                arg_sanitized_sinks = self._get_sanitized_sinks(arg)
                                
                                # ITERATION 609: Check if this argument is path-validated
                                arg_validated_sinks = self._get_validated_sinks(arg)
                                
                                # ITERATION 609 DEBUG
                                import os
                                if os.environ.get('SUMMARY_DEBUG') == '1':
                                    print(f"[SUMMARY] Checking sink arg_idx={arg_idx}")
                                    print(f"  arg={ast.dump(arg)[:80]}")
                                    print(f"  arg_flows={arg_flows}")
                                    print(f"  arg_sanitized_sinks={arg_sanitized_sinks}")
                                    print(f"  arg_validated_sinks={arg_validated_sinks}")
                                    print(f"  sink_types={sink_types}")
                                
                                if arg_flows:  # If any function params flow to this arg
                                    for sink_type in sink_types:
                                        # Only record flow to sink if argument is NOT sanitized AND NOT validated for that sink
                                        if sink_type not in arg_sanitized_sinks and sink_type not in arg_validated_sinks:
                                            if os.environ.get('SUMMARY_DEBUG') == '1':
                                                print(f"  -> Adding to params_to_sinks[{sink_type}]")
                                            if sink_type not in self.params_to_sinks:
                                                self.params_to_sinks[sink_type] = set()
                                            self.params_to_sinks[sink_type].update(arg_flows)
                                        else:
                                            # Argument is sanitized or validated - mark function as sanitizer for this sink
                                            if os.environ.get('SUMMARY_DEBUG') == '1':
                                                print(f"  -> Marking as sanitizer for sink {sink_type}")
                                            self.is_sanitizer = True
                                            self.sinks_protected.add(sink_type)
                    else:
                        # Fallback: if no contract found or no tainted_arg_indices, check all args (old behavior)
                        # For each argument to the sink call, check which function parameters flow to it
                        import os
                        if os.environ.get('SUMMARY_DEBUG') == '1':
                            print(f"  [FALLBACK] Checking all {len(node.args)} args")
                        
                        for arg in node.args:
                            arg_flows = self._get_flows(arg)
                            
                            # ITERATION 607: Check if this argument is sanitized
                            arg_sanitized_sinks = self._get_sanitized_sinks(arg)
                            
                            # ITERATION 609: Check if this argument is path-validated
                            arg_validated_sinks = self._get_validated_sinks(arg)
                            
                            if os.environ.get('SUMMARY_DEBUG') == '1':
                                print(f"    arg={ast.dump(arg)[:60]}")
                                print(f"    arg_flows={arg_flows}")
                                print(f"    arg_sanitized_sinks={arg_sanitized_sinks}")
                                print(f"    arg_validated_sinks={arg_validated_sinks}")
                            
                            if arg_flows:  # If any function params flow to this arg
                                for sink_type in sink_types:
                                    # Only record flow to sink if argument is NOT sanitized AND NOT validated for that sink
                                    if sink_type not in arg_sanitized_sinks and sink_type not in arg_validated_sinks:
                                        if os.environ.get('SUMMARY_DEBUG') == '1':
                                            print(f"      -> Adding to params_to_sinks[{sink_type}] (not validated/sanitized)")
                                        if sink_type not in self.params_to_sinks:
                                            self.params_to_sinks[sink_type] = set()
                                        self.params_to_sinks[sink_type].update(arg_flows)
                                    else:
                                        # Argument is sanitized or validated - mark function as sanitizer for this sink
                                        if os.environ.get('SUMMARY_DEBUG') == '1':
                                            print(f"      -> Validated/sanitized for sink {sink_type}, marking as protected")
                                        self.is_sanitizer = True
                                        self.sinks_protected.add(sink_type)
                else:
                    # Iteration 433: Parameterized query acts as sanitizer
                    # The query (first arg) flows through but is sanitized for SQL_EXECUTE
                    from a3_python.z3model.taint_lattice import SinkType
                    self.is_sanitizer = True
                    self.sinks_protected.add(SinkType.SQL_EXECUTE.value)
            
            # Check if we have a summary that indicates it's a sink
            if resolved_name and resolved_name in self.summaries:
                callee_summary = self.summaries[resolved_name]
                if callee_summary.dependency.is_sink:
                    self.is_sink = True
                    self.sink_types.update(callee_summary.dependency.sink_types)
                    
                    # Iteration 416: Propagate params_to_sinks from callee
                    # ITERATION 601: Handle varargs in sink propagation
                    for sink_type in callee_summary.dependency.sink_types:
                        # Get the params from callee's summary
                        callee_params_for_sink = callee_summary.dependency.params_to_sinks.get(sink_type, set())
                        
                        # For each callee parameter that flows to the sink,
                        # find which of OUR parameters flow to that argument
                        for callee_param_idx in callee_params_for_sink:
                            # Check if this is a regular parameter or vararg
                            if callee_param_idx < callee_summary.parameter_count:
                                # Regular parameter: map directly
                                if callee_param_idx < len(node.args):
                                    our_param_flows = self._get_flows(node.args[callee_param_idx])
                                    if our_param_flows:
                                        if sink_type not in self.params_to_sinks:
                                            self.params_to_sinks[sink_type] = set()
                                        self.params_to_sinks[sink_type].update(our_param_flows)
                            else:
                                # Vararg parameter: collect flows from all extra arguments
                                # callee_param_idx == parameter_count means vararg
                                # Collect from node.args[parameter_count:]
                                for arg_idx in range(callee_summary.parameter_count, len(node.args)):
                                    our_param_flows = self._get_flows(node.args[arg_idx])
                                    if our_param_flows:
                                        if sink_type not in self.params_to_sinks:
                                            self.params_to_sinks[sink_type] = set()
                                        self.params_to_sinks[sink_type].update(our_param_flows)
                
                # ITERATION 578: Propagate sanitizer information from callee summaries
                if callee_summary.dependency.is_sanitizer:
                    self.is_sanitizer = True
                    self.sinks_protected.update(callee_summary.dependency.sinks_protected)
                    
                    # Also propagate clears_sensitivity
                    if callee_summary.clears_sensitivity:
                        self.clears_sensitivity = True
            
            # Iteration 433: Check if this is a sanitizer call
            # If we call a known sanitizer, propagate sanitization
            # ITERATION 578: Also check if it clears sensitivity
            sanitizer_sinks = self._matches_contract(func_name, self.sanitizer_contracts)
            if sanitizer_sinks:
                self.is_sanitizer = True
                self.sinks_protected.update(sanitizer_sinks)
                
                # Check if this sanitizer clears sensitivity
                from ..contracts.security_lattice import get_sanitizer_contract
                contract = get_sanitizer_contract(func_name)
                if contract and contract.clears_sensitivity:
                    self.clears_sensitivity = True
        
        # ITERATION 600: Detect mutations through method calls like self.parts.append(arg)
        # This is critical for object-sensitive analysis of builder patterns
        if isinstance(node.func, ast.Attribute):
            # Check if this is self.field.method(...)
            if isinstance(node.func.value, ast.Attribute):
                # Check if it's self.field
                if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == 'self':
                    field_name = node.func.value.attr
                    method_name = node.func.attr
                    
                    # Track mutations through append, extend, add, update, etc.
                    if method_name in ('append', 'extend', 'add', 'update', 'insert'):
                        # Get flows from all arguments
                        arg_flows = set()
                        for arg in node.args:
                            arg_flows.update(self._get_flows(arg))
                        
                        # Record that these params flow into this field
                        if arg_flows:
                            old_flows = self.params_to_fields.get(field_name, set())
                            self.params_to_fields[field_name] = old_flows | arg_flows
        
        # Continue with generic visit to track flows through arguments
        self.generic_visit(node)
    
    def visit_If(self, node: ast.If) -> None:
        """
        ITERATION 609: Detect path validation patterns to prevent false positives.
        
        Pattern detected:
            if not member_path.startswith(os.path.abspath(dest)):
                raise ValueError("Path traversal")
        
        When this pattern is found, mark variables involved in the validation as validated for FILE_PATH sinks.
        This handles cases where derived paths are validated (e.g., member_path = join(dest, member.name))
        and the base parameter (dest) is used in the sink.
        """
        from ..z3model.taint_lattice import SinkType
        
        # Check if this is a validation pattern followed by raise
        # Pattern: if not X: raise
        if (isinstance(node.test, ast.UnaryOp) and
            isinstance(node.test.op, ast.Not) and
            isinstance(node.test.operand, ast.Call)):
            
            # Check if body contains only a raise statement
            has_raise = any(isinstance(stmt, ast.Raise) for stmt in node.body)
            
            if has_raise:
                # This is a guard pattern: if not CONDITION: raise
                # Check if the condition is startswith()
                call = node.test.operand
                func_name = None
                
                if isinstance(call.func, ast.Attribute):
                    # Method call: obj.startswith(...)
                    if call.func.attr == 'startswith':
                        func_name = 'startswith'
                        # Get the object being validated
                        validated_var = None
                        if isinstance(call.func.value, ast.Name):
                            validated_var = call.func.value.id
                        
                        # Also get variables referenced in the startswith argument
                        # E.g., in `member_path.startswith(os.path.abspath(dest))`, we want to mark `dest` as validated
                        validated_refs = set()
                        if validated_var:
                            validated_refs.add(validated_var)
                        
                        # Extract variables from the argument to startswith
                        if len(call.args) > 0:
                            arg = call.args[0]
                            # Find all variable references in the argument
                            for subnode in ast.walk(arg):
                                if isinstance(subnode, ast.Name):
                                    validated_refs.add(subnode.id)
                        
                        # Mark all referenced variables as validated for path-related sinks
                        path_sinks = {SinkType.FILE_PATH.value, SinkType.FILE_WRITE.value}
                        for var_name in validated_refs:
                            old_validated = self.var_validated.get(var_name, set())
                            self.var_validated[var_name] = old_validated | path_sinks
        
        # Continue visiting children (both branches)
        self.generic_visit(node)
    
    def _resolve_callee_name(self, func_name: str) -> Optional[str]:
        """
        Resolve a function name to its qualified name for summary lookup.
        
        For local calls (e.g., "execute_query"), prepend the module prefix.
        For qualified calls (e.g., "module.func"), use as-is.
        Returns None if we can't resolve it.
        """
        if not func_name:
            return None
        
        # If already qualified (contains '.'), use as-is
        if '.' in func_name:
            return func_name
        
        # Try with module prefix (for local function calls)
        if self.module_prefix:
            qualified = f"{self.module_prefix}.{func_name}"
            if qualified in self.summaries:
                return qualified
        
        # Try without prefix (might be a builtin or import)
        if func_name in self.summaries:
            return func_name
        
        return None
    
    def _get_flows(self, node: ast.expr) -> Set[int]:
        """Get the set of parameter indices that flow to an expression."""
        if isinstance(node, ast.Name):
            return self.var_flows.get(node.id, set())
        
        elif isinstance(node, ast.BinOp):
            left = self._get_flows(node.left)
            right = self._get_flows(node.right)
            return left | right
        
        elif isinstance(node, ast.UnaryOp):
            return self._get_flows(node.operand)
        
        elif isinstance(node, ast.Compare):
            flows = self._get_flows(node.left)
            for comp in node.comparators:
                flows |= self._get_flows(comp)
            return flows
        
        elif isinstance(node, ast.BoolOp):
            flows = set()
            for value in node.values:
                flows |= self._get_flows(value)
            return flows
        
        elif isinstance(node, ast.IfExp):
            test = self._get_flows(node.test)
            body = self._get_flows(node.body)
            orelse = self._get_flows(node.orelse)
            return test | body | orelse
        
        elif isinstance(node, ast.Call):
            # Join flows from all arguments
            flows = set()
            for arg in node.args:
                flows |= self._get_flows(arg)
            for kw in node.keywords:
                flows |= self._get_flows(kw.value)
            
            # ITERATION 437 FIX: Also include flows from the callable itself
            # For method calls like data.upper(), the result depends on 'data'
            # For function calls like f(x), the result depends on 'x' (already handled above)
            flows |= self._get_flows(node.func)
            
            return flows
        
        elif isinstance(node, ast.Attribute):
            return self._get_flows(node.value)
        
        elif isinstance(node, ast.Subscript):
            base = self._get_flows(node.value)
            slice_flows = self._get_flows(node.slice) if hasattr(node, 'slice') else set()
            return base | slice_flows
        
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            flows = set()
            for elt in node.elts:
                flows |= self._get_flows(elt)
            return flows
        
        elif isinstance(node, ast.Dict):
            flows = set()
            for k, v in zip(node.keys, node.values):
                if k:
                    flows |= self._get_flows(k)
                flows |= self._get_flows(v)
            return flows
        
        elif isinstance(node, ast.Constant):
            return set()  # Literals introduce no param flows
        
        elif isinstance(node, ast.JoinedStr):
            # F-string: f"{x} and {y}" -> flows from x and y
            flows = set()
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    flows |= self._get_flows(value.value)
                elif isinstance(value, ast.Constant):
                    pass  # No flows from literal parts
            return flows
        
        return set()  # Default: no flows
    
    def _get_sanitized_sinks(self, node: ast.expr) -> Set[int]:
        """
        Check if an expression is a sanitizer call and return which sinks it protects.
        
        ITERATION 607: Used to track variable sanitization (e.g., hashed = hashlib.sha256(password)).
        
        Returns:
            Set of sink type ints that this expression sanitizes for, or empty set if not a sanitizer.
        """
        if isinstance(node, ast.Call):
            # Get the function name
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = self._build_attribute_chain(node.func)
            
            if func_name:
                # Check if this matches a sanitizer contract
                sanitizer_sinks = self._matches_contract(func_name, self.sanitizer_contracts)
                if sanitizer_sinks:
                    return sanitizer_sinks
        
        # Also check if the variable being read is already sanitized
        # E.g., `x = hashed` where `hashed` was previously sanitized
        if isinstance(node, ast.Name):
            return self.var_sanitized.get(node.id, set())
        
        return set()
    
    def _get_validated_sinks(self, node: ast.expr) -> Set[int]:
        """
        ITERATION 609: Check if an expression has been path-validated and return which sinks it's safe for.
        
        Returns:
            Set of sink type ints that this expression has been validated for, or empty set.
        """
        # Check if the variable being read is validated
        # E.g., `dest` where `if not path.startswith(dest): raise` was executed
        if isinstance(node, ast.Name):
            return self.var_validated.get(node.id, set())
        
        return set()
    
    def _track_field_reads_in_expr(self, node: ast.expr) -> None:
        """
        Track field reads in an expression (ITERATION 600).
        
        If the expression reads self.field, record that field in fields_to_return.
        This is used for object-sensitive analysis to propagate taint through heap.
        """
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == 'self':
                self.fields_to_return.add(node.attr)
            # Recursively check nested attributes
            self._track_field_reads_in_expr(node.value)
        
        elif isinstance(node, ast.Call):
            # Track field reads in the callable and arguments
            self._track_field_reads_in_expr(node.func)
            for arg in node.args:
                self._track_field_reads_in_expr(arg)
            for kw in node.keywords:
                self._track_field_reads_in_expr(kw.value)
        
        elif isinstance(node, (ast.BinOp, ast.Compare, ast.BoolOp)):
            # Track in all sub-expressions
            for child in ast.walk(node):
                if isinstance(child, ast.Attribute):
                    if isinstance(child.value, ast.Name) and child.value.id == 'self':
                        self.fields_to_return.add(child.attr)


# ============================================================================
# INTERPROCEDURAL SUMMARY COMPUTATION
# ============================================================================

class SummaryComputer:
    """
    Computes taint summaries for all functions in a call graph.
    
    Uses bottom-up SCC traversal with Kleene iteration for recursive functions.
    """
    
    def __init__(
        self,
        call_graph: CallGraph,
        source_contracts: Dict[str, int] = None,
        sink_contracts: Dict[str, int] = None,
        sanitizer_contracts: Dict[str, Set[int]] = None,
    ):
        self.graph = call_graph
        
        # Convert SourceContract/SinkContract objects to ints if needed (for tests)
        self.source_contracts = {}
        if source_contracts:
            for k, v in source_contracts.items():
                if hasattr(v, 'source_type'):  # It's a SourceContract object
                    self.source_contracts[k] = v.source_type.value
                else:
                    self.source_contracts[k] = v
        
        self.sink_contracts = {}
        if sink_contracts:
            for k, v in sink_contracts.items():
                if hasattr(v, '__iter__') and not isinstance(v, (str, int)):
                    # It's already a set/collection of ints
                    self.sink_contracts[k] = set(v) if not isinstance(v, set) else v
                elif hasattr(v, 'sink_type'):
                    # It's a SinkContract object - wrap single sink_type in a set
                    self.sink_contracts[k] = {v.sink_type.value}
                else:
                    # It's a single int - wrap in a set
                    self.sink_contracts[k] = {v}
        
        self.sanitizer_contracts = sanitizer_contracts or {}
        
        self.summaries: Dict[str, TaintSummary] = {}
    
    def compute_all(self) -> Dict[str, TaintSummary]:
        """
        Compute summaries for all functions.
        
        Algorithm (from §9.5.5):
        1. Compute SCCs of G (handle recursion)
        2. Process SCCs in reverse topological order
        3. For recursive SCCs, use fixpoint iteration
        """
        sccs = self.graph.compute_sccs()
        
        for scc in sccs:
            if len(scc) == 1:
                func_name = next(iter(scc))
                if func_name not in self.graph.functions:
                    continue
                    
                # Check for self-recursion
                if func_name in self.graph.get_callees(func_name):
                    self._compute_recursive_scc(scc)
                else:
                    self._compute_single_function(func_name)
            else:
                # Mutually recursive SCC
                self._compute_recursive_scc(scc)
        
        return self.summaries
    
    def _compute_single_function(self, func_name: str) -> None:
        """Compute summary for a non-recursive function."""
        func_info = self.graph.functions.get(func_name)
        if not func_info:
            return
        
        # Check for contract-defined behavior
        if func_name in self.source_contracts:
            self.summaries[func_name] = self._make_source_summary(
                func_name, func_info, self.source_contracts[func_name]
            )
            return
        
        if func_name in self.sink_contracts:
            self.summaries[func_name] = self._make_sink_summary(
                func_name, func_info, self.sink_contracts[func_name]
            )
            return
        
        if func_name in self.sanitizer_contracts:
            self.summaries[func_name] = self._make_sanitizer_summary(
                func_name, func_info, self.sanitizer_contracts[func_name]
            )
            return
        
        # Analyze function body
        analyzer = SummaryAnalyzer(func_info, self.summaries, self.source_contracts, self.sink_contracts, self.sanitizer_contracts)
        summary = analyzer.analyze()
        self.summaries[func_name] = summary
    
    def _compute_recursive_scc(self, scc: Set[str]) -> None:
        """
        Compute summaries for a recursive SCC using Kleene iteration.
        
        Initialize: Σᵢ⁽⁰⁾ = ⊥ (no taint flows)
        Iterate: Σᵢ⁽ⁿ⁺¹⁾ = Fᵢ(Σ₁⁽ⁿ⁾, ..., Σₖ⁽ⁿ⁾)
        Terminate when: Σ⁽ⁿ⁺¹⁾ = Σ⁽ⁿ⁾
        """
        MAX_ITERATIONS = 10
        
        # Initialize with bottom (no flows)
        for func_name in scc:
            func_info = self.graph.functions.get(func_name)
            if func_info:
                self.summaries[func_name] = TaintSummary(
                    function_name=func_name,
                    parameter_count=len(func_info.parameters),
                    dependency=TaintDependency(param_to_return=set()),
                )
        
        # Iterate until fixpoint
        for iteration in range(MAX_ITERATIONS):
            changed = False
            
            for func_name in scc:
                func_info = self.graph.functions.get(func_name)
                if not func_info:
                    continue
                
                old_summary = self.summaries.get(func_name)
                
                # Recompute with current summaries
                analyzer = SummaryAnalyzer(func_info, self.summaries, self.source_contracts, self.sink_contracts, self.sanitizer_contracts)
                new_summary = analyzer.analyze()
                
                # Check for change
                if old_summary is None or old_summary.dependency.param_to_return != new_summary.dependency.param_to_return:
                    changed = True
                    self.summaries[func_name] = new_summary
            
            if not changed:
                break
    
    def _make_source_summary(
        self, name: str, func: FunctionInfo, source_type: int
    ) -> TaintSummary:
        """Create summary for a taint source function."""
        dep = TaintDependency(
            introduces_taint=True,
            source_type=source_type,
        )
        return TaintSummary(
            function_name=name,
            parameter_count=len(func.parameters),
            dependency=dep,
        )
    
    def _make_sink_summary(
        self, name: str, func: FunctionInfo, sink_type: int
    ) -> TaintSummary:
        """Create summary for a security sink function."""
        dep = TaintDependency(
            is_sink=True,
            sink_type=sink_type,
            param_to_return=set(range(len(func.parameters))),  # All params flow
        )
        return TaintSummary(
            function_name=name,
            parameter_count=len(func.parameters),
            dependency=dep,
        )
    
    def _make_sanitizer_summary(
        self, name: str, func: FunctionInfo, sinks_protected: Set[int]
    ) -> TaintSummary:
        """
        Create summary for a sanitizer function.
        
        ITERATION 578: Also check if sanitizer clears sensitivity.
        """
        # Check if this sanitizer clears sensitivity
        from ..contracts.security_lattice import get_sanitizer_contract
        clears_sensitivity_flag = False
        contract = get_sanitizer_contract(name)
        if contract and contract.clears_sensitivity:
            clears_sensitivity_flag = True
        
        dep = TaintDependency(
            is_sanitizer=True,
            sinks_protected=sinks_protected,
            param_to_return={0} if func.parameters else set(),  # First param flows
        )
        return TaintSummary(
            function_name=name,
            parameter_count=len(func.parameters),
            dependency=dep,
            clears_sensitivity=clears_sensitivity_flag,  # ITERATION 578
        )
    
    def get_summary(self, func_name: str) -> Optional[TaintSummary]:
        """Get the computed summary for a function."""
        return self.summaries.get(func_name)


def compute_summaries_for_project(
    root_path: Path,
    source_contracts: Dict[str, int] = None,
    sink_contracts: Dict[str, int] = None,
    sanitizer_contracts: Dict[str, Set[int]] = None,
) -> Tuple[CallGraph, Dict[str, TaintSummary]]:
    """
    Compute call graph and taint summaries for an entire project.
    
    Returns:
        (call_graph, summaries) tuple
    """
    from .call_graph import build_call_graph_from_directory
    
    graph = build_call_graph_from_directory(root_path)
    
    computer = SummaryComputer(
        graph,
        source_contracts=source_contracts,
        sink_contracts=sink_contracts,
        sanitizer_contracts=sanitizer_contracts,
    )
    summaries = computer.compute_all()
    
    return graph, summaries


__all__ = [
    'TaintDependency',
    'TaintSummary',
    'SummaryAnalyzer',
    'SummaryComputer',
    'compute_summaries_for_project',
]
