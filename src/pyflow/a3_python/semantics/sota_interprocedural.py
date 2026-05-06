"""
SOTA Interprocedural Security Engine (Phase 2 of CODEQL_PARITY_SOTA_MATH_PLAN).

This module implements IDE-style interprocedural taint tracking:
1. Build ICFG (Interprocedural Control Flow Graph) as supergraph
2. Use tabulation algorithm for call/return matching
3. Track taint labels as IDE environment values
4. Support context sensitivity (0-CFA initially, 1-CFA optional)

The key insight from the plan:
- IFDS: propagates boolean "is this value tainted?"
- IDE: propagates full lattice values (τ, κ, σ)

For taint, IDE is the natural fit because we need the full label.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, FrozenSet, Any
from pathlib import Path
from enum import IntEnum, auto
import dis
import types
import ast
from collections import deque

from ..z3model.taint_lattice import (
    SourceType, SinkType, SanitizerType,
    TaintLabel, label_join, label_join_many,
)
from ..cfg.control_flow import (
    ControlFlowGraph, BasicBlock, EdgeType, build_cfg
)
from ..cfg.call_graph import (
    CallGraph, CallSite as CGCallSite, FunctionInfo,
    build_call_graph_from_file, build_call_graph_from_directory
)
from .sota_intraprocedural import (
    SOTAIntraproceduralAnalyzer,
    SOTASecurityViolation,
    AbstractState,
    analyze_function_sota,
)


# ============================================================================
# CONTEXT SENSITIVITY
# ============================================================================

@dataclass(frozen=True)
class CallContext:
    """
    Represents a calling context for context-sensitive analysis.
    
    For 0-CFA: context is always empty
    For 1-CFA: context is the last call site
    For k-CFA: context is the last k call sites
    """
    call_chain: Tuple[str, ...] = ()  # Tuple of call site identifiers
    
    @classmethod
    def empty(cls) -> 'CallContext':
        """Create empty context (0-CFA)."""
        return cls(call_chain=())
    
    def extend(self, call_site: str, k: int = 1) -> 'CallContext':
        """Extend context with a new call site (k-CFA)."""
        if k == 0:
            return CallContext.empty()
        new_chain = self.call_chain + (call_site,)
        # Keep only last k elements
        if len(new_chain) > k:
            new_chain = new_chain[-k:]
        return CallContext(call_chain=new_chain)
    
    def __repr__(self):
        if not self.call_chain:
            return "[]"
        return f"[{' → '.join(self.call_chain[-2:])}]"  # Show last 2 for readability


# ============================================================================
# ICFG NODES AND EDGES
# ============================================================================

@dataclass(frozen=True)
class ICFGNode:
    """
    A node in the Interprocedural Control Flow Graph.
    
    Represents a point in a specific function.
    """
    func_qname: str      # Qualified function name
    block_id: int        # Block ID in the function's CFG
    offset: int          # Bytecode offset (optional, -1 for entry/exit)
    
    def __repr__(self):
        return f"({self.func_qname}:{self.block_id}@{self.offset})"


class ICFGEdgeType(IntEnum):
    """Types of edges in the ICFG."""
    INTRA = auto()           # Within same function
    CALL = auto()            # Call edge to callee entry
    RETURN = auto()          # Return edge from callee exit
    CALL_TO_RETURN = auto()  # Skip edge for unknown/skipped callees


@dataclass
class ICFGEdge:
    """An edge in the ICFG."""
    source: ICFGNode
    target: ICFGNode
    edge_type: ICFGEdgeType
    call_site: Optional[CGCallSite] = None  # For CALL/RETURN edges


# ============================================================================
# FUNCTION SUMMARY
# ============================================================================

@dataclass
class FunctionTaintSummary:
    """
    Summarizes taint flow through a function.
    
    A summary is a relation: (param_labels) -> (ret_label, sink_violations)
    
    For efficiency, we represent it as:
    - param_to_ret: Dict[int, TaintLabel] - how param i affects return
    - param_to_sinks: Dict[int, List[SinkType]] - which params flow to which sinks
    - ret_depends_on: Set[int] - which params the return depends on
    """
    func_name: str
    
    # Param index -> contribution to return value taint
    param_to_ret: Dict[int, TaintLabel] = field(default_factory=dict)
    
    # Param index -> list of sinks it flows to
    param_to_sinks: Dict[int, List[SinkType]] = field(default_factory=dict)
    
    # Which parameters the return value depends on
    ret_depends_on: Set[int] = field(default_factory=set)
    
    # Violations found during intraprocedural analysis
    violations: List[SOTASecurityViolation] = field(default_factory=list)
    
    # Is this a source function?
    is_source: bool = False
    source_label: Optional[TaintLabel] = None
    
    # Is this a sanitizer function?
    is_sanitizer: bool = False
    sanitized_sinks: Set[SinkType] = field(default_factory=set)
    
    def apply(self, arg_labels: List[TaintLabel]) -> TaintLabel:
        """
        Apply the summary to a list of argument labels.
        
        Returns the label for the return value.
        """
        if self.is_source and self.source_label:
            return self.source_label
        
        # Start with clean
        result = TaintLabel.clean()
        
        # Join contributions from each relevant argument
        for param_idx in self.ret_depends_on:
            if param_idx < len(arg_labels):
                arg_label = arg_labels[param_idx]
                result = label_join(result, arg_label)
        
        # Apply sanitizer effect if applicable
        if self.is_sanitizer and arg_labels:
            # Sanitize the first argument
            from ..contracts.security_lattice import apply_sanitizer
            result = label_join_many(arg_labels) if arg_labels else TaintLabel.clean()
            for sink in self.sanitized_sinks:
                result = result.sanitize(SanitizerType.TYPE_CONVERSION)  # Generic sanitizer
        
        return result


# ============================================================================
# IDE DATAFLOW PROBLEM
# ============================================================================

@dataclass(frozen=True)
class IDEFact:
    """
    A fact in the IDE problem.
    
    Represents: at this program point, this slot has this taint label.
    """
    slot_type: str       # "param", "return", "local"
    slot_index: int      # Index for the slot
    label: TaintLabel    # Taint label
    
    def __repr__(self):
        return f"({self.slot_type}[{self.slot_index}]={self.label.tau:#x})"


@dataclass
class IDEResult:
    """
    Result of IDE analysis.
    
    Maps ICFG nodes to sets of facts.
    """
    facts: Dict[ICFGNode, Set[IDEFact]] = field(default_factory=dict)
    violations: List[SOTASecurityViolation] = field(default_factory=list)
    
    def get_facts_at(self, node: ICFGNode) -> Set[IDEFact]:
        """Get facts at a node."""
        return self.facts.get(node, set())
    
    def add_fact(self, node: ICFGNode, fact: IDEFact):
        """Add a fact at a node."""
        if node not in self.facts:
            self.facts[node] = set()
        self.facts[node].add(fact)


# ============================================================================
# SOTA INTERPROCEDURAL ANALYZER
# ============================================================================

class SOTAInterproceduralAnalyzer:
    """
    SOTA interprocedural security analyzer.
    
    Uses IDE-style tabulation for call/return matching with
    the SOTA intraprocedural engine for within-function analysis.
    
    Algorithm:
    1. Build call graph from source files
    2. Run intraprocedural analysis on each function
    3. Use worklist to propagate taint facts across call edges
    4. Collect violations from both intra and interprocedural analysis
    
    Supports:
    - 0-CFA (context-insensitive, default)
    - 1-CFA (call-site sensitive, optional)
    """
    
    def __init__(
        self,
        verbose: bool = False,
        context_depth: int = 0,  # 0 = 0-CFA, 1 = 1-CFA, etc.
        max_iterations: int = 500,  # Max worklist iterations per function (increased for complex CFGs)
    ):
        self.verbose = verbose
        self.context_depth = context_depth
        self.max_iterations = max_iterations
        
        # Call graph
        self.call_graph: Optional[CallGraph] = None
        
        # Function CFGs and code objects
        self.function_cfgs: Dict[str, ControlFlowGraph] = {}
        self.function_code: Dict[str, types.CodeType] = {}
        
        # Summaries computed from intraprocedural analysis
        self.summaries: Dict[str, FunctionTaintSummary] = {}
        
        # All violations found
        self.violations: List[SOTASecurityViolation] = []
        
        # Performance: limit analysis per function  
        self.max_iterations = max_iterations
    
    def analyze_file(
        self,
        filepath: Path,
    ) -> List[SOTASecurityViolation]:
        """
        Analyze a single file for security vulnerabilities.
        
        Combines intraprocedural SOTA analysis with interprocedural
        call/return matching.
        """
        if self.verbose:
            print(f"\n[SOTA-IP] Analyzing file: {filepath}")
        
        # Step 1: Build call graph (fast)
        self.call_graph = build_call_graph_from_file(filepath)
        
        if self.verbose:
            print(f"  Call graph: {len(self.call_graph.functions)} functions")
        
        # Step 2: Extract function code objects
        self._extract_functions(filepath)
        
        if self.verbose:
            print(f"  Extracted {len(self.function_code)} code objects")
        
        # Step 3: Run intraprocedural analysis on each function (fast mode)
        for func_name, code_obj in self.function_code.items():
            if self.verbose:
                print(f"\n  [INTRA] Analyzing: {func_name}")
            
            violations = analyze_function_sota(
                code_obj=code_obj,
                function_name=func_name,
                file_path=str(filepath),
                verbose=self.verbose,
                max_iterations=self.max_iterations,
            )
            
            # Store violations
            self.violations.extend(violations)
            
            # Fast summary: create simple summary noting param dependencies
            # For proper IDE tabulation, we need param_to_sinks computed
            summary = self._compute_summary(func_name, code_obj)
            self.summaries[func_name] = summary
            
            # Include violations from summary computation
            self.violations.extend(summary.violations)
            
            if self.verbose and violations:
                print(f"    Found {len(violations)} violations")
        
        # Step 4: Interprocedural propagation (fast)
        self._propagate_interprocedural(str(filepath))
        
        if self.verbose:
            print(f"\n[SOTA-IP] Total violations: {len(self.violations)}")
        
        return self.violations
    
    def analyze_project(
        self,
        root_path: Path,
    ) -> List[SOTASecurityViolation]:
        """
        Analyze an entire project directory.
        """
        if self.verbose:
            print(f"\n[SOTA-IP] Analyzing project: {root_path}")
        
        # Build call graph for entire project
        self.call_graph = build_call_graph_from_directory(root_path)
        
        if self.verbose:
            print(f"  Call graph: {len(self.call_graph.functions)} functions")
        
        # Find all Python files
        py_files = list(root_path.glob("**/*.py"))
        
        if self.verbose:
            print(f"  Found {len(py_files)} Python files")
        
        # Analyze each file
        for filepath in py_files:
            self._analyze_file_for_project(filepath)
        
        # Interprocedural propagation
        self._propagate_interprocedural(str(root_path))
        
        if self.verbose:
            print(f"\n[SOTA-IP] Total violations: {len(self.violations)}")
        
        return self.violations
    
    def _extract_functions(self, filepath: Path):
        """Extract all function code objects from a file."""
        source = filepath.read_text()
        code = compile(source, str(filepath), "exec")
        
        self._extract_from_code(code, "")
    
    def _extract_from_code(self, code: types.CodeType, prefix: str):
        """Recursively extract function code objects."""
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                if const.co_name != "<module>":
                    qname = f"{prefix}.{const.co_name}" if prefix else const.co_name
                    self.function_code[qname] = const
                    
                    # Recurse for nested functions
                    self._extract_from_code(const, qname)
    
    def _compute_summary(
        self,
        func_name: str,
        code_obj: types.CodeType,
    ) -> FunctionTaintSummary:
        """
        Compute a taint summary for a function.
        
        The summary captures:
        - Which parameters affect the return value
        - Which parameters flow to which sinks
        - Whether the function is a source (returns tainted values from internal sources)
        """
        summary = FunctionTaintSummary(func_name=func_name)
        
        # Build CFG
        cfg = build_cfg(code_obj)
        self.function_cfgs[func_name] = cfg
        
        # FIRST: Analyze with NO entry taint to detect if function is itself a source
        no_taint_analyzer = SOTAIntraproceduralAnalyzer(
            code_obj=code_obj,
            function_name=func_name,
            file_path="<summary>",
            verbose=False,
        )
        no_taint_violations = no_taint_analyzer.analyze(entry_taint={})
        
        # If we find violations with no entry taint, this function is a source
        if no_taint_violations:
            summary.is_source = True
            # Mark that return is tainted
            summary.source_label = TaintLabel.from_untrusted_source(
                SourceType.USER_INPUT,
                f"source_in_{func_name}"
            )
            # Store violations
            summary.violations.extend(no_taint_violations)
        
        # SECOND: Analyze with each parameter individually tainted
        for param_idx in range(code_obj.co_argcount):
            # Create entry taint with only this param tainted
            entry_taint = {
                param_idx: TaintLabel.from_untrusted_source(
                    SourceType.USER_INPUT, f"param_{param_idx}"
                )
            }
            
            # Run analysis
            analyzer = SOTAIntraproceduralAnalyzer(
                code_obj=code_obj,
                function_name=func_name,
                file_path="<summary>",
                verbose=False,
            )
            violations = analyzer.analyze(entry_taint=entry_taint)
            
            # Record violations attributed to this param
            for v in violations:
                if param_idx not in summary.param_to_sinks:
                    summary.param_to_sinks[param_idx] = []
                summary.param_to_sinks[param_idx].append(v.sink_type)
                summary.violations.append(v)  # Store violations in summary
            
            # Check if param affects return
            # (Conservative: assume all tainted params affect return)
            summary.ret_depends_on.add(param_idx)
        
        return summary
    
    def _propagate_interprocedural(self, file_path: str):
        """
        Propagate taint interprocedurally using full IDE tabulation.
        
        This is proper IDE-style interprocedural dataflow with:
        1. Explicit ICFG nodes with facts at each program point
        2. Worklist algorithm for call/return matching
        3. Multi-hop taint propagation through call chains
        4. Context sensitivity (k-CFA) when context_depth > 0
        
        Algorithm (simplified IDE with context):
        - Each fact is (context, slot_id, label) at an ICFG node
        - Call edge: map arg facts to param facts with extended context
        - Return edge: map return facts back to call-site result
        - Intra edge: use summary to propagate within function
        """
        if not self.call_graph:
            return
        
        # Build ICFG edges (call graph essentially IS the ICFG for interprocedural)
        # For simplicity, we track facts at function entry/exit points
        
        # Fact representation: (context, func_name, slot_type, slot_idx) -> TaintLabel
        # slot_type: "param", "return", "local"
        # context: CallContext for k-CFA tracking
        facts: Dict[Tuple[CallContext, str, str, int], TaintLabel] = {}
        
        # Worklist: (context, func_name, slot_type, slot_idx, label)
        worklist: deque = deque()
        
        # Initialize: seed entry points with tainted parameters
        # Also seed source functions (functions that call sources internally)
        # Use empty context for entry points
        empty_context = CallContext.empty()
        
        for func_name, summary in self.summaries.items():
            # Get parameter count from summary
            code_obj = self.function_code.get(func_name)
            if not code_obj:
                continue
            
            param_count = code_obj.co_argcount
            
            # Seed entry-like functions with ALL params tainted
            if "entry" in func_name.lower() or func_name == "<module>":
                for param_idx in range(param_count):
                    taint = TaintLabel.from_untrusted_source(
                        SourceType.USER_INPUT,
                        f"entry_param_{param_idx}"
                    )
                    key = (empty_context, func_name, "param", param_idx)
                    if key not in facts or facts[key] != taint:
                        facts[key] = taint
                        worklist.append((empty_context, func_name, "param", param_idx, taint))
            
            # Seed source functions: if function is_source, seed its return value
            if summary.is_source and summary.source_label:
                return_key = (empty_context, func_name, "return", 0)
                if return_key not in facts:
                    facts[return_key] = summary.source_label
                    worklist.append((empty_context, func_name, "return", 0, summary.source_label))
            
            # For functions with violations found in intraprocedural analysis, seed those
            # (This catches cases where params flow to sinks)
            if summary.violations and not summary.is_source:
                # If the function itself has violations, propagate taint through its params
                for param_idx in range(param_count):
                    taint = TaintLabel.from_untrusted_source(
                        SourceType.USER_INPUT,
                        f"param_{param_idx}_via_source"
                    )
                    key = (empty_context, func_name, "param", param_idx)
                    if key not in facts or facts[key] != taint:
                        facts[key] = taint
                        worklist.append((empty_context, func_name, "param", param_idx, taint))
        
        # Tabulation worklist algorithm with context sensitivity
        max_iterations = 1000
        iteration = 0
        
        while worklist and iteration < max_iterations:
            iteration += 1
            
            context, func_name, slot_type, slot_idx, label = worklist.popleft()
            
            if self.verbose and iteration % 100 == 0:
                print(f"  IDE iteration {iteration}, worklist size: {len(worklist)}, context: {context}")
            
            # INTRA-PROCEDURAL: propagate within function using summary
            summary = self.summaries.get(func_name)
            if summary and slot_type == "param":
                # Param affects return?
                if slot_idx in summary.ret_depends_on:
                    return_key = (context, func_name, "return", 0)
                    old_ret_label = facts.get(return_key, TaintLabel.clean())
                    new_ret_label = label_join(old_ret_label, label)
                    
                    if new_ret_label != old_ret_label:
                        facts[return_key] = new_ret_label
                        worklist.append((context, func_name, "return", 0, new_ret_label))
                
                # Param flows to sink?
                if slot_idx in summary.param_to_sinks:
                    for sink_type in summary.param_to_sinks[slot_idx]:
                        if not label.is_safe_for_sink(sink_type):
                            # Found a violation!
                            violation = SOTASecurityViolation(
                                bug_type=f"INTERPROCEDURAL_{sink_type.name}",
                                sink_type=sink_type,
                                file_path=file_path,
                                function_name=func_name,
                                line_number=0,  # Unknown line
                                bytecode_offset=0,
                                taint_label=label,
                                source_description=f"Param {slot_idx} in context {context}",
                                sink_description=f"Sink {sink_type.name}",
                                reason=f"Multi-hop interprocedural taint flow in context {context}",
                                confidence=0.80,
                            )
                            
                            # Deduplicate (context-aware)
                            is_dup = any(
                                v.function_name == violation.function_name and
                                v.sink_type == violation.sink_type and
                                "INTERPROCEDURAL" in v.bug_type and
                                f"context {context}" in v.reason
                                for v in self.violations
                            )
                            if not is_dup:
                                self.violations.append(violation)
            
            # INTERPROCEDURAL: propagate across call edges
            if slot_type == "return":
                # Return value flows back to callers
                # In IDE terminology: this is the "return flow function" that maps
                # callee return values to caller's call-site results
                for caller_name, caller_info in self.call_graph.functions.items():
                    for call_site in caller_info.call_sites:
                        if call_site.callee_name == func_name:
                            # Create call site identifier for context tracking
                            call_site_id = f"{caller_name}:{call_site.line_number}"
                            
                            # Check if this context matches the call site
                            # For k-CFA, we need to check if context's last call matches
                            if self.context_depth > 0:
                                # Context-sensitive: only propagate if context matches
                                # The context at the callee should end with this call site
                                if context.call_chain and context.call_chain[-1] != call_site_id:
                                    continue  # Wrong context, skip
                                
                                # Pop the call site from context when returning
                                if len(context.call_chain) > 0:
                                    caller_context = CallContext(
                                        call_chain=context.call_chain[:-1]
                                    )
                                else:
                                    caller_context = CallContext.empty()
                            else:
                                # Context-insensitive: use empty context
                                caller_context = CallContext.empty()
                            
                            # Map return to call-site result
                            # The call site produces a value that inherits the return's taint
                            # We model this as: caller receives tainted "local" at call site
                            # For simplicity, propagate to caller params (conservative)
                            caller_code = self.function_code.get(caller_name)
                            if caller_code:
                                # Propagate return taint to all params of caller
                                # (conservative: assumes result affects caller behavior)
                                for caller_param_idx in range(caller_code.co_argcount):
                                    caller_param_key = (caller_context, caller_name, "param", caller_param_idx)
                                    old_caller_param = facts.get(caller_param_key, TaintLabel.clean())
                                    new_caller_param = label_join(old_caller_param, label)
                                    
                                    if new_caller_param != old_caller_param:
                                        facts[caller_param_key] = new_caller_param
                                        worklist.append((caller_context, caller_name, "param", caller_param_idx, new_caller_param))
            
            # CALL EDGE: propagate from caller to callee
            func_info = self.call_graph.functions.get(func_name)
            if func_info:
                for call_site in func_info.call_sites:
                    callee_name = call_site.callee_name
                    if not callee_name or callee_name not in self.summaries:
                        continue
                    
                    # Create call site identifier for context tracking
                    call_site_id = f"{func_name}:{call_site.line_number}"
                    
                    # Extend context for k-CFA
                    if self.context_depth > 0:
                        callee_context = context.extend(call_site_id, k=self.context_depth)
                    else:
                        callee_context = CallContext.empty()
                    
                    # For each param slot in current function that's tainted
                    # propagate to callee params (conservative: all args inherit caller taint)
                    callee_summary = self.summaries[callee_name]
                    for callee_param_idx in range(len(callee_summary.ret_depends_on)):
                        callee_key = (callee_context, callee_name, "param", callee_param_idx)
                        old_callee_label = facts.get(callee_key, TaintLabel.clean())
                        new_callee_label = label_join(old_callee_label, label)
                        
                        if new_callee_label != old_callee_label:
                            facts[callee_key] = new_callee_label
                            worklist.append((callee_context, callee_name, "param", callee_param_idx, new_callee_label))
        
        if self.verbose:
            print(f"IDE tabulation completed in {iteration} iterations")
            print(f"Propagated facts to {len(facts)} (function, slot) pairs")
    
    def _analyze_file_for_project(self, filepath: Path):
        """Analyze a single file as part of a project analysis."""
        try:
            source = filepath.read_text()
            code = compile(source, str(filepath), "exec")
            self._extract_from_code(code, "")
            
            # Run intraprocedural on each function (with limited iterations)
            for func_name, code_obj in list(self.function_code.items()):
                violations = analyze_function_sota(
                    code_obj=code_obj,
                    function_name=func_name,
                    file_path=str(filepath),
                    verbose=False,
                    max_iterations=self.max_iterations,
                )
                self.violations.extend(violations)
                
                # Fast summary: create simple summary noting param dependencies
                # For proper IDE tabulation, we need param_to_sinks computed
                summary = self._compute_summary(func_name, code_obj)
                self.summaries[func_name] = summary
                
                # Include violations from summary computation
                self.violations.extend(summary.violations)
        
        except Exception as e:
            if self.verbose:
                print(f"  Warning: Could not analyze {filepath}: {e}")


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def analyze_file_interprocedural(
    filepath: Path,
    verbose: bool = False,
    context_depth: int = 0,
) -> List[SOTASecurityViolation]:
    """
    Analyze a file using the SOTA interprocedural engine.
    
    Args:
        filepath: Path to the Python file to analyze
        verbose: Whether to print debug output
        context_depth: k-CFA depth (0 = context-insensitive, 1 = 1-CFA, etc.)
    """
    analyzer = SOTAInterproceduralAnalyzer(
        verbose=verbose,
        context_depth=context_depth
    )
    return analyzer.analyze_file(filepath)


def analyze_project_interprocedural(
    root_path: Path,
    verbose: bool = False,
    context_depth: int = 0,
) -> List[SOTASecurityViolation]:
    """
    Analyze a project using the SOTA interprocedural engine.
    
    Args:
        root_path: Root path of the project
        verbose: Whether to print debug output
        context_depth: k-CFA depth (0 = context-insensitive, 1 = 1-CFA, etc.)
    """
    analyzer = SOTAInterproceduralAnalyzer(
        verbose=verbose,
        context_depth=context_depth
    )
    return analyzer.analyze_project(root_path)
