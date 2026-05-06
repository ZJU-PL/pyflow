"""
Interprocedural Bug Tracker for All Bug Types.

Extends the interprocedural analysis to detect ALL bug types (not just security/taint)
across function and file boundaries. This is the unified bug detection layer.

Architecture:
1. **TaintSummary**: Tracks information flow (security bugs like SQL injection)
2. **CrashSummary**: Tracks crash conditions (NULL_PTR, BOUNDS, DIV_ZERO, etc.)
3. **InterproceduralBugTracker**: Combines both for complete analysis

Usage:
    tracker = InterproceduralBugTracker.from_project(Path("my_project"))
    bugs = tracker.find_all_bugs()
    
This produces a unified report of all potential bugs reachable from entry points.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path
from enum import IntEnum

from ..confidence_interval import ReachabilityIntervalPTS, RiskInterval, ConcreteWitnessEvidence
from ..stochastic_risk import risk_interval_for_precondition
from .crash_summaries import (
    REGISTERED_BUG_TYPES, PRECONDITION_TO_BUG,
    PreconditionType, Precondition,
    ExceptionType, EXCEPTION_TO_BUG,
    Nullability,
    CrashSummary,
    BytecodeCrashSummaryComputer,  # Bytecode-only analysis (AST-based removed)
    InterproceduralBugSummary, compute_all_bug_summaries,
)
from ..barriers.guard_to_barrier import translate_guard_to_barrier, guards_protect_bug
from ..barriers.context_aware_verification import verify_bug_context_aware
from ..barriers.extreme_verification import verify_bug_extreme
from .summaries import TaintSummary, SummaryComputer
from .interprocedural_taint import InterproceduralContext
from .intraprocedural_taint import IntraproceduralTaintAnalyzer, IntraproceduralBug
from ..cfg.call_graph import CallGraph, CallSite, build_call_graph_from_directory
from ..frontend.entry_points import detect_entry_points_in_project, get_entry_point_functions
from ..confidence_scoring import ConfidenceScorer


# ============================================================================
# BUG REPORT
# ============================================================================

@dataclass
class InterproceduralBug:
    """
    A bug found through interprocedural analysis.
    
    Contains full provenance: the call chain from entry point to bug site.
    Uses string bug type names from a3_python/unsafe/registry.py as the
    canonical source of truth (e.g., 'DIV_ZERO', 'NULL_PTR', 'SQL_INJECTION').
    
    The `inferred_source` field indicates whether sensitive data was identified through
    heuristic name-based inference (e.g., variable named 'password') rather than explicit
    source tracking. This should be set to True when the bug depends on sensitivity inference
    from `infer_sensitivity_from_name()` in security_tracker_lattice.py.
    """
    bug_type: str  # String name from REGISTERED_BUG_TYPES
    
    # Where the bug manifests
    crash_function: str
    crash_location: str  # file:line
    
    # Call chain from entry point
    call_chain: List[str]  # [entry, caller1, caller2, ..., crash_function]
    
    # How it happens
    reason: str
    
    # Precondition that was violated (if applicable)
    violated_precondition: Optional[Precondition] = None
    
    # Exception that would be raised
    exception_type: Optional[ExceptionType] = None
    
    # Confidence (based on how conservative the analysis was)
    confidence: float = 1.0  # 1.0 = certain, < 1.0 = may be FP

    # Quantitative reporting (barrier-compatible; does not affect verdicts)
    reachability_pts: ReachabilityIntervalPTS = field(default_factory=ReachabilityIntervalPTS.unknown)
    depth_k: Optional[int] = None
    witness: ConcreteWitnessEvidence = field(default_factory=lambda: ConcreteWitnessEvidence(present=False))
    risk_interval: Optional[RiskInterval] = None
    
    # Additional context
    tainted_sources: List[str] = field(default_factory=list)
    relevant_args: List[int] = field(default_factory=list)
    
    # SYMBOLIC VARIABLE TRACKING: Track the exact variable that causes the bug
    # Format: "param_N" for parameters, "local_NAME" for locals, "call:FUNC" for call results
    # This enables precise interprocedural guard matching
    bug_variable: Optional[str] = None
    bug_offset: Optional[int] = None  # Bytecode offset where bug occurs
    
    # Source provenance (for cleartext/sensitivity tracking)
    inferred_source: bool = False  # True if source was inferred from name/type, not explicit
    
    def __str__(self) -> str:
        chain_str = " → ".join(self.call_chain)
        return f"{self.bug_type} in {self.crash_function}: {self.reason}\n  Call chain: {chain_str}"


# ============================================================================
# VALUE STATE FOR INTERPROCEDURAL TRACKING
# ============================================================================

@dataclass
class ValueState:
    """
    Abstract state of a value for interprocedural bug detection.
    
    Tracks nullability, zero-ness, taintedness, etc.
    """
    nullability: Nullability = Nullability.TOP
    may_be_zero: bool = True
    is_tainted: bool = False
    taint_sources: Set[str] = field(default_factory=set)
    
    # Bounds info (for index values)
    may_be_negative: bool = True
    has_upper_bound: bool = False
    upper_bound: Optional[int] = None
    
    # Type info
    known_type: Optional[str] = None
    
    @classmethod
    def from_none(cls) -> 'ValueState':
        """Create state representing None."""
        return cls(nullability=Nullability.IS_NONE, may_be_zero=False)
    
    @classmethod  
    def from_literal(cls, value: Any) -> 'ValueState':
        """Create state from a literal value."""
        if value is None:
            return cls.from_none()
        state = cls(nullability=Nullability.NOT_NONE)
        if isinstance(value, (int, float)):
            state.may_be_zero = (value == 0)
            state.may_be_negative = (value < 0)
            if isinstance(value, int):
                state.has_upper_bound = True
                state.upper_bound = value
        return state
    
    def join(self, other: 'ValueState') -> 'ValueState':
        """Lattice join of two states."""
        return ValueState(
            nullability=self.nullability.join(other.nullability),
            may_be_zero=self.may_be_zero or other.may_be_zero,
            is_tainted=self.is_tainted or other.is_tainted,
            taint_sources=self.taint_sources | other.taint_sources,
            may_be_negative=self.may_be_negative or other.may_be_negative,
            has_upper_bound=self.has_upper_bound and other.has_upper_bound,
            upper_bound=min(self.upper_bound, other.upper_bound) if (self.upper_bound and other.upper_bound) else None,
        )


# ============================================================================
# INTERPROCEDURAL BUG TRACKER
# ============================================================================

@dataclass
class InterproceduralBugTracker:
    """
    Main class for interprocedural bug detection.
    
    Combines taint analysis (security bugs) with crash analysis (correctness bugs)
    to find all potential bugs reachable from program entry points.
    """
    
    # Core data
    call_graph: CallGraph
    entry_points: Set[str]
    reachable_functions: Set[str]
    root_path: Optional[Path] = None  # Root directory for the project
    
    # Summaries
    taint_summaries: Dict[str, TaintSummary] = field(default_factory=dict)
    crash_summaries: Dict[str, CrashSummary] = field(default_factory=dict)
    combined_summaries: Dict[str, InterproceduralBugSummary] = field(default_factory=dict)
    
    # Analysis state
    bugs_found: List[InterproceduralBug] = field(default_factory=list)
    analyzed: bool = False
    
    # Confidence scoring
    confidence_scorer: ConfidenceScorer = field(default_factory=ConfidenceScorer)
    
    # Intraprocedural bugs (cached)
    _intraprocedural_bugs: Dict[str, List[IntraproceduralBug]] = field(default_factory=dict)
    
    # ITERATION 518: Import aliases per file (for resolving aliased imports)
    # Maps file_path → (alias_name → real_module_path)
    # Example: "test.py" → {"ET": "xml.etree.ElementTree"}
    _import_aliases_by_file: Dict[str, Dict[str, str]] = field(default_factory=dict)
    
    @classmethod
    def from_project(cls, root_path: Path, entry_points: Optional[Set[str]] = None) -> 'InterproceduralBugTracker':
        """
        Build tracker for an entire project.
        
        Args:
            root_path: Root directory of the project
            entry_points: Optional set of entry point function names. If None, auto-detect.
                         If auto-detection finds nothing, analyze all functions.
        """
        import logging
        logger = logging.getLogger(__name__)
        from ..contracts.security_lattice import (
            get_source_contracts_for_summaries,
            get_sink_contracts_for_summaries,
            get_sanitizer_contracts_for_summaries,
            init_security_contracts,
        )
        
        # Initialize contracts (idempotent)
        logger.info(f"[PROJECT] Initializing security contracts for {root_path.name}")
        init_security_contracts()
        
        # Build call graph
        logger.info(f"[PROJECT] Building call graph from {root_path}")
        call_graph = build_call_graph_from_directory(root_path)
        logger.info(f"[PROJECT] Call graph: {len(call_graph.functions)} functions, {sum(len(f.call_sites) for f in call_graph.functions.values())} call sites")
        
        # Detect entry points
        if entry_points is None:
            logger.info(f"[PROJECT] Detecting entry points")
            entry_point_list = detect_entry_points_in_project(root_path)
            entry_points = get_entry_point_functions(entry_point_list)
            
            # If no entry points found, or none match actual functions,
            # use all functions as entry points
            if not entry_points or not (entry_points & set(call_graph.functions.keys())):
                entry_points = set(call_graph.functions.keys())
                logger.info(f"[PROJECT] Using all {len(entry_points)} functions as entry points")
            else:
                logger.info(f"[PROJECT] Found {len(entry_points)} entry points")
        
        # Compute reachable functions
        logger.info(f"[PROJECT] Computing reachability from entry points")
        reachable = call_graph.get_reachable_from(entry_points)
        logger.info(f"[PROJECT] Reachable: {len(reachable)} functions")
        
        # If reachability is empty but we have functions, include entry points themselves
        if not reachable and entry_points:
            reachable = entry_points & set(call_graph.functions.keys())
        
        # Load security contracts for library functions
        logger.info(f"[PROJECT] Loading security contracts")
        source_contracts = get_source_contracts_for_summaries()
        sink_contracts = get_sink_contracts_for_summaries()
        sanitizer_contracts = get_sanitizer_contracts_for_summaries()
        
        # Compute taint summaries
        logger.info(f"[PROJECT] Computing taint summaries for {len(call_graph.functions)} functions")
        taint_computer = SummaryComputer(
            call_graph,
            source_contracts=source_contracts,
            sink_contracts=sink_contracts,
            sanitizer_contracts=sanitizer_contracts,
        )
        taint_summaries = taint_computer.compute_all()
        logger.info(f"[PROJECT] Computed {len(taint_summaries)} taint summaries")
        
        # Compute crash summaries (using bytecode-level analysis by default)
        logger.info(f"[PROJECT] Computing crash summaries (bytecode-level)")
        crash_computer = BytecodeCrashSummaryComputer(call_graph)
        crash_summaries = crash_computer.compute_all()
        logger.info(f"[PROJECT] Computed {len(crash_summaries)} crash summaries")
        
        # Combine summaries
        logger.info(f"[PROJECT] Combining taint + crash summaries")
        combined = compute_all_bug_summaries(call_graph, taint_summaries)
        
        # Train Layer 0 fast barrier filters on the codebase (one-time learning)
        logger.info(f"[PROJECT] Training Layer 0 fast barrier filters on codebase")
        from ..barriers.extreme_verification import get_extreme_verifier
        extreme_verifier = get_extreme_verifier()
        if hasattr(extreme_verifier, 'fast_filters'):
            extreme_verifier.fast_filters.learn_from_codebase(crash_summaries)
            logger.info(f"[PROJECT] Layer 0 trained on {len(crash_summaries)} functions")
        logger.info(f"[PROJECT] Tracker ready - starting bug detection")
        
        return cls(
            call_graph=call_graph,
            entry_points=entry_points,
            reachable_functions=reachable,
            root_path=root_path,
            taint_summaries=taint_summaries,
            crash_summaries=crash_summaries,
            combined_summaries=combined,
        )
    
    def _get_import_aliases_for_file(self, file_path: Path) -> Dict[str, str]:
        """
        Get or extract import aliases for a file.
        
        Caches results to avoid re-parsing.
        
        Args:
            file_path: Path to the Python file
        
        Returns:
            Dictionary mapping alias names to real module paths
            Example: {"ET": "xml.etree.ElementTree"}
        """
        file_path_str = str(file_path)
        
        # Check cache
        if file_path_str in self._import_aliases_by_file:
            return self._import_aliases_by_file[file_path_str]
        
        # Extract imports from file
        from .intraprocedural_taint import extract_module_imports
        
        try:
            source = file_path.read_text()
            code = compile(source, file_path_str, 'exec')
            import_aliases = extract_module_imports(code)
            self._import_aliases_by_file[file_path_str] = import_aliases
            return import_aliases
        except Exception as e:
            # If we can't read/compile the file, return empty dict
            self._import_aliases_by_file[file_path_str] = {}
            return {}
    
    def _compute_confidence_for_security_bug(
        self,
        bug_type: str,
        sink_type: 'SinkType',
        call_chain_length: int,
        is_internal_sink: bool = False,
    ) -> float:
        """
        Compute confidence for a security/taint bug.
        
        Args:
            bug_type: Security bug type name
            sink_type: Type of sink (SinkType enum or int)
            call_chain_length: Length of call chain
            is_internal_sink: Whether sink is in analyzed code (True) or library (False)
        
        Returns:
            Confidence score 0.0-1.0
        """
        # Without actual taint label, we use heuristics based on sink location and chain
        from ..z3model.taint_lattice import TaintLabel, SourceType, SinkType as SinkTypeEnum, CODEQL_BUG_TYPES
        
        # Convert int to SinkType if needed
        if isinstance(sink_type, int):
            try:
                sink_type = SinkTypeEnum(sink_type)
            except ValueError:
                # Invalid sink type - return conservative score
                return 0.5
        
        # Create a hypothetical "tainted" label for scoring
        # In full implementation, this would be the actual taint label at sink
        bug_def = CODEQL_BUG_TYPES.get(bug_type)
        if bug_def and bug_def.checks_sigma and not bug_def.checks_tau:
            # σ-only bugs (e.g., CLEARTEXT_LOGGING/CLEARTEXT_STORAGE) need a sensitive label,
            # otherwise scoring will early-exit at 0.0.
            label = TaintLabel.from_sensitive_source(SourceType.PASSWORD, "hypothetical")
        elif bug_def and bug_def.checks_sigma and bug_def.checks_tau:
            # Bugs requiring both τ and σ: join both kinds of evidence.
            label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "hypothetical").join(
                TaintLabel.from_sensitive_source(SourceType.PASSWORD, "hypothetical")
            )
        else:
            label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "hypothetical")
        
        # Score with conservative parameters
        breakdown = self.confidence_scorer.score_security_bug(
            label=label,
            sink_type=sink_type,
            is_guarded=False,  # Conservative: assume no guards
            call_chain_length=call_chain_length,
            has_exception_handler=False,  # Conservative
            in_framework_context=False,
        )
        
        score = breakdown.combined_score()
        
        # Adjust based on sink location
        if is_internal_sink:
            # Internal sink: higher confidence (we analyzed it)
            score = min(1.0, score * 1.1)
        else:
            # External/library sink: lower confidence (summaries may be incomplete)
            score = score * 0.85
        
        return score
    
    def _compute_confidence_for_error_bug(
        self,
        bug_type: str,
        call_chain_length: int,
        certainty: str = 'POSSIBLE',
    ) -> float:
        """
        Compute confidence for an error bug (crash/exception).
        
        Args:
            bug_type: Error bug type name
            call_chain_length: Length of call chain
            certainty: Certainty level ('DEFINITE', 'LIKELY', 'POSSIBLE', 'UNKNOWN')
        
        Returns:
            Confidence score 0.0-1.0
        """
        breakdown = self.confidence_scorer.score_error_bug(
            bug_type=bug_type,
            certainty=certainty,
            is_guarded=False,  # Conservative
            call_chain_length=call_chain_length,
            has_exception_handler=False,  # Conservative
        )
        
        return breakdown.combined_score()
    
    def find_all_bugs(
        self, 
        apply_fp_reduction: bool = False,
        apply_intent_filter: bool = True,
        intent_confidence: float = 0.7,
        root_path: Optional[Path] = None,
        only_non_security: bool = True,  # NEW: skip security bugs for speed
    ) -> List[InterproceduralBug]:
        """
        Find all bugs reachable from entry points.
        
        Performs interprocedural analysis starting from each entry point,
        tracking value states and checking for precondition violations.
        
        Deduplicates findings by (file, line, sink_type) to avoid reporting
        the same bug multiple times from different entry points.
        
        INTERPROCEDURAL GUARD EXTENSION: Also applies guard facts computed
        from function summaries to reduce false positives.
        
        Args:
            apply_fp_reduction: If True, apply FP context adjustments to reduce
                               false positives from CLI tools, test files, etc.
            apply_intent_filter: If True, apply intent-aware filtering to report
                                only high-confidence true positives (default: True)
            intent_confidence: Minimum confidence for intent filtering (default: 0.7)
            root_path: Project root path for reading source code during intent analysis
        """
        import logging
        logger = logging.getLogger(__name__)
        
        self.bugs_found = []
        
        # SPEED OPTIMIZATION: Cache guard analysis results
        self._guard_cache = {}
        
        # ITERATION 610: For crash bugs, analyze ALL functions with may_trigger
        # Crash bugs don't require entry-point reachability - if a function CAN crash,
        # we should report it regardless of how it's called. Security bugs still
        # require reachability for taint tracking.
        logger.info(f"[BUGS] Analyzing crash bugs across {len(self.crash_summaries)} functions")
        
        # SPEED: Analyze in batches with progress reporting
        summaries_list = list(self.crash_summaries.items())
        batch_size = 100
        total_verified = 0
        total_skipped = 0
        
        for batch_start in range(0, len(summaries_list), batch_size):
            batch_end = min(batch_start + batch_size, len(summaries_list))
            if batch_start % 500 == 0 and batch_start > 0:
                logger.info(f"[BUGS] Progress: {batch_start}/{len(summaries_list)} functions analyzed, {total_verified} verified safe, {total_skipped} skipped")
            # Analyze batch
            for func_name, summary in summaries_list[batch_start:batch_end]:
                self._analyze_crash_bugs_for_function(func_name, summary)
        
        logger.info(f"[BUGS] Found {len(self.bugs_found)} potential crash bugs after verification")
        
        # For security bugs, use entry-point reachability
        if only_non_security:
            logger.info(f"[BUGS] Skipping security bug analysis (only_non_security=True)")
        else:
            logger.info(f"[BUGS] Analyzing security bugs from {len(self.entry_points)} entry points")
            for i, entry in enumerate(self.entry_points, 1):
                if i % 100 == 0:
                    logger.info(f"[BUGS] Progress: {i}/{len(self.entry_points)} entry points analyzed")
                self._analyze_from_entry(entry)
        # AST-based nondeterminism scanning (unsorted dict iteration in join/format)
        from .nondeterminism_detector import scan_file_for_nondeterminism_bugs
        scanned_files: set = set()
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in scanned_files:
                scanned_files.add(str(fp))
        # Fallback: scan source files from root_path when call graph has no functions
        if not scanned_files and root_path:
            rp = Path(root_path) if not isinstance(root_path, Path) else root_path
            if rp.is_file() and rp.suffix == '.py':
                scanned_files.add(str(rp))
            elif rp.is_dir():
                for py_file in rp.glob('*.py'):
                    scanned_files.add(str(py_file))
        for _sf in scanned_files:
            nondet_bugs = scan_file_for_nondeterminism_bugs(Path(_sf))
            for nb in nondet_bugs:
                # unsorted_join on dict-derived data is TYPE_CONFUSION:
                # str.join() requires all-string elements, dict keys may not be strings
                bug_type = 'TYPE_CONFUSION' if nb.pattern == 'unsorted_join' else 'ORDER_VIOLATION'
                self.bugs_found.append(InterproceduralBug(
                    bug_type=bug_type,
                    crash_function=nb.function_name,
                    crash_location=f"{nb.file_path}:{nb.line_number}",
                    call_chain=[nb.function_name],
                    reason=nb.reason,
                    confidence=nb.confidence,
                    reachability_pts=ReachabilityIntervalPTS.unknown(
                        evidence=[f"source=ast_nondeterminism_scan", f"pattern={nb.pattern}"]
                    ),
                    bug_variable=nb.collection_var,
                ))

        # AST + Z3 stale counter scanning (counter update after comparison)
        from .stale_counter_detector import scan_file_for_stale_counter_bugs
        scanned_files_sc: set = set()
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in scanned_files_sc:
                scanned_files_sc.add(str(fp))
        if not scanned_files_sc and root_path:
            rp = Path(root_path) if not isinstance(root_path, Path) else root_path
            if rp.is_file() and rp.suffix == '.py':
                scanned_files_sc.add(str(rp))
            elif rp.is_dir():
                for py_file in rp.glob('*.py'):
                    scanned_files_sc.add(str(py_file))
        for _sf in scanned_files_sc:
            stale_bugs = scan_file_for_stale_counter_bugs(Path(_sf))
            for sb in stale_bugs:
                self.bugs_found.append(InterproceduralBug(
                    bug_type='STALE_VALUE',
                    crash_function=sb.function_name,
                    crash_location=f"{sb.file_path}:{sb.line_number}",
                    call_chain=[sb.function_name],
                    reason=sb.reason,
                    confidence=sb.confidence,
                    reachability_pts=ReachabilityIntervalPTS.unknown(
                        evidence=[f"source=ast_stale_counter_scan", f"pattern={sb.pattern}"]
                    ),
                    bug_variable=sb.variable,
                ))

        # AST-based argument mismatch / misscoped control flow scanning
        from .argument_mismatch_detector import scan_file_for_argument_mismatch_bugs
        scanned_files_arg: set = set()
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in scanned_files_arg:
                scanned_files_arg.add(str(fp))
                argmatch_bugs = scan_file_for_argument_mismatch_bugs(Path(fp))
                for ab in argmatch_bugs:
                    bug_type = 'PRECONDITION_VIOLATION' if ab.pattern == 'wrong_argument' else 'ORDER_VIOLATION'
                    self.bugs_found.append(InterproceduralBug(
                        bug_type=bug_type,
                        crash_function=ab.function_name,
                        crash_location=f"{ab.file_path}:{ab.line_number}",
                        call_chain=[ab.function_name],
                        reason=ab.reason,
                        confidence=ab.confidence,
                        reachability_pts=ReachabilityIntervalPTS.unknown(
                            evidence=[f"source=ast_argument_mismatch_scan", f"pattern={ab.pattern}"]
                        ),
                        bug_variable=ab.variable,
                    ))

        # AST-based encoding bug scanning (hardcoded ASCII, open without encoding)
        # Missing encoding guards are classified as NULL_PTR: the code fails to guard
        # against non-ASCII input, analogous to missing None checks before attribute access.
        from .encoding_bug_detector import scan_file_for_encoding_bugs
        scanned_files_enc: set = set()
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in scanned_files_enc:
                scanned_files_enc.add(str(fp))
        # Also discover files from root_path when call_graph has no functions
        if not scanned_files_enc and self.root_path and self.root_path.is_dir():
            for py_file in self.root_path.rglob('*.py'):
                parts = py_file.relative_to(self.root_path).parts
                if not any(p.startswith('.') or p == '__pycache__' for p in parts):
                    scanned_files_enc.add(str(py_file))
        for fp_str in scanned_files_enc:
            enc_bugs = scan_file_for_encoding_bugs(Path(fp_str))
            for eb in enc_bugs:
                # Data-parse encoding bugs cause ValueError → ASSERT_FAIL class
                if eb.pattern == 'open_read_without_encoding_data_parse':
                    enc_bug_type = 'ASSERT_FAIL'
                else:
                    enc_bug_type = 'NULL_PTR'
                self.bugs_found.append(InterproceduralBug(
                    bug_type=enc_bug_type,
                    crash_function=eb.function_name,
                    crash_location=f"{eb.file_path}:{eb.line_number}",
                    call_chain=[eb.function_name],
                    reason=(
                        f"Missing encoding guard: {eb.reason} "
                        f"This is a missing-guard bug — code lacks a check before "
                        f"operations that assume ASCII-only input."
                    ),
                    confidence=eb.confidence,
                    reachability_pts=ReachabilityIntervalPTS.unknown(
                        evidence=[f"source=ast_encoding_scan", f"pattern={eb.pattern}"]
                    ),
                    bug_variable='encoding',
                ))

        # AST-based missing-None-guard scanning (variable init to None,
        # conditionally assigned, then used via attribute access without guard)
        from .none_guard_detector import scan_file_for_none_guard_bugs
        scanned_files_ng: set = set()
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in scanned_files_ng:
                scanned_files_ng.add(str(fp))
        if not scanned_files_ng and self.root_path and self.root_path.is_dir():
            for py_file in self.root_path.rglob('*.py'):
                parts = py_file.relative_to(self.root_path).parts
                if not any(p.startswith('.') or p == '__pycache__' for p in parts):
                    scanned_files_ng.add(str(py_file))
        for fp_str in scanned_files_ng:
            ng_bugs = scan_file_for_none_guard_bugs(Path(fp_str))
            for ng in ng_bugs:
                self.bugs_found.append(InterproceduralBug(
                    bug_type='NULL_PTR',
                    crash_function=ng.function_name,
                    crash_location=f"{ng.file_path}:{ng.line_number}",
                    call_chain=[ng.function_name],
                    reason=ng.reason,
                    confidence=ng.confidence,
                    reachability_pts=ReachabilityIntervalPTS.unknown(
                        evidence=[f"source=ast_none_guard_scan", f"pattern={ng.pattern}"]
                    ),
                    bug_variable=ng.variable,
                ))

        # AST-based missing-capability-guard scanning (method called without
        # checking a boolean capability attribute like supports_X, has_X, can_X)
        from .missing_capability_guard_detector import scan_project_for_capability_guard_bugs
        cap_guard_files: list = []
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in {str(p) for p in cap_guard_files}:
                cap_guard_files.append(Path(str(fp)))
        if not cap_guard_files and self.root_path and self.root_path.is_dir():
            for py_file in self.root_path.rglob('*.py'):
                parts = py_file.relative_to(self.root_path).parts
                if not any(p.startswith('.') or p == '__pycache__' for p in parts):
                    cap_guard_files.append(py_file)
        if cap_guard_files:
            cg_bugs = scan_project_for_capability_guard_bugs(cap_guard_files)
            for cg in cg_bugs:
                self.bugs_found.append(InterproceduralBug(
                    bug_type='NULL_PTR',
                    crash_function=cg.function_name,
                    crash_location=f"{cg.file_path}:{cg.line_number}",
                    call_chain=[cg.function_name],
                    reason=cg.reason,
                    confidence=cg.confidence,
                    reachability_pts=ReachabilityIntervalPTS.unknown(
                        evidence=[f"source=ast_capability_guard_scan", f"pattern={cg.pattern}"]
                    ),
                    bug_variable=cg.variable,
                ))

        # AST-based union-type attribute access detection (missing isinstance guard)
        from .union_attr_detector import scan_file_for_union_attr_bugs
        scanned_files_ua: set = set()
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in scanned_files_ua:
                scanned_files_ua.add(str(fp))
        if not scanned_files_ua and self.root_path and self.root_path.is_dir():
            for py_file in self.root_path.rglob('*.py'):
                parts = py_file.relative_to(self.root_path).parts
                if not any(p.startswith('.') or p == '__pycache__' for p in parts):
                    scanned_files_ua.add(str(py_file))
        for fp_str in scanned_files_ua:
            ua_bugs = scan_file_for_union_attr_bugs(Path(fp_str))
            for ub in ua_bugs:
                self.bugs_found.append(InterproceduralBug(
                    bug_type='TYPE_CONFUSION',
                    crash_function=ub.function_name,
                    crash_location=f"{ub.file_path}:{ub.line_number}",
                    call_chain=[ub.function_name],
                    reason=ub.reason,
                    confidence=ub.confidence,
                    reachability_pts=ReachabilityIntervalPTS.unknown(
                        evidence=[f"source=ast_union_attr_scan", f"pattern={ub.pattern}"]
                    ),
                    bug_variable=ub.variable,
                ))

        # AST-based incomplete predicate sub-field validation (fastapi#11 pattern)
        from .incomplete_predicate_subfield_detector import scan_file_for_incomplete_predicate_subfield_bugs
        scanned_files_psf: set = set()
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in scanned_files_psf:
                scanned_files_psf.add(str(fp))
        if not scanned_files_psf and self.root_path and self.root_path.is_dir():
            for py_file in self.root_path.rglob('*.py'):
                parts = py_file.relative_to(self.root_path).parts
                if not any(p.startswith('.') or p == '__pycache__' for p in parts):
                    scanned_files_psf.add(str(py_file))
        for fp_str in scanned_files_psf:
            psf_bugs = scan_file_for_incomplete_predicate_subfield_bugs(Path(fp_str))
            for pb in psf_bugs:
                self.bugs_found.append(InterproceduralBug(
                    bug_type='NULL_PTR',
                    crash_function=pb.function_name,
                    crash_location=f"{pb.file_path}:{pb.line_number}",
                    call_chain=[pb.function_name],
                    reason=pb.reason,
                    confidence=pb.confidence,
                    reachability_pts=ReachabilityIntervalPTS.unknown(
                        evidence=[f"source=ast_incomplete_predicate_subfield_scan", f"pattern={pb.pattern}"]
                    ),
                    bug_variable=pb.variable,
                ))

        # AST + Z3 symbolic config dispatch completeness scanning
        # Detects incomplete enum-to-feature-set mappings (e.g., black#6)
        from .config_dispatch_detector import scan_file_for_config_dispatch_bugs
        scanned_files_cd: set = set()
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in scanned_files_cd:
                scanned_files_cd.add(str(fp))
        if not scanned_files_cd and self.root_path and self.root_path.is_dir():
            for py_file in self.root_path.rglob('*.py'):
                parts = py_file.relative_to(self.root_path).parts
                if not any(p.startswith('.') or p == '__pycache__' for p in parts):
                    scanned_files_cd.add(str(py_file))
        for fp_str in scanned_files_cd:
            cd_bugs = scan_file_for_config_dispatch_bugs(Path(fp_str))
            for cb in cd_bugs:
                self.bugs_found.append(InterproceduralBug(
                    bug_type='TYPE_CONFUSION',
                    crash_function=cb.function_name,
                    crash_location=f"{cb.file_path}:{cb.line_number}",
                    call_chain=[cb.function_name],
                    reason=cb.reason,
                    confidence=cb.confidence,
                    reachability_pts=ReachabilityIntervalPTS.unknown(
                        evidence=[f"source=ast_config_dispatch_scan", f"pattern={cb.pattern}"]
                    ),
                    bug_variable=cb.variable,
                ))

        # AST-based incomplete isinstance dispatch in loops (fastapi#15 pattern)
        from .incomplete_isinstance_dispatch_detector import scan_file_for_incomplete_isinstance_dispatch_bugs
        scanned_files_iid: set = set()
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in scanned_files_iid:
                scanned_files_iid.add(str(fp))
        if not scanned_files_iid and self.root_path and self.root_path.is_dir():
            for py_file in self.root_path.rglob('*.py'):
                parts = py_file.relative_to(self.root_path).parts
                if not any(p.startswith('.') or p == '__pycache__' for p in parts):
                    scanned_files_iid.add(str(py_file))
        for fp_str in scanned_files_iid:
            iid_bugs = scan_file_for_incomplete_isinstance_dispatch_bugs(Path(fp_str))
            for ib in iid_bugs:
                self.bugs_found.append(InterproceduralBug(
                    bug_type='TYPE_CONFUSION',
                    crash_function=ib.function_name,
                    crash_location=f"{ib.file_path}:{ib.line_number}",
                    call_chain=[ib.function_name],
                    reason=ib.reason,
                    confidence=ib.confidence,
                    reachability_pts=ReachabilityIntervalPTS.unknown(
                        evidence=[f"source=ast_incomplete_isinstance_dispatch_scan", f"pattern={ib.pattern}"]
                    ),
                    bug_variable=ib.variable,
                ))

        # AST-based missing HTTP session config propagation (httpie#2 pattern)
        from .missing_session_config_detector import scan_file_for_missing_session_config_bugs
        scanned_files_sc: set = set()
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in scanned_files_sc:
                scanned_files_sc.add(str(fp))
        if not scanned_files_sc and self.root_path and self.root_path.is_dir():
            for py_file in self.root_path.rglob('*.py'):
                parts = py_file.relative_to(self.root_path).parts
                if not any(p.startswith('.') or p == '__pycache__' for p in parts):
                    scanned_files_sc.add(str(py_file))
        for fp_str in scanned_files_sc:
            sc_bugs = scan_file_for_missing_session_config_bugs(Path(fp_str))
            for sb in sc_bugs:
                self.bugs_found.append(InterproceduralBug(
                    bug_type='ASSERT_FAIL',
                    crash_function=sb.function_name,
                    crash_location=f"{sb.file_path}:{sb.line_number}",
                    call_chain=[sb.function_name],
                    reason=sb.reason,
                    confidence=sb.confidence,
                    reachability_pts=ReachabilityIntervalPTS.unknown(
                        evidence=[f"source=ast_missing_session_config_scan", f"pattern={sb.pattern}"]
                    ),
                    bug_variable=sb.variable,
                ))

        # AST-based str.find() result misuse detection (keras#9 pattern)
        from .find_result_misuse_detector import scan_file_for_find_result_misuse_bugs
        scanned_files_frm: set = set()
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in scanned_files_frm:
                scanned_files_frm.add(str(fp))
        if not scanned_files_frm and root_path:
            rp = Path(root_path) if not isinstance(root_path, Path) else root_path
            if rp.is_file() and rp.suffix == '.py':
                scanned_files_frm.add(str(rp))
            elif rp.is_dir():
                for py_file in rp.rglob('*.py'):
                    parts = py_file.relative_to(rp).parts
                    if not any(p.startswith('.') or p == '__pycache__' for p in parts):
                        scanned_files_frm.add(str(py_file))
        for fp_str in scanned_files_frm:
            frm_bugs = scan_file_for_find_result_misuse_bugs(Path(fp_str))
            for fb in frm_bugs:
                self.bugs_found.append(InterproceduralBug(
                    bug_type='BOUNDS',
                    crash_function=fb.function_name,
                    crash_location=f"{fb.file_path}:{fb.line_number}",
                    call_chain=[fb.function_name],
                    reason=fb.reason,
                    confidence=fb.confidence,
                    reachability_pts=ReachabilityIntervalPTS.unknown(
                        evidence=[f"source=ast_find_result_misuse_scan", f"pattern={fb.pattern}"]
                    ),
                    bug_variable=fb.variable,
                ))

        # AST-based missing wrapper attribute forwarding detection (keras#37 pattern)
        from .missing_wrapper_forwarding_detector import scan_file_for_wrapper_forwarding_bugs
        scanned_files_wf: set = set()
        for func_info in self.call_graph.functions.values():
            fp = getattr(func_info, 'file_path', None)
            if fp and str(fp) not in scanned_files_wf:
                scanned_files_wf.add(str(fp))
        if not scanned_files_wf and root_path:
            rp = Path(root_path) if not isinstance(root_path, Path) else root_path
            if rp.is_file() and rp.suffix == '.py':
                scanned_files_wf.add(str(rp))
            elif rp.is_dir():
                for py_file in rp.rglob('*.py'):
                    parts = py_file.relative_to(rp).parts
                    if not any(p.startswith('.') or p == '__pycache__' for p in parts):
                        scanned_files_wf.add(str(py_file))
        for fp_str in scanned_files_wf:
            wf_bugs = scan_file_for_wrapper_forwarding_bugs(Path(fp_str))
            for wb in wf_bugs:
                self.bugs_found.append(InterproceduralBug(
                    bug_type='NULL_PTR',
                    crash_function=wb.function_name,
                    crash_location=f"{wb.file_path}:{wb.line_number}",
                    call_chain=[wb.function_name],
                    reason=wb.reason,
                    confidence=wb.confidence,
                    reachability_pts=ReachabilityIntervalPTS.unknown(
                        evidence=[f"source=ast_wrapper_forwarding_scan", f"pattern={wb.pattern}"]
                    ),
                    bug_variable=wb.variable,
                ))

        logger.info(f"[BUGS] Total bugs before deduplication: {len(self.bugs_found)}")
        
        # Deduplicate bugs by (location, bug_type)
        # Keep the bug with the shortest call chain for each unique location+type
        logger.info(f"[BUGS] Deduplicating bugs")
        self.bugs_found = self._deduplicate_bugs(self.bugs_found)
        logger.info(f"[BUGS] After deduplication: {len(self.bugs_found)} bugs")
        
        # INTERPROCEDURAL GUARD: Apply guard-based FP reduction
        logger.info(f"[BUGS] Applying interprocedural guard analysis")
        self.bugs_found = self._apply_interprocedural_guards(self.bugs_found)
        logger.info(f"[BUGS] After guard reduction: {len(self.bugs_found)} bugs")
        
        # Apply FP context adjustments
        if apply_fp_reduction:
            self.bugs_found = self._apply_fp_context_adjustments(self.bugs_found)
        
        # Apply intent-aware filtering for high-confidence TPs only
        if apply_intent_filter:
            self.bugs_found = self.apply_intent_filtering(
                self.bugs_found, 
                min_confidence=intent_confidence,
                root_path=root_path,
            )
        
        self.analyzed = True
        return self.bugs_found
    
    def _apply_interprocedural_guards(
        self,
        bugs: List[InterproceduralBug],
    ) -> List[InterproceduralBug]:
        """
        Apply interprocedural guard analysis to reduce false positives.
        
        AUTOMATIC GUARD PROPAGATION: Uses guard facts automatically collected
        from the intraprocedural GuardAnalyzer (control_flow.py). Any guard
        pattern defined there is automatically available here.
        
        For each bug, check if interprocedural guards make it a FP:
        1. If the crash function has guards of relevant types
        2. If a callee returns a value with guarantees
        3. If the call chain validates parameters
        
        Uses GUARD_TYPE_TO_BUG_TYPES mapping from interprocedural_guards.py
        to automatically map guard patterns to bug types.
        """
        from .interprocedural_guards import get_guard_types_for_bug
        
        filtered_bugs = []
        guarded_count = 0
        
        for bug in bugs:
            # Skip guard analysis for AST-scanner-sourced bugs — they are
            # structural/module-level findings, not function-level crash bugs.
            evidence = bug.reachability_pts.evidence if bug.reachability_pts else []
            is_ast_scan = any(ev.startswith('source=ast_') for ev in evidence)
            if is_ast_scan:
                filtered_bugs.append(bug)
                continue

            is_guarded = self._is_bug_interprocedurally_guarded(bug)
            
            if is_guarded:
                guarded_count += 1
                # Mark as guarded with reduced confidence
                bug.confidence *= 0.25  # 75% reduction for interprocedurally guarded
                bug.reason += " [interprocedural guard detected]"
            
            filtered_bugs.append(bug)
        
        return filtered_bugs
    
    def _is_bug_interprocedurally_guarded(self, bug: InterproceduralBug) -> bool:
        """Check if a bug is protected by interprocedural guards.
        
        CONTEXT-AWARE VERIFICATION: Uses all 5 layers of barrier certificate system.
        OPTIMIZATION: Caches results per (bug_type, variable, function).
        """
        
        # Check cache first
        cache_key = (bug.bug_type, bug.bug_variable, bug.crash_function)
        if cache_key in self._guard_cache:
            return self._guard_cache[cache_key]
        
        # Collect call chain summaries
        call_chain_summaries = []
        for func_name in bug.call_chain:
            func_summary = self.crash_summaries.get(func_name)
            if func_summary:
                call_chain_summaries.append(func_summary)
        
        crash_summary = self.crash_summaries.get(bug.crash_function)
        if not crash_summary:
            return False
        
        # If there are unguarded instances, don't suppress the bug
        if crash_summary.get_unguarded_count(bug.bug_type) > 0:
            self._guard_cache[cache_key] = False
            return False
        
        # Run context-aware verification
        verification_result = verify_bug_context_aware(
            bug_type=bug.bug_type,
            bug_variable=bug.bug_variable,
            crash_summary=crash_summary,
            call_chain_summaries=call_chain_summaries,
            code_object=None  # Would need function.__code__
        )
        
        self._guard_cache[cache_key] = verification_result.is_safe
        return verification_result.is_safe
    
    def verify_bugs_with_dse(
        self,
        bugs: Optional[List[InterproceduralBug]] = None,
        max_steps: int = 100,
        timeout_per_function: int = 5000,
    ) -> Tuple[List[InterproceduralBug], List[InterproceduralBug], List[InterproceduralBug]]:
        """
        Verify bugs using DSE with Z3-backed symbolic execution.
        
        This is the principled approach: use SymbolicVM to actually explore
        paths and check if the unsafe state is Z3-satisfiable.
        
        Args:
            bugs: List of bugs to verify. If None, uses self.bugs_found
            max_steps: Maximum DSE steps per function
            timeout_per_function: Z3 timeout in ms per function
        
        Returns:
            Tuple of (confirmed_bugs, refuted_bugs, unknown_bugs)
            - confirmed: DSE found a path triggering the bug
            - refuted: DSE exhaustively proved no path triggers the bug
            - unknown: DSE timed out or couldn't determine
        """
        from ..semantics.symbolic_vm import SymbolicVM
        from ..unsafe.registry import check_unsafe_regions
        import types
        
        if bugs is None:
            bugs = self.bugs_found
        
        confirmed = []
        refuted = []
        unknown = []
        
        # Group bugs by function to avoid redundant DSE
        bugs_by_function: Dict[str, List[InterproceduralBug]] = {}
        for bug in bugs:
            func_name = bug.crash_function
            if func_name not in bugs_by_function:
                bugs_by_function[func_name] = []
            bugs_by_function[func_name].append(bug)
        
        for func_name, func_bugs in bugs_by_function.items():
            # Get function code object
            func_info = self.call_graph.get_function(func_name)
            if not func_info:
                unknown.extend(func_bugs)
                continue
            
            try:
                # Compile to get code object
                with open(func_info.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    source = f.read()
                
                module_code = compile(source, str(func_info.file_path), 'exec')
                func_code = self._find_code_object(module_code, func_info.name, func_info.line_number)
                
                if not func_code:
                    unknown.extend(func_bugs)
                    continue
                
                # Run DSE
                vm = SymbolicVM()
                paths = vm.explore_bounded(func_code, max_steps=max_steps)
                
                # Check which bug types are actually reachable
                reachable_bug_types = set()
                for path in paths:
                    result = check_unsafe_regions(path.state, path.trace)
                    if result:
                        reachable_bug_types.add(result.get('bug_type'))
                
                # IMPORTANT: Security bugs require interprocedural taint tracking
                # that per-function DSE cannot capture. Only use DSE to verify
                # non-security bugs (NULL_PTR, BOUNDS, DIV_ZERO, etc.)
                from ..unsafe.registry import SECURITY_BUG_TYPES
                NON_SECURITY_BUGS = {'NULL_PTR', 'BOUNDS', 'DIV_ZERO', 'TYPE_CONFUSION', 
                                     'ASSERT_FAIL', 'INTEGER_OVERFLOW', 'FP_DOMAIN',
                                     'STACK_OVERFLOW', 'MEMORY_LEAK', 'ITERATOR_INVALID'}
                
                # Classify each bug
                for bug in func_bugs:
                    # Security bugs: DSE can't verify taint flow, keep as unknown
                    if bug.bug_type in SECURITY_BUG_TYPES:
                        unknown.append(bug)
                        continue
                    
                    if bug.bug_type in reachable_bug_types:
                        # DSE confirmed this bug type is reachable
                        bug.confidence = min(bug.confidence + 0.2, 1.0)  # Boost confidence
                        confirmed.append(bug)
                    elif bug.bug_type in NON_SECURITY_BUGS and len(paths) > 0:
                        # DSE explored paths but didn't find this non-security bug
                        # Could be refuted if DSE was complete, or unknown if bounded
                        if len(paths) < max_steps // 2:
                            # Likely explored all paths - refute
                            refuted.append(bug)
                        else:
                            # Bounded exploration - unknown
                            unknown.append(bug)
                    else:
                        unknown.append(bug)
                
            except Exception as e:
                # DSE failed - unknown status
                unknown.extend(func_bugs)
        
        return confirmed, refuted, unknown
    
    def _find_code_object(
        self,
        module_code: types.CodeType,
        func_name: str,
        line_number: int
    ) -> Optional[types.CodeType]:
        """Find a function's code object by name and line number."""
        import types
        for const in module_code.co_consts:
            if isinstance(const, types.CodeType):
                if const.co_name == func_name and const.co_firstlineno == line_number:
                    return const
                # Search nested
                nested = self._find_code_object(const, func_name, line_number)
                if nested:
                    return nested
        return None
    
    def find_all_bugs_with_dse_verification(
        self,
        max_dse_steps: int = 100,
        apply_fp_reduction: bool = True,
        apply_intent_filter: bool = True,
        intent_confidence: float = 0.7,
        root_path: Optional[Path] = None,
    ) -> List[InterproceduralBug]:
        """
        Find all bugs with DSE verification.
        
        This is the full pipeline:
        1. Summary-based bug detection (fast, may have FPs)
        2. DSE verification (slower, reduces FPs)
        3. Return only confirmed + unknown bugs (drop refuted)
        
        Args:
            max_dse_steps: Maximum DSE steps for verification
            apply_fp_reduction: Apply FP context adjustments
            apply_intent_filter: Apply intent-aware filtering (default: True)
            intent_confidence: Minimum confidence for intent filtering (default: 0.7)
            root_path: Project root path for intent analysis
        """
        # First pass: summary-based detection with intent filtering
        bugs = self.find_all_bugs(
            apply_fp_reduction=apply_fp_reduction,
            apply_intent_filter=apply_intent_filter,
            intent_confidence=intent_confidence,
            root_path=root_path,
        )
        
        # Second pass: DSE verification
        confirmed, refuted, unknown = self.verify_bugs_with_dse(bugs, max_steps=max_dse_steps)
        
        # Return confirmed bugs (high confidence) and unknown (conservative)
        # Refuted bugs are dropped as they're likely FPs
        return confirmed + unknown

    def _analyze_all_crash_bugs(self) -> None:
        """
        Analyze ALL functions for crash bugs, regardless of reachability.
        
        OPTIMIZED: Renamed to _analyze_crash_bugs_for_function and called from find_all_bugs.
        This method is kept for backwards compatibility but delegates to new batched version.
        """
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"[BUGS] crash_summaries has {len(self.crash_summaries)} functions")
        
        for func_name, crash_summary in self.crash_summaries.items():
            logger.info(f"[BUGS] Checking {func_name}: may_trigger={crash_summary.may_trigger}")
            if crash_summary.may_trigger:
                logger.info(f"[BUGS]   -> Analyzing {func_name}")
                self._analyze_crash_bugs_for_function(func_name, crash_summary)
    
    def _analyze_crash_bugs_for_function(self, func_name: str, crash_summary: CrashSummary) -> None:
        """
        Analyze a single function for crash bugs.
        
        OPTIMIZATION: Extracted from _analyze_all_crash_bugs for batching.
        """
        func_info = self.call_graph.get_function(func_name)
        call_chain = [func_name]
        self._check_direct_bugs(crash_summary, call_chain, func_info)
    
    def _apply_fp_context_adjustments(
        self,
        bugs: List[InterproceduralBug],
        min_confidence: float = 0.15,
    ) -> List[InterproceduralBug]:
        """
        Apply FP context adjustments to reduce false positives.
        
        Analyzes each bug's context (source types, file path, call chain)
        and adjusts confidence accordingly. Filters out low-confidence bugs.
        
        Args:
            bugs: List of bugs to process
            min_confidence: Minimum confidence to keep (default 0.40)
        
        Returns:
            Filtered list of bugs with adjusted confidence
        """
        from ..fp_context import (
            FPContextDetector,
            adjust_confidence_for_context,
        )
        
        detector = FPContextDetector()
        filtered_bugs = []
        
        for bug in bugs:
            # Extract file path from crash_location
            file_path = None
            if ':' in bug.crash_location:
                file_path = bug.crash_location.rsplit(':', 1)[0]
            
            # Get tainted sources from bug
            tainted_sources = list(bug.tainted_sources) if bug.tainted_sources else []
            
            # Also extract source info from reason string
            if 'from' in bug.reason.lower():
                # Extract source from patterns like "Tainted data from os.environ.get(...)"
                tainted_sources.append(bug.reason)
            
            # Detect contexts
            context_result = detector.detect_contexts(
                bug_type=bug.bug_type,
                tainted_sources=tainted_sources,
                file_path=file_path,
                call_chain=bug.call_chain,
                sink_function=bug.crash_function,
            )
            
            # Apply confidence adjustment
            original_confidence = bug.confidence
            adjusted_confidence = original_confidence * context_result.confidence_multiplier

            # Record as a (conditional) risk bound driven by context priors.
            # This is metadata only; reachability is unchanged.
            bug.risk_interval = RiskInterval(
                risk_lb=0.0,
                risk_ub=max(0.0, min(1.0, adjusted_confidence)),
                threat_model_id="fp_context_v1",
                evidence=context_result.reasons.copy(),
            )
            
            # Update bug's confidence
            bug.confidence = adjusted_confidence
            
            # Filter out low-confidence bugs
            if adjusted_confidence >= min_confidence:
                filtered_bugs.append(bug)
        
        return filtered_bugs
    
    def apply_intent_filtering(
        self,
        bugs: List[InterproceduralBug],
        min_confidence: float = 0.7,
        root_path: Optional[Path] = None,
    ) -> List[InterproceduralBug]:
        """
        Apply intent-aware filtering to reduce false positives.
        
        Uses semantic analysis to determine if bugs are:
        - Intentional (test code, example code, expected behavior)
        - Protected by guards (null checks, bounds checks)
        - In framework context (self parameters, request objects)
        
        Only reports bugs with high confidence of being unintentional.
        
        Args:
            bugs: List of bugs to filter
            min_confidence: Minimum confidence to consider as TP (default 0.7 = high confidence)
            root_path: Project root path for reading source code
        
        Returns:
            Filtered list containing only high-confidence true positives
        """
        from .intent_detector import create_intent_aware_filter
        from .ast_guard_analysis import SafetyAnalyzer
        
        bug_filter = create_intent_aware_filter(threshold=min_confidence)
        safety_analyzer = SafetyAnalyzer()
        
        filtered_bugs = []
        
        for bug in bugs:
            # Parse location
            location_parts = bug.crash_location.split(':')
            crash_file = ':'.join(location_parts[:-1]) if len(location_parts) > 1 else bug.crash_location
            crash_line = location_parts[-1] if len(location_parts) > 1 else None
            
            # Try to get source code
            source_code = None
            if root_path:
                full_path = root_path / crash_file.lstrip('/')
                if not full_path.exists():
                    full_path = root_path / crash_file
                if full_path.exists():
                    try:
                        source_code = full_path.read_text(encoding='utf-8', errors='ignore')
                    except Exception:
                        pass
            
            # Run intent analysis
            should_include, adjusted_conf, analysis = bug_filter.filter_bug(
                bug_type=bug.bug_type,
                file_path=crash_file,
                function_name=bug.crash_function,
                variable_name=bug.bug_variable,
                source_code=source_code,
                line_number=int(crash_line) if crash_line and crash_line.isdigit() else None,
                original_confidence=bug.confidence,
            )
            
            # Additional AST-based safety check if we have source
            # Skip for AST-scanner-sourced bugs — they are structural findings
            # where the pattern itself is the bug, not a missing crash guard.
            evidence = bug.reachability_pts.evidence if bug.reachability_pts else []
            is_ast_scan = any(ev.startswith('source=ast_') for ev in evidence)
            if source_code and should_include and not is_ast_scan:
                func_name = bug.crash_function.split('.')[-1] if '.' in bug.crash_function else bug.crash_function
                is_guarded, guard_conf, guard_reason = safety_analyzer.is_bug_guarded(
                    source=source_code,
                    function_name=func_name,
                    bug_type=bug.bug_type,
                    variable=bug.bug_variable,
                    line_number=int(crash_line) if crash_line and crash_line.isdigit() else None
                )
                
                if is_guarded and guard_conf > 0.7:
                    should_include = False
            
            if should_include:
                bug.confidence = adjusted_conf
                filtered_bugs.append(bug)
        
        return filtered_bugs

    def _deduplicate_bugs(self, bugs: List[InterproceduralBug]) -> List[InterproceduralBug]:
        """
        Deduplicate bugs by (file:line, bug_type).
        
        For each unique (location, bug_type) pair, keep only the bug with:
        1. Shortest call chain (most direct path to bug)
        2. Highest confidence if call chains are equal length
        
        Args:
            bugs: List of bugs to deduplicate
        
        Returns:
            Deduplicated list of bugs
        """
        from collections import defaultdict
        
        # Group bugs by (location, bug_type)
        bug_groups: Dict[Tuple[str, str], List[InterproceduralBug]] = defaultdict(list)
        
        for bug in bugs:
            key = (bug.crash_location, bug.bug_type)
            bug_groups[key].append(bug)
        
        # For each group, keep only the best bug
        deduplicated = []
        for (location, bug_type), group in bug_groups.items():
            # Sort by: (1) call chain length (shorter is better), (2) confidence (higher is better)
            best_bug = min(
                group,
                key=lambda b: (len(b.call_chain), -b.confidence)
            )
            deduplicated.append(best_bug)
        
        # Sort for stable output
        deduplicated.sort(key=lambda b: (b.crash_location, b.bug_type))
        
        return deduplicated
    
    def _analyze_from_entry(self, entry_func: str) -> None:
        """Analyze all paths from an entry point."""
        # BFS/DFS through call graph
        visited: Set[Tuple[str, ...]] = set()
        worklist: List[Tuple[List[str], Dict[str, ValueState]]] = [
            ([entry_func], {})
        ]
        
        while worklist:
            call_chain, context = worklist.pop()
            current_func = call_chain[-1]
            
            # Avoid infinite loops on recursion
            chain_key = tuple(call_chain)
            if chain_key in visited:
                continue
            visited.add(chain_key)
            
            # Limit call chain depth
            if len(call_chain) > 20:
                continue
            
            # Get summary for current function
            crash_summary = self.crash_summaries.get(current_func)
            taint_summary = self.taint_summaries.get(current_func)
            
            # Get function info for file path context
            func_info = self.call_graph.get_function(current_func)
            
            # Check for direct bugs in this function
            if crash_summary:
                self._check_direct_bugs(crash_summary, call_chain, func_info)
            
            # Check for taint/security bugs in this function
            if taint_summary:
                self._check_taint_bugs(taint_summary, call_chain, func_info)
            
            # NEW: Run intraprocedural analysis for this function
            # This detects bugs within the function body via dataflow
            self._check_intraprocedural_bugs(current_func, call_chain)
            if func_info:
                for call_site in func_info.call_sites:
                    callee = call_site.callee_name
                    
                    # Check for external/library function sinks (e.g., print, logging.*)
                    if callee and callee not in self.call_graph.functions:
                        self._check_external_sink(callee, call_site, call_chain)
                    
                    if callee and callee in self.reachable_functions:
                        # Check if this call may trigger bugs
                        callee_summary = self.crash_summaries.get(callee)
                        if callee_summary:
                            self._check_call_site_bugs(
                                call_chain, call_site, callee_summary, context
                            )
                        
                        # Continue analysis into callee
                        new_chain = call_chain + [callee]
                        worklist.append((new_chain, context.copy()))
    
    def _check_direct_bugs(
        self,
        summary: CrashSummary,
        call_chain: List[str],
        func_info: Optional['FunctionInfo'] = None,
    ) -> None:
        """Check for bugs directly triggered by a function."""
        import logging
        logger = logging.getLogger(__name__)
        from ..cfg.call_graph import FunctionInfo
        func_name = summary.qualified_name
        
        logger.info(f"[TRACKER] Analyzing {func_name} for direct bugs")
        
        # Build crash_location with file path if available
        if func_info:
            crash_location = f"{func_info.file_path}:{func_info.line_number}"
        else:
            crash_location = f"{summary.function_name}"
        
        for bug_type in summary.may_trigger:
            # Determine certainty based on bug type
            # NULL_PTR and BOUNDS have higher false positive rates due to
            # path infeasibility and unmodeled invariants
            if bug_type in ('NULL_PTR', 'BOUNDS'):
                certainty = 'POSSIBLE'  # Conservative: may-analysis, not must-analysis
            else:
                certainty = 'LIKELY'  # Direct triggers are likely for other bug types
            
            # Compute confidence for this error bug
            confidence = self._compute_confidence_for_error_bug(
                bug_type=bug_type,
                call_chain_length=len(call_chain),
                certainty=certainty,
            )
            
            # ITERATION 609: Reduce confidence for guarded bugs
            # If this bug type has guards (e.g., null checks, bounds checks),
            # the code has SOME protection, reducing the likelihood it's a real bug
            # ITERATION 610: Increased reduction - if ALL paths are guarded for this bug type,
            # it's very likely a false positive (e.g., attribute access on typed params)
            
            # SYMBOLIC VARIABLE: Extract the variable causing this bug
            # This is CRITICAL for Layers 2-5 verification to work!
            bug_variable = None
            
            # For DIV_ZERO: Check divisor_params
            if bug_type == 'DIV_ZERO' and summary.divisor_params:
                param_idx = next(iter(summary.divisor_params))
                bug_variable = f"param_{param_idx}"
            
            # For BOUNDS: Check index_params
            elif bug_type == 'BOUNDS' and summary.index_params:
                param_idx = next(iter(summary.index_params.keys()))
                bug_variable = f"param_{param_idx}"
            
            # For NULL_PTR: Check param_bug_propagation or preconditions
            elif bug_type in ('NULL_PTR', 'ATTRIBUTE_ERROR'):
                # Check null_ptr_target_vars first (e.g., 'self.cell' for
                # chained access self.cell.trainable_weights).  This avoids
                # misattribution to 'self' which the intent filter suppresses.
                if hasattr(summary, 'null_ptr_target_vars') and summary.null_ptr_target_vars:
                    bug_variable = next(iter(summary.null_ptr_target_vars))
                
                # Check param_bug_propagation
                if bug_variable is None:
                    for param_idx, bug_types in summary.param_bug_propagation.items():
                        if bug_type in bug_types:
                            bug_variable = f"param_{param_idx}"
                            break
                
                # Fallback: check preconditions
                if bug_variable is None:
                    for precond in summary.preconditions:
                        if PRECONDITION_TO_BUG.get(precond.condition_type) == bug_type:
                            bug_variable = f"param_{precond.param_index}"
                            break
            
            # Generic fallback: check preconditions for any bug type
            if bug_variable is None:
                for precond in summary.preconditions:
                    if PRECONDITION_TO_BUG.get(precond.condition_type) == bug_type:
                        bug_variable = f"param_{precond.param_index}"
                        break
            
            # Last resort: check guard_type_to_vars for clues
            if bug_variable is None:
                from .interprocedural_guards import BUG_TYPE_TO_GUARD_TYPES
                for guard_type in BUG_TYPE_TO_GUARD_TYPES.get(bug_type, set()):
                    guarded_vars = summary.get_all_guarded_variables(guard_type)
                    if guarded_vars:
                        bug_variable = next(iter(guarded_vars))
                        break
            
            # Ultimate fallback: use generic variable based on bug type
            if bug_variable is None:
                if bug_type == 'DIV_ZERO':
                    bug_variable = 'divisor'
                elif bug_type in ('NULL_PTR', 'ATTRIBUTE_ERROR'):
                    bug_variable = 'obj'
                elif bug_type == 'BOUNDS':
                    bug_variable = 'index'
                else:
                    bug_variable = 'var'
            
            # EXTREME CONTEXT-AWARE VERIFICATION: ALL bugs now go through 25-paper verification
            # Layer 0 (fast barriers) will catch easy FPs in O(n) time before expensive layers
            
            # Collect call chain summaries for interprocedural analysis
            call_chain_summaries = []
            for func_name in call_chain:
                func_summary = self.crash_summaries.get(func_name)
                if func_summary:
                    call_chain_summaries.append(func_summary)
            
            # Run EXTREME context-aware verification (Layer 0 + Layers 1-5)
            # But ONLY for bugs that are marked as guarded - unguarded bugs should be reported!
            # If may_trigger contains the bug but guarded_bugs doesn't, it's definitely unguarded
            # If a bug has BOTH guarded and unguarded instances, treat as unguarded (has real risk)
            has_unguarded = summary.get_unguarded_count(bug_type) > 0
            if bug_type in summary.guarded_bugs and not has_unguarded:
                # Bug is guarded - this means guards were detected in the bytecode
                # We trust the guard detection and skip this bug unless verification explicitly
                # proves it's still reachable (which would be a guard bypass bug)
                verification_result = verify_bug_extreme(
                    bug_type=bug_type,
                    bug_variable=bug_variable,
                    crash_summary=summary,
                    call_chain_summaries=call_chain_summaries,
                    code_object=None,  # Would need actual code object
                    source_code=None   # Would need source code
                )
                
                # If guards are present, only report if verification explicitly says it's UNSAFE
                # This gives strong weight to guards - they're presumed effective unless proven otherwise
                if verification_result.is_safe or verification_result.verdict == 'UNKNOWN':
                    # Guard detected and either proven safe or unknown - skip this bug
                    logger.info(f"[TRACKER] Guarded and safe/unknown: {bug_type} on {bug_variable} - skipping")
                    continue
                else:
                    # Verification found the guard is bypassable - keep as potential bug
                    logger.warning(f"[TRACKER] Guard bypass detected: {bug_type} on {bug_variable}")
            else:
                # Bug is NOT guarded — still run quick_barrier_precheck to catch
                # obvious FPs (e.g., DIV_ZERO inside __len__, safe variable names).
                from ..barriers.quick_precheck import quick_barrier_precheck
                is_safe_quick, conf_quick, reason_quick = quick_barrier_precheck(
                    bug_type, bug_variable or '', summary
                )
                if is_safe_quick and conf_quick >= 0.85:
                    logger.info(f"[TRACKER] Quick precheck suppressed unguarded {bug_type}: {reason_quick}")
                    continue
                logger.debug(f"[TRACKER] Unguarded bug: {bug_type} on {bug_variable} - keeping")
            
            # bug_type is now a string (e.g., 'DIV_ZERO')
            bug = InterproceduralBug(
                bug_type=bug_type,
                crash_function=func_name,
                crash_location=crash_location,
                call_chain=call_chain.copy(),
                reason=f"Function may trigger {bug_type}" + (" (guarded)" if bug_type in summary.guarded_bugs else ""),
                confidence=confidence,
                reachability_pts=ReachabilityIntervalPTS.unknown(
                    evidence=["source=crash_summary", "kind=may_trigger"]
                ),
                bug_variable=bug_variable,
            )
            
            # Check for relevant exceptions
            for exc, mapped_bug in EXCEPTION_TO_BUG.items():
                if mapped_bug == bug_type and exc in summary.may_raise:
                    bug.exception_type = exc
                    break
            
            self.bugs_found.append(bug)
        
        # Check transitive bugs from callees: if a callee may crash with a bug
        # type, the caller is also at risk unless it catches the exception.
        # Only report transitive bugs when the caller's OWN direct bug of the
        # same type is guarded — this captures the pattern where a callee
        # crashes inside a guarded context (e.g., factory call inside isdir()
        # check, but factory crashes internally before the caller's None guard).
        for bug_type in summary.transitive_bugs:
            if bug_type not in summary.may_trigger:
                # Caller has no direct bug of this type — the callee's bug
                # will be reported at the callee level, so skip here
                continue
            if bug_type not in summary.guarded_bugs:
                # Caller has an unguarded direct bug — already reported above
                continue
            # Caller's direct bug is guarded, but callee crashes BEFORE the guard
            certainty = 'POSSIBLE'
            confidence = self._compute_confidence_for_error_bug(
                bug_type=bug_type,
                call_chain_length=len(call_chain),
                certainty=certainty,
            )
            
            bug = InterproceduralBug(
                bug_type=bug_type,
                crash_function=func_name,
                crash_location=crash_location,
                call_chain=call_chain.copy(),
                reason=f"Callee may trigger {bug_type} (transitive from called function)",
                confidence=confidence,
                reachability_pts=ReachabilityIntervalPTS.unknown(
                    evidence=["source=crash_summary", "kind=transitive_bug"]
                ),
                bug_variable='callee',
            )
            self.bugs_found.append(bug)
    
    def _check_taint_bugs(
        self,
        taint_summary: 'TaintSummary',
        call_chain: List[str],
        func_info: Optional['FunctionInfo'] = None,
    ) -> None:
        """Check for taint/security bugs in a function based on its taint summary."""
        from ..z3model.taint_lattice import CODEQL_BUG_TYPES
        from ..contracts.security_lattice import get_sink_contracts
        from ..cfg.call_graph import FunctionInfo
        import os
        
        DEBUG = os.environ.get('DEBUG_TAINT_SUMMARY') == '1'
        
        func_name = taint_summary.function_name
        
        # Build crash_location with file path if available
        if func_info:
            crash_location = f"{func_info.file_path}:{func_info.line_number}"
        else:
            crash_location = f"{func_name}"
        
        # Check if this function is a sink (may have multiple sink types)
        if taint_summary.dependency.is_sink and taint_summary.dependency.sink_types:
            # Iterate over all sink types this function has
            for sink_type in taint_summary.dependency.sink_types:
                # sink_type is stored as an int in summaries; normalize for comparisons.
                from ..z3model.taint_lattice import SinkType as SinkTypeEnum
                sink_type_int = sink_type.value if hasattr(sink_type, "value") else int(sink_type)
                try:
                    sink_type_enum = SinkTypeEnum(sink_type_int)
                except Exception:
                    continue

                # ITERATION 604: Check if this sink has context-dependent safety
                # ITERATION 605: Check ALL contracts for this sink_type, not just the function
                # For sinks with parameterized_check, shell_check, etc., the summary
                # cannot determine safety without call-site context. Skip summary-based
                # reporting and let intraprocedural analysis handle it.
                
                # Get all sink contracts for this sink_type across all functions
                from a3_python.contracts.security_lattice import get_all_sink_contracts
                all_sink_contracts = get_all_sink_contracts()
                
                if DEBUG:
                    print(f"[TAINT_SUMMARY] _check_taint_bugs for {func_name}, sink_type={sink_type}")
                    print(f"[TAINT_SUMMARY]   Checking contracts for sink_type {sink_type}")
                
                # Check if ANY contract for this sink_type has context-dependent checks
                has_context_dependent_check = any(
                    (c.parameterized_check or c.shell_check or c.loader_check or c.entity_check)
                    for c in all_sink_contracts if int(getattr(c.sink_type, "value", c.sink_type)) == sink_type_int
                )
                
                if DEBUG:
                    print(f"[TAINT_SUMMARY]   has_context_dependent_check={has_context_dependent_check}")
                
                if has_context_dependent_check:
                    # Skip summary-based reporting for context-dependent sinks
                    # The intraprocedural analysis will check these properly
                    if DEBUG:
                        print(f"[TAINT_SUMMARY]   Skipping summary-based reporting (context-dependent sink)")
                    continue
                
                # Map sink_type to security bug types
                for bug_name, bug_def in CODEQL_BUG_TYPES.items():
                    if bug_def.sink_type == sink_type_enum:
                        # ITERATION 607: Check if ANY parameters flow to this sink
                        # If params_to_sinks is empty or doesn't have this sink_type,
                        # then no parameters flow unsanitized to this sink -> no bug
                        if sink_type_int not in taint_summary.dependency.params_to_sinks:
                            # No parameters flow to this sink (empty or all sanitized)
                            if DEBUG:
                                print(f"[TAINT_SUMMARY]   Skipping {bug_name}: no params flow to sink {sink_type_enum.name}")
                            continue
                        
                        param_indices = taint_summary.dependency.params_to_sinks[sink_type_int]
                        if not param_indices:
                            # Empty set - all parameters are sanitized for this sink
                            if DEBUG:
                                print(f"[TAINT_SUMMARY]   Skipping {bug_name}: params sanitized for sink {sink_type_enum.name}")
                            continue
                        
                        # ITERATION 497: For σ-only bugs, check if sensitive data actually reaches the sink
                        is_sigma_only_bug = bug_def.checks_sigma and not bug_def.checks_tau
                        
                        if is_sigma_only_bug:
                            # Check if we have evidence of sensitive data reaching this sink
                            has_sigma_evidence = False
                            
                            # Check if this sink is called with sensitive parameters
                            # (e.g., does the function have σ-tainted params that flow to this sink)
                            for param_idx in param_indices:
                                if taint_summary.sigma_contribution.get(param_idx, False):
                                    # Found a sensitive parameter flowing to this sink!
                                    has_sigma_evidence = True
                                    break

                            # Virtual index -1 means an internal taint source flows to this sink.
                            # For σ-only bugs, accept this as sensitive evidence if the function
                            # itself introduces a sensitive source (e.g., getpass.getpass()).
                            if not has_sigma_evidence and (-1 in param_indices):
                                try:
                                    from ..z3model.taint_lattice import SENSITIVE_SOURCES_MASK
                                    st = taint_summary.dependency.source_type
                                    if st is not None and ((1 << int(st)) & SENSITIVE_SOURCES_MASK) != 0:
                                        has_sigma_evidence = True
                                except Exception:
                                    pass
                            
                            if not has_sigma_evidence:
                                # No evidence of sensitive data reaching this sink
                                # Skip to avoid false positive
                                if DEBUG:
                                    print(f"[TAINT_SUMMARY]   Skipping {bug_name}: no sensitive data reaches sink")
                                continue
                        
                        # Compute confidence for this security bug
                        confidence = self._compute_confidence_for_security_bug(
                            bug_type=bug_name,
                            sink_type=sink_type,
                            call_chain_length=len(call_chain),
                            is_internal_sink=True,  # This is in analyzed code
                        )
                        
                        # ITERATION 483: Reduce confidence for σ-only bugs at summary level
                        # The intraprocedural analyzer will provide precise σ tracking
                        if is_sigma_only_bug:
                            confidence *= 0.5  # Lower confidence, may be refined by intraprocedural pass
                        
                        # This function is a sink for this bug type
                        bug = InterproceduralBug(
                            bug_type=bug_name,
                            crash_function=func_name,
                            crash_location=crash_location,
                            call_chain=call_chain.copy(),
                            reason=f"Function is a {bug_name} sink (sink_type={sink_type_enum.name})",
                            confidence=confidence,
                            reachability_pts=ReachabilityIntervalPTS.unknown(
                                evidence=["source=taint_summary", "kind=sink_summary"]
                            ),
                        )
                        self.bugs_found.append(bug)
    
    def _check_external_sink(
        self,
        callee_name: str,
        call_site: 'CallSite',
        call_chain: List[str],
    ) -> None:
        """
        Check if an external function is a security sink.
        
        ITERATION 451: Now properly handles σ-only bugs (CLEARTEXT_LOGGING, CLEARTEXT_STORAGE)
        by checking if the caller's taint summary shows sensitive data flowing to the sink.
        
        ITERATION 604: Skip context-dependent sinks (parameterized queries, shell=False, etc.)
        These require call-site analysis which we can't do from summaries alone.
        """
        from ..contracts.security_lattice import get_sink_contracts
        from ..z3model.taint_lattice import CODEQL_BUG_TYPES
        import os
        
        DEBUG = os.environ.get('DEBUG_EXTERNAL_SINK') == '1'
        
        # Check if this function has a sink contract
        sink_contracts = get_sink_contracts(callee_name)
        
        if DEBUG and sink_contracts:
            print(f"[EXTERNAL_SINK] _check_external_sink for {callee_name}")
            print(f"[EXTERNAL_SINK]   Found {len(sink_contracts)} contracts")
            print(f"[EXTERNAL_SINK]   call_chain: {call_chain}")
        
        # Get the caller's taint summary to check σ tracking
        caller_name = call_chain[-1]
        caller_summary = self.taint_summaries.get(caller_name)
        
        for contract in sink_contracts:
            # ITERATION 604: Skip context-dependent sinks
            # These sinks (parameterized queries, shell=False, etc.) require call-site
            # analysis to determine safety. Summary-based interprocedural analysis
            # cannot determine this context, so we skip them here and let
            # intraprocedural analysis handle them.
            if contract.parameterized_check or contract.shell_check or contract.loader_check or contract.entity_check:
                if DEBUG:
                    print(f"[EXTERNAL_SINK]   Skipping context-dependent sink: {contract.function_id}")
                continue
            
            # This is a known sink - report as potential security bug
            sink_type = contract.sink_type
            # This is a known sink - report as potential security bug
            sink_type = contract.sink_type
            
            # Find associated bug types
            for bug_name, bug_def in CODEQL_BUG_TYPES.items():
                if bug_def.sink_type == sink_type:
                    # ITERATION 607: Check if ANY parameters flow to this sink
                    # Only report if tainted parameters actually reach this external sink
                    if caller_summary:
                        # Check if this sink type has any parameters flowing to it
                        if sink_type not in caller_summary.dependency.params_to_sinks:
                            # No parameters flow to this sink type
                            if DEBUG:
                                print(f"[EXTERNAL_SINK]   Skipping {bug_name}: no params flow to sink {sink_type.name}")
                            continue
                        
                        param_indices = caller_summary.dependency.params_to_sinks[sink_type]
                        if not param_indices:
                            # Empty set - all parameters are sanitized for this sink
                            if DEBUG:
                                print(f"[EXTERNAL_SINK]   Skipping {bug_name}: params sanitized for sink {sink_type.name}")
                            continue
                    
                    # ITERATION 451: Handle σ-only checks with interprocedural σ tracking
                    if bug_def.checks_sigma and not bug_def.checks_tau:
                        # This is a σ-only check (e.g., CLEARTEXT_LOGGING, CLEARTEXT_STORAGE)
                        # Check if we have evidence of sensitive data reaching this sink
                        has_sigma_evidence = False
                        
                        if caller_summary:
                            # Check if sensitive data flows to this external sink call
                            # The call_site would need to be analyzed to determine which params
                            # are used as arguments. For now, check if ANY parameter with σ
                            # flows to a sink of this type in the caller.
                            param_indices = caller_summary.dependency.params_to_sinks.get(sink_type, set())
                            for param_idx in param_indices:
                                if caller_summary.sigma_contribution.get(param_idx, False):
                                    # Found a sensitive parameter flowing to this sink!
                                    has_sigma_evidence = True
                                    break
                        
                        if not has_sigma_evidence:
                            # No evidence of sensitive data reaching this sink
                            # Skip to avoid false positive
                            if DEBUG:
                                print(f"[EXTERNAL_SINK]   Skipping {bug_name}: no sensitive data reaches sink")
                            continue
                    
                    # Compute confidence for external sink
                    confidence = self._compute_confidence_for_security_bug(
                        bug_type=bug_name,
                        sink_type=sink_type,
                        call_chain_length=len(call_chain),
                        is_internal_sink=False,  # External/library sink
                    )
                    
                    bug = InterproceduralBug(
                        bug_type=bug_name,
                        crash_function=call_chain[-1],
                        crash_location=f"{call_site.file_path}:{call_site.line_number}",
                        call_chain=call_chain.copy(),
                        reason=f"Call to {callee_name} at {bug_name} sink (sink_type={sink_type.name})",
                        confidence=confidence,
                        reachability_pts=ReachabilityIntervalPTS.unknown(
                            evidence=["source=external_sink_summary", f"callee={callee_name}"]
                        ),
                    )
                    self.bugs_found.append(bug)
    
    def _check_intraprocedural_bugs(
        self,
        func_name: str,
        call_chain: List[str],
    ) -> None:
        """
        Run intraprocedural taint analysis on a function.
        
        This detects bugs within the function body via detailed dataflow analysis,
        complementing the summary-based interprocedural analysis.
        """
        # Check cache first
        if func_name in self._intraprocedural_bugs:
            bugs = self._intraprocedural_bugs[func_name]
        else:
            # Get function info
            func_info = self.call_graph.get_function(func_name)
            if not func_info or not func_info.code_object:
                return
            
            # ITERATION 518: Get import aliases for this file
            import_aliases = self._get_import_aliases_for_file(func_info.file_path)
            
            # Run intraprocedural analysis
            try:
                analyzer = IntraproceduralTaintAnalyzer(
                    code_obj=func_info.code_object,
                    function_name=func_name,
                    file_path=str(func_info.file_path),
                    import_aliases=import_aliases,
                )
                bugs = analyzer.analyze()
                self._intraprocedural_bugs[func_name] = bugs
            except Exception as e:
                # Gracefully handle analysis failures
                print(f"Warning: Intraprocedural analysis failed for {func_name}: {e}")
                self._intraprocedural_bugs[func_name] = []
                return
        
        # Convert intraprocedural bugs to interprocedural bugs with call chain
        for intra_bug in bugs:
            # Create interprocedural bug with full call chain
            inter_bug = InterproceduralBug(
                bug_type=intra_bug.bug_type,
                crash_function=func_name,
                crash_location=f"{intra_bug.file_path}:{intra_bug.line_number}",
                call_chain=call_chain.copy(),
                reason=intra_bug.reason,
                confidence=intra_bug.confidence,
                inferred_source=intra_bug.inferred_source,
                reachability_pts=ReachabilityIntervalPTS.unknown(
                    evidence=["source=intraprocedural_taint"]
                ),
            )
            self.bugs_found.append(inter_bug)
    
    def _check_call_site_bugs(
        self,
        call_chain: List[str],
        call_site: CallSite,
        callee_summary: CrashSummary,
        context: Dict[str, ValueState],
    ) -> None:
        """Check for bugs at a specific call site."""
        caller = call_chain[-1]
        callee = callee_summary.qualified_name
        
        # Check precondition violations
        for precond in callee_summary.preconditions:
            # For each precondition, check if caller may violate it
            bug = self._check_precondition(
                precond, call_chain, call_site, callee_summary, context
            )
            if bug:
                self.bugs_found.append(bug)
        
        # Check for unhandled exceptions from callee
        caller_summary = self.crash_summaries.get(caller)
        if caller_summary:
            # Exceptions raised by callee that propagate up
            for exc in callee_summary.may_raise:
                if exc in EXCEPTION_TO_BUG:
                    bug_type = EXCEPTION_TO_BUG[exc]  # Now returns string
                    
                    # Compute confidence for exception propagation
                    confidence = self._compute_confidence_for_error_bug(
                        bug_type=bug_type,
                        call_chain_length=len(call_chain) + 1,
                        certainty='POSSIBLE',  # May be caught
                    )
                    
                    # ITERATION 610: Reduce confidence if this exception comes from a guarded operation
                    # If the callee has guarded_bugs for this type, the exception is likely
                    # from controlled/expected code paths, not actual bugs
                    if bug_type in callee_summary.guarded_bugs:
                        confidence *= 0.3  # Same reduction as direct guarded bugs
                    
                    bug = InterproceduralBug(
                        bug_type=bug_type,
                        crash_function=callee,
                        crash_location=f"{call_site.file_path}:{call_site.line_number}",
                        call_chain=call_chain + [callee],
                        reason=f"Call to {callee} may raise {exc.name}",
                        exception_type=exc,
                        confidence=confidence,
                    )
                    self.bugs_found.append(bug)
    
    def _check_precondition(
        self,
        precond: Precondition,
        call_chain: List[str],
        call_site: CallSite,
        callee_summary: CrashSummary,
        context: Dict[str, ValueState],
    ) -> Optional[InterproceduralBug]:
        """Check if a precondition may be violated at a call site."""
        callee = callee_summary.qualified_name
        
        # Use PRECONDITION_TO_BUG from crash_summaries (now returns strings)
        bug_type = PRECONDITION_TO_BUG.get(precond.condition_type, 'PANIC')
        
        # Check if we have arg info
        arg_idx = precond.param_index
        
        # Compute confidence for precondition violation
        confidence = self._compute_confidence_for_error_bug(
            bug_type=bug_type,
            call_chain_length=len(call_chain) + 1,
            certainty='POSSIBLE',  # Preconditions are uncertain
        )
        
        # Attach stochastic risk bound (metadata only)
        arg_state = None
        if context and precond.param_index is not None:
            arg_state = context.get(f"arg{precond.param_index}")
        risk_interval = risk_interval_for_precondition(precond, arg_state)
        
        # SYMBOLIC VARIABLE: Track which variable causes this bug
        # For precondition violations, it's the parameter that was passed
        bug_variable = f"param_{arg_idx}"

        # Create bug report
        return InterproceduralBug(
            bug_type=bug_type,
            crash_function=callee,
            crash_location=f"{call_site.file_path}:{call_site.line_number}",
            call_chain=call_chain + [callee],
            reason=f"Argument {arg_idx} may violate {precond}",
            violated_precondition=precond,
            relevant_args=[arg_idx],
            confidence=confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=["source=precondition_check", f"precond={precond.condition_type.name}"]
            ),
            risk_interval=risk_interval,
            bug_variable=bug_variable,
        )
    
    # ========================================================================
    # QUERY INTERFACE
    # ========================================================================
    
    def get_bugs_by_type(self, bug_type: str) -> List[InterproceduralBug]:
        """Get all bugs of a specific type (by string name)."""
        return [b for b in self.bugs_found if b.bug_type == bug_type]
    
    def get_bugs_in_function(self, func_name: str) -> List[InterproceduralBug]:
        """Get all bugs in a specific function."""
        return [b for b in self.bugs_found if b.crash_function == func_name]
    
    def get_security_bugs(self) -> List[InterproceduralBug]:
        """Get all security-related bugs."""
        security_types = {
            'SQL_INJECTION', 'COMMAND_INJECTION', 'CODE_INJECTION',
            'PATH_INJECTION', 'LDAP_INJECTION', 'XPATH_INJECTION',
            'NOSQL_INJECTION', 'REGEX_INJECTION', 'URL_REDIRECT',
            'HEADER_INJECTION', 'COOKIE_INJECTION', 'REFLECTED_XSS',
            'SSRF', 'UNSAFE_DESERIALIZATION', 'XXE',
            'CLEARTEXT_LOGGING', 'CLEARTEXT_STORAGE',
        }
        return [b for b in self.bugs_found if b.bug_type in security_types]
    
    def get_crash_bugs(self) -> List[InterproceduralBug]:
        """Get all crash-inducing bugs."""
        crash_types = {
            'NULL_PTR', 'BOUNDS', 'DIV_ZERO',
            'TYPE_CONFUSION', 'ASSERT_FAIL', 'PANIC',
            'STACK_OVERFLOW', 'INTEGER_OVERFLOW', 'FP_DOMAIN',
        }
        return [b for b in self.bugs_found if b.bug_type in crash_types]
    
    def get_high_confidence_bugs(self, threshold: float = 0.7) -> List[InterproceduralBug]:
        """Get bugs with confidence above threshold."""
        return [b for b in self.bugs_found if b.confidence >= threshold]
    
    def summary_report(self) -> str:
        """Generate a summary report of all found bugs."""
        if not self.analyzed:
            return "Analysis not yet run. Call find_all_bugs() first."
        
        lines = [
            "=" * 60,
            "INTERPROCEDURAL BUG ANALYSIS REPORT",
            "=" * 60,
            f"Entry points analyzed: {len(self.entry_points)}",
            f"Reachable functions: {len(self.reachable_functions)}",
            f"Total bugs found: {len(self.bugs_found)}",
            "",
            "BUGS BY TYPE:",
            "-" * 40,
        ]
        
        # Count by type (bug_type is now a string)
        type_counts: Dict[str, int] = {}
        for bug in self.bugs_found:
            type_counts[bug.bug_type] = type_counts.get(bug.bug_type, 0) + 1
        
        for bug_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  {bug_type}: {count}")
        
        lines.extend([
            "",
            "HIGH CONFIDENCE BUGS (>= 0.7):",
            "-" * 40,
        ])
        
        for bug in self.get_high_confidence_bugs():
            lines.append(f"  [{bug.confidence:.1f}] {bug}")
        
        return "\n".join(lines)


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def analyze_project_for_all_bugs(root_path: Path) -> Tuple[List[InterproceduralBug], str]:
    """
    Analyze a project for ALL bug types.
    
    Returns (list of bugs, summary report).
    """
    tracker = InterproceduralBugTracker.from_project(root_path)
    bugs = tracker.find_all_bugs()

    # AST-based encoding bug detection (hardcoded ASCII, open without encoding)
    from .encoding_bug_detector import scan_project_for_encoding_bugs
    encoding_bugs = scan_project_for_encoding_bugs(root_path)
    for eb in encoding_bugs:
        if eb.pattern == 'open_read_without_encoding_data_parse':
            enc_bug_type = 'ASSERT_FAIL'
        else:
            enc_bug_type = 'UNICODE_ERROR'
        bugs.append(InterproceduralBug(
            bug_type=enc_bug_type,
            crash_function=eb.function_name,
            crash_location=f"{eb.file_path}:{eb.line_number}",
            call_chain=[eb.function_name],
            reason=eb.reason,
            confidence=eb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_encoding_scan", f"pattern={eb.pattern}"]
            ),
            bug_variable='encoding',
        ))

    # AST-based uncaught URL/network exception detection
    from .uncaught_url_exception_detector import scan_file_for_uncaught_url_exception_bugs
    for py_file in root_path.rglob('*.py'):
        for ub in scan_file_for_uncaught_url_exception_bugs(py_file):
            bugs.append(InterproceduralBug(
                bug_type='ASSERT_FAIL',
                crash_function=ub.function_name,
                crash_location=f"{ub.file_path}:{ub.line_number}",
                call_chain=[ub.function_name],
                reason=ub.reason,
                confidence=ub.confidence,
                reachability_pts=ReachabilityIntervalPTS.unknown(
                    evidence=[f"source=ast_uncaught_url_exception_scan", f"pattern={ub.pattern}"]
                ),
                bug_variable=ub.variable,
            ))

    # AST-based format string injection detection (dynamic dict key from user input)
    from .format_string_injection_detector import scan_project_for_format_string_injection_bugs
    fmt_bugs = scan_project_for_format_string_injection_bugs(root_path)
    for fb in fmt_bugs:
        bugs.append(InterproceduralBug(
            bug_type='SQL_INJECTION',
            crash_function=fb.function_name,
            crash_location=f"{fb.file_path}:{fb.line_number}",
            call_chain=[fb.function_name],
            reason=fb.reason,
            confidence=fb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_format_string_injection_scan", f"pattern={fb.pattern}"]
            ),
            bug_variable=fb.variable,
        ))

    # AST-based missing HTTP session config propagation detection (httpie#2)
    from .missing_session_config_detector import scan_file_for_missing_session_config_bugs
    for py_file in root_path.rglob('*.py'):
        for sb in scan_file_for_missing_session_config_bugs(py_file):
            bugs.append(InterproceduralBug(
                bug_type='ASSERT_FAIL',
                crash_function=sb.function_name,
                crash_location=f"{sb.file_path}:{sb.line_number}",
                call_chain=[sb.function_name],
                reason=sb.reason,
                confidence=sb.confidence,
                reachability_pts=ReachabilityIntervalPTS.unknown(
                    evidence=[f"source=ast_missing_session_config_scan", f"pattern={sb.pattern}"]
                ),
                bug_variable=sb.variable,
            ))

    report = tracker.summary_report()
    return bugs, report


def analyze_file_for_bugs(file_path: Path) -> List[InterproceduralBug]:
    """Analyze a single file for bugs."""
    # Create minimal tracker for single file
    from ..cfg.call_graph import build_call_graph_from_file
    from ..contracts.security_lattice import (
        get_source_contracts_for_summaries,
        get_sink_contracts_for_summaries,
        get_sanitizer_contracts_for_summaries,
        init_security_contracts,
    )
    
    # Initialize contracts (idempotent)
    init_security_contracts()
    
    call_graph = build_call_graph_from_file(file_path)
    
    # All functions are entry points for single-file analysis
    entry_points = set(call_graph.functions.keys())
    reachable = entry_points.copy()
    
    # Load security contracts for library functions
    source_contracts = get_source_contracts_for_summaries()
    sink_contracts = get_sink_contracts_for_summaries()
    sanitizer_contracts = get_sanitizer_contracts_for_summaries()
    
    # Compute summaries (using bytecode-level analysis)
    crash_computer = BytecodeCrashSummaryComputer(call_graph)
    crash_summaries = crash_computer.compute_all()
    
    taint_computer = SummaryComputer(
        call_graph,
        source_contracts=source_contracts,
        sink_contracts=sink_contracts,
        sanitizer_contracts=sanitizer_contracts,
    )
    taint_summaries = taint_computer.compute_all()
    
    combined = compute_all_bug_summaries(call_graph, taint_summaries)
    
    tracker = InterproceduralBugTracker(
        call_graph=call_graph,
        entry_points=entry_points,
        reachable_functions=reachable,
        taint_summaries=taint_summaries,
        crash_summaries=crash_summaries,
        combined_summaries=combined,
    )
    
    bugs = tracker.find_all_bugs()

    # AST-based encoding bug detection (hardcoded ASCII, open without encoding)
    from .encoding_bug_detector import scan_file_for_encoding_bugs
    encoding_bugs = scan_file_for_encoding_bugs(file_path)
    for eb in encoding_bugs:
        if eb.pattern == 'open_read_without_encoding_data_parse':
            enc_bug_type = 'ASSERT_FAIL'
        else:
            enc_bug_type = 'UNICODE_ERROR'
        bugs.append(InterproceduralBug(
            bug_type=enc_bug_type,
            crash_function=eb.function_name,
            crash_location=f"{eb.file_path}:{eb.line_number}",
            call_chain=[eb.function_name],
            reason=eb.reason,
            confidence=eb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_encoding_scan", f"pattern={eb.pattern}"]
            ),
            bug_variable='encoding',
        ))

    # AST-based non-deterministic iteration detection (unsorted dict join)
    from .nondeterminism_detector import scan_file_for_nondeterminism_bugs
    nondet_bugs = scan_file_for_nondeterminism_bugs(file_path)
    for nb in nondet_bugs:
        # unsorted_join on dict-derived data is TYPE_CONFUSION:
        # str.join() requires all-string elements, dict keys may not be strings
        bug_type = 'TYPE_CONFUSION' if nb.pattern == 'unsorted_join' else 'ORDER_VIOLATION'
        bugs.append(InterproceduralBug(
            bug_type=bug_type,
            crash_function=nb.function_name,
            crash_location=f"{nb.file_path}:{nb.line_number}",
            call_chain=[nb.function_name],
            reason=nb.reason,
            confidence=nb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_nondeterminism_scan", f"pattern={nb.pattern}"]
            ),
            bug_variable=nb.collection_var,
        ))

    # AST + Z3 stale counter detection (counter update after comparison)
    from .stale_counter_detector import scan_file_for_stale_counter_bugs
    stale_bugs = scan_file_for_stale_counter_bugs(file_path)
    for sb in stale_bugs:
        bugs.append(InterproceduralBug(
            bug_type='STALE_VALUE',
            crash_function=sb.function_name,
            crash_location=f"{sb.file_path}:{sb.line_number}",
            call_chain=[sb.function_name],
            reason=sb.reason,
            confidence=sb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_stale_counter_scan", f"pattern={sb.pattern}"]
            ),
            bug_variable=sb.variable,
        ))

    # AST-based argument mismatch / misscoped control flow detection
    from .argument_mismatch_detector import scan_file_for_argument_mismatch_bugs
    argmatch_bugs = scan_file_for_argument_mismatch_bugs(file_path)
    for ab in argmatch_bugs:
        bug_type = 'PRECONDITION_VIOLATION' if ab.pattern == 'wrong_argument' else 'ORDER_VIOLATION'
        bugs.append(InterproceduralBug(
            bug_type=bug_type,
            crash_function=ab.function_name,
            crash_location=f"{ab.file_path}:{ab.line_number}",
            call_chain=[ab.function_name],
            reason=ab.reason,
            confidence=ab.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_argument_mismatch_scan", f"pattern={ab.pattern}"]
            ),
            bug_variable=ab.variable,
        ))

    # AST-based inconsistent comparison operator detection
    from .comparison_operator_detector import scan_file_for_comparison_operator_bugs
    cmp_bugs = scan_file_for_comparison_operator_bugs(file_path)
    for cb in cmp_bugs:
        bugs.append(InterproceduralBug(
            bug_type='ASSERT_FAIL',
            crash_function=cb.function_name,
            crash_location=f"{cb.file_path}:{cb.line_number}",
            call_chain=[cb.function_name],
            reason=cb.reason,
            confidence=cb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_comparison_operator_scan", f"pattern={cb.pattern}"]
            ),
            bug_variable='comparison_operator',
        ))

    # AST-based uncaught URL/network exception detection
    from .uncaught_url_exception_detector import scan_file_for_uncaught_url_exception_bugs
    url_bugs = scan_file_for_uncaught_url_exception_bugs(file_path)
    for ub in url_bugs:
        bugs.append(InterproceduralBug(
            bug_type='ASSERT_FAIL',
            crash_function=ub.function_name,
            crash_location=f"{ub.file_path}:{ub.line_number}",
            call_chain=[ub.function_name],
            reason=ub.reason,
            confidence=ub.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_uncaught_url_exception_scan", f"pattern={ub.pattern}"]
            ),
            bug_variable=ub.variable,
        ))

    # AST-based format string injection detection (dynamic dict key from user input)
    from .format_string_injection_detector import scan_file_for_format_string_injection_bugs
    fmt_bugs = scan_file_for_format_string_injection_bugs(file_path)
    for fb in fmt_bugs:
        bugs.append(InterproceduralBug(
            bug_type='SQL_INJECTION',
            crash_function=fb.function_name,
            crash_location=f"{fb.file_path}:{fb.line_number}",
            call_chain=[fb.function_name],
            reason=fb.reason,
            confidence=fb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_format_string_injection_scan", f"pattern={fb.pattern}"]
            ),
            bug_variable=fb.variable,
        ))

    # AST-based union-type attribute access detection (missing isinstance guard)
    from .union_attr_detector import scan_file_for_union_attr_bugs
    union_bugs = scan_file_for_union_attr_bugs(file_path)
    for ub in union_bugs:
        bugs.append(InterproceduralBug(
            bug_type='TYPE_CONFUSION',
            crash_function=ub.function_name,
            crash_location=f"{ub.file_path}:{ub.line_number}",
            call_chain=[ub.function_name],
            reason=ub.reason,
            confidence=ub.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_union_attr_scan", f"pattern={ub.pattern}"]
            ),
            bug_variable=ub.variable,
        ))

    # AST-based hasattr-without-type-check detection (keras#24)
    from .hasattr_type_check_detector import scan_file_for_hasattr_type_check_bugs
    hasattr_bugs = scan_file_for_hasattr_type_check_bugs(file_path)
    for hb in hasattr_bugs:
        bugs.append(InterproceduralBug(
            bug_type='TYPE_CONFUSION',
            crash_function=hb.function_name,
            crash_location=f"{hb.file_path}:{hb.line_number}",
            call_chain=[hb.function_name],
            reason=hb.reason,
            confidence=hb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_hasattr_type_check_scan", f"pattern={hb.pattern}"]
            ),
            bug_variable=hb.variable,
        ))

    # AST-based unhandled Path.relative_to() exception detection (black#16)
    from .unhandled_path_exception_detector import scan_file_for_unhandled_path_exception_bugs
    path_bugs = scan_file_for_unhandled_path_exception_bugs(file_path)
    for pb in path_bugs:
        bugs.append(InterproceduralBug(
            bug_type='ASSERT_FAIL',
            crash_function=pb.function_name,
            crash_location=f"{pb.file_path}:{pb.line_number}",
            call_chain=[pb.function_name],
            reason=pb.reason,
            confidence=pb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_unhandled_path_exception_scan", f"pattern={pb.pattern}"]
            ),
            bug_variable=pb.variable,
        ))

    # AST-based missing HTTP session config propagation detection (httpie#2)
    from .missing_session_config_detector import scan_file_for_missing_session_config_bugs
    session_bugs = scan_file_for_missing_session_config_bugs(file_path)
    for sb in session_bugs:
        bugs.append(InterproceduralBug(
            bug_type='ASSERT_FAIL',
            crash_function=sb.function_name,
            crash_location=f"{sb.file_path}:{sb.line_number}",
            call_chain=[sb.function_name],
            reason=sb.reason,
            confidence=sb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_missing_session_config_scan", f"pattern={sb.pattern}"]
            ),
            bug_variable=sb.variable,
        ))

    # AST + CFG + Z3 stale-seed / stale-state detection (keras#1)
    from .stale_seed_state_detector import scan_file_for_stale_seed_state_bugs
    seed_bugs = scan_file_for_stale_seed_state_bugs(file_path)
    for sb in seed_bugs:
        bugs.append(InterproceduralBug(
            bug_type='STALE_STATE',
            crash_function=sb.function_name,
            crash_location=f"{sb.file_path}:{sb.line_number}",
            call_chain=[sb.function_name],
            reason=sb.reason,
            confidence=sb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_stale_seed_state_scan", f"pattern={sb.pattern}"]
            ),
            bug_variable=sb.variable,
        ))

    # AST-based maketrans length-mismatch detection (keras#33)
    from .maketrans_misuse_detector import scan_file_for_maketrans_misuse_bugs
    maketrans_bugs = scan_file_for_maketrans_misuse_bugs(file_path)
    for mb in maketrans_bugs:
        bugs.append(InterproceduralBug(
            bug_type='NULL_PTR',
            crash_function=mb.function_name,
            crash_location=f"{mb.file_path}:{mb.line_number}",
            call_chain=[mb.function_name],
            reason=mb.reason,
            confidence=mb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_maketrans_misuse_scan", f"pattern={mb.pattern}"]
            ),
            bug_variable=mb.variable,
        ))

    # AST-based missing wrapper attribute forwarding detection
    from .missing_wrapper_forwarding_detector import scan_file_for_wrapper_forwarding_bugs
    wrapper_bugs = scan_file_for_wrapper_forwarding_bugs(file_path)
    for wb in wrapper_bugs:
        bugs.append(InterproceduralBug(
            bug_type='NULL_PTR',
            crash_function=wb.function_name,
            crash_location=f"{wb.file_path}:{wb.line_number}",
            call_chain=[wb.function_name],
            reason=wb.reason,
            confidence=wb.confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=[f"source=ast_wrapper_forwarding_scan", f"pattern={wb.pattern}"]
            ),
            bug_variable=wb.variable,
        ))

    return bugs


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    'InterproceduralBug',
    'ValueState',
    'InterproceduralBugTracker',
    'analyze_project_for_all_bugs',
    'analyze_file_for_bugs',
]
