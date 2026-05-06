"""
Fine-Grained Exception Bug Types with Kitchensink Barrier Verification.

Instead of classifying all unhandled exceptions as PANIC, we now categorize
by exception type and apply the appropriate barrier-theoretic verification
strategy from the 20 SOTA papers.

EXCEPTION TYPE → BUG TYPE → KITCHENSINK VERIFICATION STRATEGY
═══════════════════════════════════════════════════════════════════════════════
ValueError       → VALUE_ERROR        → Predicate Abstraction (#13) + ICE (#17)
                                        - Track value constraints through CFG
                                        - Learn predicates: valid_range(x)
                                        - FP Reduction: prove value is in-bounds

RuntimeError     → RUNTIME_ERROR      → CEGAR (#12) + Assume-Guarantee (#20)
                                        - Abstract program state
                                        - Refine on spurious counterexamples
                                        - Compositional reasoning for library calls

FileNotFoundError→ FILE_NOT_FOUND     → IC3/PDR (#10) + Stochastic (#2)
                                        - Property-directed reachability
                                        - Probabilistic path exists

PermissionError  → PERMISSION_ERROR   → Assume-Guarantee (#20)
                                        - Model OS/filesystem contracts
                                        - Compositional verification

OSError          → OS_ERROR           → CEGAR (#12) + Spacer/CHC (#11)
                                        - Horn clause encoding of syscalls
                                        - Abstract OS interaction

IOError          → IO_ERROR           → Stochastic Barriers (#2)
                                        - Probabilistic I/O failure model
                                        - Bound P(failure)

ImportError      → IMPORT_ERROR       → BMC + Houdini (#18)
                                        - Bounded checking of import paths
                                        - Conjunctive module-exists invariants

NameError        → NAME_ERROR         → Predicate Abstraction (#13)
                                        - Track defined-ness predicates
                                        - Abstract: defined(x) before use(x)

UnboundLocalError→ UNBOUND_LOCAL      → SOS-SDP (#6) + IMC (#15)
                                        - Polynomial encoding of assignment reach
                                        - Interpolation for assignment order

TimeoutError     → TIMEOUT_ERROR      → Ranking Functions + Stochastic (#2)
                                        - Termination analysis
                                        - Probabilistic timeout model

ConnectionError  → CONNECTION_ERROR   → Stochastic Barriers (#2)
                                        - Network failure probability
                                        - Retry semantics modeling

Custom/Unknown   → PANIC              → Full Portfolio (all 20 papers)
                                        - Try all methods as last resort
═══════════════════════════════════════════════════════════════════════════════

Barrier-Theoretic Foundation:
-----------------------------
For each exception type E, we define:
- U_E(σ): Unsafe predicate where exception E is raised
- B_E: Barrier certificate proving U_E unreachable
- V_E: Verification strategy from kitchensink papers

Theorem (Exception-Specific Safety):
    If ∃B_E: B_E(Init) < 0 ∧ B_E(U_E) > 0 ∧ B_E inductive
    then exception type E is unreachable.

The key insight is that different exception types have different semantic
structures that make certain verification strategies more effective:
- Numeric exceptions (ValueError): Polynomial barriers (#6-8)
- Resource exceptions (FileNotFoundError): Stochastic barriers (#2)
- State exceptions (NameError): Predicate abstraction (#13)
- Timeout exceptions: Ranking functions + stochastic (#2)
"""

from typing import Dict, List, Optional, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import IntEnum, auto
import z3


# ============================================================================
# FINE-GRAINED EXCEPTION BUG TYPES
# ============================================================================

class ExceptionBugType(IntEnum):
    """Fine-grained bug types based on exception semantics."""
    # Numeric/Value Exceptions
    VALUE_ERROR = auto()           # ValueError: invalid value for operation
    
    # Runtime/Logic Exceptions
    RUNTIME_ERROR = auto()         # RuntimeError: generic runtime failure
    NOT_IMPLEMENTED = auto()       # NotImplementedError: abstract method called
    
    # File/IO Exceptions
    FILE_NOT_FOUND = auto()        # FileNotFoundError: file doesn't exist
    PERMISSION_ERROR = auto()      # PermissionError: access denied
    OS_ERROR = auto()              # OSError: OS-level failure
    IO_ERROR = auto()              # IOError: I/O operation failure
    
    # Import/Module Exceptions
    IMPORT_ERROR = auto()          # ImportError: module not found
    MODULE_NOT_FOUND = auto()      # ModuleNotFoundError: specific module missing
    
    # Name/Scope Exceptions
    NAME_ERROR = auto()            # NameError: undefined name
    UNBOUND_LOCAL = auto()         # UnboundLocalError: local referenced before assignment
    
    # Network/Timeout Exceptions
    TIMEOUT_ERROR = auto()         # TimeoutError: operation timed out
    CONNECTION_ERROR = auto()      # ConnectionError: network failure
    
    # Encoding Exceptions
    UNICODE_ERROR = auto()         # UnicodeError: encoding/decoding failure
    LOOKUP_ERROR = auto()          # LookupError: base for KeyError/IndexError
    
    # System Exceptions
    SYSTEM_ERROR = auto()          # SystemError: interpreter error
    ENVIRONMENT_ERROR = auto()     # EnvironmentError: OS environment issue
    
    # Catch-all (truly custom exceptions)
    PANIC = auto()                 # Unknown/custom exception types


# Map Python exception names to bug types
EXCEPTION_TO_BUG_TYPE: Dict[str, ExceptionBugType] = {
    # Numeric/Value
    "ValueError": ExceptionBugType.VALUE_ERROR,
    
    # Runtime/Logic
    "RuntimeError": ExceptionBugType.RUNTIME_ERROR,
    "NotImplementedError": ExceptionBugType.NOT_IMPLEMENTED,
    
    # File/IO
    "FileNotFoundError": ExceptionBugType.FILE_NOT_FOUND,
    "PermissionError": ExceptionBugType.PERMISSION_ERROR,
    "OSError": ExceptionBugType.OS_ERROR,
    "IOError": ExceptionBugType.IO_ERROR,
    "IsADirectoryError": ExceptionBugType.OS_ERROR,
    "NotADirectoryError": ExceptionBugType.OS_ERROR,
    "FileExistsError": ExceptionBugType.OS_ERROR,
    "BlockingIOError": ExceptionBugType.IO_ERROR,
    "BrokenPipeError": ExceptionBugType.IO_ERROR,
    "ChildProcessError": ExceptionBugType.OS_ERROR,
    "ProcessLookupError": ExceptionBugType.OS_ERROR,
    "InterruptedError": ExceptionBugType.OS_ERROR,
    
    # Import/Module
    "ImportError": ExceptionBugType.IMPORT_ERROR,
    "ModuleNotFoundError": ExceptionBugType.MODULE_NOT_FOUND,
    
    # Name/Scope
    "NameError": ExceptionBugType.NAME_ERROR,
    "UnboundLocalError": ExceptionBugType.UNBOUND_LOCAL,
    
    # Network/Timeout
    "TimeoutError": ExceptionBugType.TIMEOUT_ERROR,
    "ConnectionError": ExceptionBugType.CONNECTION_ERROR,
    "ConnectionAbortedError": ExceptionBugType.CONNECTION_ERROR,
    "ConnectionRefusedError": ExceptionBugType.CONNECTION_ERROR,
    "ConnectionResetError": ExceptionBugType.CONNECTION_ERROR,
    
    # Encoding
    "UnicodeError": ExceptionBugType.UNICODE_ERROR,
    "UnicodeDecodeError": ExceptionBugType.UNICODE_ERROR,
    "UnicodeEncodeError": ExceptionBugType.UNICODE_ERROR,
    "UnicodeTranslateError": ExceptionBugType.UNICODE_ERROR,
    "LookupError": ExceptionBugType.LOOKUP_ERROR,
    
    # System
    "SystemError": ExceptionBugType.SYSTEM_ERROR,
    "EnvironmentError": ExceptionBugType.ENVIRONMENT_ERROR,
}

# Bug types that are already handled by specific modules (not reclassified)
ALREADY_CLASSIFIED_EXCEPTIONS: Set[str] = {
    "AssertionError",      # ASSERT_FAIL
    "ZeroDivisionError",   # DIV_ZERO
    "IndexError",          # BOUNDS
    "KeyError",            # BOUNDS
    "AttributeError",      # NULL_PTR
    "TypeError",           # TYPE_CONFUSION
    "RecursionError",      # STACK_OVERFLOW
    "MemoryError",         # MEMORY_LEAK
    "StopIteration",       # ITERATOR_INVALID
    "OverflowError",       # INTEGER_OVERFLOW
}


# ============================================================================
# KITCHENSINK VERIFICATION STRATEGIES PER BUG TYPE
# ============================================================================

@dataclass
class KitchensinkStrategy:
    """
    Verification strategy for a bug type using SOTA papers.
    
    Each strategy specifies:
    - Primary papers to try (most likely to succeed)
    - Secondary papers (fallback)
    - Z3 encoding hints
    - FP reduction technique
    """
    name: str
    bug_type: ExceptionBugType
    
    # Papers to try (by paper number from barriers/__init__.py)
    primary_papers: List[int]   # E.g., [13, 17] for Predicate Abstraction + ICE
    secondary_papers: List[int] # Fallback papers
    
    # Verification approach
    barrier_type: str  # "polynomial", "predicate", "ranking", "stochastic", "chc"
    
    # Z3 encoding hints
    z3_theory: str     # "LIA", "NIA", "LRA", "NRA", "BV", "Arrays"
    
    # FP reduction technique
    fp_reduction: str  # Description of how to reduce FPs
    
    # TP detection technique  
    tp_detection: str  # Description of how to confirm TPs


# Strategy registry: bug_type -> verification strategy
KITCHENSINK_STRATEGIES: Dict[ExceptionBugType, KitchensinkStrategy] = {
    ExceptionBugType.VALUE_ERROR: KitchensinkStrategy(
        name="Value Range Verification",
        bug_type=ExceptionBugType.VALUE_ERROR,
        primary_papers=[13, 17],  # Predicate Abstraction, ICE Learning
        secondary_papers=[6, 9],  # SOS-SDP, DSOS/SDSOS
        barrier_type="predicate",
        z3_theory="LIA",
        fp_reduction=(
            "Use predicate abstraction to track value constraints. "
            "Learn predicates like valid_range(x, min, max). "
            "If predicate 'valid' dominates the exception site, it's FP."
        ),
        tp_detection=(
            "Use ICE learning to find counterexample values. "
            "If ICE finds implication counterexample (valid state → invalid), "
            "it's a true positive with concrete witness."
        ),
    ),
    
    ExceptionBugType.RUNTIME_ERROR: KitchensinkStrategy(
        name="Runtime State Abstraction",
        bug_type=ExceptionBugType.RUNTIME_ERROR,
        primary_papers=[12, 20],  # CEGAR, Assume-Guarantee
        secondary_papers=[11, 15],  # Spacer/CHC, IMC
        barrier_type="predicate",
        z3_theory="LIA",
        fp_reduction=(
            "Use CEGAR to refine abstract state. "
            "If counterexample is spurious (infeasible path), refine abstraction. "
            "Assume-Guarantee for library call contracts."
        ),
        tp_detection=(
            "CEGAR loop terminates with real counterexample when: "
            "1. Path is feasible (SAT) "
            "2. State satisfies RuntimeError precondition "
            "Compositional reasoning validates library assumptions."
        ),
    ),
    
    ExceptionBugType.NOT_IMPLEMENTED: KitchensinkStrategy(
        name="Abstract Method Verification",
        bug_type=ExceptionBugType.NOT_IMPLEMENTED,
        primary_papers=[20, 13],  # Assume-Guarantee, Predicate Abstraction
        secondary_papers=[18],     # Houdini
        barrier_type="predicate",
        z3_theory="LIA",
        fp_reduction=(
            "Track type hierarchy and method implementations. "
            "If all subclasses implement the method, it's FP. "
            "Assume-Guarantee: assume subclass contract."
        ),
        tp_detection=(
            "Find call path to abstract method on base class. "
            "Houdini inference to check if all paths go through subclass."
        ),
    ),
    
    ExceptionBugType.FILE_NOT_FOUND: KitchensinkStrategy(
        name="File Existence Verification",
        bug_type=ExceptionBugType.FILE_NOT_FOUND,
        primary_papers=[10, 2],   # IC3/PDR, Stochastic Barriers
        secondary_papers=[11, 20],  # Spacer/CHC, Assume-Guarantee
        barrier_type="stochastic",
        z3_theory="LIA",
        fp_reduction=(
            "Model file system as external oracle with contracts. "
            "If path is constant and checked with os.path.exists(), it's FP. "
            "Stochastic barrier: bound P(file_missing) if runtime check exists."
        ),
        tp_detection=(
            "IC3/PDR to find path where file check is skipped. "
            "Property: ¬exists(file) → FileNotFoundError "
            "Stochastic: compute probability of missing file."
        ),
    ),
    
    ExceptionBugType.PERMISSION_ERROR: KitchensinkStrategy(
        name="Permission Contract Verification",
        bug_type=ExceptionBugType.PERMISSION_ERROR,
        primary_papers=[20, 11],  # Assume-Guarantee, Spacer/CHC
        secondary_papers=[2],      # Stochastic Barriers
        barrier_type="chc",
        z3_theory="LIA",
        fp_reduction=(
            "Model OS permission system as assume-guarantee contract. "
            "Assume: process has required permissions. "
            "Guarantee: no PermissionError raised. "
            "If permission check guards access, it's FP."
        ),
        tp_detection=(
            "CHC encoding: permission(user, resource) → can_access "
            "Find execution where permission check fails or is missing."
        ),
    ),
    
    ExceptionBugType.OS_ERROR: KitchensinkStrategy(
        name="OS Interaction Verification",
        bug_type=ExceptionBugType.OS_ERROR,
        primary_papers=[12, 11],  # CEGAR, Spacer/CHC
        secondary_papers=[2, 20],  # Stochastic, Assume-Guarantee
        barrier_type="chc",
        z3_theory="LIA",
        fp_reduction=(
            "Abstract OS as CHC predicates. "
            "CEGAR to refine OS model on spurious errors. "
            "If error handling exists, it's FP."
        ),
        tp_detection=(
            "Horn clause: os_call(args) ∧ ¬valid(args) → OSError "
            "Find args that violate OS preconditions."
        ),
    ),
    
    ExceptionBugType.IO_ERROR: KitchensinkStrategy(
        name="I/O Failure Verification",
        bug_type=ExceptionBugType.IO_ERROR,
        primary_papers=[2],       # Stochastic Barriers
        secondary_papers=[20, 12],  # Assume-Guarantee, CEGAR
        barrier_type="stochastic",
        z3_theory="LRA",
        fp_reduction=(
            "Model I/O as stochastic process with failure probability. "
            "If retry logic exists, bound overall failure probability. "
            "If P(failure) ≤ threshold with retries, it's acceptable."
        ),
        tp_detection=(
            "Stochastic barrier: compute P(I/O fails all retries). "
            "If P > threshold and no fallback, it's TP."
        ),
    ),
    
    ExceptionBugType.IMPORT_ERROR: KitchensinkStrategy(
        name="Import Resolution Verification",
        bug_type=ExceptionBugType.IMPORT_ERROR,
        primary_papers=[18, 10],  # Houdini, IC3/PDR
        secondary_papers=[13],     # Predicate Abstraction
        barrier_type="predicate",
        z3_theory="LIA",
        fp_reduction=(
            "Houdini: generate candidates 'module_exists(m)' for all imports. "
            "Check conjunction of all import predicates. "
            "If optional import with try/except, it's FP."
        ),
        tp_detection=(
            "IC3/PDR: reach state where module_exists(m) = False "
            "and import is attempted without guard."
        ),
    ),
    
    ExceptionBugType.MODULE_NOT_FOUND: KitchensinkStrategy(
        name="Module Existence Verification",
        bug_type=ExceptionBugType.MODULE_NOT_FOUND,
        primary_papers=[18, 20],  # Houdini, Assume-Guarantee
        secondary_papers=[10],     # IC3/PDR
        barrier_type="predicate",
        z3_theory="LIA",
        fp_reduction=(
            "Track requirements.txt / setup.py dependencies. "
            "Assume-Guarantee: if in deps, assume exists. "
            "Optional imports with ImportError handling are FP."
        ),
        tp_detection=(
            "Find import of undeclared dependency. "
            "Houdini: no invariant 'module_installed(m)' holds."
        ),
    ),
    
    ExceptionBugType.NAME_ERROR: KitchensinkStrategy(
        name="Name Definedness Verification",
        bug_type=ExceptionBugType.NAME_ERROR,
        primary_papers=[13, 15],  # Predicate Abstraction, IMC
        secondary_papers=[18],     # Houdini
        barrier_type="predicate",
        z3_theory="LIA",
        fp_reduction=(
            "Predicate: defined(x) before use(x). "
            "IMC interpolation: find path where defined(x) = False at use. "
            "If all paths define x before use, it's FP."
        ),
        tp_detection=(
            "IMC: A = (path_prefix), B = (use_x ∧ ¬defined_x) "
            "If A ∧ B satisfiable, extract concrete path."
        ),
    ),
    
    ExceptionBugType.UNBOUND_LOCAL: KitchensinkStrategy(
        name="Local Assignment Verification",
        bug_type=ExceptionBugType.UNBOUND_LOCAL,
        primary_papers=[6, 15],   # SOS-SDP, IMC
        secondary_papers=[13],     # Predicate Abstraction
        barrier_type="polynomial",
        z3_theory="LIA",
        fp_reduction=(
            "Polynomial encoding: assignment_count(x) ≥ 1 before use. "
            "SOS barrier: B = 1 - assignment_count(x) "
            "If B < 0 at all use sites, it's FP."
        ),
        tp_detection=(
            "IMC: find path where assignment is skipped. "
            "Interpolant gives condition for skipping assignment."
        ),
    ),
    
    ExceptionBugType.TIMEOUT_ERROR: KitchensinkStrategy(
        name="Timeout Verification",
        bug_type=ExceptionBugType.TIMEOUT_ERROR,
        primary_papers=[2],       # Stochastic Barriers + Ranking Functions
        secondary_papers=[10, 19],  # IC3/PDR, SyGuS
        barrier_type="stochastic",
        z3_theory="LRA",
        fp_reduction=(
            "Ranking function: prove operation terminates within timeout. "
            "Stochastic: bound P(duration > timeout). "
            "If ranking function exists with bound < timeout, it's FP."
        ),
        tp_detection=(
            "No ranking function found → potential non-termination. "
            "Stochastic analysis: P(timeout) > threshold. "
            "SyGuS: synthesize counterexample execution."
        ),
    ),
    
    ExceptionBugType.CONNECTION_ERROR: KitchensinkStrategy(
        name="Network Reliability Verification",
        bug_type=ExceptionBugType.CONNECTION_ERROR,
        primary_papers=[2, 20],   # Stochastic Barriers, Assume-Guarantee
        secondary_papers=[12],     # CEGAR
        barrier_type="stochastic",
        z3_theory="LRA",
        fp_reduction=(
            "Model network as stochastic channel with failure rate. "
            "Assume-Guarantee: network contract with retry semantics. "
            "If retry with exponential backoff, bound overall failure."
        ),
        tp_detection=(
            "Stochastic barrier: P(all retries fail) > threshold. "
            "Find code path with no error handling for ConnectionError."
        ),
    ),
    
    ExceptionBugType.UNICODE_ERROR: KitchensinkStrategy(
        name="Encoding Verification",
        bug_type=ExceptionBugType.UNICODE_ERROR,
        primary_papers=[13, 17],  # Predicate Abstraction, ICE
        secondary_papers=[18],     # Houdini
        barrier_type="predicate",
        z3_theory="LIA",
        fp_reduction=(
            "Track encoding predicates: valid_utf8(data), valid_ascii(data). "
            "ICE: learn invariant from encoding examples. "
            "If input is validated before decode, it's FP."
        ),
        tp_detection=(
            "Find path where unvalidated data is decoded. "
            "ICE counterexample: data that fails decoding."
        ),
    ),
    
    ExceptionBugType.LOOKUP_ERROR: KitchensinkStrategy(
        name="Lookup Verification",
        bug_type=ExceptionBugType.LOOKUP_ERROR,
        primary_papers=[13, 6],   # Predicate Abstraction, SOS-SDP
        secondary_papers=[17],     # ICE
        barrier_type="polynomial",
        z3_theory="LIA",
        fp_reduction=(
            "Polynomial barrier: 0 ≤ index < len(container). "
            "Predicate: key_exists(dict, key). "
            "If bounds/membership checked, it's FP."
        ),
        tp_detection=(
            "SOS: find index outside polynomial bounds. "
            "Predicate: find key access without membership check."
        ),
    ),
    
    ExceptionBugType.SYSTEM_ERROR: KitchensinkStrategy(
        name="System State Verification",
        bug_type=ExceptionBugType.SYSTEM_ERROR,
        primary_papers=[11, 12],  # Spacer/CHC, CEGAR
        secondary_papers=[20],     # Assume-Guarantee
        barrier_type="chc",
        z3_theory="LIA",
        fp_reduction=(
            "CHC encoding of interpreter state invariants. "
            "CEGAR: abstract interpreter as finite state. "
            "These are usually interpreter bugs, rarely FP."
        ),
        tp_detection=(
            "SystemError is internal → usually real bug. "
            "CHC: model interpreter state, find violation."
        ),
    ),
    
    ExceptionBugType.ENVIRONMENT_ERROR: KitchensinkStrategy(
        name="Environment Verification",
        bug_type=ExceptionBugType.ENVIRONMENT_ERROR,
        primary_papers=[20, 2],   # Assume-Guarantee, Stochastic
        secondary_papers=[11],     # Spacer/CHC
        barrier_type="stochastic",
        z3_theory="LIA",
        fp_reduction=(
            "Assume-Guarantee: model environment variables/config. "
            "Stochastic: bound P(env_missing). "
            "If os.environ.get with default, it's FP."
        ),
        tp_detection=(
            "Find required env var access without default. "
            "If not in deployment config, it's TP."
        ),
    ),
    
    ExceptionBugType.PANIC: KitchensinkStrategy(
        name="Full Portfolio Verification",
        bug_type=ExceptionBugType.PANIC,
        primary_papers=[1, 2, 3, 6, 9, 10, 11, 12, 13, 15, 17, 18, 19, 20],  # All papers!
        secondary_papers=[],  # No fallback - this IS the fallback
        barrier_type="portfolio",
        z3_theory="LIA",
        fp_reduction=(
            "Try all SOTA papers in sequence: "
            "1. Fast bug finding (BMC) "
            "2. Local safety (SOS, DSOS) "
            "3. Invariant discovery (Houdini, ICE, IC3, SyGuS) "
            "4. Abstraction (CEGAR, Predicate, CHC) "
            "5. Compositional (Assume-Guarantee) "
            "If any proves safe, it's FP."
        ),
        tp_detection=(
            "Full portfolio with DSE validation. "
            "If BMC finds bug AND DSE confirms reachability, it's TP. "
            "Stochastic replay for concrete witness."
        ),
    ),
}


# ============================================================================
# EXCEPTION CLASSIFICATION AND PREDICATE FUNCTIONS
# ============================================================================

def classify_exception(exception_name: str) -> ExceptionBugType:
    """
    Classify an exception into a fine-grained bug type.
    
    Args:
        exception_name: Name of the exception (e.g., "ValueError")
    
    Returns:
        ExceptionBugType for the exception
    """
    # Already handled by specific modules
    if exception_name in ALREADY_CLASSIFIED_EXCEPTIONS:
        return None  # Don't reclassify
    
    # Look up in mapping
    if exception_name in EXCEPTION_TO_BUG_TYPE:
        return EXCEPTION_TO_BUG_TYPE[exception_name]
    
    # Unknown exception → PANIC
    return ExceptionBugType.PANIC


def get_bug_type_name(bug_type: ExceptionBugType) -> str:
    """Convert ExceptionBugType to string name for registry."""
    return bug_type.name


def is_unsafe_exception(state, exception_type: ExceptionBugType) -> bool:
    """
    Check if state has an unsafe exception of the given type.
    
    Args:
        state: SymbolicVM state
        exception_type: The exception bug type to check
    
    Returns:
        True if state has uncaught exception of this type
    """
    exc = getattr(state, "exception", None)
    if exc is None:
        return False
    
    # Internal sentinel
    if exc == "InfeasiblePath":
        return False
    
    # Internal VM errors — not real Python exceptions
    if exc in ("StackUnderflow", "StackOverflow_internal"):
        return False
    
    # Check if exception is caught by a handler (catch guard)
    # If g_catch(exception_type) is established, the exception is handled
    if hasattr(state, 'has_catch_guard') and state.has_catch_guard(exc):
        return False
    
    # Check if exception matches type
    exc_name = exc if isinstance(exc, str) else type(exc).__name__
    classified = classify_exception(exc_name)
    
    if classified is None:
        return False  # Already handled by specific module
    
    return classified == exception_type


def extract_exception_counterexample(
    state, 
    path_trace: List[str],
    exception_type: ExceptionBugType
) -> dict:
    """
    Extract counterexample for exception bug.
    
    Includes kitchensink verification strategy hints.
    """
    exc = getattr(state, "exception", None)
    exc_name = exc if isinstance(exc, str) else type(exc).__name__
    strategy = KITCHENSINK_STRATEGIES.get(exception_type)
    
    return {
        "bug_type": exception_type.name,
        "exception": exc_name,
        "trace": path_trace,
        "final_state": {
            "exception": exc_name,
            "frame_count": len(getattr(state, 'frame_stack', [])),
            "halted": getattr(state, 'halted', True),
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None,
        "verification_strategy": {
            "name": strategy.name if strategy else "Unknown",
            "primary_papers": strategy.primary_papers if strategy else [],
            "barrier_type": strategy.barrier_type if strategy else "unknown",
            "z3_theory": strategy.z3_theory if strategy else "LIA",
            "fp_reduction_hint": strategy.fp_reduction if strategy else None,
            "tp_detection_hint": strategy.tp_detection if strategy else None,
        } if strategy else None,
    }


# ============================================================================
# FACTORY FUNCTIONS FOR REGISTRY
# ============================================================================

def make_exception_predicate(exception_type: ExceptionBugType) -> Callable:
    """Create predicate function for exception type."""
    def predicate(state) -> bool:
        return is_unsafe_exception(state, exception_type)
    return predicate


def make_exception_extractor(exception_type: ExceptionBugType) -> Callable:
    """Create counterexample extractor for exception type."""
    def extractor(state, path_trace: List[str]) -> dict:
        return extract_exception_counterexample(state, path_trace, exception_type)
    return extractor


# Generate predicates and extractors for all exception types
EXCEPTION_PREDICATES: Dict[str, Tuple[Callable, Callable]] = {
    bug_type.name: (
        make_exception_predicate(bug_type),
        make_exception_extractor(bug_type),
    )
    for bug_type in ExceptionBugType
    if bug_type != ExceptionBugType.PANIC  # PANIC stays in panic.py
}


# ============================================================================
# KITCHENSINK BARRIER SYNTHESIS FOR EXCEPTION TYPES
# ============================================================================

@dataclass
class ExceptionBarrierResult:
    """Result of barrier synthesis for an exception type."""
    exception_type: ExceptionBugType
    success: bool
    verdict: str  # "SAFE", "BUG", "UNKNOWN"
    
    # Which paper proved it
    paper_used: Optional[int] = None
    paper_name: Optional[str] = None
    
    # Barrier if found
    barrier: Optional[str] = None
    
    # Counterexample if bug
    counterexample: Optional[dict] = None
    
    # Timing
    synthesis_time_ms: float = 0.0


def verify_exception_with_kitchensink(
    code_obj,
    exception_type: ExceptionBugType,
    timeout_ms: int = 10000,
    verbose: bool = False,
) -> ExceptionBarrierResult:
    """
    Use kitchensink barrier verification to prove exception unreachable or find bug.
    
    Applies the appropriate SOTA papers for the exception type.
    
    Args:
        code_obj: Compiled code object to verify
        exception_type: Type of exception to verify
        timeout_ms: Timeout in milliseconds
        verbose: Enable verbose output
    
    Returns:
        ExceptionBarrierResult with verdict
    """
    import time
    start_time = time.time()
    
    strategy = KITCHENSINK_STRATEGIES.get(exception_type)
    if not strategy:
        return ExceptionBarrierResult(
            exception_type=exception_type,
            success=False,
            verdict="UNKNOWN",
        )
    
    # Try primary papers first
    for paper_num in strategy.primary_papers:
        result = _try_paper_for_exception(
            code_obj, exception_type, paper_num, strategy, timeout_ms // len(strategy.primary_papers), verbose
        )
        if result.success:
            result.synthesis_time_ms = (time.time() - start_time) * 1000
            return result
    
    # Try secondary papers
    for paper_num in strategy.secondary_papers:
        result = _try_paper_for_exception(
            code_obj, exception_type, paper_num, strategy, timeout_ms // max(1, len(strategy.secondary_papers)), verbose
        )
        if result.success:
            result.synthesis_time_ms = (time.time() - start_time) * 1000
            return result
    
    # No proof found
    return ExceptionBarrierResult(
        exception_type=exception_type,
        success=False,
        verdict="UNKNOWN",
        synthesis_time_ms=(time.time() - start_time) * 1000,
    )


# Paper number to name mapping
PAPER_NAMES: Dict[int, str] = {
    1: "HSCC'04 Hybrid Barrier Certificates",
    2: "Stochastic Barrier Certificates",
    3: "SOS Emptiness",
    6: "Parrilo SOS-SDP",
    7: "Lasserre Hierarchy",
    8: "Sparse SOS",
    9: "DSOS/SDSOS",
    10: "IC3/PDR",
    11: "Spacer/CHC",
    12: "CEGAR",
    13: "Predicate Abstraction",
    15: "IMC/Interpolation",
    17: "ICE Learning",
    18: "Houdini",
    19: "SyGuS",
    20: "Assume-Guarantee",
}


def _try_paper_for_exception(
    code_obj,
    exception_type: ExceptionBugType,
    paper_num: int,
    strategy: KitchensinkStrategy,
    timeout_ms: int,
    verbose: bool,
) -> ExceptionBarrierResult:
    """
    Try a specific paper's technique for proving exception safety.
    
    This is the core dispatch that routes to the appropriate barrier engine.
    """
    paper_name = PAPER_NAMES.get(paper_num, f"Paper #{paper_num}")
    
    if verbose:
        print(f"  [Paper #{paper_num}] Trying {paper_name} for {exception_type.name}...")
    
    try:
        # Dispatch based on barrier type
        if strategy.barrier_type == "predicate":
            return _try_predicate_abstraction(code_obj, exception_type, paper_num, timeout_ms, verbose)
        elif strategy.barrier_type == "polynomial":
            return _try_polynomial_barrier(code_obj, exception_type, paper_num, timeout_ms, verbose)
        elif strategy.barrier_type == "stochastic":
            return _try_stochastic_barrier(code_obj, exception_type, paper_num, timeout_ms, verbose)
        elif strategy.barrier_type == "chc":
            return _try_chc_solving(code_obj, exception_type, paper_num, timeout_ms, verbose)
        elif strategy.barrier_type == "portfolio":
            return _try_portfolio(code_obj, exception_type, timeout_ms, verbose)
        else:
            return ExceptionBarrierResult(
                exception_type=exception_type,
                success=False,
                verdict="UNKNOWN",
            )
    except Exception as e:
        if verbose:
            print(f"    Error: {type(e).__name__}: {e}")
        return ExceptionBarrierResult(
            exception_type=exception_type,
            success=False,
            verdict="UNKNOWN",
        )


def _try_predicate_abstraction(code_obj, exception_type, paper_num, timeout_ms, verbose):
    """Try predicate abstraction papers (#13, #17, #18)."""
    # Placeholder - in practice, calls barriers.predicate_abstraction
    return ExceptionBarrierResult(
        exception_type=exception_type,
        success=False,
        verdict="UNKNOWN",
    )


def _try_polynomial_barrier(code_obj, exception_type, paper_num, timeout_ms, verbose):
    """Try polynomial SOS barrier papers (#6, #7, #8, #9)."""
    # Placeholder - in practice, calls barriers.sos_unified
    return ExceptionBarrierResult(
        exception_type=exception_type,
        success=False,
        verdict="UNKNOWN",
    )


def _try_stochastic_barrier(code_obj, exception_type, paper_num, timeout_ms, verbose):
    """Try stochastic barrier paper (#2)."""
    # Placeholder - in practice, calls barriers.stochastic_barrier
    return ExceptionBarrierResult(
        exception_type=exception_type,
        success=False,
        verdict="UNKNOWN",
    )


def _try_chc_solving(code_obj, exception_type, paper_num, timeout_ms, verbose):
    """Try CHC solving papers (#11, #12)."""
    # Placeholder - in practice, calls barriers.spacer_chc
    return ExceptionBarrierResult(
        exception_type=exception_type,
        success=False,
        verdict="UNKNOWN",
    )


def _try_portfolio(code_obj, exception_type, timeout_ms, verbose):
    """Try full portfolio for PANIC."""
    # Placeholder - calls analyze_file_kitchensink internally
    return ExceptionBarrierResult(
        exception_type=exception_type,
        success=False,
        verdict="UNKNOWN",
    )
