"""
Taint tracking for security bug detection (barrier-certificate-theory.md §11).

Implements the taint analysis framework for detecting security vulnerabilities:
- Sources: program points where untrusted/sensitive data enters
- Sinks: program points where data flows to sensitive operations
- Sanitizers: operations that clean/validate data

Two taint bits per value:
- τ(v) ∈ {0, 1}: untrusted taint (0=trusted, 1=tainted from external input)
- σ(v) ∈ {0, 1}: sensitivity taint (0=not sensitive, 1=sensitive like passwords)

Mode A (pure symbolic): Sound over-approximation of taint flows
Mode B (concolic): Optional concrete validation (does not affect verdicts)
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Set, Optional, FrozenSet
import z3

from ..confidence_interval import ReachabilityIntervalPTS, RiskInterval, ConcreteWitnessEvidence


class TaintSource(Enum):
    """Categories of taint sources."""
    # Untrusted (τ=1) sources - external input
    HTTP_PARAM = auto()         # request.GET, request.POST, request.args
    USER_INPUT = auto()         # input(), sys.stdin
    ENVIRONMENT = auto()        # os.environ
    FILE_CONTENT = auto()       # open().read() from untrusted paths
    NETWORK_RECV = auto()       # socket.recv, urllib, requests
    ARGV = auto()               # sys.argv
    DATABASE_RESULT = auto()    # cursor.fetchone(), etc.
    
    # Sensitive (σ=1) sources - secret data
    PASSWORD = auto()           # getpass.getpass, password fields
    API_KEY = auto()            # Environment vars matching *KEY*, *TOKEN*
    CREDENTIALS = auto()        # .netrc, keyring, secrets
    PII = auto()                # User data, email, SSN patterns
    CRYPTO_KEY = auto()         # Private keys, symmetric keys


class SinkType(Enum):
    """Categories of security sinks."""
    # Injection sinks (τ check)
    SQL_EXECUTE = auto()        # cursor.execute, raw SQL
    COMMAND_SHELL = auto()      # os.system, subprocess with shell=True
    CODE_EVAL = auto()          # eval, exec, compile
    FILE_PATH = auto()          # open(path), os.path operations
    LDAP_QUERY = auto()         # ldap.search_s
    XPATH_QUERY = auto()        # lxml.xpath, tree.find
    NOSQL_QUERY = auto()        # collection.find
    REGEX_PATTERN = auto()      # re.compile, re.match with pattern
    HTTP_REQUEST = auto()       # requests.get(url), urllib.urlopen
    XML_PARSE = auto()          # xml.etree.parse, lxml.parse
    DESERIALIZE = auto()        # pickle.loads, yaml.load
    HEADER_SET = auto()         # response.headers, Set-Cookie
    HTML_OUTPUT = auto()        # HttpResponse, render_template_string
    REDIRECT_URL = auto()       # redirect(url)
    COOKIE_VALUE = auto()       # response.set_cookie(value=...)
    
    # Sensitive data sinks (σ check)
    LOG_OUTPUT = auto()         # logging.*, print
    FILE_WRITE = auto()         # open().write
    NETWORK_SEND = auto()       # socket.send, requests.post
    EXCEPTION_MSG = auto()      # raise Exception(msg)
    CRYPTO_WEAK = auto()        # hashlib.md5, DES


class SanitizerType(Enum):
    """Categories of sanitizers that clear taint."""
    # SQL injection sanitizers
    PARAMETERIZED_QUERY = auto()  # Using ? or %s placeholders
    ORM_ESCAPE = auto()           # Django ORM, SQLAlchemy with binds
    
    # Command injection sanitizers
    SHELL_QUOTE = auto()          # shlex.quote
    ARRAY_COMMAND = auto()        # subprocess.run([...]) without shell=True
    
    # Path sanitizers
    BASENAME = auto()             # os.path.basename
    REALPATH_CHECK = auto()       # realpath + startswith check
    SECURE_FILENAME = auto()      # werkzeug.utils.secure_filename
    
    # XSS sanitizers
    HTML_ESCAPE = auto()          # html.escape, markupsafe.escape
    TEMPLATE_AUTOESCAPE = auto()  # Jinja2 autoescape=True
    
    # URL sanitizers
    URL_VALIDATE = auto()         # urlparse + allowlist check
    RELATIVE_URL = auto()         # Ensure URL is relative
    
    # Regex sanitizers
    RE_ESCAPE = auto()            # re.escape
    
    # Deserialization sanitizers
    SAFE_LOADER = auto()          # yaml.safe_load, json.loads
    
    # General sanitizers
    TYPE_CONVERSION = auto()      # int(), float() - validates format
    ALLOWLIST_CHECK = auto()      # Explicit allowlist validation
    ENCRYPTION = auto()           # Encryption before storage
    HASHING = auto()              # Hashing (declassification for σ)
    LDAP_ESCAPE = auto()          # ldap.filter.escape_filter_chars


@dataclass(frozen=True)
class TaintLabel:
    """
    A taint label tracking source origin and type.
    
    Immutable for use in sets.
    """
    source_type: TaintSource
    source_location: str  # File:line or description
    is_sensitive: bool = False  # σ=1 if True
    
    def __repr__(self):
        kind = "sensitive" if self.is_sensitive else "untrusted"
        return f"TaintLabel({self.source_type.name}, {self.source_location}, {kind})"


@dataclass
class TaintState:
    """
    Taint state for a symbolic value.
    
    Tracks both untrusted (τ) and sensitive (σ) taint bits,
    along with the set of taint labels for provenance tracking.
    """
    # τ(v) - untrusted taint bit (True if value from external input)
    untrusted: bool = False
    
    # σ(v) - sensitivity taint bit (True if value is secret/PII)
    sensitive: bool = False
    
    # Set of taint labels (for detailed tracking and error messages)
    labels: FrozenSet[TaintLabel] = field(default_factory=frozenset)
    
    # Sanitizers that have been applied to this value
    sanitizers_applied: FrozenSet[SanitizerType] = field(default_factory=frozenset)
    
    @staticmethod
    def clean() -> 'TaintState':
        """Create a clean (untainted) state."""
        return TaintState()
    
    @staticmethod
    def from_source(source: TaintSource, location: str, sensitive: bool = False) -> 'TaintState':
        """Create taint state from a source."""
        label = TaintLabel(source, location, sensitive)
        return TaintState(
            untrusted=not sensitive,  # Untrusted sources set τ=1
            sensitive=sensitive,       # Sensitive sources set σ=1
            labels=frozenset([label])
        )
    
    def merge(self, other: 'TaintState') -> 'TaintState':
        """
        Merge two taint states (for τ(z) = τ(x) ∨ τ(y)).
        
        Used when combining values through operations.
        """
        return TaintState(
            untrusted=self.untrusted or other.untrusted,
            sensitive=self.sensitive or other.sensitive,
            labels=self.labels | other.labels,
            sanitizers_applied=self.sanitizers_applied & other.sanitizers_applied
        )
    
    def sanitize(self, sanitizer: SanitizerType) -> 'TaintState':
        """
        Apply a sanitizer to this taint state.
        
        Does NOT automatically clear taint - the sink check must verify
        that the appropriate sanitizer was applied.
        """
        return TaintState(
            untrusted=self.untrusted,
            sensitive=self.sensitive,
            labels=self.labels,
            sanitizers_applied=self.sanitizers_applied | frozenset([sanitizer])
        )
    
    def clear_untrusted(self) -> 'TaintState':
        """Clear untrusted taint (for validated input)."""
        return TaintState(
            untrusted=False,
            sensitive=self.sensitive,
            labels=frozenset(l for l in self.labels if l.is_sensitive),
            sanitizers_applied=self.sanitizers_applied
        )
    
    def clear_sensitive(self) -> 'TaintState':
        """Clear sensitive taint (for declassified data like hashes)."""
        return TaintState(
            untrusted=self.untrusted,
            sensitive=False,
            labels=frozenset(l for l in self.labels if not l.is_sensitive),
            sanitizers_applied=self.sanitizers_applied
        )
    
    def is_tainted_for_sink(self, sink_type: SinkType) -> bool:
        """
        Check if this value is dangerously tainted for a given sink.
        
        Injection sinks check τ, logging sinks check σ.
        Also checks if appropriate sanitizer was applied.
        """
        required_sanitizers = _get_required_sanitizers(sink_type)
        
        # If any required sanitizer was applied, value is safe
        if required_sanitizers & self.sanitizers_applied:
            return False
        
        # Injection sinks check untrusted taint
        if _is_injection_sink(sink_type):
            return self.untrusted
        
        # Sensitive data sinks check sensitivity taint
        if _is_sensitive_sink(sink_type):
            return self.sensitive
        
        return False
    
    @property
    def is_tainted(self) -> bool:
        """Check if value has any taint."""
        return self.untrusted or self.sensitive


def _is_injection_sink(sink_type: SinkType) -> bool:
    """Check if sink requires untrusted (τ) taint check."""
    return sink_type in {
        SinkType.SQL_EXECUTE,
        SinkType.COMMAND_SHELL,
        SinkType.CODE_EVAL,
        SinkType.FILE_PATH,
        SinkType.LDAP_QUERY,
        SinkType.XPATH_QUERY,
        SinkType.NOSQL_QUERY,
        SinkType.REGEX_PATTERN,
        SinkType.HTTP_REQUEST,
        SinkType.XML_PARSE,
        SinkType.DESERIALIZE,
        SinkType.HEADER_SET,
        SinkType.HTML_OUTPUT,
        SinkType.REDIRECT_URL,
        SinkType.COOKIE_VALUE,
    }


def _is_sensitive_sink(sink_type: SinkType) -> bool:
    """Check if sink requires sensitivity (σ) taint check."""
    return sink_type in {
        SinkType.LOG_OUTPUT,
        SinkType.FILE_WRITE,
        SinkType.NETWORK_SEND,
        SinkType.EXCEPTION_MSG,
        SinkType.CRYPTO_WEAK,
    }


def _get_required_sanitizers(sink_type: SinkType) -> FrozenSet[SanitizerType]:
    """Get sanitizers that would make a value safe for a given sink."""
    sanitizer_map = {
        SinkType.SQL_EXECUTE: frozenset([
            SanitizerType.PARAMETERIZED_QUERY,
            SanitizerType.ORM_ESCAPE,
        ]),
        SinkType.COMMAND_SHELL: frozenset([
            SanitizerType.SHELL_QUOTE,
            SanitizerType.ARRAY_COMMAND,
        ]),
        SinkType.FILE_PATH: frozenset([
            SanitizerType.BASENAME,
            SanitizerType.REALPATH_CHECK,
            SanitizerType.SECURE_FILENAME,
        ]),
        SinkType.HTML_OUTPUT: frozenset([
            SanitizerType.HTML_ESCAPE,
            SanitizerType.TEMPLATE_AUTOESCAPE,
        ]),
        SinkType.REDIRECT_URL: frozenset([
            SanitizerType.URL_VALIDATE,
            SanitizerType.RELATIVE_URL,
        ]),
        SinkType.REGEX_PATTERN: frozenset([
            SanitizerType.RE_ESCAPE,
        ]),
        SinkType.DESERIALIZE: frozenset([
            SanitizerType.SAFE_LOADER,
        ]),
        SinkType.LDAP_QUERY: frozenset([
            SanitizerType.LDAP_ESCAPE,
        ]),
        SinkType.LOG_OUTPUT: frozenset([
            SanitizerType.HASHING,
            SanitizerType.ENCRYPTION,
        ]),
        SinkType.CRYPTO_WEAK: frozenset([
            SanitizerType.HASHING,  # Using proper KDF
        ]),
    }
    return sanitizer_map.get(sink_type, frozenset())


# ============================================================================
# Z3 SYMBOLIC TAINT TRACKING
# ============================================================================

def create_symbolic_taint(name: str) -> tuple[z3.BoolRef, z3.BoolRef]:
    """
    Create symbolic taint bits for a fresh symbolic value.
    
    Returns (τ, σ) as Z3 boolean expressions.
    Used in Mode A for sound over-approximation.
    """
    tau = z3.Bool(f"taint_untrusted_{name}")
    sigma = z3.Bool(f"taint_sensitive_{name}")
    return tau, sigma


def taint_propagate_binop(
    left_tau: z3.BoolRef, left_sigma: z3.BoolRef,
    right_tau: z3.BoolRef, right_sigma: z3.BoolRef
) -> tuple[z3.BoolRef, z3.BoolRef]:
    """
    Symbolic taint propagation for binary operations.
    
    τ(z) = τ(x) ∨ τ(y)
    σ(z) = σ(x) ∨ σ(y)
    """
    result_tau = z3.Or(left_tau, right_tau)
    result_sigma = z3.Or(left_sigma, right_sigma)
    return result_tau, result_sigma


def taint_propagate_unop(tau: z3.BoolRef, sigma: z3.BoolRef) -> tuple[z3.BoolRef, z3.BoolRef]:
    """Taint propagation for unary operations (identity)."""
    return tau, sigma


def check_sink_safety(
    tau: z3.BoolRef,
    sigma: z3.BoolRef,
    sink_type: SinkType,
    sanitized: z3.BoolRef = None,
    solver: z3.Solver = None
) -> z3.BoolRef:
    """
    Create a Z3 constraint representing sink safety.
    
    Returns a constraint that must hold for the sink to be safe.
    If the constraint can be violated, there's a potential security bug.
    """
    if sanitized is None:
        sanitized = z3.BoolVal(False)
    
    if _is_injection_sink(sink_type):
        # Safe if: not tainted OR sanitized
        safe = z3.Or(z3.Not(tau), sanitized)
    elif _is_sensitive_sink(sink_type):
        # Safe if: not sensitive OR sanitized (declassified)
        safe = z3.Or(z3.Not(sigma), sanitized)
    else:
        safe = z3.BoolVal(True)
    
    return safe


# ============================================================================
# SECURITY BUG TYPES
# ============================================================================

@dataclass
class SecurityViolation:
    """A detected security violation."""
    bug_type: str           # e.g., "SQL_INJECTION", "CLEARTEXT_LOGGING"
    cwe: str               # CWE identifier
    sink_type: SinkType
    sink_location: str     # File:line
    taint_sources: FrozenSet[TaintLabel]
    message: str
    
    # For barrier certificate extraction
    path_condition: Optional[z3.BoolRef] = None
    counterexample: Optional[dict] = None

    # Quantitative reporting (optional; does not affect verdicts)
    reachability_pts: ReachabilityIntervalPTS = field(default_factory=ReachabilityIntervalPTS.unknown)
    depth_k: Optional[int] = None
    witness: ConcreteWitnessEvidence = field(default_factory=lambda: ConcreteWitnessEvidence(present=False))
    risk_interval: Optional[RiskInterval] = None


# Map from sink type to (bug_type, CWE)
SINK_TO_BUG_TYPE = {
    SinkType.SQL_EXECUTE: ("SQL_INJECTION", "CWE-089"),
    SinkType.COMMAND_SHELL: ("COMMAND_INJECTION", "CWE-078"),
    SinkType.CODE_EVAL: ("CODE_INJECTION", "CWE-094"),
    SinkType.FILE_PATH: ("PATH_INJECTION", "CWE-022"),
    SinkType.LDAP_QUERY: ("LDAP_INJECTION", "CWE-090"),
    SinkType.XPATH_QUERY: ("XPATH_INJECTION", "CWE-643"),
    SinkType.NOSQL_QUERY: ("NOSQL_INJECTION", "CWE-943"),
    SinkType.REGEX_PATTERN: ("REGEX_INJECTION", "CWE-730"),
    SinkType.HTTP_REQUEST: ("SSRF", "CWE-918"),
    SinkType.XML_PARSE: ("XXE", "CWE-611"),
    SinkType.DESERIALIZE: ("UNSAFE_DESERIALIZATION", "CWE-502"),
    SinkType.HEADER_SET: ("HEADER_INJECTION", "CWE-113"),
    SinkType.HTML_OUTPUT: ("REFLECTED_XSS", "CWE-079"),
    SinkType.REDIRECT_URL: ("URL_REDIRECT", "CWE-601"),
    SinkType.COOKIE_VALUE: ("COOKIE_INJECTION", "CWE-020"),
    SinkType.LOG_OUTPUT: ("CLEARTEXT_LOGGING", "CWE-532"),
    SinkType.FILE_WRITE: ("CLEARTEXT_STORAGE", "CWE-312"),
    SinkType.NETWORK_SEND: ("CLEARTEXT_TRANSMISSION", "CWE-319"),
    SinkType.EXCEPTION_MSG: ("STACK_TRACE_EXPOSURE", "CWE-209"),
    SinkType.CRYPTO_WEAK: ("WEAK_CRYPTO", "CWE-327"),
}


def create_violation(
    sink_type: SinkType,
    sink_location: str,
    taint_state: TaintState
) -> SecurityViolation:
    """Create a security violation from sink check failure."""
    bug_type, cwe = SINK_TO_BUG_TYPE.get(sink_type, ("UNKNOWN_SECURITY", "CWE-000"))
    
    return SecurityViolation(
        bug_type=bug_type,
        cwe=cwe,
        sink_type=sink_type,
        sink_location=sink_location,
        taint_sources=taint_state.labels,
        message=f"{bug_type}: Tainted data from {[l.source_type.name for l in taint_state.labels]} reaches {sink_type.name} at {sink_location}",
        reachability_pts=ReachabilityIntervalPTS.unknown(
            evidence=["created_by=z3model.taint.create_violation", f"sink={sink_type.name}"]
        ),
    )
