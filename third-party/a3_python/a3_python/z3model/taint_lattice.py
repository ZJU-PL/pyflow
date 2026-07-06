"""
Full Taint Product Lattice for Bytecode-Level Security Analysis.

This module implements the precise mathematical model from leak_theory.md:

    L = P(T) × P(K) × P(T)

where a label ℓ = (τ, κ, σ) consists of:
    - τ ⊆ T: untrusted sources this value may depend on
    - κ ⊆ K: sink types for which this value has been sanitized
    - σ ⊆ T: sensitivity sources this value may contain

The lattice ordering is pointwise:
    (τ₁, κ₁, σ₁) ⊑ (τ₂, κ₂, σ₂) ⟺ τ₁ ⊆ τ₂ ∧ κ₁ ⊇ κ₂ ∧ σ₁ ⊆ σ₂

Note the reversal for κ: more sanitization means "lower" (safer) in the lattice.

Bytecode-Level Semantics
========================
This lattice is designed for bytecode-level abstract interpretation over
Python's CPython bytecode. Each bytecode opcode has a corresponding taint
transfer function:

    LOAD_FAST/LOAD_NAME: ℓ_result = ℓ_var (propagate from variable)
    STORE_FAST/STORE_NAME: ℓ_var' = ℓ_value ⊔ ℓ_pc (include PC taint)
    BINARY_OP (add, mul, etc.): ℓ_result = ℓ_left ⊔ ℓ_right
    BINARY_SUBSCR: ℓ_result = ℓ_container ⊔ ℓ_index (subscript propagates)
    CALL_FUNCTION: ℓ_result = ⊔{ℓ_arg | arg ∈ args} ⊔ ℓ_func_summary
    COMPARE_OP: ℓ_result = ℓ_left ⊔ ℓ_right (comparison propagates)
    POP_JUMP_IF_*: Updates ℓ_pc for implicit flow tracking
    RETURN_VALUE: Propagates taint to caller

Z3 Encoding
===========
    - τ: BitVec of width |T| (number of taint source types)
    - κ: BitVec of width |K| (number of sink types)
    - σ: BitVec of width |T| (same as τ for sensitivity)

This encoding enables precise reasoning about all 67 CodeQL security bug types
as reachability into specific unsafe regions defined by lattice constraints.

Integration with SymbolicVM
===========================
The taint labels integrate with symbolic_vm.py:
    - SymbolicValue carries an optional TaintLabel or SymbolicTaintLabel
    - Guard conditions (established_guards) can track sanitizer effects
    - Z3 path conditions can include taint flow constraints
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Dict, Optional, FrozenSet, Set, Tuple, List, Union
import z3

from ..confidence_interval import ReachabilityIntervalPTS, RiskInterval, ConcreteWitnessEvidence


# ============================================================================
# TAINT SOURCE ENUMERATION
# ============================================================================
# |T| = 16 distinct source types (fits in 16-bit bitvector)

class SourceType(IntEnum):
    """
    Taint source types (T) - enumerated for bitvector encoding.
    
    Untrusted sources (set τ bit):
        HTTP_PARAM, USER_INPUT, ENVIRONMENT, FILE_CONTENT,
        NETWORK_RECV, ARGV, DATABASE_RESULT, COOKIE, HEADER
    
    Sensitivity sources (set σ bit):
        PASSWORD, API_KEY, CREDENTIALS, PII, CRYPTO_KEY,
        SESSION_TOKEN, PRIVATE_DATA
    """
    # Untrusted external input (τ)
    HTTP_PARAM = 0       # request.GET, request.POST, request.args
    USER_INPUT = 1       # input(), sys.stdin
    ENVIRONMENT = 2      # os.environ, os.getenv
    FILE_CONTENT = 3     # open().read() from untrusted paths
    NETWORK_RECV = 4     # socket.recv, urllib, requests response
    ARGV = 5             # sys.argv
    DATABASE_RESULT = 6  # cursor.fetchone() - may be tainted if DB is untrusted
    COOKIE = 7           # HTTP cookies
    HEADER = 8           # HTTP request headers
    
    # Sensitive/secret data (σ)
    PASSWORD = 9         # getpass.getpass, password fields
    API_KEY = 10         # Environment vars matching *KEY*, *TOKEN*
    CREDENTIALS = 11     # .netrc, keyring, secrets
    PII = 12             # User personal data, SSN, email
    CRYPTO_KEY = 13      # Private keys, symmetric keys
    SESSION_TOKEN = 14   # Session IDs, auth tokens
    PRIVATE_DATA = 15    # Generic private/classified data


# Masks for source type categories
UNTRUSTED_SOURCES_MASK = (
    (1 << SourceType.HTTP_PARAM) |
    (1 << SourceType.USER_INPUT) |
    (1 << SourceType.ENVIRONMENT) |
    (1 << SourceType.FILE_CONTENT) |
    (1 << SourceType.NETWORK_RECV) |
    (1 << SourceType.ARGV) |
    (1 << SourceType.DATABASE_RESULT) |
    (1 << SourceType.COOKIE) |
    (1 << SourceType.HEADER)
)

SENSITIVE_SOURCES_MASK = (
    (1 << SourceType.PASSWORD) |
    (1 << SourceType.API_KEY) |
    (1 << SourceType.CREDENTIALS) |
    (1 << SourceType.PII) |
    (1 << SourceType.CRYPTO_KEY) |
    (1 << SourceType.SESSION_TOKEN) |
    (1 << SourceType.PRIVATE_DATA)
)

NUM_SOURCE_TYPES = 16  # |T|


# ============================================================================
# SINK TYPE ENUMERATION
# ============================================================================
# |K| = 32 distinct sink types (fits in 32-bit bitvector)

class SinkType(IntEnum):
    """
    Security sink types (K) - enumerated for bitvector encoding.
    
    Each sink type corresponds to one or more CodeQL queries.
    The κ bitvector tracks which sink types a value has been sanitized for.
    """
    # Injection sinks (τ check) - CWE-089 through CWE-943
    SQL_EXECUTE = 0           # CWE-089: SQL Injection
    COMMAND_SHELL = 1         # CWE-078: OS Command Injection
    CODE_EVAL = 2             # CWE-094: Code Injection (eval/exec)
    FILE_PATH = 3             # CWE-022: Path Traversal
    LDAP_QUERY = 4            # CWE-090: LDAP Injection
    XPATH_QUERY = 5           # CWE-643: XPath Injection
    NOSQL_QUERY = 6           # CWE-943: NoSQL Injection
    REGEX_PATTERN = 7         # CWE-730: ReDoS
    HTTP_REQUEST = 8          # CWE-918: SSRF
    XML_PARSE = 9             # CWE-611: XXE
    DESERIALIZE = 10          # CWE-502: Deserialization
    HEADER_SET = 11           # CWE-113: Header Injection
    HTML_OUTPUT = 12          # CWE-079: XSS
    REDIRECT_URL = 13         # CWE-601: Open Redirect
    COOKIE_VALUE = 14         # CWE-020: Cookie Tampering
    TEMPLATE_RENDER = 15      # CWE-1336: Template Injection
    LOG_FORGING = 16          # CWE-117: Log Forging
    EMAIL_HEADER = 17         # CWE-093: Email Header Injection
    
    # Sensitive data sinks (σ check) - cleartext/exposure
    LOG_OUTPUT = 18           # CWE-532: Cleartext Logging
    FILE_WRITE = 19           # CWE-312: Cleartext Storage
    NETWORK_SEND = 20         # CWE-319: Cleartext Transmission
    EXCEPTION_MSG = 21        # CWE-209: Stack Trace Exposure
    HTTP_RESPONSE = 22        # CWE-200: Information Exposure
    DEBUG_OUTPUT = 23         # Debug/error messages
    
    # Cryptographic sinks
    CRYPTO_WEAK = 24          # CWE-327: Weak Crypto
    CRYPTO_KEY_USE = 25       # CWE-321: Hard-coded Key
    RANDOM_SEED = 26          # CWE-330: Weak Random
    HASH_PASSWORD = 27        # CWE-328: Reversible Password Hash
    
    # Resource access sinks
    NETWORK_BIND = 28         # CWE-284: Unauthorized Bind
    FILE_CHMOD = 29           # CWE-732: Incorrect Permissions
    RESOURCE_ALLOC = 30       # CWE-400: Resource Exhaustion
    PROCESS_CREATE = 31       # CWE-269: Improper Privilege


NUM_SINK_TYPES = 32  # |K|


# ============================================================================
# SANITIZER TYPE ENUMERATION
# ============================================================================
# Each sanitizer clears specific sink types (adds bits to κ)

class SanitizerType(IntEnum):
    """
    Sanitizer types - each sanitizer makes a value safe for specific sinks.
    
    The mapping from sanitizer to applicable sinks is defined in
    SANITIZER_TO_SINKS below.
    """
    # SQL
    PARAMETERIZED_QUERY = 0
    ORM_ESCAPE = 1
    SQL_ESCAPE = 2
    
    # Command
    SHELL_QUOTE = 3
    ARRAY_COMMAND = 4
    
    # Path
    BASENAME = 5
    REALPATH_CHECK = 6
    SECURE_FILENAME = 7
    CANONICALIZE = 8
    
    # XSS/HTML
    HTML_ESCAPE = 9
    TEMPLATE_AUTOESCAPE = 10
    DOM_PURIFY = 11
    
    # URL
    URL_VALIDATE = 12
    RELATIVE_URL = 13
    URL_PARSE_VALIDATE = 14
    
    # Regex
    RE_ESCAPE = 15
    
    # Deserialization
    SAFE_LOADER = 16
    JSON_PARSE = 17
    
    # LDAP
    LDAP_ESCAPE = 18
    
    # XPath
    XPATH_ESCAPE = 19
    
    # XML
    DISABLE_ENTITIES = 20
    DEFUSED_XML = 21
    
    # Header
    HEADER_SANITIZE = 22
    
    # Type conversion
    TYPE_CONVERSION = 23
    ALLOWLIST_CHECK = 24
    
    # Declassification (for σ)
    ENCRYPTION = 25
    HASHING = 26
    REDACTION = 27
    TOKENIZATION = 28
    
    # Regex validation patterns (constrains input domain)
    REGEX_ALPHANUMERIC = 29    # ^[a-zA-Z0-9_]+$
    REGEX_DIGITS = 30          # ^\d+$
    REGEX_HOSTNAME = 31        # ^[a-z0-9.-]+$
    REGEX_EMAIL = 32           # email validation pattern
    REGEX_UUID = 33            # UUID pattern
    REGEX_FILEPATH = 34        # safe filepath pattern
    REGEX_URL_PATH = 35        # URL path component pattern
    REGEX_SLUG = 36            # ^[a-z0-9-]+$
    REGEX_HEX = 37             # ^[0-9a-fA-F]+$
    REGEX_BASE64 = 38          # Base64 pattern


NUM_SANITIZER_TYPES = 39


# Mapping: sanitizer -> set of sink types it makes safe
SANITIZER_TO_SINKS: Dict[SanitizerType, FrozenSet[SinkType]] = {
    SanitizerType.PARAMETERIZED_QUERY: frozenset({SinkType.SQL_EXECUTE}),
    SanitizerType.ORM_ESCAPE: frozenset({SinkType.SQL_EXECUTE}),
    SanitizerType.SQL_ESCAPE: frozenset({SinkType.SQL_EXECUTE}),
    
    SanitizerType.SHELL_QUOTE: frozenset({SinkType.COMMAND_SHELL}),
    SanitizerType.ARRAY_COMMAND: frozenset({SinkType.COMMAND_SHELL, SinkType.PROCESS_CREATE}),
    
    SanitizerType.BASENAME: frozenset({SinkType.FILE_PATH}),
    SanitizerType.REALPATH_CHECK: frozenset({SinkType.FILE_PATH}),
    SanitizerType.SECURE_FILENAME: frozenset({SinkType.FILE_PATH}),
    SanitizerType.CANONICALIZE: frozenset({SinkType.FILE_PATH}),
    
    SanitizerType.HTML_ESCAPE: frozenset({SinkType.HTML_OUTPUT, SinkType.TEMPLATE_RENDER}),
    SanitizerType.TEMPLATE_AUTOESCAPE: frozenset({SinkType.HTML_OUTPUT, SinkType.TEMPLATE_RENDER}),
    SanitizerType.DOM_PURIFY: frozenset({SinkType.HTML_OUTPUT}),
    
    SanitizerType.URL_VALIDATE: frozenset({SinkType.REDIRECT_URL, SinkType.HTTP_REQUEST}),
    SanitizerType.RELATIVE_URL: frozenset({SinkType.REDIRECT_URL}),
    SanitizerType.URL_PARSE_VALIDATE: frozenset({SinkType.HTTP_REQUEST, SinkType.REDIRECT_URL}),
    
    SanitizerType.RE_ESCAPE: frozenset({SinkType.REGEX_PATTERN}),
    
    SanitizerType.SAFE_LOADER: frozenset({SinkType.DESERIALIZE}),
    SanitizerType.JSON_PARSE: frozenset({SinkType.DESERIALIZE}),
    
    SanitizerType.LDAP_ESCAPE: frozenset({SinkType.LDAP_QUERY}),
    SanitizerType.XPATH_ESCAPE: frozenset({SinkType.XPATH_QUERY}),
    
    SanitizerType.DISABLE_ENTITIES: frozenset({SinkType.XML_PARSE}),
    SanitizerType.DEFUSED_XML: frozenset({SinkType.XML_PARSE}),
    
    SanitizerType.HEADER_SANITIZE: frozenset({SinkType.HEADER_SET, SinkType.EMAIL_HEADER}),
    
    SanitizerType.TYPE_CONVERSION: frozenset({
        SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL
    }),
    SanitizerType.ALLOWLIST_CHECK: frozenset({
        SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL,
        SinkType.HTTP_REQUEST, SinkType.REDIRECT_URL
    }),
    
    # Declassification sanitizers (for sensitive data)
    SanitizerType.ENCRYPTION: frozenset({
        SinkType.LOG_OUTPUT, SinkType.FILE_WRITE, SinkType.NETWORK_SEND,
        SinkType.HTTP_RESPONSE, SinkType.DEBUG_OUTPUT
    }),
    SanitizerType.HASHING: frozenset({
        SinkType.LOG_OUTPUT, SinkType.FILE_WRITE, SinkType.HASH_PASSWORD
    }),
    SanitizerType.REDACTION: frozenset({
        SinkType.LOG_OUTPUT, SinkType.EXCEPTION_MSG, SinkType.DEBUG_OUTPUT
    }),
    SanitizerType.TOKENIZATION: frozenset({
        SinkType.HTTP_RESPONSE, SinkType.FILE_WRITE
    }),
    
    # Regex validation patterns - constrain input domain
    SanitizerType.REGEX_ALPHANUMERIC: frozenset({
        SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL,
        SinkType.LDAP_QUERY, SinkType.NOSQL_QUERY
    }),
    SanitizerType.REGEX_DIGITS: frozenset({
        SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL,
        SinkType.LDAP_QUERY, SinkType.NOSQL_QUERY
    }),
    SanitizerType.REGEX_HOSTNAME: frozenset({
        SinkType.HTTP_REQUEST, SinkType.REDIRECT_URL, SinkType.SQL_EXECUTE,
        SinkType.FILE_PATH, SinkType.NETWORK_BIND
    }),
    SanitizerType.REGEX_EMAIL: frozenset({
        SinkType.SQL_EXECUTE, SinkType.EMAIL_HEADER, SinkType.LDAP_QUERY
    }),
    SanitizerType.REGEX_UUID: frozenset({
        SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.HTTP_REQUEST
    }),
    SanitizerType.REGEX_FILEPATH: frozenset({
        SinkType.FILE_PATH, SinkType.SQL_EXECUTE
    }),
    SanitizerType.REGEX_URL_PATH: frozenset({
        SinkType.HTTP_REQUEST, SinkType.REDIRECT_URL
    }),
    SanitizerType.REGEX_SLUG: frozenset({
        SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.HTTP_REQUEST,
        SinkType.REDIRECT_URL
    }),
    SanitizerType.REGEX_HEX: frozenset({
        SinkType.SQL_EXECUTE, SinkType.FILE_PATH, SinkType.COMMAND_SHELL
    }),
    SanitizerType.REGEX_BASE64: frozenset({
        SinkType.SQL_EXECUTE, SinkType.FILE_PATH
    }),
}


# ============================================================================
# Z3 BITVECTOR TYPES
# ============================================================================

# Type aliases for Z3 bitvectors
TaintBV = z3.BitVecRef      # 16-bit for τ (untrusted sources)
SanitizedBV = z3.BitVecRef  # 32-bit for κ (sanitized sinks)
SensitiveBV = z3.BitVecRef  # 16-bit for σ (sensitivity sources)

TAU_WIDTH = 16       # Bits for τ (untrusted taint sources)
KAPPA_WIDTH = 32     # Bits for κ (sanitized sink types)
SIGMA_WIDTH = 16     # Bits for σ (sensitivity sources)


def tau_zero() -> z3.BitVecVal:
    """Create zero bitvector for τ (no untrusted taint)."""
    return z3.BitVecVal(0, TAU_WIDTH)


def kappa_full() -> z3.BitVecVal:
    """Create full bitvector for κ (sanitized for all sinks)."""
    return z3.BitVecVal((1 << KAPPA_WIDTH) - 1, KAPPA_WIDTH)


def kappa_zero() -> z3.BitVecVal:
    """Create zero bitvector for κ (not sanitized for any sink)."""
    return z3.BitVecVal(0, KAPPA_WIDTH)


def sigma_zero() -> z3.BitVecVal:
    """Create zero bitvector for σ (no sensitivity)."""
    return z3.BitVecVal(0, SIGMA_WIDTH)


# ============================================================================
# TAINT LABEL (CONCRETE)
# ============================================================================

@dataclass(frozen=True)
class TaintLabel:
    """
    Concrete taint label: ℓ = (τ, κ, σ) as Python integers (bitmasks).
    
    This is the concrete (non-symbolic) representation for efficient tracking
    during execution. For Z3 symbolic reasoning, use SymbolicTaintLabel.
    
    Invariants:
        - τ & SENSITIVE_SOURCES_MASK == 0 (untrusted ⊆ untrusted sources)
        - σ & UNTRUSTED_SOURCES_MASK == 0 (sensitivity ⊆ sensitivity sources)
    """
    tau: int = 0       # Untrusted source bitmask
    kappa: int = (1 << KAPPA_WIDTH) - 1  # Sanitized sinks (default: all)
    sigma: int = 0     # Sensitivity source bitmask
    
    # Provenance tracking (optional, for error messages)
    provenance: FrozenSet[str] = field(default_factory=frozenset)
    
    @staticmethod
    def clean() -> 'TaintLabel':
        """The bottom element ⊥ = (∅, K, ∅): clean, sanitized for all."""
        return TaintLabel()
    
    @staticmethod
    def from_untrusted_source(source: SourceType, location: str = "") -> 'TaintLabel':
        """Create label from an untrusted source (τ set)."""
        prov = frozenset({f"{source.name}@{location}"}) if location else frozenset()
        return TaintLabel(
            tau=1 << source,
            kappa=0,  # Not sanitized for anything yet
            sigma=0,
            provenance=prov
        )
    
    @staticmethod
    def from_sensitive_source(source: SourceType, location: str = "") -> 'TaintLabel':
        """Create label from a sensitive source (σ set)."""
        prov = frozenset({f"{source.name}@{location}"}) if location else frozenset()
        return TaintLabel(
            tau=0,
            kappa=0,  # Not declassified for any sink - needs explicit declassification
            sigma=1 << source,
            provenance=prov
        )
    
    def join(self, other: 'TaintLabel') -> 'TaintLabel':
        """
        Lattice join: ℓ₁ ⊔ ℓ₂ = (τ₁ ∪ τ₂, κ₁ ∩ κ₂, σ₁ ∪ σ₂).
        
        Taint merges through data combination:
        - Untrusted taint is inherited from both (∪)
        - Sanitization only preserved if both were sanitized (∩)
        - Sensitivity inherited from both (∪)
        """
        return TaintLabel(
            tau=self.tau | other.tau,
            kappa=self.kappa & other.kappa,
            sigma=self.sigma | other.sigma,
            provenance=self.provenance | other.provenance
        )
    
    def sanitize(self, sanitizer: SanitizerType) -> 'TaintLabel':
        """
        Apply sanitizer: adds sink types to κ (sanitized set).
        
        Does NOT remove taint sources - only marks value as safe for specific sinks.
        """
        sinks = SANITIZER_TO_SINKS.get(sanitizer, frozenset())
        new_kappa = self.kappa
        for sink in sinks:
            new_kappa |= (1 << sink)
        return TaintLabel(
            tau=self.tau,
            kappa=new_kappa,
            sigma=self.sigma,
            provenance=self.provenance
        )
    
    def is_safe_for_sink(self, sink: SinkType) -> bool:
        """
        Check if value is safe for a given sink type.
        
        Safe_k(ℓ) ⟺ (τ = ∅) ∨ (k ∈ κ)  for injection sinks
        Safe_k(ℓ) ⟺ (σ = ∅) ∨ (k ∈ κ)  for sensitive sinks
        Safe_k(ℓ) ⟺ (τ = ∅ ∧ σ = ∅) ∨ (k ∈ κ)  for deserialization (both)
        
        For injection sinks: no untrusted taint OR sanitized for this sink.
        For sensitive sinks: no sensitivity OR declassified.
        For deserialization: no untrusted AND no sensitive OR sanitized.
        """
        import os
        TAINT_DEBUG = os.environ.get('TAINT_DEBUG') == '1'
        
        sink_bit = 1 << sink
        
        # Deserialization sinks (check BOTH τ and σ)
        # Unsafe if EITHER untrusted input OR sensitive data is deserialized
        if sink == SinkType.DESERIALIZE:
            result = ((self.tau == 0 and self.sigma == 0) or ((self.kappa & sink_bit) != 0))
            if TAINT_DEBUG:
                print(f"               [is_safe_for_sink] Deserialization sink check:")
                print(f"                 τ={bin(self.tau)}, σ={bin(self.sigma)}, κ={bin(self.kappa)}, sink_bit={bin(sink_bit)}")
                print(f"                 (τ == 0 and σ == 0) = {self.tau == 0 and self.sigma == 0}")
                print(f"                 (κ & sink_bit) = {self.kappa & sink_bit}")
                print(f"                 → result = {result}")
            return result
        
        # Injection sinks (check τ)
        if sink <= SinkType.EMAIL_HEADER:
            result = (self.tau == 0) or ((self.kappa & sink_bit) != 0)
            if TAINT_DEBUG:
                print(f"               [is_safe_for_sink] Injection sink check:")
                print(f"                 τ={bin(self.tau)}, κ={bin(self.kappa)}, sink_bit={bin(sink_bit)}")
                print(f"                 (τ == 0) = {self.tau == 0}")
                print(f"                 (κ & sink_bit) = {self.kappa & sink_bit}")
                print(f"                 → result = {result}")
            return result
        
        # Sensitive data sinks (check σ)
        result = (self.sigma == 0) or ((self.kappa & sink_bit) != 0)
        if TAINT_DEBUG:
            print(f"               [is_safe_for_sink] Sensitive sink check:")
            print(f"                 σ={bin(self.sigma)}, κ={bin(self.kappa)}, sink_bit={bin(sink_bit)}")
            print(f"                 (σ == 0) = {self.sigma == 0}")
            print(f"                 (κ & sink_bit) = {self.kappa & sink_bit}")
            print(f"                 → result = {result}")
        return result
    
    def has_untrusted_taint(self) -> bool:
        """Check if τ ≠ ∅ (has any untrusted taint)."""
        return self.tau != 0
    
    def has_sensitivity(self) -> bool:
        """Check if σ ≠ ∅ (has any sensitivity)."""
        return self.sigma != 0
    
    def has_any_taint(self) -> bool:
        """Check if τ ≠ ∅ ∨ σ ≠ ∅ (has any taint at all)."""
        return self.tau != 0 or self.sigma != 0
    
    def has_sensitivity_taint(self) -> bool:
        """Alias for has_sensitivity() for consistency with API."""
        return self.has_sensitivity()
    
    def with_sensitivity(self, source: SourceType) -> 'TaintLabel':
        """
        Add sensitivity taint (σ) from a source.
        
        Used for runtime inference: when we see dict['password'], add PASSWORD sensitivity.
        """
        return TaintLabel(
            tau=self.tau,
            kappa=self.kappa,
            sigma=self.sigma | (1 << source),
            provenance=self.provenance | frozenset({source.name})
        )
    
    def is_sanitized_for(self, sink: SinkType) -> bool:
        """Check if k ∈ κ (sanitized for specific sink)."""
        return (self.kappa & (1 << sink)) != 0
    
    def get_untrusted_sources(self) -> Set[SourceType]:
        """Get the set of untrusted sources in τ."""
        return {s for s in SourceType if (self.tau & (1 << s)) != 0 and s < 9}
    
    def get_sensitivity_sources(self) -> Set[SourceType]:
        """Get the set of sensitivity sources in σ."""
        return {s for s in SourceType if (self.sigma & (1 << s)) != 0 and s >= 9}


# ============================================================================
# SYMBOLIC TAINT LABEL (Z3)
# ============================================================================

@dataclass
class SymbolicTaintLabel:
    """
    Symbolic taint label: ℓ = (τ, κ, σ) as Z3 bitvectors.
    
    Used in Mode A (pure symbolic) for sound over-approximation.
    Enables SMT-based reasoning about all possible taint flows.
    """
    tau: z3.BitVecRef      # 16-bit untrusted sources
    kappa: z3.BitVecRef    # 32-bit sanitized sinks
    sigma: z3.BitVecRef    # 16-bit sensitivity sources
    
    @staticmethod
    def clean() -> 'SymbolicTaintLabel':
        """The bottom element ⊥ = (0, 0xFFFFFFFF, 0): clean, fully sanitized."""
        return SymbolicTaintLabel(
            tau=tau_zero(),
            kappa=kappa_full(),
            sigma=sigma_zero()
        )
    
    @staticmethod
    def fresh(name: str) -> 'SymbolicTaintLabel':
        """Create fresh symbolic taint label with unconstrained variables."""
        return SymbolicTaintLabel(
            tau=z3.BitVec(f"{name}_tau", TAU_WIDTH),
            kappa=z3.BitVec(f"{name}_kappa", KAPPA_WIDTH),
            sigma=z3.BitVec(f"{name}_sigma", SIGMA_WIDTH)
        )
    
    @staticmethod
    def from_untrusted_source(source: SourceType) -> 'SymbolicTaintLabel':
        """Create label from an untrusted source (τ bit set, κ=0)."""
        return SymbolicTaintLabel(
            tau=z3.BitVecVal(1 << source, TAU_WIDTH),
            kappa=kappa_zero(),  # Not sanitized
            sigma=sigma_zero()
        )
    
    @staticmethod
    def from_sensitive_source(source: SourceType) -> 'SymbolicTaintLabel':
        """Create label from a sensitive source (σ bit set)."""
        return SymbolicTaintLabel(
            tau=tau_zero(),
            kappa=kappa_full(),  # Sensitivity doesn't need sanitization
            sigma=z3.BitVecVal(1 << source, SIGMA_WIDTH)
        )
    
    def join(self, other: 'SymbolicTaintLabel') -> 'SymbolicTaintLabel':
        """
        Symbolic lattice join: ℓ₁ ⊔ ℓ₂ = (τ₁ | τ₂, κ₁ & κ₂, σ₁ | σ₂).
        """
        return SymbolicTaintLabel(
            tau=self.tau | other.tau,
            kappa=self.kappa & other.kappa,
            sigma=self.sigma | other.sigma
        )
    
    def sanitize(self, sink: SinkType) -> 'SymbolicTaintLabel':
        """Add a single sink to the sanitized set."""
        sink_bit = z3.BitVecVal(1 << sink, KAPPA_WIDTH)
        return SymbolicTaintLabel(
            tau=self.tau,
            kappa=self.kappa | sink_bit,
            sigma=self.sigma
        )
    
    def sanitize_many(self, sinks: FrozenSet[SinkType]) -> 'SymbolicTaintLabel':
        """Add multiple sinks to the sanitized set."""
        sink_mask = sum(1 << s for s in sinks)
        return SymbolicTaintLabel(
            tau=self.tau,
            kappa=self.kappa | z3.BitVecVal(sink_mask, KAPPA_WIDTH),
            sigma=self.sigma
        )
    
    def is_safe_for_sink_constraint(self, sink: SinkType) -> z3.BoolRef:
        """
        Create Z3 constraint for sink safety.
        
        Safe_k(ℓ) ⟺ (τ = 0) ∨ ((κ >> k) & 1 = 1)
        
        For injection sinks: check τ.
        For sensitive sinks: check σ.
        """
        sink_bit = z3.BitVecVal(1 << sink, KAPPA_WIDTH)
        sanitized = (self.kappa & sink_bit) != z3.BitVecVal(0, KAPPA_WIDTH)
        
        # Injection sinks (check τ)
        if sink <= SinkType.EMAIL_HEADER:
            no_taint = self.tau == tau_zero()
            return z3.Or(no_taint, sanitized)
        
        # Sensitive data sinks (check σ)
        no_sensitivity = self.sigma == sigma_zero()
        return z3.Or(no_sensitivity, sanitized)
    
    def is_unsafe_for_sink_constraint(self, sink: SinkType) -> z3.BoolRef:
        """
        Create Z3 constraint for sink UNSAFETY (for bug detection).
        
        Unsafe_k(ℓ) ⟺ (τ ≠ 0) ∧ (k ∉ κ)  [for injection sinks]
        Unsafe_k(ℓ) ⟺ (σ ≠ 0) ∧ (k ∉ κ)  [for sensitive sinks]
        """
        return z3.Not(self.is_safe_for_sink_constraint(sink))
    
    def with_sensitivity(self, source: SourceType) -> 'SymbolicTaintLabel':
        """
        Add sensitivity taint (σ) from a source.
        
        Used for runtime inference: when we see dict['password'], add PASSWORD sensitivity.
        """
        return SymbolicTaintLabel(
            tau=self.tau,
            kappa=self.kappa,
            sigma=self.sigma | z3.BitVecVal(1 << source, SIGMA_WIDTH)
        )


# ============================================================================
# CODEQL BUG TYPE MAPPING
# ============================================================================
# Maps each of the 47 CodeQL security queries to (sink_type, check_tau_or_sigma, cwe)

@dataclass(frozen=True)
class SecurityBugType:
    """Definition of a security bug type from CodeQL."""
    name: str
    cwe: str
    sink_type: SinkType
    checks_tau: bool = True   # Check untrusted taint (τ)
    checks_sigma: bool = False  # Check sensitivity (σ)
    description: str = ""


# All 47 CodeQL security bug types
CODEQL_BUG_TYPES: Dict[str, SecurityBugType] = {
    # ===== INJECTION BUGS (check τ) =====
    
    # SQL Injection family
    "SQL_INJECTION": SecurityBugType(
        "SQL_INJECTION", "CWE-089", SinkType.SQL_EXECUTE,
        description="SQL query built from untrusted input"
    ),
    "SQLI_WITH_FORMAT": SecurityBugType(
        "SQLI_WITH_FORMAT", "CWE-089", SinkType.SQL_EXECUTE,
        description="SQL query built with string formatting"
    ),
    
    # Command Injection family
    "COMMAND_INJECTION": SecurityBugType(
        "COMMAND_INJECTION", "CWE-078", SinkType.COMMAND_SHELL,
        description="OS command built from untrusted input"
    ),
    "SHELL_COMMAND_CONSTRUCTION": SecurityBugType(
        "SHELL_COMMAND_CONSTRUCTION", "CWE-078", SinkType.COMMAND_SHELL,
        description="Shell command string constructed unsafely"
    ),
    
    # Code Injection family
    "CODE_INJECTION": SecurityBugType(
        "CODE_INJECTION", "CWE-094", SinkType.CODE_EVAL,
        description="Code evaluated from untrusted input"
    ),
    "EVAL_INJECTION": SecurityBugType(
        "EVAL_INJECTION", "CWE-095", SinkType.CODE_EVAL,
        description="eval() called with untrusted input"
    ),
    "EXEC_INJECTION": SecurityBugType(
        "EXEC_INJECTION", "CWE-094", SinkType.CODE_EVAL,
        description="exec() called with untrusted input"
    ),
    
    # Path Traversal family
    "PATH_INJECTION": SecurityBugType(
        "PATH_INJECTION", "CWE-022", SinkType.FILE_PATH,
        description="File path constructed from untrusted input"
    ),
    "TARSLIP": SecurityBugType(
        "TARSLIP", "CWE-022", SinkType.FILE_PATH,
        description="Tar extraction with path traversal"
    ),
    "ZIPSLIP": SecurityBugType(
        "ZIPSLIP", "CWE-022", SinkType.FILE_PATH,
        description="Zip extraction with path traversal"
    ),
    
    # LDAP Injection
    "LDAP_INJECTION": SecurityBugType(
        "LDAP_INJECTION", "CWE-090", SinkType.LDAP_QUERY,
        description="LDAP query built from untrusted input"
    ),
    
    # XPath Injection
    "XPATH_INJECTION": SecurityBugType(
        "XPATH_INJECTION", "CWE-643", SinkType.XPATH_QUERY,
        description="XPath query built from untrusted input"
    ),
    
    # NoSQL Injection
    "NOSQL_INJECTION": SecurityBugType(
        "NOSQL_INJECTION", "CWE-943", SinkType.NOSQL_QUERY,
        description="NoSQL query built from untrusted input"
    ),
    
    # ReDoS
    "REGEX_INJECTION": SecurityBugType(
        "REGEX_INJECTION", "CWE-730", SinkType.REGEX_PATTERN,
        description="Regex pattern from untrusted input (ReDoS)"
    ),
    "POLYNOMIAL_REDOS": SecurityBugType(
        "POLYNOMIAL_REDOS", "CWE-1333", SinkType.REGEX_PATTERN,
        description="Polynomial-time regex with untrusted input"
    ),
    "EXPONENTIAL_REDOS": SecurityBugType(
        "EXPONENTIAL_REDOS", "CWE-1333", SinkType.REGEX_PATTERN,
        description="Exponential-time regex with untrusted input"
    ),
    
    # SSRF
    "SSRF": SecurityBugType(
        "SSRF", "CWE-918", SinkType.HTTP_REQUEST,
        description="HTTP request to untrusted URL"
    ),
    "FULL_SSRF": SecurityBugType(
        "FULL_SSRF", "CWE-918", SinkType.HTTP_REQUEST,
        description="Full URL controlled by attacker"
    ),
    "PARTIAL_SSRF": SecurityBugType(
        "PARTIAL_SSRF", "CWE-918", SinkType.HTTP_REQUEST,
        description="Partial URL (path) controlled by attacker"
    ),
    
    # XXE
    "XXE": SecurityBugType(
        "XXE", "CWE-611", SinkType.XML_PARSE,
        description="XML parsing with external entities enabled"
    ),
    "XXE_LOCAL_FILE": SecurityBugType(
        "XXE_LOCAL_FILE", "CWE-611", SinkType.XML_PARSE,
        description="XXE used for local file read"
    ),
    "XML_BOMB": SecurityBugType(
        "XML_BOMB", "CWE-776", SinkType.XML_PARSE,
        description="XML entity expansion attack (billion laughs)"
    ),
    
    # Deserialization
    "UNSAFE_DESERIALIZATION": SecurityBugType(
        "UNSAFE_DESERIALIZATION", "CWE-502", SinkType.DESERIALIZE,
        description="Deserialization of untrusted data"
    ),
    "PICKLE_INJECTION": SecurityBugType(
        "PICKLE_INJECTION", "CWE-502", SinkType.DESERIALIZE,
        description="Pickle load of untrusted data"
    ),
    "YAML_INJECTION": SecurityBugType(
        "YAML_INJECTION", "CWE-502", SinkType.DESERIALIZE,
        description="YAML load without SafeLoader"
    ),
    
    # Header Injection
    "HEADER_INJECTION": SecurityBugType(
        "HEADER_INJECTION", "CWE-113", SinkType.HEADER_SET,
        description="HTTP header value from untrusted input"
    ),
    
    # XSS
    "REFLECTED_XSS": SecurityBugType(
        "REFLECTED_XSS", "CWE-079", SinkType.HTML_OUTPUT,
        description="Reflected cross-site scripting"
    ),
    "STORED_XSS": SecurityBugType(
        "STORED_XSS", "CWE-079", SinkType.HTML_OUTPUT,
        description="Stored cross-site scripting"
    ),
    "DOM_XSS": SecurityBugType(
        "DOM_XSS", "CWE-079", SinkType.HTML_OUTPUT,
        description="DOM-based cross-site scripting"
    ),
    
    # Open Redirect
    "URL_REDIRECT": SecurityBugType(
        "URL_REDIRECT", "CWE-601", SinkType.REDIRECT_URL,
        description="Open redirect vulnerability"
    ),
    "UNVALIDATED_REDIRECT": SecurityBugType(
        "UNVALIDATED_REDIRECT", "CWE-601", SinkType.REDIRECT_URL,
        description="Redirect to unvalidated URL"
    ),
    
    # Template Injection
    "TEMPLATE_INJECTION": SecurityBugType(
        "TEMPLATE_INJECTION", "CWE-1336", SinkType.TEMPLATE_RENDER,
        description="Server-side template injection"
    ),
    "JINJA2_INJECTION": SecurityBugType(
        "JINJA2_INJECTION", "CWE-1336", SinkType.TEMPLATE_RENDER,
        description="Jinja2 template injection"
    ),
    
    # Log Forging
    "LOG_INJECTION": SecurityBugType(
        "LOG_INJECTION", "CWE-117", SinkType.LOG_FORGING,
        description="Log entries forged from untrusted input"
    ),
    
    # Email Header Injection
    "EMAIL_INJECTION": SecurityBugType(
        "EMAIL_INJECTION", "CWE-093", SinkType.EMAIL_HEADER,
        description="Email header injection"
    ),
    
    # Cookie Injection
    "COOKIE_INJECTION": SecurityBugType(
        "COOKIE_INJECTION", "CWE-020", SinkType.COOKIE_VALUE,
        description="Cookie value from untrusted input (cookie poisoning)"
    ),
    
    # ===== SENSITIVE DATA EXPOSURE (check σ) =====
    
    "CLEARTEXT_LOGGING": SecurityBugType(
        "CLEARTEXT_LOGGING", "CWE-532", SinkType.LOG_OUTPUT,
        checks_tau=False, checks_sigma=True,
        description="Sensitive data logged in cleartext"
    ),
    "CLEARTEXT_STORAGE": SecurityBugType(
        "CLEARTEXT_STORAGE", "CWE-312", SinkType.FILE_WRITE,
        checks_tau=False, checks_sigma=True,
        description="Sensitive data stored in cleartext"
    ),
    "CLEARTEXT_TRANSMISSION": SecurityBugType(
        "CLEARTEXT_TRANSMISSION", "CWE-319", SinkType.NETWORK_SEND,
        checks_tau=False, checks_sigma=True,
        description="Sensitive data transmitted in cleartext"
    ),
    "STACK_TRACE_EXPOSURE": SecurityBugType(
        "STACK_TRACE_EXPOSURE", "CWE-209", SinkType.EXCEPTION_MSG,
        checks_tau=False, checks_sigma=True,
        description="Stack trace exposed in error message"
    ),
    "INFORMATION_EXPOSURE": SecurityBugType(
        "INFORMATION_EXPOSURE", "CWE-200", SinkType.HTTP_RESPONSE,
        checks_tau=False, checks_sigma=True,
        description="Sensitive information exposed in response"
    ),
    
    # ===== CRYPTOGRAPHIC ISSUES =====
    
    "WEAK_CRYPTO": SecurityBugType(
        "WEAK_CRYPTO", "CWE-327", SinkType.CRYPTO_WEAK,
        description="Use of weak cryptographic algorithm"
    ),
    "WEAK_SENSITIVE_DATA_HASHING": SecurityBugType(
        "WEAK_SENSITIVE_DATA_HASHING", "CWE-327", SinkType.CRYPTO_WEAK,
        checks_tau=False, checks_sigma=True,
        description="Weak cryptographic hash for sensitive data (passwords, keys)"
    ),
    "HARDCODED_CREDENTIALS": SecurityBugType(
        "HARDCODED_CREDENTIALS", "CWE-321", SinkType.CRYPTO_KEY_USE,
        checks_tau=False, checks_sigma=True,
        description="Hard-coded cryptographic key or password"
    ),
    "WEAK_RANDOM": SecurityBugType(
        "WEAK_RANDOM", "CWE-330", SinkType.RANDOM_SEED,
        description="Weak random number generator for security"
    ),
    "INSECURE_HASH": SecurityBugType(
        "INSECURE_HASH", "CWE-328", SinkType.HASH_PASSWORD,
        description="Reversible or weak hash for passwords"
    ),
    
    # ===== RESOURCE CONTROL =====
    
    "RESOURCE_EXHAUSTION": SecurityBugType(
        "RESOURCE_EXHAUSTION", "CWE-400", SinkType.RESOURCE_ALLOC,
        description="Uncontrolled resource allocation"
    ),
    "DENIAL_OF_SERVICE": SecurityBugType(
        "DENIAL_OF_SERVICE", "CWE-400", SinkType.RESOURCE_ALLOC,
        description="Denial of service via resource exhaustion"
    ),
    "IMPROPER_PRIVILEGE": SecurityBugType(
        "IMPROPER_PRIVILEGE", "CWE-269", SinkType.PROCESS_CREATE,
        description="Improper privilege management"
    ),
    "INSECURE_PERMISSIONS": SecurityBugType(
        "INSECURE_PERMISSIONS", "CWE-732", SinkType.FILE_CHMOD,
        description="Incorrect file/directory permissions"
    ),
}


# ============================================================================
# UNSAFE REGION PREDICATES
# ============================================================================

def create_unsafe_region_constraint(
    bug_type: SecurityBugType,
    label: SymbolicTaintLabel,
    at_sink: z3.BoolRef = None
) -> z3.BoolRef:
    """
    Create Z3 constraint defining the unsafe region for a bug type.
    
    U_k = { s | pc = π_sink ∧ ¬Safe_k(ℓ_arg) }
    
    Returns constraint that is SAT iff state is in the unsafe region.
    """
    # Safety check based on bug type
    if bug_type.checks_tau:
        # Injection bug: check untrusted taint
        tainted = label.tau != tau_zero()
        not_sanitized = (label.kappa & z3.BitVecVal(1 << bug_type.sink_type, KAPPA_WIDTH)) == z3.BitVecVal(0, KAPPA_WIDTH)
        unsafe = z3.And(tainted, not_sanitized)
    else:
        # Sensitivity bug: check sensitivity
        sensitive = label.sigma != sigma_zero()
        not_declassified = (label.kappa & z3.BitVecVal(1 << bug_type.sink_type, KAPPA_WIDTH)) == z3.BitVecVal(0, KAPPA_WIDTH)
        unsafe = z3.And(sensitive, not_declassified)
    
    # If we have a predicate for "at sink location", conjoin it
    if at_sink is not None:
        return z3.And(at_sink, unsafe)
    return unsafe


def create_barrier_certificate(
    bug_type: SecurityBugType,
    label: SymbolicTaintLabel,
    guard_sanitized: z3.BoolRef = None
) -> z3.ArithRef:
    """
    Create a linear barrier certificate for security property.
    
    B(s) = δ_sink(pc) · (g_sanitized + (1-τ) - 0.5)
    
    where:
        - δ_sink(pc) = 1 at sink site, large positive otherwise
        - g_sanitized = 1 if sanitizer was applied
        - τ = 1 if tainted
    
    Positive (≥ 0.5) means safe, negative (≤ -0.5) means unsafe.
    """
    # Convert taint bits to 0/1 integers
    if bug_type.checks_tau:
        tainted = z3.If(label.tau != tau_zero(), z3.IntVal(1), z3.IntVal(0))
    else:
        tainted = z3.If(label.sigma != sigma_zero(), z3.IntVal(1), z3.IntVal(0))
    
    sanitized = z3.If(guard_sanitized, z3.IntVal(1), z3.IntVal(0)) if guard_sanitized else z3.IntVal(0)
    
    # Barrier: sanitized + (1 - tainted) - 0.5
    # = 0.5 if not tainted (safe)
    # = sanitized - 0.5 if tainted (safe only if sanitized)
    barrier = sanitized + (1 - tainted)
    return barrier


# ============================================================================
# SECURITY VIOLATION
# ============================================================================

@dataclass
class SecurityViolation:
    """A detected security violation with full lattice information."""
    bug_type: str
    cwe: str
    sink_type: SinkType
    sink_location: str
    
    # Full lattice state at violation point
    taint_label: TaintLabel
    
    # Message for reporting
    message: str
    
    # Confidence score (0.0-1.0) from multi-factor analysis
    confidence: float = 0.70  # Default moderate confidence

    # Quantitative reporting (barrier-compatible; does not affect verdicts)
    reachability_pts: ReachabilityIntervalPTS = field(default_factory=ReachabilityIntervalPTS.unknown)
    depth_k: Optional[int] = None  # First-hit depth in PTS_R when known
    witness: ConcreteWitnessEvidence = field(default_factory=lambda: ConcreteWitnessEvidence(present=False))
    risk_interval: Optional[RiskInterval] = None
    
    # Z3 path condition (for counterexample extraction)
    path_condition: Optional[z3.BoolRef] = None
    
    # Concrete witness values
    counterexample: Optional[Dict] = None
    
    def get_source_summary(self) -> str:
        """Get human-readable summary of taint sources."""
        sources = []
        for s in self.taint_label.get_untrusted_sources():
            sources.append(f"untrusted:{s.name}")
        for s in self.taint_label.get_sensitivity_sources():
            sources.append(f"sensitive:{s.name}")
        return ", ".join(sources) if sources else "unknown"


def create_violation(
    bug_type_name: str,
    sink_location: str,
    label: TaintLabel,
    is_guarded: bool = False,
    call_chain_length: int = 1,
    has_exception_handler: bool = False,
    in_framework_context: bool = False,
    taint_source_ids: Optional[Set[str]] = None,
) -> SecurityViolation:
    """
    Create a security violation from a sink check failure.
    
    Uses multi-factor confidence scoring (iter 428) to assess confidence.
    """
    from ..confidence_scoring import compute_security_confidence
    
    bug_type = CODEQL_BUG_TYPES.get(bug_type_name)
    if bug_type is None:
        # Fallback for unknown bug types
        return SecurityViolation(
            bug_type=bug_type_name,
            cwe="CWE-000",
            sink_type=SinkType.SQL_EXECUTE,  # Default
            sink_location=sink_location,
            taint_label=label,
            message=f"{bug_type_name}: Taint violation at {sink_location}",
            confidence=0.50,  # Low confidence for unknown bug types
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=["created_by=create_violation", "unknown_bug_type"]
            ),
        )
    
    # Build detailed message
    sources = label.get_untrusted_sources() | label.get_sensitivity_sources()
    source_names = [s.name for s in sources]
    
    # ITERATION 524: Include provenance chain for concrete taint path
    provenance_str = ""
    if label.provenance:
        provenance_list = sorted(label.provenance)
        provenance_str = f" Taint path: {' → '.join(provenance_list)}"
    
    # Compute multi-factor confidence score
    confidence = compute_security_confidence(
        label=label,
        sink_type=bug_type.sink_type,
        is_guarded=is_guarded,
        call_chain_length=call_chain_length,
        has_exception_handler=has_exception_handler,
        in_framework_context=in_framework_context,
        taint_sources=taint_source_ids,
    )
    
    return SecurityViolation(
        bug_type=bug_type.name,
        cwe=bug_type.cwe,
        sink_type=bug_type.sink_type,
        sink_location=sink_location,
        taint_label=label,
        message=f"{bug_type.name} ({bug_type.cwe}): {bug_type.description}. "
                f"Sources: {source_names}.{provenance_str} Location: {sink_location}",
        confidence=confidence,
        reachability_pts=ReachabilityIntervalPTS.unknown(
            evidence=["created_by=create_violation", f"sink={bug_type.sink_type.name}"]
        ),
    )


# ============================================================================
# LABEL TRANSFORMER FUNCTIONS
# ============================================================================

def label_join(l1: TaintLabel, l2: TaintLabel) -> TaintLabel:
    """Lattice join for binary operations."""
    return l1.join(l2)


def label_join_many(labels: List[TaintLabel]) -> TaintLabel:
    """Lattice join for n-ary operations (e.g., function call with many args)."""
    result = TaintLabel.clean()
    for label in labels:
        result = result.join(label)
    return result


def symbolic_label_join(l1: SymbolicTaintLabel, l2: SymbolicTaintLabel) -> SymbolicTaintLabel:
    """Symbolic lattice join."""
    return l1.join(l2)


def symbolic_label_join_many(labels: List[SymbolicTaintLabel]) -> SymbolicTaintLabel:
    """Symbolic lattice join for n-ary operations."""
    result = SymbolicTaintLabel.clean()
    for label in labels:
        result = result.join(label)
    return result


# ============================================================================
# PC TAINT (IMPLICIT FLOW TRACKING)
# ============================================================================

@dataclass
class PCTaint:
    """
    Program counter taint for implicit flow tracking.
    
    When branching on tainted data, the PC taint captures which sources
    influenced control flow. All assignments under this PC inherit the taint.
    """
    tau_pc: int = 0  # Untrusted sources influencing control flow
    sigma_pc: int = 0  # Sensitivity sources influencing control flow
    provenance_pc: frozenset = field(default_factory=frozenset)  # Provenance for PC taint
    
    def merge_from_condition(self, label: TaintLabel) -> 'PCTaint':
        """Merge condition's taint into PC taint (entering branch)."""
        return PCTaint(
            tau_pc=self.tau_pc | label.tau,
            sigma_pc=self.sigma_pc | label.sigma,
            provenance_pc=self.provenance_pc | label.provenance
        )
    
    def apply_to_assignment(self, label: TaintLabel) -> TaintLabel:
        """Apply PC taint to an assignment (for implicit flow)."""
        # When applying PC taint, the result is tainted but not sanitized
        # unless the original value was explicitly sanitized
        new_kappa = label.kappa if self.tau_pc == 0 else 0
        return TaintLabel(
            tau=label.tau | self.tau_pc,
            kappa=new_kappa,  # PC taint removes implicit sanitization
            sigma=label.sigma | self.sigma_pc,
            provenance=label.provenance | self.provenance_pc
        )
    
    def is_clean(self) -> bool:
        """Check if PC has no taint."""
        return self.tau_pc == 0 and self.sigma_pc == 0


@dataclass
class SymbolicPCTaint:
    """Symbolic PC taint for Z3 reasoning about implicit flows."""
    tau_pc: z3.BitVecRef
    sigma_pc: z3.BitVecRef
    
    @staticmethod
    def clean() -> 'SymbolicPCTaint':
        return SymbolicPCTaint(tau_zero(), sigma_zero())
    
    def merge_from_condition(self, label: SymbolicTaintLabel) -> 'SymbolicPCTaint':
        return SymbolicPCTaint(
            tau_pc=self.tau_pc | label.tau,
            sigma_pc=self.sigma_pc | label.sigma
        )
    
    def apply_to_assignment(self, label: SymbolicTaintLabel) -> SymbolicTaintLabel:
        return SymbolicTaintLabel(
            tau=label.tau | self.tau_pc,
            kappa=label.kappa,
            sigma=label.sigma | self.sigma_pc
        )


# ============================================================================
# BYTECODE-LEVEL TAINT TRANSFER FUNCTIONS
# ============================================================================

class BytecodeTaintTransfer:
    """
    Taint transfer functions for CPython bytecode opcodes.
    
    These implement the abstract semantics [[op]] : L → L for each
    bytecode instruction, enabling bytecode-level taint analysis.
    """
    
    @staticmethod
    def binary_op(left: TaintLabel, right: TaintLabel) -> TaintLabel:
        """
        Transfer for BINARY_ADD, BINARY_SUBTRACT, BINARY_MULTIPLY, etc.
        
        [[binop]](ℓ₁, ℓ₂) = ℓ₁ ⊔ ℓ₂
        """
        return left.join(right)
    
    @staticmethod
    def subscript(container: TaintLabel, index: TaintLabel) -> TaintLabel:
        """
        Transfer for BINARY_SUBSCR.
        
        [[subscr]](ℓ_container, ℓ_index) = ℓ_container ⊔ ℓ_index
        
        Note: Index taint propagates because attacker-controlled index
        can select attacker-controlled data from container.
        """
        return container.join(index)
    
    @staticmethod
    def store_subscr(container: TaintLabel, index: TaintLabel, value: TaintLabel) -> TaintLabel:
        """
        Transfer for STORE_SUBSCR. Returns taint of modified container.
        
        [[store_subscr]](ℓ_container, ℓ_index, ℓ_value) = ℓ_container ⊔ ℓ_value
        """
        return container.join(value)
    
    @staticmethod
    def attr_load(obj: TaintLabel) -> TaintLabel:
        """
        Transfer for LOAD_ATTR.
        
        [[getattr]](ℓ_obj) = ℓ_obj
        
        Attribute access preserves object taint.
        """
        return obj
    
    @staticmethod
    def attr_store(obj: TaintLabel, value: TaintLabel) -> TaintLabel:
        """
        Transfer for STORE_ATTR. Returns taint of modified object.
        
        [[setattr]](ℓ_obj, ℓ_value) = ℓ_obj ⊔ ℓ_value
        """
        return obj.join(value)
    
    @staticmethod
    def unary_op(operand: TaintLabel) -> TaintLabel:
        """
        Transfer for UNARY_NOT, UNARY_NEGATIVE, etc.
        
        [[unaryop]](ℓ) = ℓ
        """
        return operand
    
    @staticmethod
    def call(
        func: TaintLabel,
        args: List[TaintLabel],
        summary_return: Optional[TaintLabel] = None
    ) -> TaintLabel:
        """
        Transfer for CALL_FUNCTION / CALL.
        
        [[call]](ℓ_func, [ℓ_arg₁, ..., ℓ_argₙ]) = ⊔{ℓ_argᵢ} ⊔ ℓ_summary
        
        If function summary is available, use it; otherwise conservative.
        """
        result = label_join_many(args)
        if summary_return is not None:
            result = result.join(summary_return)
        return result
    
    @staticmethod
    def compare(left: TaintLabel, right: TaintLabel) -> TaintLabel:
        """
        Transfer for COMPARE_OP.
        
        [[compare]](ℓ₁, ℓ₂) = ℓ₁ ⊔ ℓ₂
        
        The boolean result carries the taint of both operands.
        """
        return left.join(right)
    
    @staticmethod
    def contains(container: TaintLabel, item: TaintLabel) -> TaintLabel:
        """
        Transfer for CONTAINS_OP (in/not in).
        
        [[contains]](ℓ_container, ℓ_item) = ℓ_container ⊔ ℓ_item
        """
        return container.join(item)
    
    @staticmethod
    def format_value(value: TaintLabel, fmt_spec: Optional[TaintLabel] = None) -> TaintLabel:
        """
        Transfer for FORMAT_VALUE (f-string formatting).
        
        [[format]](ℓ_value, ℓ_fmt) = ℓ_value ⊔ ℓ_fmt
        """
        if fmt_spec is not None:
            return value.join(fmt_spec)
        return value
    
    @staticmethod
    def build_string(parts: List[TaintLabel]) -> TaintLabel:
        """
        Transfer for BUILD_STRING (f-string concatenation).
        
        [[build_string]]([ℓ₁, ..., ℓₙ]) = ⊔{ℓᵢ}
        """
        return label_join_many(parts)
    
    @staticmethod
    def build_collection(elements: List[TaintLabel]) -> TaintLabel:
        """
        Transfer for BUILD_LIST, BUILD_TUPLE, BUILD_SET.
        
        [[build_collection]]([ℓ₁, ..., ℓₙ]) = ⊔{ℓᵢ}
        """
        return label_join_many(elements)
    
    @staticmethod
    def build_map(keys: List[TaintLabel], values: List[TaintLabel]) -> TaintLabel:
        """
        Transfer for BUILD_MAP.
        
        [[build_map]](keys, values) = ⊔{ℓ_kᵢ} ⊔ ⊔{ℓ_vᵢ}
        """
        return label_join_many(keys + values)
    
    @staticmethod
    def unpack_sequence(seq: TaintLabel, count: int) -> List[TaintLabel]:
        """
        Transfer for UNPACK_SEQUENCE.
        
        [[unpack]](ℓ_seq, n) = [ℓ_seq, ..., ℓ_seq]  (n copies)
        
        Each unpacked element inherits the sequence's taint.
        """
        return [seq] * count
    
    @staticmethod
    def import_name() -> TaintLabel:
        """
        Transfer for IMPORT_NAME.
        
        Imported modules are clean unless from untrusted sources.
        """
        return TaintLabel.clean()
    
    @staticmethod
    def list_extend(target: TaintLabel, source: TaintLabel) -> TaintLabel:
        """
        Transfer for LIST_EXTEND.
        
        [[list_extend]](ℓ_target, ℓ_source) = ℓ_target ⊔ ℓ_source
        """
        return target.join(source)


class SymbolicBytecodeTaintTransfer:
    """
    Symbolic (Z3) taint transfer functions for bytecode opcodes.
    
    Parallel to BytecodeTaintTransfer but operates on SymbolicTaintLabel
    for SMT-based reasoning.
    """
    
    @staticmethod
    def binary_op(left: SymbolicTaintLabel, right: SymbolicTaintLabel) -> SymbolicTaintLabel:
        """Symbolic binary operation transfer."""
        return left.join(right)
    
    @staticmethod
    def subscript(container: SymbolicTaintLabel, index: SymbolicTaintLabel) -> SymbolicTaintLabel:
        """Symbolic subscript transfer."""
        return container.join(index)
    
    @staticmethod
    def call(
        func: SymbolicTaintLabel,
        args: List[SymbolicTaintLabel],
        summary_return: Optional[SymbolicTaintLabel] = None
    ) -> SymbolicTaintLabel:
        """Symbolic call transfer."""
        result = symbolic_label_join_many(args)
        if summary_return is not None:
            result = result.join(summary_return)
        return result
    
    @staticmethod
    def compare(left: SymbolicTaintLabel, right: SymbolicTaintLabel) -> SymbolicTaintLabel:
        """Symbolic compare transfer."""
        return left.join(right)
    
    @staticmethod
    def build_collection(elements: List[SymbolicTaintLabel]) -> SymbolicTaintLabel:
        """Symbolic collection build transfer."""
        return symbolic_label_join_many(elements)
    
    @staticmethod
    def conditional_taint(
        cond: z3.BoolRef,
        if_true: SymbolicTaintLabel,
        if_false: SymbolicTaintLabel
    ) -> SymbolicTaintLabel:
        """
        Create a conditional taint label based on path condition.
        
        This enables path-sensitive taint tracking:
        [[ite]](φ, ℓ_true, ℓ_false) = ITE(φ, ℓ_true, ℓ_false)
        """
        return SymbolicTaintLabel(
            tau=z3.If(cond, if_true.tau, if_false.tau),
            kappa=z3.If(cond, if_true.kappa, if_false.kappa),
            sigma=z3.If(cond, if_true.sigma, if_false.sigma)
        )


# ============================================================================
# BYTECODE SINK DETECTION
# ============================================================================

# Mapping of dangerous function names to sink types for bytecode analysis
FUNCTION_TO_SINK: Dict[str, SinkType] = {
    # SQL
    'execute': SinkType.SQL_EXECUTE,
    'executemany': SinkType.SQL_EXECUTE,
    'executescript': SinkType.SQL_EXECUTE,
    'raw': SinkType.SQL_EXECUTE,  # Django ORM
    
    # Command execution
    'system': SinkType.COMMAND_SHELL,
    'popen': SinkType.COMMAND_SHELL,
    'spawn': SinkType.COMMAND_SHELL,
    'call': SinkType.COMMAND_SHELL,  # subprocess.call
    'run': SinkType.COMMAND_SHELL,   # subprocess.run
    'Popen': SinkType.PROCESS_CREATE,
    
    # Code evaluation
    'eval': SinkType.CODE_EVAL,
    'exec': SinkType.CODE_EVAL,
    'compile': SinkType.CODE_EVAL,
    
    # File operations
    'open': SinkType.FILE_PATH,
    'read': SinkType.FILE_PATH,
    'write': SinkType.FILE_WRITE,
    'unlink': SinkType.FILE_PATH,
    'remove': SinkType.FILE_PATH,
    'rmdir': SinkType.FILE_PATH,
    
    # Network
    'urlopen': SinkType.HTTP_REQUEST,
    'request': SinkType.HTTP_REQUEST,
    'get': SinkType.HTTP_REQUEST,
    'post': SinkType.HTTP_REQUEST,
    'send': SinkType.NETWORK_SEND,
    
    # Deserialization
    'load': SinkType.DESERIALIZE,  # pickle.load, yaml.load
    'loads': SinkType.DESERIALIZE,
    
    # XML
    'parse': SinkType.XML_PARSE,
    'fromstring': SinkType.XML_PARSE,
    
    # Logging
    'info': SinkType.LOG_OUTPUT,
    'debug': SinkType.LOG_OUTPUT,
    'warning': SinkType.LOG_OUTPUT,
    'error': SinkType.LOG_OUTPUT,
    'critical': SinkType.LOG_OUTPUT,
    
    # Templates
    'render': SinkType.TEMPLATE_RENDER,
    'render_template': SinkType.TEMPLATE_RENDER,
    'render_template_string': SinkType.TEMPLATE_RENDER,
    
    # Redirect
    'redirect': SinkType.REDIRECT_URL,
}

# Module-qualified sinks for more precise matching
MODULE_FUNCTION_TO_SINK: Dict[Tuple[str, str], SinkType] = {
    ('os', 'system'): SinkType.COMMAND_SHELL,
    ('os', 'popen'): SinkType.COMMAND_SHELL,
    ('os', 'execv'): SinkType.COMMAND_SHELL,
    ('os', 'execve'): SinkType.COMMAND_SHELL,
    ('os', 'spawnl'): SinkType.COMMAND_SHELL,
    ('subprocess', 'call'): SinkType.COMMAND_SHELL,
    ('subprocess', 'run'): SinkType.COMMAND_SHELL,
    ('subprocess', 'Popen'): SinkType.PROCESS_CREATE,
    ('pickle', 'load'): SinkType.DESERIALIZE,
    ('pickle', 'loads'): SinkType.DESERIALIZE,
    ('yaml', 'load'): SinkType.DESERIALIZE,
    ('yaml', 'unsafe_load'): SinkType.DESERIALIZE,
    ('sqlite3.Connection', 'execute'): SinkType.SQL_EXECUTE,
    ('sqlite3.Cursor', 'execute'): SinkType.SQL_EXECUTE,
    ('builtins', 'eval'): SinkType.CODE_EVAL,
    ('builtins', 'exec'): SinkType.CODE_EVAL,
    ('builtins', 'open'): SinkType.FILE_PATH,
    ('requests', 'get'): SinkType.HTTP_REQUEST,
    ('requests', 'post'): SinkType.HTTP_REQUEST,
    ('urllib.request', 'urlopen'): SinkType.HTTP_REQUEST,
    ('flask', 'redirect'): SinkType.REDIRECT_URL,
    ('django.shortcuts', 'redirect'): SinkType.REDIRECT_URL,
}


def get_sink_for_call(func_name: str, module: Optional[str] = None) -> Optional[SinkType]:
    """
    Determine the sink type for a function call at bytecode level.
    
    Used by bytecode analyzers to identify security-relevant sinks
    when processing CALL_FUNCTION / CALL opcodes.
    
    Args:
        func_name: The function name being called
        module: Optional module name for qualified lookup
    
    Returns:
        The SinkType if this is a known sink, None otherwise
    """
    # Try module-qualified lookup first
    if module:
        key = (module, func_name)
        if key in MODULE_FUNCTION_TO_SINK:
            return MODULE_FUNCTION_TO_SINK[key]
    
    # Fall back to unqualified function name
    return FUNCTION_TO_SINK.get(func_name)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Enums
    'SourceType', 'SinkType', 'SanitizerType',
    
    # Constants
    'NUM_SOURCE_TYPES', 'NUM_SINK_TYPES', 'NUM_SANITIZER_TYPES',
    'TAU_WIDTH', 'KAPPA_WIDTH', 'SIGMA_WIDTH',
    'UNTRUSTED_SOURCES_MASK', 'SENSITIVE_SOURCES_MASK',
    'SANITIZER_TO_SINKS',
    
    # Labels
    'TaintLabel', 'SymbolicTaintLabel',
    
    # PC Taint
    'PCTaint', 'SymbolicPCTaint',
    
    # Bug Types
    'SecurityBugType', 'CODEQL_BUG_TYPES',
    
    # Violations
    'SecurityViolation', 'create_violation',
    
    # Unsafe regions
    'create_unsafe_region_constraint', 'create_barrier_certificate',
    
    # Label operations
    'label_join', 'label_join_many',
    'symbolic_label_join', 'symbolic_label_join_many',
    
    # Z3 helpers
    'tau_zero', 'kappa_zero', 'kappa_full', 'sigma_zero',
    
    # Bytecode-level transfer functions
    'BytecodeTaintTransfer', 'SymbolicBytecodeTaintTransfer',
    
    # Bytecode sink detection
    'FUNCTION_TO_SINK', 'MODULE_FUNCTION_TO_SINK', 'get_sink_for_call',
]
