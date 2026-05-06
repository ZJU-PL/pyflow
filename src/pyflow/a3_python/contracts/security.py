"""
Security contracts for sources, sinks, and sanitizers (barrier-certificate-theory.md §11).

This module defines the security-relevant behavior of library functions:
- Sources: Functions that introduce tainted/sensitive data
- Sinks: Functions where tainted data causes security bugs
- Sanitizers: Functions that clean/validate data

Mode A (pure symbolic): All contracts are over-approximating relations R_f ⊇ Sem_f
Mode B (concolic): Optional concrete validation, does not affect verdicts
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Callable, FrozenSet
from enum import Enum
import z3

from a3_python.z3model.taint import (
    TaintSource, SinkType, SanitizerType, TaintState, TaintLabel,
    SecurityViolation, create_violation
)
from a3_python.z3model.values import SymbolicValue
from a3_python.contracts.relations import (
    RelationalSummary, RelationalCase, PostCondition, HavocCase,
    register_relational_summary
)


# ============================================================================
# SOURCE CONTRACTS
# ============================================================================

@dataclass
class SourceContract:
    """Contract for a taint source function."""
    function_id: str            # e.g., "os.environ.__getitem__"
    source_type: TaintSource    # Type of taint to apply
    is_sensitive: bool = False  # σ=1 vs τ=1
    arg_patterns: List[str] = field(default_factory=list)  # Arg patterns for sensitive detection
    description: str = ""


# Registry of source contracts
_source_contracts: Dict[str, SourceContract] = {}


def register_source(contract: SourceContract) -> None:
    """Register a taint source contract."""
    _source_contracts[contract.function_id] = contract


def get_source_contract(function_id: str) -> Optional[SourceContract]:
    """Get source contract for a function."""
    return _source_contracts.get(function_id)


def is_taint_source(function_id: str) -> bool:
    """Check if function is a taint source."""
    return function_id in _source_contracts


# ============================================================================
# SINK CONTRACTS
# ============================================================================

@dataclass
class SinkContract:
    """Contract for a security sink function."""
    function_id: str           # e.g., "cursor.execute"
    sink_type: SinkType        # Type of sink (determines bug type)
    tainted_arg_indices: List[int] = field(default_factory=list)  # Which args to check
    parameterized_check: bool = False  # For SQL: check if params provided
    shell_check: bool = False  # For subprocess: check shell=True
    description: str = ""


# Registry of sink contracts
_sink_contracts: Dict[str, SinkContract] = {}


def register_sink(contract: SinkContract) -> None:
    """Register a sink contract."""
    _sink_contracts[contract.function_id] = contract


def get_sink_contract(function_id: str) -> Optional[SinkContract]:
    """Get sink contract for a function."""
    return _sink_contracts.get(function_id)


def is_security_sink(function_id: str) -> bool:
    """Check if function is a security sink."""
    return function_id in _sink_contracts


# ============================================================================
# SANITIZER CONTRACTS
# ============================================================================

@dataclass
class SanitizerContract:
    """Contract for a sanitizer function."""
    function_id: str              # e.g., "shlex.quote"
    sanitizer_type: SanitizerType
    clears_untrusted: bool = True   # Clears τ
    clears_sensitive: bool = False  # Clears σ
    applicable_sinks: FrozenSet[SinkType] = field(default_factory=frozenset)
    description: str = ""


# Registry of sanitizer contracts
_sanitizer_contracts: Dict[str, SanitizerContract] = {}


def register_sanitizer(contract: SanitizerContract) -> None:
    """Register a sanitizer contract."""
    _sanitizer_contracts[contract.function_id] = contract


def get_sanitizer_contract(function_id: str) -> Optional[SanitizerContract]:
    """Get sanitizer contract for a function."""
    return _sanitizer_contracts.get(function_id)


def is_sanitizer(function_id: str) -> bool:
    """Check if function is a sanitizer."""
    return function_id in _sanitizer_contracts


# ============================================================================
# INITIALIZATION: REGISTER ALL SECURITY CONTRACTS
# ============================================================================

def init_security_contracts():
    """
    Initialize all security contracts for sources, sinks, and sanitizers.
    
    These are justified by Python library documentation and security best practices.
    """
    _init_source_contracts()
    _init_sink_contracts()
    _init_sanitizer_contracts()


def _init_source_contracts():
    """Register taint source contracts."""
    
    # ========== HTTP/Web Sources (τ=1) ==========
    
    # Django
    register_source(SourceContract(
        function_id="request.GET.__getitem__",
        source_type=TaintSource.HTTP_PARAM,
        description="Django GET parameter"
    ))
    register_source(SourceContract(
        function_id="request.GET.get",
        source_type=TaintSource.HTTP_PARAM,
        description="Django GET parameter (with default)"
    ))
    register_source(SourceContract(
        function_id="request.POST.__getitem__",
        source_type=TaintSource.HTTP_PARAM,
        description="Django POST parameter"
    ))
    register_source(SourceContract(
        function_id="request.POST.get",
        source_type=TaintSource.HTTP_PARAM,
        description="Django POST parameter (with default)"
    ))
    register_source(SourceContract(
        function_id="request.body",
        source_type=TaintSource.HTTP_PARAM,
        description="Django raw request body"
    ))
    
    # Flask
    register_source(SourceContract(
        function_id="request.args.get",
        source_type=TaintSource.HTTP_PARAM,
        description="Flask query parameter"
    ))
    register_source(SourceContract(
        function_id="request.args.__getitem__",
        source_type=TaintSource.HTTP_PARAM,
        description="Flask query parameter"
    ))
    register_source(SourceContract(
        function_id="request.form.get",
        source_type=TaintSource.HTTP_PARAM,
        description="Flask form parameter"
    ))
    register_source(SourceContract(
        function_id="request.form.__getitem__",
        source_type=TaintSource.HTTP_PARAM,
        description="Flask form parameter"
    ))
    register_source(SourceContract(
        function_id="request.get_json",
        source_type=TaintSource.HTTP_PARAM,
        description="Flask JSON body"
    ))
    register_source(SourceContract(
        function_id="request.data",
        source_type=TaintSource.HTTP_PARAM,
        description="Flask raw request data"
    ))
    register_source(SourceContract(
        function_id="request.cookies.get",
        source_type=TaintSource.HTTP_PARAM,
        description="Flask cookie value"
    ))
    
    # ========== User Input Sources (τ=1) ==========
    
    register_source(SourceContract(
        function_id="builtins.input",
        source_type=TaintSource.USER_INPUT,
        description="User console input"
    ))
    register_source(SourceContract(
        function_id="sys.stdin.read",
        source_type=TaintSource.USER_INPUT,
        description="Standard input read"
    ))
    register_source(SourceContract(
        function_id="sys.stdin.readline",
        source_type=TaintSource.USER_INPUT,
        description="Standard input readline"
    ))
    
    # ========== Environment Sources (τ=1) ==========
    
    register_source(SourceContract(
        function_id="os.environ.__getitem__",
        source_type=TaintSource.ENVIRONMENT,
        description="Environment variable"
    ))
    register_source(SourceContract(
        function_id="os.environ.get",
        source_type=TaintSource.ENVIRONMENT,
        description="Environment variable (with default)"
    ))
    register_source(SourceContract(
        function_id="os.getenv",
        source_type=TaintSource.ENVIRONMENT,
        description="Environment variable"
    ))
    
    # ========== Command Line Sources (τ=1) ==========
    
    register_source(SourceContract(
        function_id="sys.argv.__getitem__",
        source_type=TaintSource.ARGV,
        description="Command line argument"
    ))
    
    # ========== File Content Sources (τ=1) ==========
    
    register_source(SourceContract(
        function_id="file.read",
        source_type=TaintSource.FILE_CONTENT,
        description="File content read"
    ))
    register_source(SourceContract(
        function_id="file.readline",
        source_type=TaintSource.FILE_CONTENT,
        description="File line read"
    ))
    register_source(SourceContract(
        function_id="file.readlines",
        source_type=TaintSource.FILE_CONTENT,
        description="File lines read"
    ))
    register_source(SourceContract(
        function_id="pathlib.Path.read_text",
        source_type=TaintSource.FILE_CONTENT,
        description="Path read_text"
    ))
    register_source(SourceContract(
        function_id="pathlib.Path.read_bytes",
        source_type=TaintSource.FILE_CONTENT,
        description="Path read_bytes"
    ))
    
    # ========== Network Sources (τ=1) ==========
    
    register_source(SourceContract(
        function_id="socket.recv",
        source_type=TaintSource.NETWORK_RECV,
        description="Socket receive"
    ))
    register_source(SourceContract(
        function_id="socket.recvfrom",
        source_type=TaintSource.NETWORK_RECV,
        description="Socket receive with address"
    ))
    register_source(SourceContract(
        function_id="urllib.request.urlopen",
        source_type=TaintSource.NETWORK_RECV,
        description="URL content fetch"
    ))
    register_source(SourceContract(
        function_id="requests.get",
        source_type=TaintSource.NETWORK_RECV,
        description="HTTP GET response"
    ))
    register_source(SourceContract(
        function_id="requests.post",
        source_type=TaintSource.NETWORK_RECV,
        description="HTTP POST response"
    ))
    
    # ========== Database Sources (τ=1) ==========
    
    register_source(SourceContract(
        function_id="cursor.fetchone",
        source_type=TaintSource.DATABASE_RESULT,
        description="Database row"
    ))
    register_source(SourceContract(
        function_id="cursor.fetchall",
        source_type=TaintSource.DATABASE_RESULT,
        description="Database rows"
    ))
    register_source(SourceContract(
        function_id="cursor.fetchmany",
        source_type=TaintSource.DATABASE_RESULT,
        description="Database rows"
    ))
    
    # ========== Sensitive Sources (σ=1) ==========
    
    register_source(SourceContract(
        function_id="getpass.getpass",
        source_type=TaintSource.PASSWORD,
        is_sensitive=True,
        description="Password input"
    ))
    register_source(SourceContract(
        function_id="keyring.get_password",
        source_type=TaintSource.CREDENTIALS,
        is_sensitive=True,
        description="Keyring credential"
    ))


def _init_sink_contracts():
    """Register security sink contracts."""
    
    # ========== SQL Injection Sinks ==========
    
    register_sink(SinkContract(
        function_id="cursor.execute",
        sink_type=SinkType.SQL_EXECUTE,
        tainted_arg_indices=[0],  # First arg is query
        parameterized_check=True,  # Safe if params provided
        description="SQL query execution"
    ))
    register_sink(SinkContract(
        function_id="cursor.executemany",
        sink_type=SinkType.SQL_EXECUTE,
        tainted_arg_indices=[0],
        parameterized_check=True,
        description="SQL batch execution"
    ))
    register_sink(SinkContract(
        function_id="connection.execute",
        sink_type=SinkType.SQL_EXECUTE,
        tainted_arg_indices=[0],
        parameterized_check=True,
        description="SQLAlchemy execute"
    ))
    register_sink(SinkContract(
        function_id="engine.execute",
        sink_type=SinkType.SQL_EXECUTE,
        tainted_arg_indices=[0],
        parameterized_check=True,
        description="SQLAlchemy engine execute"
    ))
    register_sink(SinkContract(
        function_id="Model.objects.raw",
        sink_type=SinkType.SQL_EXECUTE,
        tainted_arg_indices=[0],
        parameterized_check=True,
        description="Django raw SQL"
    ))
    
    # ========== Command Injection Sinks ==========
    
    register_sink(SinkContract(
        function_id="os.system",
        sink_type=SinkType.COMMAND_SHELL,
        tainted_arg_indices=[0],
        description="Shell command execution"
    ))
    register_sink(SinkContract(
        function_id="os.popen",
        sink_type=SinkType.COMMAND_SHELL,
        tainted_arg_indices=[0],
        description="Shell command with pipe"
    ))
    register_sink(SinkContract(
        function_id="subprocess.call",
        sink_type=SinkType.COMMAND_SHELL,
        tainted_arg_indices=[0],
        shell_check=True,  # Only dangerous if shell=True
        description="Subprocess call"
    ))
    register_sink(SinkContract(
        function_id="subprocess.run",
        sink_type=SinkType.COMMAND_SHELL,
        tainted_arg_indices=[0],
        shell_check=True,
        description="Subprocess run"
    ))
    register_sink(SinkContract(
        function_id="subprocess.Popen",
        sink_type=SinkType.COMMAND_SHELL,
        tainted_arg_indices=[0],
        shell_check=True,
        description="Subprocess Popen"
    ))
    
    # ========== Code Injection Sinks ==========
    
    register_sink(SinkContract(
        function_id="builtins.eval",
        sink_type=SinkType.CODE_EVAL,
        tainted_arg_indices=[0],
        description="Dynamic code evaluation"
    ))
    register_sink(SinkContract(
        function_id="builtins.exec",
        sink_type=SinkType.CODE_EVAL,
        tainted_arg_indices=[0],
        description="Dynamic code execution"
    ))
    register_sink(SinkContract(
        function_id="builtins.compile",
        sink_type=SinkType.CODE_EVAL,
        tainted_arg_indices=[0],
        description="Dynamic code compilation"
    ))
    register_sink(SinkContract(
        function_id="builtins.__import__",
        sink_type=SinkType.CODE_EVAL,
        tainted_arg_indices=[0],
        description="Dynamic import"
    ))
    
    # ========== Path Injection Sinks ==========
    
    register_sink(SinkContract(
        function_id="builtins.open",
        sink_type=SinkType.FILE_PATH,
        tainted_arg_indices=[0],
        description="File open"
    ))
    register_sink(SinkContract(
        function_id="os.remove",
        sink_type=SinkType.FILE_PATH,
        tainted_arg_indices=[0],
        description="File removal"
    ))
    register_sink(SinkContract(
        function_id="os.unlink",
        sink_type=SinkType.FILE_PATH,
        tainted_arg_indices=[0],
        description="File unlink"
    ))
    register_sink(SinkContract(
        function_id="shutil.copy",
        sink_type=SinkType.FILE_PATH,
        tainted_arg_indices=[0, 1],
        description="File copy"
    ))
    register_sink(SinkContract(
        function_id="shutil.move",
        sink_type=SinkType.FILE_PATH,
        tainted_arg_indices=[0, 1],
        description="File move"
    ))
    register_sink(SinkContract(
        function_id="pathlib.Path.open",
        sink_type=SinkType.FILE_PATH,
        tainted_arg_indices=[],  # Path itself is tainted
        description="Pathlib open"
    ))
    register_sink(SinkContract(
        function_id="flask.send_file",
        sink_type=SinkType.FILE_PATH,
        tainted_arg_indices=[0],
        description="Flask send_file"
    ))
    register_sink(SinkContract(
        function_id="tarfile.extractall",
        sink_type=SinkType.FILE_PATH,
        tainted_arg_indices=[0],  # path argument
        description="Tar extraction (TarSlip)"
    ))
    register_sink(SinkContract(
        function_id="tarfile.extract",
        sink_type=SinkType.FILE_PATH,
        tainted_arg_indices=[0, 1],  # member, path
        description="Tar member extraction"
    ))
    
    # ========== XSS Sinks ==========
    
    register_sink(SinkContract(
        function_id="django.http.HttpResponse",
        sink_type=SinkType.HTML_OUTPUT,
        tainted_arg_indices=[0],
        description="Django HTTP response"
    ))
    register_sink(SinkContract(
        function_id="flask.render_template_string",
        sink_type=SinkType.HTML_OUTPUT,
        tainted_arg_indices=[0],
        description="Flask template string (dangerous!)"
    ))
    register_sink(SinkContract(
        function_id="flask.Markup",
        sink_type=SinkType.HTML_OUTPUT,
        tainted_arg_indices=[0],
        description="Flask safe markup"
    ))
    
    # ========== SSRF Sinks ==========
    
    register_sink(SinkContract(
        function_id="requests.get",
        sink_type=SinkType.HTTP_REQUEST,
        tainted_arg_indices=[0],  # URL
        description="HTTP GET request"
    ))
    register_sink(SinkContract(
        function_id="requests.post",
        sink_type=SinkType.HTTP_REQUEST,
        tainted_arg_indices=[0],
        description="HTTP POST request"
    ))
    register_sink(SinkContract(
        function_id="urllib.request.urlopen",
        sink_type=SinkType.HTTP_REQUEST,
        tainted_arg_indices=[0],
        description="URL open"
    ))
    register_sink(SinkContract(
        function_id="httpx.get",
        sink_type=SinkType.HTTP_REQUEST,
        tainted_arg_indices=[0],
        description="HTTPX GET"
    ))
    
    # ========== Deserialization Sinks ==========
    
    register_sink(SinkContract(
        function_id="pickle.loads",
        sink_type=SinkType.DESERIALIZE,
        tainted_arg_indices=[0],
        description="Pickle deserialization"
    ))
    register_sink(SinkContract(
        function_id="pickle.load",
        sink_type=SinkType.DESERIALIZE,
        tainted_arg_indices=[0],
        description="Pickle file deserialization"
    ))
    register_sink(SinkContract(
        function_id="yaml.load",
        sink_type=SinkType.DESERIALIZE,
        tainted_arg_indices=[0],
        description="YAML load (unsafe without Loader)"
    ))
    register_sink(SinkContract(
        function_id="yaml.unsafe_load",
        sink_type=SinkType.DESERIALIZE,
        tainted_arg_indices=[0],
        description="YAML unsafe load"
    ))
    register_sink(SinkContract(
        function_id="marshal.loads",
        sink_type=SinkType.DESERIALIZE,
        tainted_arg_indices=[0],
        description="Marshal deserialization"
    ))
    
    # ========== XXE/XML Sinks ==========
    
    register_sink(SinkContract(
        function_id="xml.etree.ElementTree.parse",
        sink_type=SinkType.XML_PARSE,
        tainted_arg_indices=[0],
        description="XML parse"
    ))
    register_sink(SinkContract(
        function_id="xml.etree.ElementTree.fromstring",
        sink_type=SinkType.XML_PARSE,
        tainted_arg_indices=[0],
        description="XML from string"
    ))
    register_sink(SinkContract(
        function_id="lxml.etree.parse",
        sink_type=SinkType.XML_PARSE,
        tainted_arg_indices=[0],
        description="LXML parse"
    ))
    register_sink(SinkContract(
        function_id="lxml.etree.fromstring",
        sink_type=SinkType.XML_PARSE,
        tainted_arg_indices=[0],
        description="LXML from string"
    ))
    
    # ========== LDAP Injection Sinks ==========
    
    register_sink(SinkContract(
        function_id="ldap.search_s",
        sink_type=SinkType.LDAP_QUERY,
        tainted_arg_indices=[0, 2],  # base, filterstr
        description="LDAP search"
    ))
    register_sink(SinkContract(
        function_id="ldap3.Connection.search",
        sink_type=SinkType.LDAP_QUERY,
        tainted_arg_indices=[0, 1],  # search_base, search_filter
        description="LDAP3 search"
    ))
    
    # ========== XPath Injection Sinks ==========
    
    register_sink(SinkContract(
        function_id="lxml.etree.XPath",
        sink_type=SinkType.XPATH_QUERY,
        tainted_arg_indices=[0],
        description="XPath compilation"
    ))
    register_sink(SinkContract(
        function_id="tree.xpath",
        sink_type=SinkType.XPATH_QUERY,
        tainted_arg_indices=[0],
        description="XPath query"
    ))
    register_sink(SinkContract(
        function_id="tree.find",
        sink_type=SinkType.XPATH_QUERY,
        tainted_arg_indices=[0],
        description="Element find"
    ))
    
    # ========== NoSQL Injection Sinks ==========
    
    register_sink(SinkContract(
        function_id="collection.find",
        sink_type=SinkType.NOSQL_QUERY,
        tainted_arg_indices=[0],
        description="MongoDB find"
    ))
    register_sink(SinkContract(
        function_id="collection.find_one",
        sink_type=SinkType.NOSQL_QUERY,
        tainted_arg_indices=[0],
        description="MongoDB find_one"
    ))
    register_sink(SinkContract(
        function_id="db.command",
        sink_type=SinkType.NOSQL_QUERY,
        tainted_arg_indices=[0],
        description="MongoDB command"
    ))
    
    # ========== Regex Injection Sinks ==========
    
    register_sink(SinkContract(
        function_id="re.compile",
        sink_type=SinkType.REGEX_PATTERN,
        tainted_arg_indices=[0],
        description="Regex compilation"
    ))
    register_sink(SinkContract(
        function_id="re.match",
        sink_type=SinkType.REGEX_PATTERN,
        tainted_arg_indices=[0],
        description="Regex match"
    ))
    register_sink(SinkContract(
        function_id="re.search",
        sink_type=SinkType.REGEX_PATTERN,
        tainted_arg_indices=[0],
        description="Regex search"
    ))
    register_sink(SinkContract(
        function_id="re.sub",
        sink_type=SinkType.REGEX_PATTERN,
        tainted_arg_indices=[0],
        description="Regex substitution"
    ))
    
    # ========== URL Redirect Sinks ==========
    
    register_sink(SinkContract(
        function_id="flask.redirect",
        sink_type=SinkType.REDIRECT_URL,
        tainted_arg_indices=[0],
        description="Flask redirect"
    ))
    register_sink(SinkContract(
        function_id="django.shortcuts.redirect",
        sink_type=SinkType.REDIRECT_URL,
        tainted_arg_indices=[0],
        description="Django redirect"
    ))
    register_sink(SinkContract(
        function_id="django.http.HttpResponseRedirect",
        sink_type=SinkType.REDIRECT_URL,
        tainted_arg_indices=[0],
        description="Django HTTP redirect"
    ))
    
    # ========== Header Injection Sinks ==========
    
    register_sink(SinkContract(
        function_id="response.__setitem__",
        sink_type=SinkType.HEADER_SET,
        tainted_arg_indices=[1],  # value
        description="Response header set"
    ))
    
    # ========== Sensitive Data Sinks (σ check) ==========
    
    register_sink(SinkContract(
        function_id="logging.info",
        sink_type=SinkType.LOG_OUTPUT,
        tainted_arg_indices=[0],
        description="Logging info"
    ))
    register_sink(SinkContract(
        function_id="logging.debug",
        sink_type=SinkType.LOG_OUTPUT,
        tainted_arg_indices=[0],
        description="Logging debug"
    ))
    register_sink(SinkContract(
        function_id="logging.warning",
        sink_type=SinkType.LOG_OUTPUT,
        tainted_arg_indices=[0],
        description="Logging warning"
    ))
    register_sink(SinkContract(
        function_id="logging.error",
        sink_type=SinkType.LOG_OUTPUT,
        tainted_arg_indices=[0],
        description="Logging error"
    ))
    register_sink(SinkContract(
        function_id="builtins.print",
        sink_type=SinkType.LOG_OUTPUT,
        tainted_arg_indices=[0],
        description="Print output"
    ))
    
    # ========== Cleartext Storage Sinks (σ check) ==========
    
    register_sink(SinkContract(
        function_id="file.write",
        sink_type=SinkType.FILE_WRITE,
        tainted_arg_indices=[0],
        description="File write (cleartext storage check)"
    ))
    register_sink(SinkContract(
        function_id="io.TextIOWrapper.write",
        sink_type=SinkType.FILE_WRITE,
        tainted_arg_indices=[0],
        description="Text file write (cleartext storage check)"
    ))
    register_sink(SinkContract(
        function_id="io.BufferedWriter.write",
        sink_type=SinkType.FILE_WRITE,
        tainted_arg_indices=[0],
        description="Buffered file write (cleartext storage check)"
    ))
    
    # ========== Weak Crypto Sinks ==========
    
    register_sink(SinkContract(
        function_id="hashlib.md5",
        sink_type=SinkType.CRYPTO_WEAK,
        tainted_arg_indices=[0],
        description="MD5 hash (weak for passwords)"
    ))
    register_sink(SinkContract(
        function_id="hashlib.sha1",
        sink_type=SinkType.CRYPTO_WEAK,
        tainted_arg_indices=[0],
        description="SHA1 hash (weak for passwords)"
    ))


def _init_sanitizer_contracts():
    """Register sanitizer contracts."""
    
    # ========== Command Injection Sanitizers ==========
    
    register_sanitizer(SanitizerContract(
        function_id="shlex.quote",
        sanitizer_type=SanitizerType.SHELL_QUOTE,
        applicable_sinks=frozenset([SinkType.COMMAND_SHELL]),
        description="Shell argument escaping"
    ))
    
    # ========== Path Sanitizers ==========
    
    register_sanitizer(SanitizerContract(
        function_id="os.path.basename",
        sanitizer_type=SanitizerType.BASENAME,
        applicable_sinks=frozenset([SinkType.FILE_PATH]),
        description="Strip directory path"
    ))
    register_sanitizer(SanitizerContract(
        function_id="werkzeug.utils.secure_filename",
        sanitizer_type=SanitizerType.SECURE_FILENAME,
        applicable_sinks=frozenset([SinkType.FILE_PATH]),
        description="Werkzeug filename sanitizer"
    ))
    
    # ========== XSS Sanitizers ==========
    
    register_sanitizer(SanitizerContract(
        function_id="html.escape",
        sanitizer_type=SanitizerType.HTML_ESCAPE,
        applicable_sinks=frozenset([SinkType.HTML_OUTPUT]),
        description="HTML escape"
    ))
    register_sanitizer(SanitizerContract(
        function_id="markupsafe.escape",
        sanitizer_type=SanitizerType.HTML_ESCAPE,
        applicable_sinks=frozenset([SinkType.HTML_OUTPUT]),
        description="Markupsafe escape"
    ))
    register_sanitizer(SanitizerContract(
        function_id="django.utils.html.escape",
        sanitizer_type=SanitizerType.HTML_ESCAPE,
        applicable_sinks=frozenset([SinkType.HTML_OUTPUT]),
        description="Django HTML escape"
    ))
    
    # ========== Regex Sanitizers ==========
    
    register_sanitizer(SanitizerContract(
        function_id="re.escape",
        sanitizer_type=SanitizerType.RE_ESCAPE,
        applicable_sinks=frozenset([SinkType.REGEX_PATTERN]),
        description="Regex metachar escape"
    ))
    
    # ========== Safe Deserializers ==========
    
    register_sanitizer(SanitizerContract(
        function_id="yaml.safe_load",
        sanitizer_type=SanitizerType.SAFE_LOADER,
        applicable_sinks=frozenset([SinkType.DESERIALIZE]),
        description="YAML safe loader"
    ))
    register_sanitizer(SanitizerContract(
        function_id="json.loads",
        sanitizer_type=SanitizerType.SAFE_LOADER,
        applicable_sinks=frozenset([SinkType.DESERIALIZE]),
        description="JSON (safe by design)"
    ))
    
    # ========== Type Conversion Sanitizers ==========
    
    register_sanitizer(SanitizerContract(
        function_id="builtins.int",
        sanitizer_type=SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset([SinkType.SQL_EXECUTE, SinkType.FILE_PATH]),
        description="Integer conversion (validates format)"
    ))
    register_sanitizer(SanitizerContract(
        function_id="builtins.float",
        sanitizer_type=SanitizerType.TYPE_CONVERSION,
        applicable_sinks=frozenset([SinkType.SQL_EXECUTE]),
        description="Float conversion (validates format)"
    ))
    
    # ========== Declassification Sanitizers (for σ) ==========
    
    register_sanitizer(SanitizerContract(
        function_id="hashlib.pbkdf2_hmac",
        sanitizer_type=SanitizerType.HASHING,
        clears_untrusted=False,
        clears_sensitive=True,
        applicable_sinks=frozenset([SinkType.LOG_OUTPUT, SinkType.FILE_WRITE]),
        description="PBKDF2 password hashing (declassification)"
    ))
    register_sanitizer(SanitizerContract(
        function_id="bcrypt.hashpw",
        sanitizer_type=SanitizerType.HASHING,
        clears_untrusted=False,
        clears_sensitive=True,
        applicable_sinks=frozenset([SinkType.LOG_OUTPUT, SinkType.FILE_WRITE]),
        description="bcrypt password hashing (declassification)"
    ))


# ============================================================================
# VM INTEGRATION HELPERS
# ============================================================================

def apply_source_taint(
    function_id: str,
    location: str,
    current_taint: TaintState = None
) -> TaintState:
    """
    Apply taint from a source function to a value.
    
    Called by the VM when executing a source function.
    """
    contract = get_source_contract(function_id)
    if contract is None:
        return current_taint or TaintState.clean()
    
    source_taint = TaintState.from_source(
        contract.source_type,
        location,
        contract.is_sensitive
    )
    
    if current_taint:
        return current_taint.merge(source_taint)
    return source_taint


def check_sink_taint(
    function_id: str,
    location: str,
    arg_taints: List[TaintState],
    call_kwargs: dict = None
) -> Optional[SecurityViolation]:
    """
    Check if calling a sink with tainted arguments is a security violation.
    
    Called by the VM when executing a sink function.
    Returns SecurityViolation if violation detected, None otherwise.
    """
    contract = get_sink_contract(function_id)
    if contract is None:
        return None
    
    # For SQL sinks, check if parameterized
    if contract.parameterized_check and len(arg_taints) > 1:
        # If second arg (params) provided, likely safe
        # TODO: More precise check
        pass
    
    # For subprocess sinks, check shell=True
    if contract.shell_check:
        if call_kwargs and not call_kwargs.get('shell', False):
            return None  # Safe: shell=False
    
    # Check tainted args
    for idx in contract.tainted_arg_indices:
        if idx < len(arg_taints):
            taint = arg_taints[idx]
            if taint.is_tainted_for_sink(contract.sink_type):
                return create_violation(contract.sink_type, location, taint)
    
    return None


def apply_sanitizer(
    function_id: str,
    input_taint: TaintState
) -> TaintState:
    """
    Apply a sanitizer to a tainted value.
    
    Called by the VM when executing a sanitizer function.
    """
    contract = get_sanitizer_contract(function_id)
    if contract is None:
        return input_taint
    
    result = input_taint.sanitize(contract.sanitizer_type)
    
    if contract.clears_untrusted:
        result = result.clear_untrusted()
    if contract.clears_sensitive:
        result = result.clear_sensitive()
    
    return result
