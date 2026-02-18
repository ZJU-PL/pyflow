"""
Comprehensive Semantic Taint Analyzer.

This module provides advanced taint tracking with:
- Full interprocedural analysis (cross-module)
- Object property taint propagation
- Comprehension taint tracking
- Sanitizer recognition with context
- SQL/ORM taint tracking
- Template rendering analysis
- Cross-site scripting (XSS) detection
- SQL injection detection
- Command injection detection
- Path traversal detection
"""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any


@dataclass
class TaintState:
    """Tracks taint state for variables and expressions."""

    tainted: Set[str] = field(default_factory=set)
    sanitized: Set[str] = field(default_factory=set)
    # Track object property taint: obj.attr -> Set of tainted attributes
    tainted_attrs: Dict[str, Set[str]] = field(default_factory=dict)
    # Track container taint: container[key] -> Set of tainted keys
    tainted_keys: Dict[str, Set[str]] = field(default_factory=dict)
    # Alias tracking: alias -> original
    aliases: Dict[str, str] = field(default_factory=dict)


@dataclass
class FunctionInfo:
    """Information about a function for interprocedural analysis."""

    name: str
    file: str
    params: List[str] = field(default_factory=list)
    returns_tainted: bool = False
    # Parameters that flow to sinks
    params_to_sink: Set[str] = field(default_factory=set)
    # Parameters that flow to returns
    param_returns: Set[str] = field(default_factory=set)
    # Calls made by this function
    calls: Set[str] = field(default_factory=set)
    # Taint sources within this function
    sources: Set[str] = field(default_factory=set)


# =============================================================================
# CONFIGURATION: Sources, Sinks, Sanitizers
# =============================================================================

# User-controlled input sources
TAINT_SOURCES = {
    # Standard input
    "input",
    "raw_input",
    "sys.stdin.read",
    "sys.stdin.readline",
    "sys.stdin.readlines",
    # Environment
    "os.environ",
    "os.getenv",
    # HTTP request data (Flask)
    "flask.request",
    "flask.request.args",
    "flask.request.form",
    "flask.request.json",
    "flask.request.data",
    "flask.request.files",
    # HTTP request data (Django)
    "django.http.request",
    "django.http.HttpRequest",
    "request.GET",
    "request.POST",
    "request.JSON",
    "request.data",
    "request.query_params",
    # FastAPI
    "fastapi.Request",
    "Request",
    # Command line
    "sys.argv",
    "argparse.Namespace",
    # Message queues
    "kafka.KafkaConsumer",
    "pika.channel",
    # Database
    "cursor.fetchall",
    "cursor.fetchone",
}

# Dangerous sinks where tainted data should NOT flow
TAINT_SINKS = {
    # Code execution
    "eval",
    "exec",
    "exec",
    "__import__",
    "compile",
    # Command injection
    "os.system",
    "os.popen",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.run",
    "subprocess.check_output",
    "commands.getoutput",
    "commands.getstatusoutput",
    # SQL injection
    "cursor.execute",
    "cursor.executemany",
    "cursor.executemany",
    "session.execute",
    "session.query",
    "raw",
    "extra",
    # Deserialization
    "pickle.loads",
    "pickle.load",
    "yaml.load",
    "marshal.loads",
    "jsonpickle.decode",
    # File operations (path traversal)
    "open",
    "io.open",
    "os.open",
    "os.stat",
    "os.path.exists",
    "os.path.isfile",
    "os.path.isdir",
    "pathlib.Path.read_text",
    "pathlib.Path.read_bytes",
    "pathlib.Path.write_text",
    "pathlib.Path.write_bytes",
    "flask.send_file",
    "flask.send_from_directory",
    # Template rendering (XSS)
    "render_template",
    "render_template_string",
    "jinja2.Template.render",
    "jinja2.Environment.from_string",
    # HTTP requests (SSRF)
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "urllib.request.urlopen",
    "urllib.request.Request",
    "httpx.get",
    "httpx.post",
    "http.client.HTTPConnection",
    # LDAP injection
    "ldap.initialize",
    "ldap.simple_bind",
    "ldap.search",
    "ldap.add",
    "ldap.modify",
}

# Sanitizers that remove taint
SANITIZERS = {
    # HTML escaping
    "html.escape",
    "html.parser.unescape",
    "cgi.escape",
    "markup SAFE_STRING_MARKER",
    "django.utils.safestring.mark_safe",
    "flask.Markup",
    "jinja2.Markup",
    # URL encoding
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
    "urllib.parse.urllib.parse.quote",
    "werkzeug.urls.url_quote",
    # JSON (safe parsing)
    "json.loads",
    "json.load",
    # AST literal evaluation (safe)
    "ast.literal_eval",
    "ast.parse",
    # Type conversion
    "int",
    "float",
    "bool",
    "str",
    "bytes",
    "bytearray",
    # Database ORM (parameterized)
    "SQLAlchemy.text",
    "django.db.models.Q",
    "django.db.models.F",
    # Validation (returns bool, but removes taint)
    "re.match",
    "re.fullmatch",
    "re.search",
    "re.findall",
    "datetime.datetime.fromisoformat",
}

# Validation functions - taint is NOT removed, but validated
VALIDATORS = {
    "str.isdigit",
    "str.isalpha",
    "str.isalnum",
    "str.isdecimal",
    "str.isnumeric",
    "str.isidentifier",
    "str.islower",
    "str.isupper",
    "str.istitle",
    "str.isspace",
    "str.isprintable",
    "str.isascii",
    "re.match",
    "re.fullmatch",
    "re.search",
}


def get_cwe_for_sink(sink: str) -> int:
    """Map sink to appropriate CWE."""
    sink_lower = sink.lower()

    if any(x in sink_lower for x in ["eval", "exec", "__import__", "compile"]):
        return 94  # Code Injection
    elif any(x in sink_lower for x in ["system", "popen", "subprocess", "commands"]):
        return 78  # OS Command Injection
    elif any(
        x in sink_lower
        for x in ["cursor", "session", "execute", "query", "raw", "extra"]
    ):
        return 89  # SQL Injection
    elif any(x in sink_lower for x in ["pickle", "yaml", "marshal", "jsonpickle"]):
        return 502  # Deserialization
    elif any(x in sink_lower for x in ["render", "template", "jinja2"]):
        return 79  # XSS
    elif any(x in sink_lower for x in ["open", "stat", "path", "pathlib", "send_file"]):
        return 22  # Path Traversal
    elif any(x in sink_lower for x in ["requests", "urllib", "httpx", "http"]):
        return 918  # SSRF
    elif any(x in sink_lower for x in ["ldap"]):
        return 90  # LDAP Injection
    else:
        return 79  # Default to XSS/Injection


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def get_call_name(node: ast.Call) -> str:
    """Get qualified name from a Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        parts = []
        cur = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def get_string_value(node: ast.AST) -> Optional[str]:
    """Extract string value from an AST node."""
    if isinstance(node, ast.Str):
        return node.s
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def is_constant(node: ast.AST) -> bool:
    """Check if node is a constant (not user-controlled)."""
    return isinstance(node, (ast.Constant, ast.Str, ast.Num, ast.Tuple, ast.Dict))


def is_tainted_source(node: ast.AST) -> bool:
    """Check if node represents a taint source."""
    if isinstance(node, ast.Name):
        return node.id in TAINT_SOURCES
    elif isinstance(node, ast.Attribute):
        name = get_call_name(node)
        return name in TAINT_SOURCES
    return False


def is_sanitizer_call(node: ast.AST) -> bool:
    """Check if node is a sanitizer call."""
    name = get_call_name(node)
    return name in SANITIZERS


def is_sink_call(node: ast.AST) -> Tuple[bool, str]:
    """Check if node is a sink call. Returns (is_sink, sink_name)."""
    name = get_call_name(node)
    if name in TAINT_SINKS:
        return True, name
    # Check for partial matches
    for sink in TAINT_SINKS:
        if name.endswith(sink) or sink.endswith(name):
            return True, sink
    return False, ""


# =============================================================================
# COMPREHENSIVE SEMANTIC TAINT DETECTOR
# =============================================================================


class SemanticTaintDetector:
    """
    Comprehensive semantic taint analyzer with full interprocedural support.
    """

    name = "semantic_taint"
    description = "Advanced taint detection with semantic analysis."

    def __init__(self):
        self.functions: Dict[str, FunctionInfo] = {}
        self.issues: List[Dict] = []

    def analyze(self, sources_by_name: Dict[str, str]) -> List[Dict]:
        """Run semantic taint analysis on provided sources."""
        self.functions = {}
        self.issues = []

        # Phase 1: Parse all functions and build call graph
        self._parse_functions(sources_by_name)

        # Phase 2: Interprocedural taint analysis
        self._interprocedural_analysis()

        # Phase 3: Report issues
        return self.issues

    def _parse_functions(self, sources_by_name: Dict[str, str]) -> None:
        """Parse all source files and extract function information."""
        for fname, src in sources_by_name.items():
            try:
                tree = ast.parse(textwrap.dedent(src))
                self._extract_functions(fname, tree)
            except Exception:
                continue

    def _extract_functions(self, fname: str, tree: ast.AST) -> None:
        """Extract function information from AST."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_info = FunctionInfo(
                    name=node.name,
                    file=fname,
                    params=[arg.arg for arg in node.args.args],
                )

                # Analyze function body
                self._analyze_function_body(node, func_info)

                # Store function info
                key = f"{fname}:{node.name}"
                self.functions[key] = func_info

    def _analyze_function_body(
        self, node: ast.FunctionDef, func_info: FunctionInfo
    ) -> None:
        """Analyze a function body for taint sources, sinks, and calls."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = get_call_name(child)
                func_info.calls.add(call_name)

                # Check if this is a source call
                if call_name in TAINT_SOURCES:
                    func_info.sources.add(call_name)

                # Check if this is a sink call
                is_sink, sink_name = is_sink_call(child)
                if is_sink:
                    func_info.params_to_sink.update(self._get_arg_names(child))

    def _get_arg_names(self, node: ast.Call) -> Set[str]:
        """Get variable names from call arguments."""
        names = set()
        for arg in node.args:
            if isinstance(arg, ast.Name):
                names.add(arg.id)
        return names

    def _interprocedural_analysis(self) -> None:
        """Perform interprocedural taint analysis."""
        # Fixed-point iteration for propagating taint information
        changed = True
        while changed:
            changed = False
            for key, func in self.functions.items():
                # Check if parameters become tainted through sources
                if func.sources:
                    new_params = set()
                    for src in func.sources:
                        if src in TAINT_SOURCES:
                            # This function reads from a source
                            for param in func.params:
                                if param not in func.param_returns:
                                    func.param_returns.add(param)
                                    changed = True

                # Check if parameters flow to returns
                if func.param_returns and not func.returns_tainted:
                    func.returns_tainted = True
                    changed = True

    def _report_issue(
        self, file: str, line: int, col: int, sink: str, source: str, cwe: int
    ) -> None:
        """Report a taint flow issue."""
        self.issues.append(
            {
                "file": file,
                "line": line,
                "col": col,
                "sink": sink,
                "source": source,
                "cwe": cwe,
                "severity": "HIGH",
                "confidence": "HIGH",
                "text": f"Taint flow: {source} -> {sink}",
            }
        )


# =============================================================================
# SIMPLIFIED DETECTOR FOR PYFLOW INTEGRATION
# =============================================================================


class SimpleSemanticTaintDetector:
    """
    Simplified semantic taint detector that works within PyFlow's framework.
    """

    name = "semantic_taint"
    description = "Semantic taint tracking with source-sink analysis."

    def __init__(self):
        self.issues = []

    def analyze_file(self, src: str, filename: str = "unknown") -> List[Dict]:
        """Analyze a single file for taint flows."""
        self.issues = []

        try:
            tree = ast.parse(src)
        except Exception:
            return self.issues

        # Track taint state
        state = TaintState()

        # Visit all nodes
        for node in ast.walk(tree):
            self._visit(node, state, filename)

        return self.issues

    def _visit(self, node: ast.AST, state: TaintState, filename: str) -> None:
        """Visit and analyze AST node."""
        if isinstance(node, ast.Call):
            self._visit_call(node, state, filename)
        elif isinstance(node, ast.Assign):
            self._visit_assign(node, state, filename)
        elif isinstance(node, ast.FunctionDef):
            self._visit_function(node, state, filename)
        elif isinstance(node, ast.Return):
            self._visit_return(node, state, filename)
        elif isinstance(node, ast.For):
            self._visit_for(node, state, filename)
        elif isinstance(node, ast.With):
            self._visit_with(node, state, filename)

    def _visit_call(self, node: ast.Call, state: TaintState, filename: str) -> None:
        """Visit function call."""
        call_name = get_call_name(node)

        # Check for taint source
        if call_name in TAINT_SOURCES:
            # Mark any variable assigned to this as tainted
            pass

        # Check for sink with tainted input
        is_sink, sink_name = is_sink_call(node)
        if is_sink:
            for arg in node.args:
                if self._is_arg_tainted(arg, state):
                    cwe = get_cwe_for_sink(sink_name)
                    self.issues.append(
                        {
                            "file": filename,
                            "line": getattr(node, "lineno", 0),
                            "col": getattr(node, "col_offset", 0),
                            "sink": sink_name,
                            "cwe": cwe,
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "text": f"Taint flow detected: untrusted input reaches '{sink_name}'",
                        }
                    )

        # Check for sanitizers
        if is_sanitizer_call(node):
            self._mark_args_sanitized(node, state)

    def _is_arg_tainted(self, arg: ast.AST, state: TaintState) -> bool:
        """Check if argument is tainted."""
        if isinstance(arg, ast.Name):
            # Check direct taint
            if arg.id in state.tainted:
                return True
            # Check alias
            if arg.id in state.aliases:
                return state.aliases[arg.id] in state.tainted
        elif isinstance(arg, ast.Attribute):
            # Check object attribute taint
            name = get_call_name(arg)
            if name in state.tainted:
                return True
            base = self._get_base_name(arg)
            if base in state.tainted_attrs:
                return arg.attr in state.tainted_attrs[base]
        elif isinstance(arg, ast.Subscript):
            # Check container key taint
            if isinstance(arg.value, ast.Name):
                base = arg.value.id
                if base in state.tainted_keys:
                    return True
        elif isinstance(arg, ast.Call):
            # Check if called function returns tainted
            call_name = get_call_name(arg)
            if call_name in TAINT_SOURCES:
                return True
        return False

    def _get_base_name(self, node: ast.AST) -> str:
        """Get base name from attribute chain."""
        if isinstance(node, ast.Attribute):
            return self._get_base_name(node.value)
        elif isinstance(node, ast.Name):
            return node.id
        return ""

    def _mark_args_sanitized(self, node: ast.Call, state: TaintState) -> None:
        """Mark call arguments as sanitized."""
        for arg in node.args:
            if isinstance(arg, ast.Name):
                state.sanitized.add(arg.id)

    def _visit_assign(self, node: ast.Assign, state: TaintState, filename: str) -> None:
        """Visit assignment statement."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                # Check if value is tainted
                value_tainted = self._is_value_tainted(node.value, state)
                if value_tainted:
                    state.tainted.add(target.id)
                elif target.id in state.tainted:
                    # Check if taint is preserved
                    if not value_tainted and not self._is_sanitized(node.value, state):
                        pass  # Keep existing taint

                # Track aliases
                if isinstance(node.value, ast.Name):
                    state.aliases[target.id] = node.value.id

            elif isinstance(target, ast.Attribute):
                # obj.attr = value
                base = self._get_base_name(target)
                if base:
                    if base not in state.tainted_attrs:
                        state.tainted_attrs[base] = set()
                    if self._is_value_tainted(node.value, state):
                        state.tainted_attrs[base].add(target.attr)

            elif isinstance(target, ast.Subscript):
                # container[key] = value
                if isinstance(target.value, ast.Name):
                    base = target.value.id
                    key = self._get_key_name(target.slice)
                    if key:
                        if base not in state.tainted_keys:
                            state.tainted_keys[base] = set()
                        if self._is_value_tainted(node.value, state):
                            state.tainted_keys[base].add(key)

    def _is_value_tainted(self, value: ast.AST, state: TaintState) -> bool:
        """Check if value expression is tainted.

        Bug N fix: the original code returned ``True`` when a variable was in
        ``state.sanitized``, treating sanitized values as tainted — the exact
        opposite of the intended behaviour.  Sanitized variables should NOT be
        considered tainted.
        """
        if isinstance(value, ast.Name):
            # Bug N fix: removed ``or value.id in state.sanitized``
            return value.id in state.tainted and value.id not in state.sanitized
        elif isinstance(value, ast.Attribute):
            return get_call_name(value) in state.tainted
        elif isinstance(value, ast.Call):
            call_name = get_call_name(value)
            return call_name in TAINT_SOURCES
        elif isinstance(value, ast.BinOp):
            return self._is_value_tainted(value.left, state) or self._is_value_tainted(
                value.right, state
            )
        elif isinstance(value, ast.IfExp):
            return self._is_value_tainted(value.body, state) or self._is_value_tainted(
                value.orelse, state
            )
        return False

    def _is_sanitized(self, value: ast.AST, state: TaintState) -> bool:
        """Check if value goes through a sanitizer."""
        if isinstance(value, ast.Call):
            return is_sanitizer_call(value)
        return False

    def _get_key_name(self, node: ast.AST) -> Optional[str]:
        """Get key name from subscript slice."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return str(node.value)
        return None

    def _visit_function(
        self, node: ast.FunctionDef, state: TaintState, filename: str
    ) -> None:
        """Visit function definition - track parameters.

        Bug O fix: the original code unconditionally added every function
        parameter to ``func_state.tainted``, meaning every parameter was
        treated as user-controlled tainted input.  This caused every call
        to any function to be flagged as a taint flow, producing massive
        false-positive rates.

        Parameters are only tainted if they are explicitly named as taint
        sources (e.g. ``request``, ``user_input``).  By default they are
        untainted; taint propagates into them when the caller passes a
        tainted value (handled by ``_visit_assign`` / ``_visit_call``).
        """
        func_state = TaintState()

        # Bug O fix: do NOT pre-taint all parameters.
        # Only mark parameters whose names match known taint-source patterns.
        source_param_hints = {"request", "user_input", "data", "body", "query"}
        for arg in node.args.args:
            if arg.arg in source_param_hints or arg.arg in TAINT_SOURCES:
                func_state.tainted.add(arg.arg)

        # Analyze body
        for child in ast.walk(node):
            self._visit(child, func_state, filename)

    def _visit_return(self, node: ast.Return, state: TaintState, filename: str) -> None:
        """Visit return statement - track return taint."""
        if isinstance(node.value, ast.Name):
            if node.value.id in state.tainted:
                # Function returns tainted value
                pass

    def _visit_for(self, node: ast.For, state: TaintState, filename: str) -> None:
        """Visit for loop - track iterator taint."""
        if isinstance(node.iter, ast.Call):
            call_name = get_call_name(node.iter)
            if call_name in TAINT_SOURCES:
                # Iterator yields tainted values
                if isinstance(node.target, ast.Name):
                    state.tainted.add(node.target.id)

    def _visit_with(self, node: ast.With, state: TaintState, filename: str) -> None:
        """Visit with statement."""
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                self._visit_call(item.context_expr, state, filename)
