"""
Deserialization Security Checks.

Detects unsafe deserialization patterns (CWE-502):
- B401: ``pickle.load`` / ``pickle.loads`` with user-controlled data
- B402: ``yaml.load`` with unsafe or missing Loader
- B403: ``marshal.load`` / ``marshal.loads``
- B404: ``jsonpickle`` deserialization APIs
- B405: ``shelve.open`` with user-controlled path

Safe alternatives:
- Prefer ``json.loads`` for untrusted data formats.
- Use ``yaml.safe_load`` or ``yaml.load(..., Loader=yaml.SafeLoader)``.
- Avoid ``pickle``/``marshal`` for untrusted inputs.
- Avoid ``jsonpickle.decode`` for untrusted inputs.
- Restrict ``shelve`` paths to trusted, fixed locations.
"""

import ast

from ..core import issue
from ..core import test_properties as test


PICKLE_FUNCS = {"pickle.load", "pickle.loads"}
MARSHAL_FUNCS = {"marshal.load", "marshal.loads"}
YAML_LOAD_FUNC = "yaml.load"
SHELVE_OPEN_FUNC = "shelve.open"
JSONPICKLE_DESERIALIZE_FUNCS = {
    "jsonpickle.decode",
    "jsonpickle.loads",
    "jsonpickle.load",
}

SAFE_YAML_LOADERS = {
    "SafeLoader",
    "CSafeLoader",
    "yaml.SafeLoader",
    "yaml.CSafeLoader",
}

USER_INPUT_CALLS = {
    "input",
    "raw_input",
    "sys.stdin.read",
    "sys.stdin.readline",
    "sys.stdin.readlines",
    "request.get_json",
    "request.json",
    "request.get_data",
    "request.form.get",
    "request.args.get",
}

SUSPICIOUS_NAME_HINTS = (
    "user",
    "input",
    "request",
    "payload",
    "body",
    "param",
    "query",
    "form",
    "data",
    "stream",
)


def _make_deserialization_issue(text, confidence="HIGH", severity="HIGH"):
    """Create a standard CWE-502 issue."""
    return issue.Issue(
        severity=severity,
        confidence=confidence,
        cwe=issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA,
        text=text,
    )


def _get_qualified_name(node):
    """Build dotted name from Name/Attribute AST nodes."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _get_qualified_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _matches_function(context, candidates):
    """Check if current call matches an exact qualified function name."""
    qual = getattr(context, "call_function_name_qual", None)
    return qual in candidates


def _matches_jsonpickle_deserializer(context):
    """Check jsonpickle deserialization APIs by qualified name."""
    qual = getattr(context, "call_function_name_qual", None)
    if not qual:
        return False

    if qual in JSONPICKLE_DESERIALIZE_FUNCS:
        return True

    # Handle nested forms such as jsonpickle.unpickler.decode
    return qual.startswith("jsonpickle.") and qual.endswith(".decode")


def _get_call_arg(call_node, position=0, keyword=None):
    """Get a positional or keyword argument from a call node."""
    if call_node is None or not hasattr(call_node, "args"):
        return None

    if keyword:
        for kw in getattr(call_node, "keywords", []):
            if kw.arg == keyword:
                return kw.value

    if len(call_node.args) > position:
        return call_node.args[position]

    return None


def _name_looks_user_controlled(name):
    """Heuristic for variable names likely tied to untrusted input."""
    lowered = name.lower()
    return any(hint in lowered for hint in SUSPICIOUS_NAME_HINTS)


def _is_user_controlled(node):
    """Best-effort check for user-controlled values in AST expressions.

    This function is conservative to reduce false positives.
    Only considers data as user-controlled if there's strong evidence.
    """
    if node is None:
        return False

    # Constants (strings, numbers, etc.) are NEVER user-controlled
    if isinstance(node, (ast.Constant, ast.Str, ast.Num)):
        return False

    # List/Tuple/Dict literals - check if any element is user-controlled
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(_is_user_controlled(elt) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return (
            any(_is_user_controlled(v) for v in node.values) if node.values else False
        )

    if isinstance(node, ast.Name):
        # Only flag if name strongly suggests user input
        name_lower = node.id.lower()
        # High-confidence user input markers only
        high_confidence_markers = (
            "input",
            "user_input",
            "request_data",
            "post_data",
            "get_data",
            "form_data",
            "body",
            "payload",
        )
        return any(
            marker == name_lower for marker in high_confidence_markers
        ) or name_lower in ("request", "args", "query")

    if isinstance(node, ast.Attribute):
        dotted = _get_qualified_name(node)
        if dotted:
            # Check for Flask/Django request attributes
            if any(
                dotted.startswith(prefix)
                for prefix in (
                    "flask.request.",
                    "request.",
                    "django.request.",
                    "http.request.",
                )
            ):
                return True
            # Check for specific high-risk attributes
            if any(
                dotted.endswith(suffix)
                for suffix in (
                    ".args",
                    ".form",
                    ".json",
                    ".data",
                    ".get_data",
                    ".post_data",
                )
            ):
                return True
        return _is_user_controlled(node.value)

    if isinstance(node, ast.Subscript):
        # Check container[user_input] pattern
        if isinstance(node.slice, (ast.Name, ast.Call)):
            return _is_user_controlled(node.value) or _is_user_controlled(node.slice)
        return _is_user_controlled(node.value)

    if isinstance(node, ast.Call):
        callee = _get_qualified_name(node.func)
        if callee in USER_INPUT_CALLS:
            return True
        if callee and (
            callee.startswith("request.")
            or callee.startswith("flask.request.")
            or callee.startswith("django.http.request.")
        ):
            return True
        return any(_is_user_controlled(arg) for arg in node.args) or any(
            _is_user_controlled(kw.value)
            for kw in node.keywords
            if kw.value is not None
        )

    # For other complex expressions (BinOp, etc.), be conservative
    # Only flag if there's clear user input involvement
    return False

    if isinstance(node, ast.JoinedStr):
        return any(_is_user_controlled(v) for v in node.values)

    if isinstance(node, ast.FormattedValue):
        return _is_user_controlled(node.value)

    if isinstance(node, ast.BinOp):
        return _is_user_controlled(node.left) or _is_user_controlled(node.right)

    if isinstance(node, ast.BoolOp):
        return any(_is_user_controlled(v) for v in node.values)

    if isinstance(node, ast.IfExp):
        return (
            _is_user_controlled(node.test)
            or _is_user_controlled(node.body)
            or _is_user_controlled(node.orelse)
        )

    if isinstance(node, ast.UnaryOp):
        return _is_user_controlled(node.operand)

    if isinstance(node, ast.Compare):
        return _is_user_controlled(node.left) or any(
            _is_user_controlled(c) for c in node.comparators
        )

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_is_user_controlled(elt) for elt in node.elts)

    if isinstance(node, ast.Dict):
        return any(_is_user_controlled(k) for k in node.keys if k is not None) or any(
            _is_user_controlled(v) for v in node.values
        )

    return False


def _loader_name(loader_node):
    """Extract loader identifier from YAML Loader argument."""
    if loader_node is None:
        return None

    if isinstance(loader_node, ast.Name):
        return loader_node.id

    if isinstance(loader_node, ast.Attribute):
        return _get_qualified_name(loader_node)

    return None


def _is_safe_yaml_loader(loader_node):
    """Return True for SafeLoader/CSafeLoader forms."""
    name = _loader_name(loader_node)
    return name in SAFE_YAML_LOADERS


@test.checks("Call")
@test.with_id("B401")
def pickle_with_user_input(context):
    """Detect pickle.load(s) with potentially user-controlled input."""
    if not _matches_function(context, PICKLE_FUNCS):
        return None

    payload = _get_call_arg(context.node, position=0)
    if _is_user_controlled(payload):
        # Safe alternative: use JSON or a strict schema-based parser.
        return _make_deserialization_issue(
            "pickle.load/loads with user-controlled input can execute arbitrary "
            "code during deserialization."
        )
    return None


@test.checks("Call")
@test.with_id("B402")
def yaml_load_with_unsafe_loader(context):
    """Detect yaml.load() when Loader is unsafe or omitted."""
    if not _matches_function(context, {YAML_LOAD_FUNC}):
        return None

    loader_arg = _get_call_arg(context.node, keyword="Loader")
    if loader_arg is None:
        # Safe alternative: yaml.safe_load(data).
        return _make_deserialization_issue(
            "yaml.load called without SafeLoader; use yaml.safe_load or "
            "Loader=yaml.SafeLoader for untrusted input.",
            confidence="HIGH",
            severity="HIGH",
        )

    if not _is_safe_yaml_loader(loader_arg):
        # Safe alternative: yaml.SafeLoader / yaml.CSafeLoader.
        return _make_deserialization_issue(
            "yaml.load uses a non-safe Loader, which can deserialize arbitrary "
            "Python objects from untrusted data.",
            confidence="HIGH",
            severity="HIGH",
        )
    return None


@test.checks("Call")
@test.with_id("B403")
def marshal_deserialization(context):
    """Detect marshal.load(s), which is unsafe for untrusted input."""
    if _matches_function(context, MARSHAL_FUNCS):
        # Safe alternative: JSON for untrusted data interchange.
        return _make_deserialization_issue(
            "marshal.load/loads should not be used with untrusted input; "
            "it is not designed as a secure serialization format.",
            confidence="HIGH",
            severity="HIGH",
        )
    return None


@test.checks("Call")
@test.with_id("B404")
def jsonpickle_deserialization(context):
    """Detect jsonpickle deserialization APIs."""
    if _matches_jsonpickle_deserializer(context):
        # Safe alternative: json.loads + explicit schema validation.
        return _make_deserialization_issue(
            "jsonpickle deserialization can reconstruct arbitrary objects; "
            "avoid it for untrusted data.",
            confidence="HIGH",
            severity="HIGH",
        )
    return None


@test.checks("Call")
@test.with_id("B405")
def shelve_open_with_user_input(context):
    """Detect shelve.open() with user-controlled storage path."""
    if not _matches_function(context, {SHELVE_OPEN_FUNC}):
        return None

    filename = _get_call_arg(context.node, position=0)
    if _is_user_controlled(filename):
        # Safe alternative: fixed allowlisted path and strict access controls.
        return _make_deserialization_issue(
            "shelve.open with user-controlled path can expose unsafe pickle-based "
            "deserialization behavior.",
            confidence="MEDIUM",
            severity="HIGH",
        )
    return None
