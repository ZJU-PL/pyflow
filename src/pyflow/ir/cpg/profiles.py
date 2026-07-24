"""
Framework semantic profiles for the CPG taint engine.

Each profile defines SOURCES, SINKS, and GUARDS dictionaries keyed by
call-pattern strings, enabling framework-aware taint analysis.

Usage::

    from pyflow.ir.cpg.profiles import detect_profile, apply_profile

    engine = CPGTaintEngine(cpg)
    profile = detect_profile(source_code)
    if profile:
        apply_profile(engine, profile)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Set

from pyflow.ir.cpg.taint import CPGTaintEngine


@dataclass
class FrameworkProfile:
    sources: Dict[str, str] = field(default_factory=dict)
    sinks: Dict[str, str] = field(default_factory=dict)
    guards: Dict[str, str] = field(default_factory=dict)
    detection_imports: Set[str] = field(default_factory=set)

    def name(self) -> str:
        return self.__class__.__name__.replace("Profile", "").lower()


@dataclass
class FlaskProfile(FrameworkProfile):
    sources: Dict[str, str] = field(default_factory=lambda: {
        "request.args": "query-params",
        "request.form": "post-body",
        "request.json": "json-body",
        "request.data": "raw-body",
        "request.cookies": "cookies",
        "request.headers": "headers",
        "request.files": "file-upload",
        "request.values": "combined",
        "request.get_data": "raw-body",
        "get_json": "json-body",
        "form.get": "post-body",
        "args.get": "query-params",
        "flask.request": "http-request",
    })
    sinks: Dict[str, str] = field(default_factory=lambda: {
        "subprocess.run": "cmd-injection",
        "subprocess.call": "cmd-injection",
        "subprocess.Popen": "cmd-injection",
        "os.system": "cmd-injection",
        "os.popen": "cmd-injection",
        "eval": "code-injection",
        "exec": "code-injection",
        "cursor.execute": "sql-injection",
        "db.execute": "sql-injection",
        "render_template_string": "ssti",
        "Markup": "xss",
        "jinja2.Template": "ssti",
        "open": "path-traversal",
        "pickle.loads": "deserialization",
        "yaml.load": "deserialization",
        "send_file": "path-traversal",
    })
    guards: Dict[str, str] = field(default_factory=lambda: {
        "escape": "xss-escape",
        "html.escape": "xss-escape",
        "markupsafe.escape": "xss-escape",
        "bleach.clean": "xss-sanitize",
        "int": "type-cast",
        "float": "type-cast",
        "bool": "type-cast",
        "re.fullmatch": "regex-validate",
        "re.match": "regex-validate",
        "parameterized": "sql-param",
    })
    detection_imports: Set[str] = field(default_factory=lambda: {
        "from flask", "import flask", "flask.",
    })


@dataclass
class DjangoProfile(FrameworkProfile):
    sources: Dict[str, str] = field(default_factory=lambda: {
        "request.GET": "query-params",
        "request.POST": "post-body",
        "request.body": "raw-body",
        "request.headers": "headers",
        "request.COOKIES": "cookies",
        "request.FILES": "file-upload",
        "request.META": "meta-data",
        "request.GET.get": "query-params",
        "request.POST.get": "post-body",
        "HttpRequest.GET": "query-params",
        "HttpRequest.POST": "post-body",
    })
    sinks: Dict[str, str] = field(default_factory=lambda: {
        "subprocess.run": "cmd-injection",
        "subprocess.call": "cmd-injection",
        "os.system": "cmd-injection",
        "eval": "code-injection",
        "exec": "code-injection",
        "cursor.execute": "sql-injection",
        "RawSQL": "sql-injection",
        "extra": "sql-injection",
        "render": "xss",
        "mark_safe": "xss",
        "open": "path-traversal",
        "pickle.loads": "deserialization",
        "yaml.load": "deserialization",
    })
    guards: Dict[str, str] = field(default_factory=lambda: {
        "escape": "xss-escape",
        "html.escape": "xss-escape",
        "mark_safe": "xss-safe",
        "int": "type-cast",
        "float": "type-cast",
        "bool": "type-cast",
        "re.fullmatch": "regex-validate",
        "parameterized": "sql-param",
        "connection.cursor": "sql-cursor",
    })
    detection_imports: Set[str] = field(default_factory=lambda: {
        "from django", "import django", "django.",
    })


@dataclass
class FastAPIProfile(FrameworkProfile):
    sources: Dict[str, str] = field(default_factory=lambda: {
        "Request.query_params": "query-params",
        "Request.body": "raw-body",
        "Request.headers": "headers",
        "Request.cookies": "cookies",
        "Path": "path-param",
        "Query": "query-param",
        "Body": "body-param",
        "Form": "form-param",
    })
    sinks: Dict[str, str] = field(default_factory=lambda: {
        "subprocess.run": "cmd-injection",
        "eval": "code-injection",
        "exec": "code-injection",
        "cursor.execute": "sql-injection",
        "open": "path-traversal",
        "pickle.loads": "deserialization",
    })
    guards: Dict[str, str] = field(default_factory=lambda: {
        "int": "type-cast",
        "float": "type-cast",
        "str": "type-cast",
        "re.fullmatch": "regex-validate",
    })
    detection_imports: Set[str] = field(default_factory=lambda: {
        "from fastapi", "import fastapi", "fastapi.",
    })


@dataclass
class TornadoProfile(FrameworkProfile):
    sources: Dict[str, str] = field(default_factory=lambda: {
        "get_argument": "query-param",
        "get_arguments": "query-params",
        "get_body_argument": "post-body",
        "get_query_argument": "query-param",
        "request.body": "raw-body",
        "request.headers": "headers",
    })
    sinks: Dict[str, str] = field(default_factory=lambda: {
        "subprocess.run": "cmd-injection",
        "eval": "code-injection",
        "exec": "code-injection",
        "cursor.execute": "sql-injection",
        "render_string": "ssti",
    })
    guards: Dict[str, str] = field(default_factory=lambda: {
        "escape": "xss-escape",
        "int": "type-cast",
    })
    detection_imports: Set[str] = field(default_factory=lambda: {
        "from tornado", "import tornado", "tornado.",
    })


@dataclass
class PythonStdlibProfile(FrameworkProfile):
    sources: Dict[str, str] = field(default_factory=lambda: {
        "input": "stdin",
        "sys.stdin.read": "stdin",
        "sys.stdin.readline": "stdin",
        "sys.argv": "cli-arg",
        "os.environ": "env-var",
        "os.getenv": "env-var",
        "os.environ.get": "env-var",
        "cursor.fetchone": "db-result",
        "cursor.fetchall": "db-result",
        "cursor.fetchmany": "db-result",
    })
    sinks: Dict[str, str] = field(default_factory=lambda: {
        "subprocess.run": "cmd-injection",
        "subprocess.call": "cmd-injection",
        "subprocess.Popen": "cmd-injection",
        "os.system": "cmd-injection",
        "os.popen": "cmd-injection",
        "eval": "code-injection",
        "exec": "code-injection",
        "open": "path-traversal",
        "os.path.join": "path-traversal",
        "pickle.loads": "deserialization",
        "yaml.load": "deserialization",
        "marshal.loads": "deserialization",
        "requests.get": "ssrf",
        "requests.post": "ssrf",
        "requests.put": "ssrf",
        "urllib.request.urlopen": "ssrf",
    })
    guards: Dict[str, str] = field(default_factory=lambda: {
        "int": "type-cast",
        "float": "type-cast",
        "bool": "type-cast",
        "uuid.UUID": "uuid-validate",
        "re.fullmatch": "regex-validate",
        "re.match": "regex-validate",
        "html.escape": "xss-escape",
    })


_PROFILES: Dict[str, FrameworkProfile] = {}


def _register() -> None:
    for cls in (
        FlaskProfile,
        DjangoProfile,
        FastAPIProfile,
        TornadoProfile,
        PythonStdlibProfile,
    ):
        profile = cls()
        _PROFILES[profile.name()] = profile


_register()


def detect_profile(source: str) -> Optional[FrameworkProfile]:
    source_lower = source.lower()
    best: Optional[FrameworkProfile] = None
    for profile in _PROFILES.values():
        for marker in profile.detection_imports:
            if marker.lower() in source_lower:
                return profile
    if best is None:
        best = _PROFILES.get("pythonstdlib")
    return best


def apply_profile(
    engine: CPGTaintEngine,
    profile: FrameworkProfile,
    *,
    sinks_as_cwe: bool = True,
) -> CPGTaintEngine:
    for src in profile.sources:
        engine.add_source(src)
    for sink, vuln in profile.sinks.items():
        cwe = vuln if sinks_as_cwe and vuln.startswith("CWE") else sink
        engine.add_sink(sink, cwe=cwe)
    for guard in profile.guards:
        engine.add_sanitizer(guard)
    return engine


def detect_and_apply(
    engine: CPGTaintEngine,
    source: str,
) -> CPGTaintEngine:
    profile = detect_profile(source)
    if profile is not None:
        apply_profile(engine, profile)
    return engine