"""Source, sink, and CWE configuration for semantic taint analysis."""

# User-controlled input sources
TAINT_SOURCES = {
    # Standard input
    "input",
    "raw_input",
    "sys.stdin.read",
    "sys.stdin.readline",
    "sys.stdin.readlines",
    # Environment
    "sys.argv",
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
    "argparse.Namespace",
    # Message queues
    "kafka.KafkaConsumer",
    "pika.channel",
    # Database
    "cursor.fetchall",
    "cursor.fetchone",
    "taint_src",
}
DEFAULT_SOURCES = TAINT_SOURCES

# Dangerous sinks where tainted data should NOT flow
TAINT_SINKS = {
    # Code execution
    "eval",
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
    "taint_sink",
}
DEFAULT_SINKS = TAINT_SINKS


def get_cwe_for_sink(sink: str) -> int:
    """Map sink names to the most specific CWE we support."""
    sink_lower = sink.lower()

    if any(x in sink_lower for x in ["eval", "exec", "__import__", "compile"]):
        return 94  # Code Injection
    if any(x in sink_lower for x in ["system", "popen", "subprocess", "commands"]):
        return 78  # OS Command Injection
    if any(
        x in sink_lower
        for x in ["cursor", "session", "execute", "query", "raw", "extra"]
    ):
        return 89  # SQL Injection
    if any(x in sink_lower for x in ["pickle", "yaml", "marshal", "jsonpickle"]):
        return 502  # Deserialization
    if any(x in sink_lower for x in ["render", "template", "jinja2"]):
        return 79  # XSS
    if any(x in sink_lower for x in ["open", "stat", "path", "pathlib", "send_file"]):
        return 22  # Path Traversal
    if any(x in sink_lower for x in ["requests", "urllib", "httpx", "http"]):
        return 918  # SSRF
    if any(x in sink_lower for x in ["ldap"]):
        return 90  # LDAP Injection
    return 79
