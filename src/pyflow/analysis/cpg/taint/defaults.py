"""Default taint sources, sinks, sanitizers, and propagation protocols."""

from __future__ import annotations
from typing import Dict, FrozenSet, Set


_DEFAULT_SOURCES: Set[str] = {
    "request.args",
    "request.form",
    "request.json",
    "request.data",
    "request.cookies",
    "request.headers",
    "request.files",
    "request.values",
    "request.get_data",
    "os.environ",
    "os.getenv",
    "os.environ.get",
    "input",
    "sys.stdin.read",
    "sys.argv",
    "cursor.fetchone",
    "cursor.fetchall",
    "cursor.fetchmany",
    "get_json",
    "form.get",
    "args.get",
    "pd.read_csv",
    "pd.read_json",
    "pd.read_sql",
    "pd.read_excel",
    "pd.read_parquet",
    "df.query",
    "spark.sql",
    "sc.textFile",
}

_DEFAULT_SINKS: Dict[str, str] = {
    "subprocess.run": "CWE-78",
    "subprocess.call": "CWE-78",
    "subprocess.Popen": "CWE-78",
    "os.system": "CWE-78",
    "os.popen": "CWE-78",
    "eval": "CWE-95",
    "exec": "CWE-95",
    "cursor.execute": "CWE-89",
    "db.execute": "CWE-89",
    "conn.execute": "CWE-89",
    "session.execute": "CWE-89",
    "engine.execute": "CWE-89",
    "spark.sql": "CWE-89",
    "execute": "CWE-89",
    "requests.get": "CWE-918",
    "requests.post": "CWE-918",
    "requests.put": "CWE-918",
    "requests.request": "CWE-918",
    "urllib.request.urlopen": "CWE-918",
    "urllib.urlopen": "CWE-918",
    "open": "CWE-22",
    "os.path.join": "CWE-22",
    "pathlib.Path": "CWE-22",
    "pickle.loads": "CWE-502",
    "yaml.load": "CWE-502",
    "marshal.loads": "CWE-502",
    "render_template_string": "CWE-79",
    "Markup": "CWE-79",
    "jinja2.Template": "CWE-79",
    "df.query": "CWE-89",
}

_DEFAULT_SANITIZERS: Dict[str, FrozenSet[str]] = {
    "html.escape": frozenset({"CWE-79"}),
    "markupsafe.escape": frozenset({"CWE-79"}),
    "bleach.clean": frozenset({"CWE-79"}),
    "escape": frozenset({"CWE-79"}),
    "urllib.parse.quote": frozenset({"CWE-89", "CWE-918"}),
    "quote": frozenset({"CWE-918"}),
    "quote_plus": frozenset({"CWE-918"}),
    "int": frozenset({"CWE-89", "CWE-78"}),
    "float": frozenset({"CWE-89"}),
    "bool": frozenset({"CWE-89"}),
    "uuid.UUID": frozenset({"CWE-89"}),
    "re.match": frozenset({"CWE-89", "CWE-78", "CWE-22"}),
    "re.fullmatch": frozenset({"CWE-89", "CWE-78", "CWE-22"}),
    "re.search": frozenset({"CWE-89"}),
    "parameterized": frozenset({"CWE-89"}),
    "sqlalchemy.text": frozenset({"CWE-89"}),
    "flask_wtf.csrf": frozenset({"CWE-352"}),
}

_SQL_SINKS: FrozenSet[str] = frozenset({"execute", "executemany", "executescript"})

_DUNDER_PROPAGATE: FrozenSet[str] = frozenset(
    {
        "__str__",
        "__repr__",
        "__add__",
        "__getattr__",
        "__getitem__",
        "__iter__",
    }
)
