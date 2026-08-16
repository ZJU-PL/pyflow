"""Security scenarios adapted from the PySpector regression suite.

The source scenarios were derived from PySpector's Apache-2.0-licensed tests:

* ``test_semantic_provenance.py``
* ``test_taint_engine_extension.py``
* ``test_a_sink_rules.py``
* ``test_false_positive_reductions.py``
* ``test_missing_rules.py``

Copyright 2025-2026 Tommaso Bona / PySpector contributors.

The cases are expressed in pyflow-neutral terms instead of retaining
PySpector rule identifiers.  This lets the same semantic expectations run
against multiple pyflow analysis engines.
"""

from __future__ import annotations

from dataclasses import dataclass


ALL_TAINT_ENGINES = ("ast-dataflow", "cpg", "ifds")


@dataclass(frozen=True)
class ModelSpec:
    """Declarative call model used by a corpus case."""

    name: str
    sources: tuple[str, ...] = ()
    sinks: tuple[str, ...] = ()
    sanitizers: tuple[str, ...] = ()
    sink_positions: tuple[int, ...] = (0,)
    sink_receiver: bool = False
    propagate_all_to_return: bool = False


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    sources: tuple[str, ...]
    sinks: tuple[str, ...]


@dataclass(frozen=True)
class TaintCase:
    name: str
    source: str
    models: tuple[ModelSpec, ...]
    rules: tuple[RuleSpec, ...]
    expected_rule_ids: frozenset[str]
    engines: tuple[str, ...] = ALL_TAINT_ENGINES


USER_SOURCE = ModelSpec("source", sources=("user_input",))
REQUEST_GET_SOURCE = ModelSpec("request.GET.get", sources=("user_input",))
REQUEST_POST_SOURCE = ModelSpec("request.POST.get", sources=("user_input",))
FLASK_ARGS_SOURCE = ModelSpec("request.args.get", sources=("user_input",))
INPUT_SOURCE = ModelSpec("input", sources=("user_input",))


def _rule(sink: str, rule_id: str = "PYSPECTOR-CORPUS") -> RuleSpec:
    return RuleSpec(rule_id, ("user_input",), (sink,))


TAINT_CASES = (
    TaintCase(
        name="django_get_to_getattr",
        source=(
            "def main():\n" "    attr = request.GET.get('field')\n" "    getattr(user, attr)\n"
        ),
        models=(
            REQUEST_GET_SOURCE,
            ModelSpec("getattr", sinks=("attribute_access",), sink_positions=(1,)),
        ),
        rules=(_rule("attribute_access"),),
        expected_rule_ids=frozenset({"PYSPECTOR-CORPUS"}),
    ),
    TaintCase(
        name="django_post_to_setattr",
        source=(
            "def main():\n"
            "    attr = request.POST.get('field')\n"
            "    setattr(user, attr, 'value')\n"
        ),
        models=(
            REQUEST_POST_SOURCE,
            ModelSpec("setattr", sinks=("attribute_write",), sink_positions=(1,)),
        ),
        rules=(_rule("attribute_write"),),
        expected_rule_ids=frozenset({"PYSPECTOR-CORPUS"}),
    ),
    TaintCase(
        name="flask_args_to_delattr",
        source=(
            "def main():\n" "    attr = request.args.get('field')\n" "    delattr(user, attr)\n"
        ),
        models=(
            FLASK_ARGS_SOURCE,
            ModelSpec("delattr", sinks=("attribute_delete",), sink_positions=(1,)),
        ),
        rules=(_rule("attribute_delete"),),
        expected_rule_ids=frozenset({"PYSPECTOR-CORPUS"}),
    ),
    TaintCase(
        name="input_to_getattr",
        source=("def main():\n" "    attr = input('attribute: ')\n" "    getattr(user, attr)\n"),
        models=(
            INPUT_SOURCE,
            ModelSpec("getattr", sinks=("attribute_access",), sink_positions=(1,)),
        ),
        rules=(_rule("attribute_access"),),
        expected_rule_ids=frozenset({"PYSPECTOR-CORPUS"}),
    ),
    TaintCase(
        name="request_path_to_open",
        source=("def main():\n" "    path = request.GET.get('filename')\n" "    open(path)\n"),
        models=(REQUEST_GET_SOURCE, ModelSpec("open", sinks=("path",))),
        rules=(_rule("path"),),
        expected_rule_ids=frozenset({"PYSPECTOR-CORPUS"}),
    ),
    TaintCase(
        name="hardcoded_path_is_safe",
        source="def main():\n    open('config.toml')\n",
        models=(ModelSpec("open", sinks=("path",)),),
        rules=(_rule("path"),),
        expected_rule_ids=frozenset(),
    ),
    TaintCase(
        name="locally_constructed_path_is_safe",
        source=(
            "def main():\n"
            "    base = '/var/data'\n"
            "    name = 'output.txt'\n"
            "    open(base + '/' + name)\n"
        ),
        models=(ModelSpec("open", sinks=("path",)),),
        rules=(_rule("path"),),
        expected_rule_ids=frozenset(),
    ),
    TaintCase(
        name="unknown_string_method_preserves_taint",
        source=(
            "def main():\n"
            "    value = source()\n"
            "    cleaned = value.strip()\n"
            "    sink(cleaned)\n"
        ),
        models=(USER_SOURCE, ModelSpec("sink", sinks=("dangerous",))),
        rules=(_rule("dangerous"),),
        expected_rule_ids=frozenset({"PYSPECTOR-CORPUS"}),
    ),
    TaintCase(
        name="percent_formatted_sql_is_tainted",
        source=(
            "def main(cursor):\n"
            "    value = source()\n"
            "    query = 'SELECT * FROM users WHERE name=%s' % value\n"
            "    cursor.execute(query)\n"
        ),
        models=(USER_SOURCE, ModelSpec("cursor.execute", sinks=("sql",))),
        rules=(_rule("sql"),),
        expected_rule_ids=frozenset({"PYSPECTOR-CORPUS"}),
    ),
    TaintCase(
        name="fstring_sql_is_tainted",
        source=(
            "def main(cursor):\n"
            "    value = source()\n"
            "    cursor.execute(f'SELECT * FROM users WHERE name={value}')\n"
        ),
        models=(USER_SOURCE, ModelSpec("cursor.execute", sinks=("sql",))),
        rules=(_rule("sql"),),
        expected_rule_ids=frozenset({"PYSPECTOR-CORPUS"}),
    ),
    TaintCase(
        name="literal_sql_is_safe",
        source=("def main(cursor):\n" "    cursor.execute('SELECT * FROM users')\n"),
        models=(ModelSpec("cursor.execute", sinks=("sql",)),),
        rules=(_rule("sql"),),
        expected_rule_ids=frozenset(),
    ),
    TaintCase(
        name="parameterized_sql_value_is_not_statement_taint",
        source=(
            "def main(cursor):\n"
            "    value = source()\n"
            "    cursor.execute('SELECT * FROM users WHERE name=?', (value,))\n"
        ),
        models=(
            USER_SOURCE,
            ModelSpec("cursor.execute", sinks=("sql",), sink_positions=(0,)),
        ),
        rules=(_rule("sql"),),
        expected_rule_ids=frozenset(),
    ),
    TaintCase(
        name="universal_sanitizer_clears_taint",
        source=("def main():\n" "    value = source()\n" "    sink(clean(value))\n"),
        models=(
            USER_SOURCE,
            ModelSpec("clean", sanitizers=("*",)),
            ModelSpec("sink", sinks=("dangerous",)),
        ),
        rules=(_rule("dangerous"),),
        expected_rule_ids=frozenset(),
    ),
    TaintCase(
        name="kind_scoped_sanitizer_preserves_other_taint",
        source=("def main():\n" "    value = source()\n" "    sink(clean_html(value))\n"),
        models=(
            ModelSpec("source", sources=("html", "shell")),
            ModelSpec("clean_html", sanitizers=("html",)),
            ModelSpec("sink", sinks=("dangerous",)),
        ),
        rules=(
            RuleSpec("HTML-FLOW", ("html",), ("dangerous",)),
            RuleSpec("SHELL-FLOW", ("shell",), ("dangerous",)),
        ),
        expected_rule_ids=frozenset({"SHELL-FLOW"}),
    ),
    TaintCase(
        name="tainted_format_receiver_is_a_sink",
        source=("def main():\n" "    template = source()\n" "    template.format(name='alice')\n"),
        models=(
            USER_SOURCE,
            ModelSpec(
                "format",
                sinks=("format_string",),
                sink_positions=(),
                sink_receiver=True,
            ),
        ),
        rules=(_rule("format_string"),),
        expected_rule_ids=frozenset({"PYSPECTOR-CORPUS"}),
        engines=("ifds",),
    ),
    TaintCase(
        name="tainted_format_argument_with_literal_receiver_is_safe",
        source=("def main():\n" "    value = source()\n" "    '{}'.format(value)\n"),
        models=(
            USER_SOURCE,
            ModelSpec(
                "format",
                sinks=("format_string",),
                sink_positions=(),
                sink_receiver=True,
            ),
        ),
        rules=(_rule("format_string"),),
        expected_rule_ids=frozenset(),
        engines=("cpg", "ifds"),
    ),
    TaintCase(
        name="modeled_path_join_propagates_to_open",
        source=(
            "def main():\n"
            "    name = source()\n"
            "    path = os.path.join('/srv/data', name)\n"
            "    open(path)\n"
        ),
        models=(
            USER_SOURCE,
            ModelSpec("os.path.join", propagate_all_to_return=True),
            ModelSpec("open", sinks=("path",)),
        ),
        rules=(_rule("path"),),
        expected_rule_ids=frozenset({"PYSPECTOR-CORPUS"}),
    ),
    TaintCase(
        name="environment_path_is_operator_controlled",
        source=("def main():\n" "    path = os.environ.get('CONFIG_PATH')\n" "    open(path)\n"),
        models=(ModelSpec("open", sinks=("path",)),),
        rules=(_rule("path"),),
        expected_rule_ids=frozenset(),
    ),
    TaintCase(
        name="system_generated_path_is_safe",
        source=("def main():\n" "    path = tempfile.mkstemp()[1]\n" "    open(path)\n"),
        models=(ModelSpec("open", sinks=("path",)),),
        rules=(_rule("path"),),
        expected_rule_ids=frozenset(),
    ),
    TaintCase(
        name="tainted_symlink_source_is_reported",
        source=("def main():\n" "    path = source()\n" "    os.symlink(path, '/tmp/link')\n"),
        models=(USER_SOURCE, ModelSpec("os.symlink", sinks=("path",))),
        rules=(_rule("path"),),
        expected_rule_ids=frozenset({"PYSPECTOR-CORPUS"}),
    ),
    TaintCase(
        name="hardcoded_symlink_source_is_safe",
        source="def main():\n    os.symlink('/srv/source', '/tmp/link')\n",
        models=(ModelSpec("os.symlink", sinks=("path",)),),
        rules=(_rule("path"),),
        expected_rule_ids=frozenset(),
    ),
)


@dataclass(frozen=True)
class NonSinkCase:
    name: str
    statement: str


# PySpector disabled these rules after finding that ordinary transformations and
# introspection primitives caused large numbers of false positives.  The corpus
# protects pyflow from accidentally treating them as security sinks in the
# bundled stdlib taint policy.
NON_SINK_CASES = (
    NonSinkCase("hasattr", "hasattr(obj, value)"),
    NonSinkCase("vars", "vars(value)"),
    NonSinkCase("dir", "dir(value)"),
    NonSinkCase("callable", "callable(value)"),
    NonSinkCase("bytes", "bytes(value, 'utf-8')"),
    NonSinkCase("bytearray", "bytearray(value, 'utf-8')"),
    NonSinkCase("memoryview", "memoryview(value)"),
    NonSinkCase("ord", "ord(value)"),
    NonSinkCase("chr", "chr(value)"),
    NonSinkCase("center", "'x'.center(value)"),
    NonSinkCase("ljust", "'x'.ljust(value)"),
    NonSinkCase("rjust", "'x'.rjust(value)"),
    NonSinkCase("range", "range(value)"),
    NonSinkCase("join", "'/'.join(value)"),
    NonSinkCase("sorted", "sorted(value)"),
    NonSinkCase("sum", "sum(value)"),
    NonSinkCase("set", "set(value)"),
)


@dataclass(frozen=True)
class PatternCase:
    name: str
    source: str
    required_ids: frozenset[str] = frozenset()
    forbidden_ids: frozenset[str] = frozenset()
    filename: str = "sample.py"


PATTERN_CASES = (
    PatternCase(
        "yaml_safe_loader",
        "import yaml\ndata = yaml.load(stream, Loader=yaml.SafeLoader)\n",
        forbidden_ids=frozenset({"B402"}),
    ),
    PatternCase(
        "yaml_without_loader",
        "import yaml\ndata = yaml.load(stream)\n",
        required_ids=frozenset({"B402"}),
    ),
    PatternCase(
        "regex_compile_is_not_code_execution",
        "import re\npattern = re.compile(r'[a-z]+')\n",
        forbidden_ids=frozenset({"PY515", "SHELL645", "SHELL670"}),
    ),
    PatternCase(
        "pickle_loads_remains_reported",
        "import pickle\nvalue = pickle.loads(data)\n",
        required_ids=frozenset({"B301"}),
    ),
    PatternCase(
        "jsonpickle_decode_remains_reported",
        "import jsonpickle\nvalue = jsonpickle.decode(data)\n",
        required_ids=frozenset({"B404"}),
    ),
    PatternCase(
        "dill_loads_remains_reported",
        "import dill\nvalue = dill.loads(data)\n",
        required_ids=frozenset({"B301"}),
    ),
    PatternCase(
        "tls_verification_disabled",
        "response = requests.get(url, verify=False)\n",
        required_ids=frozenset({"B508"}),
    ),
    PatternCase(
        "tls_verification_enabled",
        "response = requests.get(url, verify=True)\n",
        forbidden_ids=frozenset({"B508"}),
    ),
    PatternCase(
        "torch_load_without_weights_only",
        "import torch\nmodel = torch.load(path)\n",
        required_ids=frozenset({"B611"}),
    ),
    PatternCase(
        "torch_load_with_weights_only",
        "import torch\nmodel = torch.load(path, weights_only=True)\n",
        forbidden_ids=frozenset({"B611"}),
    ),
    PatternCase(
        "flask_debug_enabled",
        "app.run(host='0.0.0.0', debug=True)\n",
        required_ids=frozenset({"B202"}),
    ),
    PatternCase(
        "flask_debug_disabled",
        "app.run(host='0.0.0.0', debug=False)\n",
        forbidden_ids=frozenset({"B202", "F101", "F109"}),
    ),
    PatternCase(
        "django_debug_enabled",
        "DEBUG = True\n",
        required_ids=frozenset({"D101"}),
        filename="settings.py",
    ),
    PatternCase(
        "django_debug_disabled",
        "DEBUG = False\n",
        forbidden_ids=frozenset({"B201", "D101"}),
        filename="settings.py",
    ),
    PatternCase(
        "csrf_exempt_production_view",
        (
            "from django.views.decorators.csrf import csrf_exempt\n"
            "@csrf_exempt\n"
            "def webhook(request):\n"
            "    return None\n"
        ),
        required_ids=frozenset({"A105"}),
        filename="views.py",
    ),
    PatternCase(
        "archive_extractall",
        "archive.extractall('/tmp/output')\n",
        required_ids=frozenset({"B108"}),
    ),
    PatternCase(
        "huggingface_trust_remote_code",
        (
            "model = transformers.AutoModel.from_pretrained(\n"
            "    name, trust_remote_code=True\n"
            ")\n"
        ),
        required_ids=frozenset({"B612"}),
    ),
)
