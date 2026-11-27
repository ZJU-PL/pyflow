"""Cross-subsystem integration tests for the TypeInfo -> CallGraph / IFDS / Alias bridge."""

from __future__ import annotations

from pyflow.analysis.alias.flow_sensitive import HeapAnalysis
from pyflow.analysis.callgraph.constraint_based import (
    AnalysisOptions,
    ConstraintCallGraphBuilder,
)
from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
from pyflow.analysis.taint_policy import TaintRule
from pyflow.analysis.typeinfo.core.typesystem import ANY, NoneType, TypeSystem, make_union
from pyflow.analysis.typeinfo.publication import (
    TypeFactBridge,
    publish_typeinfo_facts,
    type_fact_from_proper_type,
)
from pyflow.api.ifds import load_analysis_session, run_nullness_analysis
from pyflow.checker.ifds.api import run_taint_analysis
from pyflow.ir.core import Capabilities, PublishedProcedureTypes, PublishedTypeFact


def test_published_type_fact_helpers_and_catalog_publication(tmp_path):
    ts = TypeSystem()
    int_t = ts.convert_type_hint(int)
    str_t = ts.convert_type_hint(str)

    opt_int = type_fact_from_proper_type(make_union((int_t, NoneType())))
    assert isinstance(opt_int, PublishedTypeFact)
    assert opt_int.type_names == ("builtins.int",)
    assert opt_int.is_optional is True
    assert opt_int.is_gradual is False
    assert opt_int.primary_type_name == "builtins.int"
    assert opt_int.is_definite_non_optional is False

    gradual_str = type_fact_from_proper_type(make_union((str_t, ANY)))
    assert gradual_str is not None
    assert gradual_str.is_gradual is True
    assert gradual_str.primary_type_name == "builtins.str"

    target = tmp_path / "sample_pub.py"
    target.write_text("""
class Worker:
    def run(self) -> int:
        return 1

def make_worker() -> Worker:
    return Worker()

def driver(w: Worker) -> int:
    made = make_worker()
    return w.run() + made.run()
""")

    session = load_analysis_session([target], entry_file=target)
    catalog = session.program.ir
    assert catalog.facts.has(Capabilities.TYPE_SYMBOL_TYPES)
    assert catalog.facts.has(Capabilities.TYPE_CALL_RETURNS)
    assert catalog.facts.has(Capabilities.TYPE_PROCEDURE_SUMMARIES)

    proc_summaries = {
        code_id.qualname: next(iter(result.values))
        for code_id, result in catalog.facts.items(Capabilities.TYPE_PROCEDURE_SUMMARIES)
        if result.values
    }
    driver_summary = next(
        summary
        for qualname, summary in proc_summaries.items()
        if qualname.endswith("driver") and isinstance(summary, PublishedProcedureTypes)
    )
    w_fact = driver_summary.param_type("w")
    assert w_fact is not None
    assert any(name.endswith("Worker") for name in w_fact.type_names)
    assert driver_summary.return_type is not None
    assert "builtins.int" in driver_summary.return_type.type_names

    # Broken/missing files are isolated gracefully when publishing explicitly
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n")
    publish_typeinfo_facts(catalog, source_files={str(broken): "def broken(:\n"})


def test_callgraph_consumes_typeinfo_for_type_aliases_factories_and_attributes():
    source = """
class Alpha:
    def execute(self):
        return 1

class Beta:
    def execute(self):
        return 2

class Gamma:
    def execute(self):
        return 3

class Repo:
    def save(self):
        return True

type Handler = Alpha | Beta

active_handler: Handler

_REGISTRY = {}

def make_repo() -> Repo:
    return _REGISTRY["repo"]()

class Service:
    repo: Repo

    def process(self):
        return self.repo.save()

def dispatch(handler: Handler):
    return handler.execute()

def entry(flag):
    active_handler.execute()
    candidate = Alpha() if flag else Gamma()
    dispatch(candidate)
    r = make_repo()
    r.save()
    s = Service()
    s.process()
"""
    graph_with_typeinfo = ConstraintCallGraphBuilder(
        source,
        options=AnalysisOptions(use_type_hints=True, use_typeinfo_facts=True),
    ).build()

    edges_with = graph_with_typeinfo.get()
    # PEP 695 TypeAlias resolves both Alpha and Beta on annotated global
    assert "main.Alpha.execute" in edges_with.get("main.entry", set())
    assert "main.Beta.execute" in edges_with.get("main.entry", set())
    # Parameter annotation filtering via TypeAlias keeps Alpha and filters out Gamma
    assert "main.Alpha.execute" in edges_with.get("main.dispatch", set())
    assert "main.Gamma.execute" not in edges_with.get("main.dispatch", set())
    # Dynamic factory return annotation resolves Repo.save
    assert "main.Repo.save" in edges_with.get("main.entry", set())
    # Annotated class attribute resolves self.repo.save()
    assert "main.Repo.save" in edges_with.get("main.Service.process", set())

    # Toggling use_typeinfo_facts=False disables the TypeInfo fallback
    graph_without_typeinfo = ConstraintCallGraphBuilder(
        source,
        options=AnalysisOptions(use_type_hints=True, use_typeinfo_facts=False),
    ).build()
    edges_without = graph_without_typeinfo.get()
    assert "main.Repo.save" not in edges_without.get("main.Service.process", set())
    assert "main.Beta.execute" not in edges_without.get("main.entry", set())


def test_callgraph_consumes_typeinfo_for_type_checking_only_import(tmp_path):
    worker_file = tmp_path / "worker_mod.py"
    worker_file.write_text("""
class Worker:
    def run(self):
        return 42
""")
    app_file = tmp_path / "app_mod.py"
    app_source = """
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from worker_mod import Worker

current_worker: "Worker"

def trigger():
    return current_worker.run()
"""
    app_file.write_text(app_source)

    graph = ConstraintCallGraphBuilder(
        app_source,
        entry_path=str(app_file),
        project_root=str(tmp_path),
        additional_sources={str(worker_file): worker_file.read_text()},
        options=AnalysisOptions(use_type_hints=True, use_typeinfo_facts=True),
    ).build()

    assert "worker_mod.Worker.run" in graph.get().get("main.trigger", set())


def test_ifds_taint_uses_typeinfo_for_annotated_receiver_and_chained_factory(tmp_path):
    helper = tmp_path / "db_helper.py"
    helper.write_text("""
import sqlite3

def get_cursor() -> sqlite3.Cursor:
    conn = sqlite3.connect(":memory:")
    return conn.cursor()
""")
    app = tmp_path / "app.py"
    app.write_text("""
import sqlite3
from db_helper import get_cursor

def read_input():
    return "untrusted"

def run_param(cur: sqlite3.Cursor):
    q = read_input()
    cur.execute(q)

def run_chained():
    q = read_input()
    get_cursor().execute(q)
""")

    models = CallModelRegistry(
        [
            CallModel("read_input", source_kinds=frozenset({"user.input"})),
            CallModel("sqlite3.Cursor.execute", sink_kinds=frozenset({"sql.sink"})),
        ]
    )
    rules = (
        TaintRule(
            "SQLI-TYPEINFO",
            "Untrusted input reaches sqlite3.Cursor.execute",
            frozenset({"user.input"}),
            frozenset({"sql.sink"}),
        ),
    )

    _session_param, result_param, _ = run_taint_analysis(
        [app, helper],
        function="run_param",
        call_models=models,
        rules=rules,
    )
    assert len(result_param.findings) == 1
    assert result_param.findings[0].sink_name == "sqlite3.Cursor.execute"

    _session_chain, result_chain, _ = run_taint_analysis(
        [app, helper],
        function="run_chained",
        call_models=models,
        rules=rules,
    )
    assert len(result_chain.findings) == 1
    assert result_chain.findings[0].sink_name == "sqlite3.Cursor.execute"


def test_ifds_nullness_uses_typeinfo_optional_return_without_explicit_model(tmp_path):
    target = tmp_path / "opt_return.py"
    target.write_text("""
import re

def extract_digits(text: str):
    match = re.search(r"\\d+", text)
    return match.group(0)
""")

    # No nullable_return_names passed: nullness discovers Optional[Match] via TypeInfo facts
    _session, result = run_nullness_analysis(
        [target],
        function="extract_digits",
    )
    assert result.findings, "Expected nullness finding on unguarded re.search().group(0)"
    assert any("match" in finding.expression_label for finding in result.findings)


def test_alias_projects_typeinfo_metadata_weakly_attaches_factory_class_and_preserves_soundness(
    tmp_path,
):
    factory_stub = tmp_path / "ext_factory.pyi"
    factory_stub.write_text("""
from models import Box

def make_box() -> Box: ...
""")
    models = tmp_path / "models.py"
    models.write_text("""
from ext_factory import make_box

class Box:
    def touch(self):
        return self

def inspect_types(a: int, b: str):
    box = make_box()
    return a, b, box
""")

    session = load_analysis_session([models], entry_file=models)
    heap_analysis = HeapAnalysis()
    graph = heap_analysis.analyze(session.compiler, session.program)

    inspect_code = next(
        code for code in session.program.liveCode if code.codeName() == "inspect_types"
    )
    a_local = next(
        node
        for _nid, node in session.program.ir.nodes_for_code(inspect_code)
        if getattr(node, "name", None) == "a"
    )
    b_local = next(
        node
        for _nid, node in session.program.ir.nodes_for_code(inspect_code)
        if getattr(node, "name", None) == "b"
    )
    box_local = next(
        node
        for _nid, node in session.program.ir.nodes_for_code(inspect_code)
        if getattr(node, "name", None) == "box"
    )

    loc_a = heap_analysis.heap.locations_for_local(inspect_code, a_local)[0]
    loc_b = heap_analysis.heap.locations_for_local(inspect_code, b_local)[0]
    loc_box = heap_analysis.heap.locations_for_local(inspect_code, box_local)[0]

    # 1. Published TypeInfo metadata is projected onto PointsToGraph entries
    assert "builtins.int" in graph.inferred_types_for(loc_a)
    assert "builtins.str" in graph.inferred_types_for(loc_b)
    assert any(name.endswith("Box") for name in graph.inferred_types_for(loc_box))
    entry_a = graph.get(loc_a)
    assert entry_a is not None
    assert "builtins.int" in entry_a.to_dict().get("inferred_types", [])

    # 2. Soundness contract: parameter type annotations NEVER exclude parameter may-alias!
    assert graph.may_alias(loc_a, loc_b)

    # 3. Typed opaque factory return weakly attaches local class Box on __class__
    class_slot = heap_analysis.heap.dynamic_attribute_location(loc_box, "__class__")
    possible_classes = graph.possible_values_at(class_slot)
    assert (
        possible_classes.locations
    ), "Expected weak __class__ attachment from TypeInfo return fact"


def test_type_fact_bridge_laziness_and_caching():
    bridge = TypeFactBridge(enable_static_inference=True)
    assert bridge._service is None
    bridge.register_module_source(
        "demo",
        """
class Item:
    pass

def build() -> Item:
    return Item()
""",
    )
    assert bridge._service is None
    fact = bridge.return_type("demo", "build")
    assert bridge._service is not None
    assert fact is not None
    assert fact.primary_type_name == "demo.Item"
    # Second query hits cache
    assert bridge.return_type("demo", "build") is fact
