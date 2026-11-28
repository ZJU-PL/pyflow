"""Comprehensive unit and integration tests for PyFlow's shared infrastructure pillars.

Covers:
1. Workspace & SourceStore (file discovery, PEP 263, AST LRU cache, inode dedup, monorepo roots)
2. AnalysisEnvironment & ModuleGraph / ExportTable (branches, Tarjan SCC, re-exports, __all__)
3. Shared AnnotationExpr parser & unified SourceSpan / Diagnostic / Provenance
4. Declarative LibraryModelRegistry (Models-as-Data) & content-addressed SummaryCache
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import textwrap
from unittest.mock import patch

from pyflow.analysis.cache import IncrementalCache, SummaryCache, SummaryCacheKey
from pyflow.analysis.callgraph.constraint_based.engine import ConstraintCallGraphBuilder
from pyflow.analysis.typeinfo.inference.cache import (
    ProjectInferenceCache,
    TYPE_SUMMARY_SCHEMA_VERSION,
    options_fingerprint,
)
from pyflow.analysis.typeinfo.inference.engine import InferenceOptions, StaticTypeInferenceEngine
from pyflow.analysis.typeinfo.inference.models import (
    InferenceDiagnostic,
    InferenceProvenance,
    SourceSpan as TypeInfoSourceSpan,
)
from pyflow.analysis.typeinfo.resolution.imports import iter_module_imports
from pyflow.frontend.extractor import FileExtractionDiagnostic
from pyflow.frontend.frameworks import framework_entry_functions, http_entry_functions
from pyflow.frontend.source import read_python_source
from pyflow.language.annotations import (
    CallableAnnotation,
    GenericAnnotation,
    LiteralAnnotation,
    NameAnnotation,
    NoneAnnotation,
    UnionAnnotation,
    UnpackedAnnotation,
    WrappedAnnotation,
    extract_element_annotations,
    extract_literal_values,
    is_optional_annotation,
    is_type_object_annotation,
    iter_referenced_type_names,
    parse_annotation_ast,
    parse_annotation_str,
    unwrap_annotation_wrappers,
)
from pyflow.language.asttools.origin import SourceOrigin
from pyflow.language.diagnostics import Diagnostic, Provenance, SourceSpan
from pyflow.language.environment import (
    AnalysisEnvironment,
    evaluate_static_condition,
    iter_active_imports,
    iter_active_statements,
)
from pyflow.language.modules import (
    DEFAULT_IGNORED_DIRS,
    ModuleExportTable,
    ModuleGraph,
    SourceStore,
    Workspace,
    discover_source_roots,
    parse_source_cached,
    resolve_relative_module,
)
from pyflow.language.modules.imports import discover_module_exports, iter_import_nodes_in_scope
from pyflow.language.modules.type_stubs import StubDiagnostic
from pyflow.model import default_library_models, load_library_models

# ---------------------------------------------------------------------------
# Pillar 1: Workspace & SourceStore
# ---------------------------------------------------------------------------


def test_source_store_encoding_hashing_ast_cache_and_symlink_dedup(tmp_path: Path) -> None:
    latin1 = tmp_path / "latin1.py"
    latin1.write_bytes(b"# -*- coding: latin-1 -*-\nLABEL = 'caf\xe9'\n")
    bom = tmp_path / "bom.py"
    bom.write_bytes("\ufeffX = 1\n".encode("utf-8"))
    link = tmp_path / "latin1_link.py"
    link.symlink_to(latin1)

    assert "café" in read_python_source(latin1)

    store = SourceStore(max_ast_cache=4)
    rec1 = store.load(latin1)
    rec2 = store.load(bom)
    assert "café" in rec1.text
    assert rec2.text == "X = 1\n"
    assert len(rec1.content_hash) == 32
    assert store.canonical_path(link) == rec1.real_path

    tree_a = store.parse_ast(latin1)
    tree_b = store.parse_ast(latin1)
    assert tree_a is tree_b  # cached read-only AST hit

    # Syntax errors are cached cleanly and re-raised on subsequent parses.
    bad = tmp_path / "bad.py"
    bad.write_text("def broken(:\n", encoding="utf-8")
    for _ in range(2):
        try:
            store.parse_ast(bad)
            assert False, "expected SyntaxError"
        except SyntaxError:
            pass

    # Process-wide parse_source_cached returns identical AST object on hit.
    t1 = parse_source_cached("VALUE = 42\n", filename="cached_demo.py")
    t2 = parse_source_cached("VALUE = 42\n", filename="cached_demo.py")
    assert t1 is t2


def test_workspace_discovery_src_layout_and_monorepo_roots(tmp_path: Path) -> None:
    # Monorepo layout: libs/core/mypkg + src/app + ignored dirs + template dirs.
    (tmp_path / "libs" / "core" / "mypkg").mkdir(parents=True)
    (tmp_path / "libs" / "core" / "mypkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "libs" / "core" / "mypkg" / "util.py").write_text(
        "def helper():\n    return 1\n", encoding="utf-8"
    )
    (tmp_path / "src" / "app").mkdir(parents=True)
    (tmp_path / "src" / "app" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "app" / "main.py").write_text(
        "from mypkg.util import helper\nRES = helper()\n", encoding="utf-8"
    )
    (tmp_path / "node_modules" / "junk").mkdir(parents=True)
    (tmp_path / "node_modules" / "junk" / "bad.py").write_text("def (:\n", encoding="utf-8")
    (tmp_path / "templates" / "{{cookiecutter.pkg}}").mkdir(parents=True)
    (tmp_path / "templates" / "{{cookiecutter.pkg}}" / "x.py").write_text(
        "X = 1\n", encoding="utf-8"
    )

    ws = Workspace(tmp_path, discover_roots=True)
    modules = dict(ws.iter_modules())
    assert "app.main" in modules
    assert "mypkg.util" in modules
    assert not any(name.startswith("src.") for name in modules)
    assert not any("node_modules" in name for name in modules)
    assert not any("cookiecutter" in name for name in modules)

    # ProjectContext wired with discovered monorepo roots resolves mypkg.util directly.
    res = ws.project_context.find_module("mypkg.util")
    assert res is not None and res.path is not None
    assert Path(res.path).name == "util.py"
    assert "node_modules" in DEFAULT_IGNORED_DIRS


def test_discover_source_roots_standalone(tmp_path: Path) -> None:
    lib = tmp_path / "packages" / "alpha" / "alphapkg"
    lib.mkdir(parents=True)
    (lib / "__init__.py").write_text("", encoding="utf-8")
    mod = lib / "core.py"
    mod.write_text("X = 1\n", encoding="utf-8")
    entry = tmp_path / "run.py"
    entry.write_text("import alphapkg.core\n", encoding="utf-8")

    sources = {str(p): p.read_text(encoding="utf-8") for p in tmp_path.rglob("*.py")}
    roots = discover_source_roots(tmp_path, sources)
    assert str((tmp_path / "packages" / "alpha").resolve()) in roots


# ---------------------------------------------------------------------------
# Pillar 2: AnalysisEnvironment & ModuleGraph / ExportTable
# ---------------------------------------------------------------------------


def test_analysis_environment_static_condition_evaluation() -> None:
    env_311_linux = AnalysisEnvironment(
        python_version=(3, 11), platform="linux", type_checking=True
    )
    env_39_win = AnalysisEnvironment(python_version=(3, 9), platform="win32", type_checking=False)
    env_neutral = AnalysisEnvironment(python_version=(3, 12), platform="darwin", type_checking=None)

    def eval_expr(code: str, env: AnalysisEnvironment, aliases=None):
        return evaluate_static_condition(ast.parse(code, mode="eval").body, env, aliases=aliases)

    assert eval_expr("TYPE_CHECKING", env_311_linux) is True
    assert eval_expr("typing.TYPE_CHECKING", env_39_win) is False
    assert eval_expr("typing_extensions.TYPE_CHECKING", env_311_linux) is True
    assert eval_expr("TC", env_311_linux, {"TC": "typing.TYPE_CHECKING"}) is True
    assert eval_expr("TYPE_CHECKING", env_neutral) is None
    assert eval_expr("not TYPE_CHECKING", env_39_win) is True

    assert eval_expr("sys.version_info >= (3, 11)", env_311_linux) is True
    assert eval_expr("sys.version_info >= (3, 11)", env_39_win) is False
    assert eval_expr("(3, 10) <= sys.version_info < (3, 12)", env_311_linux) is True
    assert eval_expr("sys.version_info[:2] == (3, 11)", env_311_linux) is True
    assert eval_expr("sys.version_info.minor == 9", env_39_win) is True

    assert eval_expr("sys.platform == 'win32'", env_39_win) is True
    assert eval_expr("sys.platform == 'win32'", env_311_linux) is False
    assert eval_expr("sys.platform.startswith('linux')", env_311_linux) is True
    assert eval_expr("sys.platform in ('darwin', 'linux')", env_neutral) is True
    assert eval_expr("os.name == 'nt'", env_39_win) is True
    assert eval_expr("os.name == 'posix'", env_311_linux) is True

    # Kleene 3-valued logic preserves dynamic unknowns conservatively.
    assert eval_expr("False and some_flag", env_311_linux) is False
    assert eval_expr("True or some_flag", env_311_linux) is True
    assert eval_expr("True and some_flag", env_311_linux) is None
    assert eval_expr("False or some_flag", env_311_linux) is None

    assert env_311_linux.fingerprint() != env_39_win.fingerprint()


def test_iter_active_statements_and_imports_prune_dead_branches() -> None:
    src = textwrap.dedent("""
        import sys
        from typing import TYPE_CHECKING as TC

        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib

        if TC:
            import only_for_types
        else:
            import only_for_runtime

        if dynamic_flag:
            import dyn_a
        else:
            import dyn_b
    """)
    tree = ast.parse(src)
    env_rt = AnalysisEnvironment(python_version=(3, 12), platform="linux", type_checking=False)
    env_tc = env_rt.for_type_checking()

    rt_names = [
        alias.name
        for node in iter_active_imports(tree.body, env_rt)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    assert "tomllib" in rt_names
    assert "tomli" not in rt_names
    assert "only_for_runtime" in rt_names
    assert "only_for_types" not in rt_names
    assert "dyn_a" in rt_names and "dyn_b" in rt_names

    tc_names = [
        alias.name
        for node in iter_active_imports(tree.body, env_tc)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    assert "only_for_types" in tc_names
    assert "only_for_runtime" not in tc_names

    # Shared iter_import_nodes_in_scope & iter_module_imports respect explicit environment.
    scoped_names = [
        alias.name
        for node in iter_import_nodes_in_scope(tree.body, environment=env_rt)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    assert "only_for_runtime" in scoped_names
    assert "only_for_types" not in scoped_names

    env_mod_imports = [
        alias.name
        for node in iter_module_imports(tree.body, environment=env_tc)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    assert "only_for_types" in env_mod_imports
    assert "only_for_runtime" not in env_mod_imports
    all_mod_imports = [
        alias.name
        for node in iter_module_imports(tree.body)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    assert "only_for_types" in all_mod_imports and "only_for_runtime" in all_mod_imports

    active_stmts = list(iter_active_statements(tree.body, env_rt))
    assert any(isinstance(s, ast.If) for s in active_stmts)  # dynamic_flag kept intact


def test_module_graph_relative_imports_all_scc_reexports_and_fingerprints(tmp_path: Path) -> None:
    assert resolve_relative_module("pkg.sub", "mod", 1, is_package=True) == "pkg.sub.mod"
    assert resolve_relative_module("pkg.sub.a", "b", 1, is_package=False) == "pkg.sub.b"
    assert resolve_relative_module("pkg.sub.a", "top", 2, is_package=False) == "pkg.top"

    sources = {
        "pkg": (
            "from .api import *\n"
            "__all__ = ['Widget']\n"
            "__all__ += ['make_widget']\n"
            "__all__.append('Alias')\n",
            str(tmp_path / "pkg" / "__init__.py"),
        ),
        "pkg.api": (
            "from .core import Widget as Widget, make_widget\n"
            "from .cycle_a import A as Alias\n"
            "__all__ = ['Widget']\n"
            "__all__.extend(['make_widget', 'Alias'])\n",
            str(tmp_path / "pkg" / "api.py"),
        ),
        "pkg.core": (
            "class Widget:\n    pass\ndef make_widget():\n    return Widget()\n",
            str(tmp_path / "pkg" / "core.py"),
        ),
        "pkg.cycle_a": (
            "from .cycle_b import B\nclass A:\n    pass\n",
            str(tmp_path / "pkg" / "cycle_a.py"),
        ),
        "pkg.cycle_b": (
            "from .cycle_a import A\nclass B:\n    pass\n",
            str(tmp_path / "pkg" / "cycle_b.py"),
        ),
    }

    graph = ModuleGraph.from_sources(sources)
    assert graph.modules["pkg"].explicit_all == ("Widget", "make_widget", "Alias")
    assert discover_module_exports(sources["pkg"][0]) == ["Widget", "make_widget", "Alias"]

    # Re-export chains across star imports & explicit re-exports.
    assert graph.resolve_reexport("pkg", "Widget") == ("pkg.core", "Widget")
    assert graph.resolve_reexport("pkg", "make_widget") == ("pkg.core", "make_widget")
    assert graph.resolve_reexport("pkg", "Alias") == ("pkg.cycle_a", "A")
    assert graph.expanded_exports("pkg") == {
        "Alias": ("pkg.cycle_a", "A"),
        "Widget": ("pkg.core", "Widget"),
        "make_widget": ("pkg.core", "make_widget"),
    }

    # Bottom-up SCC ordering: pkg.core and cycle SCC precede pkg.api which precedes pkg.
    sccs = graph.sccs()
    assert ("pkg.cycle_a", "pkg.cycle_b") in sccs
    topo = graph.topological_order()
    assert topo.index("pkg.core") < topo.index("pkg.api") < topo.index("pkg")
    assert "pkg" in graph.transitive_dependents("pkg.core")

    # Merkle dependency fingerprint changes when a transitive dependency changes.
    fp_before = graph.dependency_fingerprint("pkg")
    mutated = dict(sources)
    mutated["pkg.core"] = (
        "class Widget:\n    x = 1\ndef make_widget():\n    return Widget()\n",
        sources["pkg.core"][1],
    )
    graph2 = ModuleGraph.from_sources(mutated)
    assert graph2.dependency_fingerprint("pkg") != fp_before

    # Round-trip ModuleExportTable serialization.
    raw = graph.modules["pkg"].to_dict()
    rehydrated = ModuleExportTable.from_dict(raw)
    assert rehydrated.module_name == "pkg"
    assert rehydrated.explicit_all == ("Widget", "make_widget", "Alias")
    assert len(rehydrated.imports) == len(graph.modules["pkg"].imports)


# ---------------------------------------------------------------------------
# Pillar 3: Shared Annotation Parser & Unified SourceSpan / Diagnostic
# ---------------------------------------------------------------------------


def test_shared_annotation_parser_and_helpers() -> None:
    aliases = {"Opt": "typing.Optional", "Ann": "typing_extensions.Annotated"}
    ann = parse_annotation_str("Ann[Final[Opt[list['pkg.Item']]], 'meta']", aliases=aliases)
    assert isinstance(ann, WrappedAnnotation)
    unwrapped = unwrap_annotation_wrappers(ann)
    assert isinstance(unwrapped, UnionAnnotation)
    assert is_optional_annotation(ann)
    assert list(iter_referenced_type_names(ann)) == ["list", "pkg.Item"]

    elem_anns = extract_element_annotations(ann)
    assert elem_anns == (NameAnnotation("pkg.Item"),)

    type_obj = parse_annotation_str("Optional[Annotated[type[Base], 'cls']]")
    assert is_type_object_annotation(type_obj)
    assert not is_type_object_annotation(parse_annotation_str("int | str"))

    lit = parse_annotation_str("Literal['a', -1, None]")
    assert isinstance(lit, LiteralAnnotation)
    assert extract_literal_values(lit) == ("a", -1, None)

    cb = parse_annotation_str("Callable[[int, str], bool]")
    assert isinstance(cb, CallableAnnotation)
    assert cb.params == (NameAnnotation("int"), NameAnnotation("str"))
    assert cb.returns == NameAnnotation("bool")

    cb_dots = parse_annotation_str("Callable[..., None]")
    assert isinstance(cb_dots, CallableAnnotation)
    assert cb_dots.params is None
    assert cb_dots.returns == NoneAnnotation()

    unpacked = parse_annotation_ast(ast.parse("tuple[*Ts]", mode="eval").body)
    assert isinstance(unpacked, GenericAnnotation)
    assert isinstance(unpacked.args[0], UnpackedAnnotation)


def test_callgraph_uses_shared_annotation_parser_for_wrappers_and_type_objects() -> None:
    source = textwrap.dedent("""
        import typing as t
        from typing import Annotated, Final, Optional, Type

        class Service:
            def run(self):
                return 1

        def get_cls() -> "Optional[Annotated[Type[Service], 'meta']]":
            ...

        def get_svc() -> Final[Service]:
            ...

        def get_opt_svc() -> t.Optional[Service]:
            ...

        def get_str_svc() -> "Service":
            ...

        def entry():
            cls = get_cls()
            cls().run()
            svc = get_svc()
            svc.run()
            opt = get_opt_svc()
            opt.run()
            s = get_str_svc()
            s.run()

        entry()
    """)
    builder = ConstraintCallGraphBuilder(source)
    graph = builder.build()
    edges = graph.get()
    assert "main.Service.run" in edges["main.entry"]
    assert isinstance(graph.structured_diagnostics(), list)


def test_unified_diagnostics_spans_and_provenance_adapters() -> None:
    assert TypeInfoSourceSpan is SourceSpan
    assert issubclass(InferenceProvenance, Provenance)

    node = ast.parse("x = 1\n").body[0]
    span = SourceSpan.from_ast(node)
    assert span is not None and span.lineno == 1 and span.col_offset == 0

    origin = SourceOrigin.from_span(span, filename="app.py", name="f")
    assert origin.to_source_span() == span

    ext_diag = FileExtractionDiagnostic(
        filename="bad.py",
        stage="parse",
        exception_type="SyntaxError",
        message="bad",
        line=3,
        column=4,
    ).to_diagnostic()
    assert isinstance(ext_diag, Diagnostic)
    assert ext_diag.category == "extraction"
    assert ext_diag.lineno == 3 and ext_diag.col_offset == 4
    assert ext_diag.affects_completeness is True

    stub_diag = StubDiagnostic(
        code="type_stub_failed",
        category="type_stub",
        module_name="demo",
        message="broken stub",
        path="demo.pyi",
        lineno=7,
        col_offset=2,
    ).to_diagnostic()
    assert stub_diag.module_name == "demo" and stub_diag.lineno == 7

    inf_diag = InferenceDiagnostic(
        code="annotation-mismatch",
        message="bad type",
        span=span,
    ).to_diagnostic(module_name="app", filename="app.py")
    assert inf_diag.to_dict()["code"] == "annotation-mismatch"
    assert inf_diag.to_dict()["lineno"] == 1

    cg_diag = Diagnostic.from_callgraph_message("Constraint fixpoint time budget exhausted")
    assert cg_diag.code == "callgraph-budget-exhausted"
    assert cg_diag.affects_completeness is True


# ---------------------------------------------------------------------------
# Pillar 4: Declarative Models-as-Data Registry & SummaryCache
# ---------------------------------------------------------------------------


def test_library_model_registry_builtins_and_custom_json_pack(tmp_path: Path) -> None:
    defaults = default_library_models()
    assert defaults.is_passthrough_class_decorator("dataclasses.dataclass")
    assert defaults.is_passthrough_class_decorator("attrs.define")
    assert defaults.is_passthrough_class_decorator("rich.repr.auto")
    assert defaults.is_passthrough_function_decorator("functools.lru_cache")
    assert defaults.lookup_callable("signal.signal") is not None
    assert defaults.lookup_callable("signal.signal").callback_arg_positions == (1,)
    assert "flask.Flask" in defaults.factory_classes(entrypoint_kinds=("http",))

    # Custom JSON pack extends cleanly without mutating the process-wide defaults.
    custom_json = tmp_path / "custom_models.json"
    custom_json.write_text(
        json.dumps(
            {
                "decorators": [
                    {
                        "qualified_names": ["acme.entity"],
                        "target_kind": "class",
                        "behavior": "passthrough",
                    }
                ],
                "framework_routes": [
                    {
                        "name": "acme_rpc",
                        "entrypoint_kind": "rpc",
                        "factory_classes": ["acme.RpcServer"],
                        "decorator_methods": ["expose"],
                        "hint_tokens": ["RpcServer"],
                    }
                ],
                "callables": [
                    {
                        "qualified_name": "acme.on_event",
                        "callback_arg_positions": [1],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    extended = load_library_models([custom_json])
    assert extended.is_passthrough_class_decorator("acme.entity")
    assert not defaults.is_passthrough_class_decorator("acme.entity")

    sources = {
        "rpc.py": (
            "from acme import RpcServer\n"
            "srv = RpcServer()\n"
            "@srv.expose('ping')\n"
            "def handle_ping():\n"
            "    return 'pong'\n"
        ),
        "cli.py": ("import click\n" "@click.command()\n" "def run_cli():\n" "    pass\n"),
    }
    assert framework_entry_functions(sources, entrypoint_kinds=("rpc",), registry=extended) == {
        ("rpc.py", "handle_ping")
    }
    assert framework_entry_functions(sources, entrypoint_kinds=("cli",), registry=extended) == {
        ("cli.py", "run_cli")
    }
    assert http_entry_functions(sources) == set()


def test_typeinfo_and_callgraph_consume_library_models() -> None:
    # TypeInfo preserves class identity for modeled pass-through decorators
    # (including rich.repr.auto and functools.total_ordering from builtin_models.json),
    # while truly unknown decorators stay unknown.
    src = textwrap.dedent("""
        import functools
        import rich.repr

        @rich.repr.auto
        @functools.total_ordering
        class Config:
            port: int = 8080

        @missing_decorator
        class MysteryClass:
            def ping(self) -> int:
                return 1

        def make() -> Config:
            return Config()

        cfg = Config()
        m_inst = MysteryClass()
    """)
    engine = StaticTypeInferenceEngine()
    res = engine.infer_source("demo", src)
    assert not [d for d in res.diagnostics if d.code == "annotation-mismatch"]
    assert res.value_of("Config").unknown is False
    assert str(res.type_of("cfg")) == "demo.Config"
    assert res.functions["demo.make"].return_type.type.full_name == "demo.Config"
    assert res.value_of("MysteryClass").unknown is True
    assert res.value_of("m_inst").unknown is True
    assert res.type_of("m_inst") is None

    # Constraint call graph resolves callback edges from Models-as-Data
    # (both positional & keyword callbacks hitting the registry fallback).
    cg_src = textwrap.dedent("""
        import heapq
        import itertools
        import signal
        import sys
        import weakref

        def on_sig(signum, frame):
            return signum

        def on_cleanup():
            return 1

        def pred(x):
            return x > 0

        def score(x):
            return x

        def on_audit(event, args):
            return event

        def setup(obj, items):
            signal.signal(signal.SIGTERM, on_sig)
            weakref.finalize(obj, on_cleanup)
            itertools.takewhile(pred, items)
            heapq.nlargest(3, items, key=score)
            sys.addaudithook(on_audit)

        setup(object(), [1, 2, 3])
    """)
    edges = ConstraintCallGraphBuilder(cg_src).build().get()
    assert "main.on_sig" in edges["main.setup"]
    assert "main.on_cleanup" in edges["main.setup"]
    assert "main.pred" in edges["main.setup"]
    assert "main.score" in edges["main.setup"]
    assert "main.on_audit" in edges["main.setup"]


def test_summary_cache_persistence_invalidation_and_integrations(tmp_path: Path) -> None:
    db_path = tmp_path / "cache" / "summaries.db"
    env_a = AnalysisEnvironment(python_version=(3, 12), platform="linux", type_checking=True)
    env_b = AnalysisEnvironment(python_version=(3, 11), platform="linux", type_checking=True)

    # 1. Persistent round-trip across separate SummaryCache instances & key dimensions.
    key = SummaryCacheKey(
        namespace="type_summary",
        module_name="pkg.mod",
        file_hash="hash_v1",
        env_fingerprint=env_a.fingerprint(),
        dependency_hash="dep_v1",
        schema_version="v1",
    )
    with SummaryCache(db_path) as cache:
        assert cache.get(key) is None
        cache.put(key, {"symbols": {"X": "int"}})
        assert cache.get(key) == {"symbols": {"X": "int"}}

    with SummaryCache(db_path) as cache2:
        assert cache2.get(key) == {"symbols": {"X": "int"}}
        # Changing file_hash, dep_hash, env_fingerprint, or schema_version misses safely.
        assert (
            cache2.get(
                SummaryCacheKey(
                    "type_summary", "pkg.mod", "hash_v2", env_a.fingerprint(), "dep_v1", "v1"
                )
            )
            is None
        )
        assert (
            cache2.get(
                SummaryCacheKey(
                    "type_summary", "pkg.mod", "hash_v1", env_b.fingerprint(), "dep_v1", "v1"
                )
            )
            is None
        )
        assert (
            cache2.get(
                SummaryCacheKey(
                    "type_summary", "pkg.mod", "hash_v1", env_a.fingerprint(), "dep_v1", "v2"
                )
            )
            is None
        )
        assert cache2.prune_stale_schemas("type_summary", "v2") == 1
        assert cache2.stats().entries == 0

    # 2. ModuleGraph integration + transitive invalidation.
    pkg = tmp_path / "proj" / "demo"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "leaf.py").write_text("VAL = 1\n", encoding="utf-8")
    (pkg / "mid.py").write_text("from demo.leaf import VAL\nOUT = VAL\n", encoding="utf-8")
    (pkg / "unrelated.py").write_text("Z = 9\n", encoding="utf-8")

    ws = Workspace(tmp_path / "proj", environment=env_a)
    with SummaryCache(db_path) as cache:
        g1 = ModuleGraph.from_workspace(ws, summary_cache=cache)
        assert cache.writes == 4
        # Second build hits cached ModuleExportTables without re-parsing ASTs.
        with patch.object(
            ws.source_store, "parse_ast", side_effect=AssertionError("should use cache")
        ):
            g2 = ModuleGraph.from_workspace(ws, summary_cache=cache)
        assert set(g2.modules) == set(g1.modules)
        assert cache.hits >= 4

        # Invalidating demo.leaf removes demo.leaf and demo.mid, keeping demo.unrelated.
        removed = cache.invalidate_affected(["demo.leaf"], g2, namespace="module_exports")
        assert removed == 2
        assert cache.stats().entries == 2

    # 3. IncrementalCache & ProjectInferenceCache persistence integration.
    with IncrementalCache(str(db_path)) as inc:
        inf_cache = ProjectInferenceCache(summary_cache=inc.summary_cache, environment=env_a)
        res = StaticTypeInferenceEngine().infer_source("demo.leaf", "ANSWER: int = 42\n")
        opts_key = options_fingerprint(InferenceOptions())
        inf_cache.put("demo.leaf", "fp123", opts_key, res)
        persisted = inf_cache.get_persisted_summary("demo.leaf", "fp123", opts_key)
        assert persisted is not None
        assert persisted["schema_version"] == TYPE_SUMMARY_SCHEMA_VERSION
        assert persisted["symbols"]["demo.leaf.ANSWER"]["type"] == "int"
