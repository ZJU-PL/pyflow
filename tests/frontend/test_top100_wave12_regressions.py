"""Regression tests for Wave 12 frontend, typeinfo, and callgraph top-100 fixes."""

from __future__ import annotations

import ast as python_ast
import textwrap
from pathlib import Path

import pytest

from pyflow.analysis.callgraph import (
    extract_call_graph_constraint,
    extract_call_site_edge_index_constraint,
    extract_value_flow_graph_constraint,
)
from pyflow.analysis.callgraph.constraint_based.engine import ConstraintCallGraphBuilder
from pyflow.analysis.callgraph.constraint_based.model import (
    UNKNOWN_VALUE,
    AnalysisOptions,
    make_string,
)
from pyflow.analysis.typeinfo import (
    InferenceOptions,
    StaticTypeInferenceEngine,
    TypeInfoService,
)
from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    CallableType,
    ClassDescriptor,
    Instance,
    TupleType,
    TypeSystem,
    TypeVarType,
)
from pyflow.analysis.typeinfo.resolution.docstrings import expand_typestr
from pyflow.analysis.typeinfo.resolution.format_strings import (
    check_percent_format,
    check_str_format,
    str_format_fields,
)
from pyflow.analysis.typeinfo.resolution.typing_syntax import substitute_type_vars
from pyflow.frontend.conversion.ast import ASTConverter
from pyflow.frontend.frameworks import http_entry_functions
from pyflow.language.modules._scope_graph import ScopeGraph
from pyflow.language.modules.project_resolution import ProjectContext
from pyflow.language.python import ast as pyflow_ast

# ---------------------------------------------------------------------------
# CallGraph & ProjectContext regressions
# ---------------------------------------------------------------------------


def test_callgraph_skip_stdlib_modules_skips_typeshed_stubs_but_keeps_local_shadow(
    tmp_path: Path,
) -> None:
    """skip_stdlib_modules=True must skip stdlib stubs without hiding project-local shadows."""
    entry = tmp_path / "app.py"
    local_shadow = tmp_path / "json.py"
    local_shadow.write_text("def custom_load():\n    return 1\n", encoding="utf-8")
    source = textwrap.dedent("""
        import os
        import re
        import sys
        import typing
        import json

        def run():
            return json.custom_load()
        """)
    entry.write_text(source, encoding="utf-8")

    builder = ConstraintCallGraphBuilder(
        source,
        entry_path=str(entry),
        project_root=str(tmp_path),
        options=AnalysisOptions(skip_stdlib_modules=True, skip_external_modules=False),
    )
    builder._load_modules()

    # Stdlib modules (including those backed by bundled typeshed .pyi stubs)
    # must not be loaded into the call graph.
    for stdlib_mod in ("os", "re", "sys", "typing", "_typeshed", "builtins"):
        assert stdlib_mod not in builder.modules
    # A project-local module shadowing a stdlib name must still be loaded.
    assert "json" in builder.modules


def test_callgraph_strict_precision_mode_widens_int_tokens_and_caps_combinations() -> None:
    """strict_precision_mode must not concatenate #int tokens or explode on loops."""
    builder = ConstraintCallGraphBuilder(
        "",
        options=AnalysisOptions(strict_precision_mode=True, max_values_per_binding=4),
    )
    assert builder._combine_string_values({make_string("#1")}, {make_string("#2")}) == {
        make_string("#int")
    }
    lhs = {make_string(f"a{i}") for i in range(4)}
    rhs = {make_string(f"b{i}") for i in range(4)}
    assert builder._combine_string_values(lhs, rhs) == {UNKNOWN_VALUE}

    fib_source = textwrap.dedent("""
        def fib_search(arr, val):
            fib_k_2 = 0
            fib_k_1 = 1
            fib_k = fib_k_1 + fib_k_2
            while fib_k < len(arr):
                fib_k_2 = fib_k_1
                fib_k_1 = fib_k
                fib_k = fib_k_1 + fib_k_2
            return fib_k
        """)
    cg = extract_call_graph_constraint(
        fib_source,
        context_sensitive=True,
        context_depth=2,
        strict_precision_mode=True,
        fixpoint_max_seconds=2.0,
        warn_on_fixpoint_truncation=False,
    )
    assert "main.fib_search" in cg.get()


def test_callgraph_value_flow_and_call_site_apis_accept_project_root_and_skip_external(
    tmp_path: Path,
) -> None:
    """Constraint VFG and call-site edge APIs accept project_root/skip_external_modules."""
    entry = tmp_path / "entry.py"
    helper = tmp_path / "helper.py"
    helper.write_text("def target():\n    return 42\n", encoding="utf-8")
    src = "from helper import target\n\ndef main():\n    return target()\n\nmain()\n"
    entry.write_text(src, encoding="utf-8")

    vfg = extract_value_flow_graph_constraint(
        src,
        source_path=str(entry),
        project_root=str(tmp_path),
        skip_external_modules=True,
        additional_sources={str(helper): helper.read_text(encoding="utf-8")},
    )
    assert isinstance(vfg, dict)

    edges = extract_call_site_edge_index_constraint(
        src,
        source_path=str(entry),
        project_root=str(tmp_path),
        skip_external_modules=True,
        additional_sources={str(helper): helper.read_text(encoding="utf-8")},
    )
    all_targets = {t for targets in edges.values() for t in targets}
    assert any("target" in t for t in all_targets)


def test_project_context_find_module_shares_cache_across_sibling_files(tmp_path: Path) -> None:
    """Sibling files sharing the same search path should reuse cached module hits."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "a.py").write_text("", encoding="utf-8")
    (pkg / "b.py").write_text("", encoding="utf-8")
    (pkg / "target.py").write_text("X = 1\n", encoding="utf-8")

    ctx = ProjectContext(tmp_path, sys_path=[])
    r1 = ctx.find_module("pkg.target", script_path=str(pkg / "a.py"))
    cache_size_after_first = len(ctx._find_module_cache)
    r2 = ctx.find_module("pkg.target", script_path=str(pkg / "b.py"))

    assert r1 is not None and r2 is not None
    assert r1.path == r2.path
    assert len(ctx._find_module_cache) == cache_size_after_first


# ---------------------------------------------------------------------------
# TypeInfo regressions
# ---------------------------------------------------------------------------


def test_typeinfo_service_keeps_third_party_typed_package_annotations_lazy(tmp_path: Path) -> None:
    """Collecting a third-party py.typed package must not eagerly crawl unused submodules."""
    site = tmp_path / "site-packages"
    pkg = site / "biglib"
    pkg.mkdir(parents=True)
    (pkg / "py.typed").write_text("", encoding="utf-8")
    (pkg / "deep.py").write_text("class DeepPayload:\n    value: int\n", encoding="utf-8")
    (pkg / "base.py").write_text(
        "class BaseClient:\n    def ping(self) -> str:\n        return 'ok'\n",
        encoding="utf-8",
    )
    (pkg / "__init__.py").write_text(
        textwrap.dedent("""
            from biglib.base import BaseClient
            from biglib.deep import DeepPayload

            class Client(BaseClient):
                def fetch(self) -> DeepPayload:
                    ...
            """),
        encoding="utf-8",
    )

    project = tmp_path / "proj"
    project.mkdir()
    app_src = "from biglib import Client\n\nc: Client\n"
    app_path = project / "app.py"
    app_path.write_text(app_src, encoding="utf-8")

    ctx = ProjectContext(project, sys_path=[str(site)])
    svc = TypeInfoService(ctx)
    svc.collect_module("app", source=app_src, path=str(app_path))

    assert "biglib" in svc._collected_modules
    assert "biglib.deep" not in svc._collected_modules
    # Inherited base methods are still loaded lazily on demand.
    members = svc.members_of("biglib.Client")
    assert "ping" in members
    assert "biglib.base" in svc._collected_modules


def test_typeinfo_str_and_percent_format_regressions() -> None:
    """Format string checks handle **kwargs, *args, mixed {}/{name}, nested specs, and Any."""
    assert str_format_fields("{:.{width}f}") == ["", "width"]
    assert check_str_format("{} {name}", 1, {"name"}) == []
    assert check_str_format("{.attr} {name}", 1, {"name"}) == []
    assert check_str_format("{a} {b}", 0, set(), has_double_starred=True) == []
    assert check_str_format("{} {}", 0, set(), has_starred=True) == []
    assert any("mix automatic and manual" in m for m in check_str_format("{} {0}", 2, set()))

    ts = TypeSystem()
    str_t = Instance(ts.to_class_descriptor(str))
    int_t = Instance(ts.to_class_descriptor(int))
    assert check_percent_format("%(a)s %(b)d", str_t, ts) == []
    assert check_percent_format("%d %s", TupleType((ANY, str_t)), ts) == []
    assert check_percent_format("%d %s", TupleType((int_t,), unknown_size=True), ts) == []

    source = textwrap.dedent("""
        def fmt(data: dict[str, str], items: list[int], dyn) -> None:
            a = "{avatar_url} {user}".format(**data)
            b = "{} {}".format(*items)
            c = "{} {name}".format(1, name="ok")
            d = "{:.{width}f}".format(3.14, width=2)
            e = "%d %s" % (dyn, "ok")
            f = "%(k)s %(v)d" % data
        """)
    res = StaticTypeInferenceEngine().infer_source("m", source)
    assert not [d for d in res.diagnostics if d.code == "format-string-mismatch"]


def test_typeinfo_constructor_arity_respects_starred_and_double_starred_args() -> None:
    """Dataclass, NamedTuple, and TypedDict constructors accept *args/**kwargs unpacking."""
    source = textwrap.dedent("""
        from dataclasses import dataclass
        from typing import NamedTuple, TypedDict

        @dataclass
        class Ctx:
            user_id: str
            consented: bool
            org_id: str

        class Point(NamedTuple):
            x: int
            y: int

        class Config(TypedDict):
            host: str
            port: int

        def build(uid: str, defaults: dict, coords: list[int], cfg: dict):
            c = Ctx(user_id=uid, **defaults)
            p = Point(*coords)
            t1 = Config(**cfg)
            t2 = Config(cfg)
            return c, p, t1, t2
        """)
    res = StaticTypeInferenceEngine().infer_source("m", source)
    assert not [d for d in res.diagnostics if d.code == "call-arity-mismatch"]


def test_typeinfo_attr_defined_respects_transitive_unresolved_bases() -> None:
    """Subclasses of classes with unresolved external bases must not report attr-defined."""
    source = textwrap.dedent("""
        from nonexistent_pkg import ExternalBase

        class Mid(ExternalBase):
            pass

        class Leaf(Mid):
            def use(self):
                return self.inherited_from_external
        """)
    opts = InferenceOptions(check_member_access=True)
    res = StaticTypeInferenceEngine(options=opts).infer_source("m", source)
    assert not [d for d in res.diagnostics if d.code == "attr-defined"]


def test_typeinfo_gradual_union_index_and_unknown_dict_get() -> None:
    """Gradual unions absorb index diagnostics and unknown_dict.get preserves unknown."""
    source = textwrap.dedent("""
        from typing import Any

        def index_gradual(x: list[str] | Any) -> Any:
            return x["key"]

        def load_unknown(raw):
            data = raw or {}
            conf = data.get("cfg", {})
            base = {"a": 1}
            base.update(conf)
            return base["a"]
        """)
    res = StaticTypeInferenceEngine().infer_source("m", source)
    assert not [d for d in res.diagnostics if d.code == "index"]
    summary = res.functions["m.load_unknown"]
    assert summary.return_value.unknown or str(summary.return_type) == "Any"


def test_typeinfo_docstring_expand_typestr_word_boundaries_and_bool() -> None:
    """expand_typestr must split on word boundaries and recognize bool literals."""
    assert expand_typestr("Error or None") == ["Error", "None"]
    assert expand_typestr("Profile or Sequence of int") == ["Profile", "Sequence"]
    assert expand_typestr("Generator or Iterator") == ["Generator", "Iterator"]
    assert expand_typestr("{True, False}") == ["bool", "bool"]


def test_typeinfo_substitute_type_vars_preserves_callable_overloads() -> None:
    """substitute_type_vars must preserve and substitute CallableType.overloads."""
    t_var = TypeVarType("T")
    int_t = Instance(ClassDescriptor(int))
    str_t = Instance(ClassDescriptor(str))
    overload_1 = CallableType((t_var,), t_var)
    overload_2 = CallableType((t_var, str_t), str_t)
    fn_type = CallableType((t_var,), t_var, overloads=(overload_1, overload_2))

    substituted = substitute_type_vars(fn_type, {"T": int_t})
    assert isinstance(substituted, CallableType)
    assert substituted.arg_types == (int_t,)
    assert substituted.return_type == int_t
    assert len(substituted.overloads) == 2
    assert substituted.overloads[0].arg_types == (int_t,)
    assert substituted.overloads[0].return_type == int_t
    assert substituted.overloads[1].arg_types == (int_t, str_t)


# ---------------------------------------------------------------------------
# Frontend & Language/Modules regressions
# ---------------------------------------------------------------------------


def test_comprehension_lowering_avoids_duplicate_outer_iter_and_captures_lambda_free_vars() -> None:
    """Lifted outer iterables are not dead-captured, while lambda free vars are captured."""
    converter = ASTConverter(verbose=False)

    comp = converter._convert_expression(
        python_ast.parse("[(a, b) for (a, b) in items if a]", mode="eval").body
    )
    assert isinstance(comp, pyflow_ast.DirectCall)
    assert comp.code.codeparameters.paramnames == ["__pyflow_outer_iter"]
    assert len(comp.args) == 1
    assert isinstance(comp.args[0], pyflow_ast.Local)
    assert comp.args[0].name == "items"

    lam_comp = converter._convert_expression(
        python_ast.parse("[lambda y: factor * y + x for x in xs]", mode="eval").body
    )
    assert isinstance(lam_comp, pyflow_ast.DirectCall)
    param_names = lam_comp.code.codeparameters.paramnames
    assert "factor" in param_names
    assert "y" not in param_names
    assert "xs" not in param_names
    assert "__pyflow_outer_iter" in param_names


def test_http_entry_functions_detects_factories_annassign_branches_and_typed_params() -> None:
    """http_entry_functions detects modern Flask/FastAPI/Starlette handler patterns."""
    sources = {
        "factory.py": textwrap.dedent("""
            from flask import Flask

            def create_app():
                app = Flask(__name__)

                @app.route("/health")
                def health():
                    return "ok"

                return app
            """),
        "router.py": textwrap.dedent("""
            from fastapi.routing import APIRouter
            from fastapi import FastAPI

            router: APIRouter = APIRouter()

            @router.post("/items")
            async def create_item():
                return {}

            def register(app: FastAPI):
                @app.get("/ping")
                def ping():
                    return "pong"
            """),
        "branch.py": textwrap.dedent("""
            from fastapi import FastAPI

            def build_app(debug: bool):
                if debug:
                    app = FastAPI(debug=True)
                else:
                    app = FastAPI(debug=False)

                @app.get("/status")
                def status():
                    return "up"
            """),
    }
    entries = http_entry_functions(sources)
    assert ("factory.py", "create_app.health") in entries
    assert ("router.py", "create_item") in entries
    assert ("router.py", "register.ping") in entries
    assert ("branch.py", "build_app.status") in entries


def test_scope_graph_tracks_async_function_definitions() -> None:
    """ScopeGraph should track async def declarations and their inner scopes."""
    tree = python_ast.parse(textwrap.dedent("""
            async def fetch(url):
                data = url
                return data
            """))
    sg = ScopeGraph().build(tree)
    assert "fetch" in sg.declarations["Mod"]
    assert "fetch" in sg.declarations
    assert "data" in sg.declarations["fetch"]
