"""Regressions from whole-project constraint call graph scans."""

import textwrap
import warnings

import pytest

from pyflow.analysis.callgraph.constraint_based.engine import ConstraintCallGraphBuilder
from pyflow.analysis.callgraph.constraint_based.model import AnalysisOptions, make_class


@pytest.mark.parametrize("context_sensitive", [False, True])
@pytest.mark.parametrize("capture", [False, True])
@pytest.mark.parametrize("use_lambda", [False, True])
def test_class_decorator_factory_preserves_each_class(context_sensitive, capture, use_lambda):
    source = textwrap.dedent("""
        def fa(): pass
        def fb(): pass
        def deco(callback):
            def inner(cls):
                CAPTURE
                return cls
            return inner
        @deco(fa)
        class A:
            def a(self): pass
        @deco(fb)
        class B:
            def b(self): pass
        class C(A):
            def run(self):
                self.a()
                self.b()
        C().run()
    """).replace("CAPTURE", "callback()" if capture else "pass")
    if use_lambda:
        source = source.replace(
            "    def inner(cls):\n        "
            + ("callback()" if capture else "pass")
            + "\n        return cls\n    return inner",
            (
                "    return lambda cls: (callback(), cls)[1]"
                if capture
                else "    return lambda cls: cls"
            ),
        )
    builder = ConstraintCallGraphBuilder(
        source, options=AnalysisOptions(context_sensitive=context_sensitive, context_depth=3)
    )
    with warnings.catch_warnings(record=True) as caught:
        graph = builder.build().get()
    assert builder.classes["main.C"].bases == ["main.A"]
    assert builder.module_bindings["main"]["A"] == {make_class("main.A")}
    assert builder.module_bindings["main"]["B"] == {make_class("main.B")}
    assert "main.A.a" in graph["main.C.run"]
    assert "main.B.b" not in graph["main.C.run"]
    assert not any("Inconsistent MRO" in str(item.message) for item in caught)
    if capture:
        contexts = [
            callees
            for (scope, context), callees in builder.scope_callees.items()
            if scope.startswith("main.deco.") and context[0] == "<decorator>"
        ]
        assert {"main.fa"} in contexts
        assert {"main.fb"} in contexts
        assert not any({"main.fa", "main.fb"} <= callees for callees in contexts)


def test_monorepo_sources_have_one_import_identity(tmp_path):
    package = tmp_path / "pkg-core" / "mypkg"
    package.mkdir(parents=True)
    entry = package / "__init__.py"
    entry.write_text("from mypkg import mod\ndef run(): mod.f()\nrun()\n")
    (package / "mod.py").write_text("def f(): pass\n")
    sources = {str(path): path.read_text() for path in package.glob("*.py")}
    builder = ConstraintCallGraphBuilder(
        entry.read_text(),
        entry_path=str(entry),
        additional_sources=sources,
        project_root=str(tmp_path),
        canonical_entry_names=True,
    )
    graph = builder.build().get()
    assert set(builder.modules) == {"mypkg", "mypkg.mod"}
    assert "mypkg.mod.f" in graph["mypkg.run"]
    assert not any("pkg-core" in node for node in graph)


@pytest.mark.parametrize(
    "import_statement, call",
    [
        ("from mypkg import mod", "mod.f()"),
        ("import mypkg.mod as mod", "mod.f()"),
        ("import mypkg.mod", "mypkg.mod.f()"),
    ],
)
def test_alternate_import_names_reuse_loaded_file(tmp_path, import_statement, call):
    package = tmp_path / "component" / "mypkg"
    package.mkdir(parents=True)
    entry = package / "__init__.py"
    entry.write_text(
        f"{import_statement}\nimport component.mypkg.mod as alias\n"
        f"def run():\n {call}\n alias.f()\nrun()\n"
    )
    (package / "mod.py").write_text("def f(): pass\n")
    sources = {str(path): path.read_text() for path in package.glob("*.py")}
    builder = ConstraintCallGraphBuilder(
        entry.read_text(),
        entry_path=str(entry),
        additional_sources=sources,
        project_root=str(tmp_path),
        canonical_entry_names=True,
    )
    graph = builder.build().get()
    assert len({info.path for info in builder.modules.values()}) == len(builder.modules) == 2
    assert graph["mypkg.run"] == {"mypkg.mod.f"}
    assert "component.mypkg.mod.f" not in graph
    assert builder.module_aliases["component.mypkg.mod"] == "mypkg.mod"


def test_resolved_subscript_drops_provisional_dynamic_site():
    builder = ConstraintCallGraphBuilder(textwrap.dedent("""
        def fa(): pass
        class A:
            table = {"a": fa}
        def run():
            return A.table["a"]()
        run()
    """))
    graph = builder.build().get()
    assert graph["main.run"] == {"main.fa"}
    sites = [
        callees
        for site, callees in builder.call_site_edge_index().items()
        if site.caller_scope == "main.run"
    ]
    assert sites == [frozenset({"main.fa"})]


def test_genuinely_unknown_alternative_keeps_dynamic_site():
    builder = ConstraintCallGraphBuilder(textwrap.dedent("""
        def fa(): pass
        class A:
            table = {"a": fa, "b": input()}
        def run(key):
            A.table[key]()
        run("a")
        run("b")
    """))
    graph = builder.build().get()
    assert "main.fa" in graph["main.run"]
    assert any(callee.startswith("<dynamic>.") for callee in graph["main.run"])


def test_default_budget_scales_past_ten_thousand():
    source = "\n".join(f"def f{i}(): f{i + 1}()" for i in range(60))
    source += "\ndef f60(): pass\nf0()\n"
    builder = ConstraintCallGraphBuilder(source)
    graph = builder.build()
    assert builder.solver_stats.iteration_budget == len(builder.scopes) * 256 > 10000
    assert graph.converged is True
    assert graph.diagnostics == []
    assert "main.f60" in graph.get()["main.f59"]


def test_explicit_truncation_is_exposed_without_warning():
    builder = ConstraintCallGraphBuilder(
        "def f(): pass\nf()\n",
        options=AnalysisOptions(fixpoint_max_iterations=1, warn_on_fixpoint_truncation=False),
    )
    graph = builder.build()
    assert graph.converged is False
    assert "budget exhausted" in graph.diagnostics[0]


@pytest.mark.parametrize("runtime_alias", [False, True])
@pytest.mark.parametrize("attribute_import", [False, True])
def test_reexports_never_create_package_qualified_phantoms(
    tmp_path, runtime_alias, attribute_import
):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("from .bridge import Mixin, Base, f\n")
    bridge = "from .impl import Mixin, Base, f\n"
    if runtime_alias:
        bridge = "from . import impl\nMixin = impl.Mixin\nBase = impl.Base\nf = impl.f\n"
    (package / "bridge.py").write_text(bridge)
    (package / "impl.py").write_text("class Base: pass\nclass Mixin(Base): pass\ndef f(): pass\n")
    source = (
        "from pkg import Mixin, f\nfrom pkg.impl import Base\n"
        "class C(Mixin, Base):\n def run(self): f()\ndef g(): f()\n"
    )
    if attribute_import:
        source = "import pkg\n" + source.replace("f()", "pkg.f()")
    entry = tmp_path / "main.py"
    entry.write_text(source)
    builder = ConstraintCallGraphBuilder(source, entry_path=str(entry))
    with warnings.catch_warnings(record=True) as caught:
        graph = builder.build().get()
    assert graph["main.g"] == {"pkg.impl.f"}
    assert "pkg.f" not in graph
    assert "pkg.bridge.f" not in graph
    assert builder.classes["main.C"].bases == ["pkg.impl.Mixin", "pkg.impl.Base"]
    assert not any("Inconsistent MRO" in str(item.message) for item in caught)


def test_cyclic_reexports_converge_without_ghost_targets(tmp_path):
    (tmp_path / "a.py").write_text("from b import f\ndef g(): f()\n")
    (tmp_path / "b.py").write_text("from a import g\ndef f(): pass\n")
    source = "from a import f, g\nf()\ng()\n"
    entry = tmp_path / "main.py"
    entry.write_text(source)
    builder = ConstraintCallGraphBuilder(source, entry_path=str(entry))
    graph = builder.build().get()
    assert graph["main"] == {"b.f", "a.g"}
    assert graph["a.g"] == {"b.f"}
    assert "a.f" not in graph
    assert "b.g" not in graph


@pytest.mark.parametrize("local_alias", [False, True])
def test_same_named_nested_base_uses_predefinition_binding(local_alias):
    source = "class Input: pass\nclass Other: pass\nclass Outer:\n"
    if local_alias:
        source += " Input = Other\n"
    source += " class Input(Input): pass\n"
    builder = ConstraintCallGraphBuilder(source)
    with warnings.catch_warnings(record=True) as caught:
        builder.build()
    bases = builder.classes["main.Outer.Input"].bases
    assert "main.Outer.Input" not in bases
    if local_alias:
        # Scope assignments remain flow-insensitive, so module Input may
        # remain an alternative, but the defining class must never reappear.
        assert "main.Other" in bases
    else:
        assert bases == ["main.Input"]
    assert not any("Inconsistent MRO" in str(item.message) for item in caught)


def test_alternative_bases_use_conservative_dispatch_without_invalid_mro_warning():
    builder = ConstraintCallGraphBuilder(textwrap.dedent("""
        class Base:
            def f(self): pass
        class Derived(Base):
            def f(self): pass
        def make(base):
            class C(base): pass
            return C()
        def run():
            make(Base).f()
            make(Derived).f()
        run()
    """))
    with warnings.catch_warnings(record=True) as caught:
        graph = builder.build().get()
    assert {"main.Base.f", "main.Derived.f"} <= graph["main.run"]
    assert not any("Inconsistent MRO" in str(item.message) for item in caught)


def test_default_budget_has_absolute_cap_and_explicit_override():
    source = "\n".join(f"def f{i}(): pass" for i in range(250))
    builder = ConstraintCallGraphBuilder(source)
    assert builder.build().converged
    assert builder.solver_stats.iteration_budget == 50000
    explicit = ConstraintCallGraphBuilder(
        source, options=AnalysisOptions(fixpoint_max_iterations=60000)
    )
    explicit.build()
    assert explicit.solver_stats.iteration_budget == 60000


@pytest.mark.parametrize("presolve", [False, True])
def test_time_budget_returns_partial_graph_with_reason(monkeypatch, presolve):
    from pyflow.analysis.callgraph.constraint_based import engine

    ticks = iter([0.0, 2.0])
    monkeypatch.setattr(engine.time, "monotonic", lambda: next(ticks, 2.0))
    builder = ConstraintCallGraphBuilder(
        "def f(): pass\nf()\n",
        options=AnalysisOptions(
            fixpoint_max_seconds=1.0,
            semi_naive_presolve=presolve,
            warn_on_fixpoint_truncation=False,
        ),
    )
    graph = builder.build()
    assert not graph.converged
    assert graph.termination_reason == "time_limit"
    assert "time budget exhausted" in graph.diagnostics[0]
    assert "main.f" in graph.get()


def test_imported_source_uses_declared_encoding(tmp_path):
    (tmp_path / "impl.py").write_bytes(b'# coding: latin-1\nlabel = "caf\xe9"\ndef f(): pass\n')
    entry = tmp_path / "main.py"
    entry.write_text("from impl import f\nf()\n")
    builder = ConstraintCallGraphBuilder(entry.read_text(), entry_path=str(entry))
    graph = builder.build()
    assert "impl.f" in graph.get()["main"]
    assert graph.diagnostics == []


@pytest.mark.parametrize(
    "layout", ["lib", "libs/core", "packages/core", "arbitrary/component", "src", "pkg-core"]
)
@pytest.mark.parametrize("namespace", [False, True])
@pytest.mark.parametrize("import_style", ["from_module", "from_package", "module"])
def test_monorepo_imports_reach_the_canonical_function_body(
    tmp_path, layout, namespace, import_style
):
    package = tmp_path / layout / "mypkg"
    package.mkdir(parents=True)
    if not namespace:
        (package / "__init__.py").write_text("")
    (package / "mod.py").write_text("def f(): pass\ndef run(): f()\n")
    app = tmp_path / "apps" / "app" / "main.py"
    app.parent.mkdir(parents=True)
    source = {
        "from_module": "from mypkg.mod import run\ndef entry(): run()\n",
        "from_package": "from mypkg import mod\ndef entry(): mod.run()\n",
        "module": "import mypkg.mod\ndef entry(): mypkg.mod.run()\n",
    }[import_style]
    app.write_text(source)
    sources = {str(path): path.read_text() for path in tmp_path.rglob("*.py")}
    builder = ConstraintCallGraphBuilder(
        source,
        entry_path=str(app),
        additional_sources=sources,
        project_root=str(tmp_path),
        canonical_entry_names=True,
    )
    graph = builder.build()
    assert graph.converged
    assert graph.get()["apps.app.main.entry"] == {"mypkg.mod.run"}
    assert graph.get()["mypkg.mod.run"] == {"mypkg.mod.f"}
    assert "mypkg.mod.run" in builder.functions
    assert not any(node.endswith(".mypkg.mod.run") for node in graph.get())
    paths = [str(info.path) for info in builder.modules.values()]
    assert len(paths) == len(set(paths))


def test_import_root_inference_preserves_regular_and_namespace_prefixes(tmp_path):
    package = tmp_path / "company" / "pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "mod.py").write_text("def f(): pass\n")
    entry = tmp_path / "app.py"
    entry.write_text("from company.pkg.mod import f\nf()\n")
    sources = {str(path): path.read_text() for path in tmp_path.rglob("*.py")}
    for regular_parent in (False, True):
        if regular_parent:
            (tmp_path / "company" / "__init__.py").write_text("")
            sources[str(tmp_path / "company" / "__init__.py")] = ""
        builder = ConstraintCallGraphBuilder(
            entry.read_text(),
            entry_path=str(entry),
            additional_sources=sources,
            project_root=str(tmp_path),
            canonical_entry_names=True,
        )
        graph = builder.build().get()
        assert graph["app"] == {"company.pkg.mod.f"}
        assert "pkg.mod.f" not in graph


def test_monorepo_in_memory_sources_share_import_roots(tmp_path):
    app = tmp_path / "apps" / "main.py"
    source = "from mypkg.mod import run\nrun()\n"
    sources = {
        str(app): source,
        str(tmp_path / "libs" / "core" / "mypkg" / "__init__.py"): "",
        str(tmp_path / "libs" / "core" / "mypkg" / "mod.py"): "def f(): pass\ndef run(): f()\n",
    }
    builder = ConstraintCallGraphBuilder(
        source,
        entry_path=str(app),
        additional_sources=sources,
        project_root=str(tmp_path),
        canonical_entry_names=True,
    )
    graph = builder.build().get()
    assert graph["apps.main"] == {"mypkg.mod.run"}
    assert graph["mypkg.mod.run"] == {"mypkg.mod.f"}


def test_monorepo_roots_do_not_merge_distinct_companion_scripts(tmp_path):
    for component, package in [("core", "mypkg"), ("other", "otherpkg")]:
        library = tmp_path / "libs" / component
        (library / package).mkdir(parents=True)
        (library / package / "__init__.py").write_text("def run(): pass\n")
        (library / "scripts").mkdir()
        (library / "scripts" / "check.py").write_text("def check(): pass\n")
    entry = tmp_path / "app.py"
    entry.write_text("from mypkg import run\nfrom otherpkg import run as other\nrun()\nother()\n")
    sources = {str(path): path.read_text() for path in tmp_path.rglob("*.py")}
    builder = ConstraintCallGraphBuilder(
        entry.read_text(),
        entry_path=str(entry),
        additional_sources=sources,
        project_root=str(tmp_path),
        canonical_entry_names=True,
    )
    graph = builder.build().get()
    assert graph["app"] == {"mypkg.run", "otherpkg.run"}
    assert "libs.core.scripts.check.check" in graph
    assert "libs.other.scripts.check.check" in graph
    assert len(builder.modules) == len(sources)
    assert "scripts.check" not in builder.project_context._source_map()
