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
    entry.write_text(f"{import_statement}\ndef run(): {call}\nrun()\n")
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
    assert "component.mypkg.mod.f" in graph["component.mypkg.run"]
    assert "mypkg.mod.f" not in graph


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
