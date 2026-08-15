# SPDX-FileCopyrightText: 2026 PyFlow Contributors
# SPDX-License-Identifier: MIT
"""Tests for the migrated PythonStAn pointer analysis module."""

from __future__ import annotations

from pathlib import Path

from pyflow.analysis.alias.kcfa import PointerAnalysis
from pyflow.analysis.alias.kcfa._pythonstan.world.pipeline import Pipeline
from pyflow.analysis.alias.kcfa._pythonstan.world.namespace import NamespaceManager


class TestBasicPointerAnalysis:

    def test_list_alias(self) -> None:
        source = "x = [1, 2, 3]\ny = x"
        result = PointerAnalysis(source).run()
        pts_x = result.points_to("x")
        pts_y = result.points_to("y")
        assert pts_x == pts_y
        assert len(pts_x) > 0

    def test_object_call_alias(self) -> None:
        source = "x = object()\ny = x"
        result = PointerAnalysis(source, k=1).run()
        pts_x = result.points_to("x")
        pts_y = result.points_to("y")
        assert pts_x == pts_y
        assert len(pts_x) > 0

    def test_constants(self) -> None:
        source = "x = 42\ny = 3.14"
        result = PointerAnalysis(source).run()
        pts_x = result.points_to("x")
        pts_y = result.points_to("y")
        assert len(pts_x) > 0
        assert len(pts_y) > 0
        assert pts_x != pts_y

    def test_class_instance(self) -> None:
        source = """
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

p = Point(1, 2)
q = p
"""
        result = PointerAnalysis(source, k=1).run()
        pts_p = result.points_to("p")
        pts_q = result.points_to("q")
        assert pts_p == pts_q
        assert len(pts_p) > 0

    def test_inherited_method_return_flows_to_call_target(self) -> None:
        source = """
class A:
    def m(self):
        return object()

class B(A):
    pass

b = B()
y = b.m()
"""
        result = PointerAnalysis(source, k=1).run()
        pts_y = result.points_to("y")

        assert pts_y
        assert any("AllocKind.OBJECT" in obj for obj in pts_y)

    def test_multiple_inheritance_uses_mro_first_method(self) -> None:
        source = """
class A:
    def m(self):
        return object()

class B:
    def m(self):
        return []

class C(A, B):
    pass

c = C()
y = c.m()
"""
        result = PointerAnalysis(source, k=1).run()
        pts_y = result.points_to("y")

        assert pts_y
        assert any("AllocKind.OBJECT" in obj for obj in pts_y)
        assert all("AllocKind.LIST" not in obj for obj in pts_y)

    def test_dict_constructor_keyword_value_flows_to_subscript_load(self) -> None:
        source = '''
v = object()
d = dict(a=v)
y = d["a"]
'''
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y") == result.points_to("v")

    def test_dict_constructor_unpack_flows_to_subscript_load(self) -> None:
        source = '''
v = object()
base = {"a": v}
d = dict(**base)
y = d["a"]
'''
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y") == result.points_to("v")

    def test_function_pointer(self) -> None:
        source = """
def foo():
    return 42

f = foo
"""
        result = PointerAnalysis(source, k=1).run()
        pts_f = result.points_to("f")
        pts_foo = result.points_to("foo")
        assert len(pts_f) > 0
        assert pts_f == pts_foo

    def test_call_edges(self) -> None:
        source = """
def foo():
    return 42

x = foo()
"""
        result = PointerAnalysis(source, k=1).run()
        edges = result.call_edges()
        assert isinstance(edges, list)

    def test_empty_source(self) -> None:
        result = PointerAnalysis("pass").run()
        assert isinstance(result.points_to("x"), set)
        assert len(result.points_to("x")) == 0

    def test_uncalled_function_body_is_not_analyzed(self) -> None:
        source = """
x = [1]
def f():
    x = [2]
    return x
"""
        result = PointerAnalysis(source, k=1).run()
        bindings = result.bindings_for_name("x")
        assert len(bindings) == 1
        assert result.points_to("x") == set().union(*(pts for _, pts in bindings))

    def test_return_values_remain_separate_across_call_contexts(self) -> None:
        source = """
def ident(value):
    return value

a = object()
b = []
x = ident(a)
y = ident(b)
"""
        result = PointerAnalysis(source, k=1).run()

        def module_points_to(name: str) -> set[str]:
            return set().union(*(
                pts
                for binding, pts in result.bindings_for_name(name)
                if "<module " in binding
            ))

        assert module_points_to("x") == module_points_to("a")
        assert module_points_to("y") == module_points_to("b")
        assert module_points_to("x").isdisjoint(module_points_to("y"))

    def test_explicit_nonlocal_resolves_through_lexical_scopes(self) -> None:
        source = """
def outer():
    x = object()
    def middle():
        def inner():
            nonlocal x
            return x
        return inner
    return middle()

f = outer()
y = f()
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y")
        assert any("AllocKind.OBJECT" in obj for obj in result.points_to("y"))

    def test_param_context_preserves_argument_order(self) -> None:
        source = """
def first(a, b):
    return a

x = object()
y = []
r1 = first(x, y)
r2 = first(y, x)
"""
        result = PointerAnalysis(source, context_policy="1-param").run()
        callees = [callee for _, callee in result.call_edges() if "first" in callee]

        assert len(callees) == 2
        assert len(set(callees)) == 2

    def test_pointer_stdlib_stubs_are_resolved_from_vendor_tree(
        self, monkeypatch
    ) -> None:
        from pyflow.analysis.alias.kcfa._pythonstan.world import namespace

        monkeypatch.setattr(namespace, "builtin_module_names", lambda: {"math"})
        manager = NamespaceManager()
        manager.build("/tmp", [], mock_libs=True, prefer_mock_libs=True)
        resolved = manager.resolve_import("math")
        assert resolved is not None
        _, path = resolved
        assert Path(path).resolve() == manager.mock_root / "math.py"

    def test_imported_module_attribute_flows_to_local(self, tmp_path) -> None:
        (tmp_path / "mod.py").write_text("v = object()\n", encoding="utf-8")
        entry = tmp_path / "main.py"
        entry.write_text("import mod\nx = mod.v\n", encoding="utf-8")

        pipeline = Pipeline(
            config={
                "filename": str(entry),
                "project_path": str(tmp_path),
                "library_paths": [],
                "mock_libs": True,
                "prefer_mock_libs": True,
                "lazy_ir_construction": False,
                "import_level": -1,
                "time_count": False,
                "analysis": [
                    {
                        "name": "pointer-analysis",
                        "id": "PointerAnalysis",
                        "description": "k-CFA pointer analysis",
                        "prev_analysis": ["cfg"],
                        "inter_procedure": True,
                        "options": {
                            "type": "pointer analysis",
                            "context_policy": "1-cfa",
                        },
                    }
                ],
            }
        )
        pipeline.run()
        result = pipeline.analysis_manager.get_results("pointer-analysis")
        state = result.query()._state
        pts_x = {
            str(obj)
            for cvar, pts in state._env.items()
            if getattr(getattr(cvar, "content", cvar), "name", None) == "x"
            for obj in pts
        }
        assert pts_x
