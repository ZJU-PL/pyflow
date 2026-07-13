# SPDX-FileCopyrightText: 2026 PyFlow Contributors
# SPDX-License-Identifier: MIT
"""Tests for the migrated PythonStAn pointer analysis module."""

from __future__ import annotations

import pytest

from pyflow.analysis.pointer import PointerAnalysis
from pyflow.analysis.pointer._pythonstan.world.pipeline import Pipeline
from pyflow.analysis.pointer._pythonstan.world.namespace import NamespaceManager


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

    def test_dict_constructor_keyword_value_flows_to_subscript_load(self) -> None:
        source = '''
v = object()
d = dict(a=v)
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

    def test_points_to_unions_matching_context_bindings(self) -> None:
        source = """
x = [1]
def f():
    x = [2]
    return x
"""
        result = PointerAnalysis(source, k=1).run()
        bindings = result.bindings_for_name("x")
        assert len(bindings) >= 2
        assert result.points_to("x") == set().union(*(pts for _, pts in bindings))

    def test_pointer_stdlib_stubs_are_resolved_from_vendor_tree(self) -> None:
        manager = NamespaceManager()
        manager.build("/tmp", [], mock_libs=True, prefer_mock_libs=True)
        resolved = manager.resolve_import("math")
        assert resolved is not None
        _, path = resolved
        assert "/analysis/pointer/_pythonstan/stubs/stdlib/math.py" in path

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
