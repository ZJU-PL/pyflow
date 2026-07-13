import pytest

from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.module_summary import (
    ClassSummary,
    FunctionSummary,
    ModuleSummary,
)
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.object import AllocKind
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.points_to_set import PointsToSet


def test_empty_module_summary():
    summary = ModuleSummary.empty("pkg.mod")

    assert summary.module_name == "pkg.mod"
    assert summary.get_export_names() == set()


def test_function_summary_merge_unions_returns(object_factory):
    obj_a = object_factory()
    obj_b = object_factory()
    first = FunctionSummary("f", ("x",), {"ctx": PointsToSet.singleton(obj_a)})
    second = FunctionSummary("f", ("x",), {"ctx": PointsToSet.singleton(obj_b)})

    merged = first.merge(second)

    assert set(merged.context_returns["ctx"]) == {obj_a, obj_b}


def test_function_summary_rejects_different_names():
    with pytest.raises(ValueError):
        FunctionSummary("f").merge(FunctionSummary("g"))


def test_class_summary_merge_combines_methods_and_attributes(alloc_site_factory, object_factory):
    obj_a = object_factory()
    obj_b = object_factory()
    first = ClassSummary(
        "C",
        alloc_site_factory(AllocKind.CLASS),
        methods={"m": FunctionSummary("m")},
        attributes={"a": PointsToSet.singleton(obj_a)},
    )
    second = ClassSummary(
        "C",
        first.alloc_site,
        methods={"n": FunctionSummary("n")},
        attributes={"a": PointsToSet.singleton(obj_b)},
    )

    merged = first.merge(second)

    assert set(merged.methods) == {"m", "n"}
    assert set(merged.attributes["a"]) == {obj_a, obj_b}


def test_module_summary_merge_combines_exports_functions_and_classes(object_factory, alloc_site_factory):
    obj_a = object_factory()
    obj_b = object_factory()
    first = ModuleSummary(
        "pkg.mod",
        exports={"x": PointsToSet.singleton(obj_a)},
        functions={"f": FunctionSummary("f")},
    )
    second = ModuleSummary(
        "pkg.mod",
        exports={"x": PointsToSet.singleton(obj_b)},
        classes={"C": ClassSummary("C", alloc_site_factory(AllocKind.CLASS))},
    )

    merged = first.merge(second)

    assert set(merged.exports["x"]) == {obj_a, obj_b}
    assert merged.get_export_names() == {"x", "f", "C"}
