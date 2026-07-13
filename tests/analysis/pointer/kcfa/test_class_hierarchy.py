from tests.analysis.pointer.test_mro_hierarchy import _class_obj

from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.class_hierarchy import (
    ClassHierarchyManager,
)


def test_add_class_tracks_bases_subclasses_and_name_lookup():
    hierarchy = ClassHierarchyManager()
    base = _class_obj("Base")
    child = _class_obj("Child", ["Base"])

    hierarchy.add_class(base)
    hierarchy.add_class(child, [base])

    assert hierarchy.get_bases(child) == [base]
    assert hierarchy.get_subclasses(base) == [child]
    assert hierarchy.lookup_class_by_name("Child") == {child}


def test_get_mro_for_diamond_hierarchy():
    hierarchy = ClassHierarchyManager()
    top = _class_obj("Top")
    left = _class_obj("Left", ["Top"])
    right = _class_obj("Right", ["Top"])
    bottom = _class_obj("Bottom", ["Left", "Right"])

    hierarchy.add_class(top)
    hierarchy.add_class(left, [top])
    hierarchy.add_class(right, [top])
    hierarchy.add_class(bottom, [left, right])

    assert hierarchy.get_mro(bottom) == [bottom, left, right, top]
