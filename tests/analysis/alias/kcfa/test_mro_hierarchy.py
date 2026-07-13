"""Tests for the current AbstractObject-based class hierarchy manager."""

import ast

from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.class_hierarchy import (
    ClassHierarchyManager,
    compute_c3_mro,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.context import CallStringContext
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import (
    AbstractObject,
    AllocKind,
    AllocSite,
)
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRClass


def _class_obj(name: str, bases: list[str] | None = None) -> AbstractObject:
    base_text = f"({', '.join(bases)})" if bases else ""
    cls = ast.parse(f"class {name}{base_text}:\n    pass\n").body[0]
    ir_cls = IRClass(name, cls)
    return AbstractObject(CallStringContext((), 1), AllocSite(ir_cls, AllocKind.CLASS))


def test_c3_mro_simple_inheritance():
    hierarchy = ClassHierarchyManager()
    base = _class_obj("Base")
    child = _class_obj("Child", ["Base"])

    hierarchy.add_class(base)
    hierarchy.add_class(child, [base])

    assert compute_c3_mro(child, hierarchy) == [child, base]


def test_c3_mro_diamond_inheritance():
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


def test_hierarchy_tracks_bases_and_subclasses():
    hierarchy = ClassHierarchyManager()
    base = _class_obj("Base")
    child = _class_obj("Child", ["Base"])

    hierarchy.add_class(base)
    hierarchy.add_class(child, [base])

    assert hierarchy.get_bases(child) == [base]
    assert hierarchy.get_subclasses(base) == [child]
    assert hierarchy.has_class(child)


def test_lookup_class_by_name_uses_alloc_site_name():
    hierarchy = ClassHierarchyManager()
    cls = _class_obj("Named")

    hierarchy.add_class(cls)

    assert hierarchy.lookup_class_by_name("Named") == {cls}


def test_mro_cache_invalidates_when_bases_change():
    hierarchy = ClassHierarchyManager()
    base_a = _class_obj("BaseA")
    base_b = _class_obj("BaseB")
    child = _class_obj("Child", ["BaseA"])

    hierarchy.add_class(base_a)
    hierarchy.add_class(base_b)
    hierarchy.add_class(child, [base_a])
    assert hierarchy.get_mro(child) == [child, base_a]

    hierarchy.update_bases(child, [base_b])
    assert hierarchy.get_mro(child) == [child, base_b]
