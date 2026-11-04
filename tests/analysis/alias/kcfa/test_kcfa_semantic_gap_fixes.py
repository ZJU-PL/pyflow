# SPDX-FileCopyrightText: 2026 PyFlow Contributors
# SPDX-License-Identifier: MIT
"""Regression tests for k-CFA semantic gaps found on real-world patterns."""

from __future__ import annotations

import textwrap

from pyflow.analysis.alias.kcfa import PointerAnalysis


def _points(result, name: str) -> set[str]:
    return result.points_to_name_union(name)


def _has_list(points: set[str]) -> bool:
    return any("AllocKind.LIST" in point for point in points)


def test_super_new_resolves_singleton_instance() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class Singleton:
                _instance = None

                def __new__(cls):
                    if cls._instance is None:
                        cls._instance = super().__new__(cls)
                    return cls._instance

                def __init__(self):
                    self.value = [1]

            s = Singleton()
            r = s.value
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_super_new_in_subclass_resolves_instance() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class Base:
                def __new__(cls):
                    return object.__new__(cls)

            class Sub(Base):
                def __new__(cls):
                    return super().__new__(cls)

                def __init__(self):
                    self.value = [1]

            s = Sub()
            r = s.value
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_abc_subclass_is_published_with_stdlib_stubs(tmp_path) -> None:
    entry = tmp_path / "mod.py"
    entry.write_text(
        textwrap.dedent("""
            from abc import ABC, abstractmethod

            class Base(ABC):
                def m(self):
                    return [1]

            class Impl(Base):
                def m(self):
                    return [2]

            i = Impl()
            r = i.m()
            """),
        encoding="utf-8",
    )

    result = PointerAnalysis.from_project(entry, k=1, max_import_depth=-1).run()

    assert result.binding_ids_for_name("Base")
    assert result.binding_ids_for_name("Impl")
    assert _has_list(_points(result, "r"))


def test_metaclass_new_delegating_to_type_new_publishes_class() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class Meta(type):
                def __new__(mcls, name, bases, namespace):
                    return super().__new__(mcls, name, bases, namespace)

            class Base(metaclass=Meta):
                def m(self):
                    return [1]

            class Impl(Base):
                pass

            r = Impl().m()
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_metaclass_new_returning_sentinel_still_controls_result() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            sentinel = object()

            class Meta(type):
                def __new__(mcls, name, bases, namespace):
                    return sentinel

            class A(metaclass=Meta):
                pass

            x = A
            """),
        k=1,
    ).run()

    assert _points(result, "x") == _points(result, "sentinel")
    assert all("AllocKind.CLASS" not in point for point in _points(result, "x"))


def test_star_args_and_kwargs_forwarding_preserves_keyword_value() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            def f(x, y):
                return y

            def wrapper(*args, **kwargs):
                return f(*args, **kwargs)

            r = wrapper(1, y=[1])
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_dict_view_write_reaches_instance_attribute() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class Config:
                pass

            c = Config()
            c.__dict__["x"] = [1]
            r = c.x
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_vars_view_write_reaches_instance_attribute() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class Config:
                def __init__(self, **kwargs):
                    vars(self).update(kwargs)

            c = Config(x=[1])
            r = c.x
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_dict_update_through_dunder_dict_reaches_attribute() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class Config:
                def __init__(self, **kwargs):
                    self.__dict__.update(kwargs)

            c = Config(x=[1])
            r = c.x
            """),
        k=1,
    ).run()

    assert _has_list(_points(result, "r"))


def test_sum_of_lists_preserves_elements() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            r = sum([[1], [2]], [])
            s = r[0]
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "s"))


def test_tuple_subclass_constructor_populates_elements() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class T(tuple):
                pass

            t = T(([1], [2]))
            r = t[1]
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_exec_with_explicit_namespace_is_incomplete() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            ns = {}
            exec("y = [1]", ns)
            r = ns["y"]
            """),
        k=1,
    ).run()

    assert result.complete is False
    query = result.points_to_query("r")
    assert query.complete is False
    assert any(reason["kind"] == "dynamic_code_namespace" for reason in result.incomplete_reasons())


def test_native_access_paths_do_not_explode_with_varying_branches() -> None:
    source = textwrap.dedent("""
        import argparse

        def f(x, c):
            if c == 0:
                return x.a0
            if c == 1:
                return x.a1
            if c == 2:
                return x.a2
            if c == 3:
                return x.a3
            return x.a4

        def main():
            x = argparse.ArgumentParser()
            for i in range(3):
                x = f(x, i)
            return x

        r = main()
        """)

    result = PointerAnalysis(source, k=0, max_iterations=100_000).run()

    assert result.fixpoint_complete
    # Before the short-prefix summary this reached ~175k objects and did not
    # finish in under a minute.
    assert len(_points(result, "x")) < 200


def test_class_getitem_is_resolved_as_implicit_classmethod() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class Box:
                @classmethod
                def __class_getitem__(cls, item):
                    return cls

            r = Box[int]
            """),
        k=1,
    ).run()

    assert result.complete
    assert any("AllocKind.CLASS" in point for point in _points(result, "r"))


def test_undecorated_class_getitem_is_treated_as_classmethod() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class Box:
                def __class_getitem__(cls, item):
                    return [1]

            r = Box[int]
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_class_subscription_without_class_getitem_is_incomplete() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class C:
                pass

            r = C[int]
            """),
        k=1,
    ).run()

    query = result.points_to_query("r")
    assert query.complete is False
    assert any(reason["kind"] == "class_subscription" for reason in result.incomplete_reasons())


def test_abc_subclass_with_class_keyword_and_init_subclass() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            from abc import ABC

            class Base(ABC):
                registry = {}

                def __init_subclass__(cls, name=None, **kwargs):
                    Base.registry[name] = cls

            class A(Base, name="a"):
                def m(self):
                    return [1]

            r = Base.registry["a"]().m()
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_metaclass_new_receives_non_colliding_class_keywords() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class Meta(type):
                def __new__(mcls, name, bases, namespace, **kwargs):
                    cls = super().__new__(mcls, name, bases, namespace)
                    cls.tag = kwargs.get("tag")
                    return cls

            class A(metaclass=Meta, tag=[1]):
                pass

            r = A.tag
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_module_level_getattr_supplies_missing_attributes(tmp_path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "lazy.py").write_text("def __getattr__(name):\n    return [1]\n", encoding="utf-8")
    entry = pkg / "main.py"
    entry.write_text("from pkg import lazy\nr = lazy.anything\n", encoding="utf-8")

    result = PointerAnalysis.from_project(entry, k=1, max_import_depth=-1).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_enum_member_init_payload_is_modeled() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            import enum

            class Color(enum.Enum):
                RED = (1, [1])
                BLUE = (2, [2])

                def __init__(self, code, payload):
                    self.code = code
                    self.payload = payload

            r = Color.RED.payload
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_enum_member_new_is_reported_incomplete() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            import enum

            class Color(enum.Enum):
                RED = 1

                def __new__(cls, value):
                    obj = object.__new__(cls)
                    obj._value_ = value
                    obj.extra = [value]
                    return obj

            r = Color.RED.extra
            """),
        k=1,
    ).run()

    query = result.points_to_query("r")
    assert query.complete is False
    assert any(
        reason["kind"] == "enum_member_new_unmodeled" for reason in result.incomplete_reasons()
    )


def test_singledispatchmethod_registered_implementation() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            from functools import singledispatchmethod

            class C:
                @singledispatchmethod
                def f(self, x):
                    return "base"

                @f.register
                def _(self, x: int):
                    return [1]

            c = C()
            r = c.f(1)
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_dict_subclass_getitem_uses_missing_hook() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class D(dict):
                def __missing__(self, key):
                    return [1]

            d = D()
            r = d["x"]
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))


def test_collections_namedtuple_fields_are_distinct() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            from collections import namedtuple

            P = namedtuple("P", ["x", "y"])
            p = P([1], [2])
            r = p.x
            s = p.y
            """),
        k=1,
    ).run()

    assert result.complete
    assert _has_list(_points(result, "r"))
    assert _has_list(_points(result, "s"))
    assert _points(result, "r") != _points(result, "s")


def test_collections_namedtuple_string_field_spec() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            from collections import namedtuple

            P = namedtuple("P", "cb")
            p = P([1])
            r = p.cb
            """),
        k=1,
    ).run()

    assert _has_list(_points(result, "r"))


def test_metaclass_getattr_is_reported_incomplete() -> None:
    result = PointerAnalysis(
        textwrap.dedent("""
            class Meta(type):
                def __getattr__(cls, name):
                    return [1]

            class C(metaclass=Meta):
                pass

            r = C.anything
            """),
        k=1,
    ).run()

    query = result.points_to_query("r")
    assert query.complete is False
    assert any(
        reason["kind"] == "metaclass_getattr_unmodeled" for reason in result.incomplete_reasons()
    )
