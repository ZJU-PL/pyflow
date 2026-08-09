from __future__ import annotations

import pytest

from pyflow.checker.class_pollution.api import run_class_pollution_analysis


def _analyze_source(tmp_path, source: str, function: str):
    path = tmp_path / "case.py"
    path.write_text(source)
    _session, result = run_class_pollution_analysis([path], function=function)
    assert result.is_complete
    return result


def test_recursive_merge_uses_bounded_self_summary(tmp_path):
    result = _analyze_source(
        tmp_path,
        """
def merge(src, dst):
    for key, value in src.items():
        if dst.get(key) and type(value) == dict:
            merge(value, getattr(dst, key))
        else:
            dst[key] = value
            setattr(dst, key, value)
""",
        "merge",
    )

    assert {finding.mutation_kind for finding in result.findings} == {
        "attribute",
        "item",
    }
    assert {
        (finding.key_origin.label, finding.target_origin.label)
        for finding in result.findings
    } == {("src", "dst")}
    assert all(len(finding.object_path) == 1 for finding in result.findings)


@pytest.mark.parametrize(
    ("function", "source"),
    [
        (
            "through_attrgetter",
            """
from operator import attrgetter

def through_attrgetter(obj, path, value):
    target = attrgetter(path[:-1])(obj)
    setattr(target, path[-1], value)
""",
        ),
        (
            "through_eval",
            """
def through_eval(obj, path, value):
    expression = 'obj'
    for part in path[:-1]:
        expression += f'.{part}'
    target = eval(expression)
    setattr(target, path[-1], value)
""",
        ),
        (
            "through_itemgetter",
            """
from operator import itemgetter

def through_itemgetter(obj, path, value):
    target = itemgetter(path[:-1])(obj)
    target[path[-1]] = value
""",
        ),
        (
            "through_reduce",
            """
import functools

def recursive_getattr(obj, path):
    def get_one(current, name):
        return getattr(current, name)
    return functools.reduce(get_one, [obj] + path.split('.'))

def through_reduce(obj, path, value):
    prefix, _, last = path.rpartition('.')
    target = recursive_getattr(obj, prefix) if prefix else obj
    setattr(target, last, value)
""",
        ),
    ],
)
def test_getter_combinators_are_modeled(tmp_path, function, source):
    result = _analyze_source(tmp_path, source, function)

    assert len(result.findings) == 1
    assert result.findings[0].key_origin.label == "path"
    assert result.findings[0].target_origin.label == "obj"


def test_walrus_comprehension_updates_outer_target(tmp_path):
    result = _analyze_source(
        tmp_path,
        """
def assign_path(obj, path, value):
    *prefix, last = path.split('.')
    [obj := getattr(obj, part) for part in prefix]
    setattr(obj, last, value)
""",
        "assign_path",
    )

    assert len(result.findings) == 1
    assert result.findings[0].target_origin.label == "obj"


def test_static_safe_projection_breaks_pollutable_object_state(tmp_path):
    result = _analyze_source(
        tmp_path,
        """
def assign_path(obj, path, value):
    for part in path[:-1]:
        obj = obj.__dict__.get(part)
    child = obj['fixed_child']
    setattr(child, path[-1], value)
""",
        "assign_path",
    )

    assert result.findings == ()


def test_dunder_prefix_guard_refines_key_language(tmp_path):
    result = _analyze_source(
        tmp_path,
        """
def assign_path(obj, key, value):
    if key.startswith('__'):
        return
    target = getattr(obj, key)
    setattr(target, key, value)
""",
        "assign_path",
    )

    assert result.findings == ()


def test_literal_allowlist_guard_refines_key_language(tmp_path):
    result = _analyze_source(
        tmp_path,
        """
def assign_path(obj, key, value):
    if key not in {'name', 'title'}:
        return
    target = getattr(obj, key)
    setattr(target, key, value)
""",
        "assign_path",
    )

    assert result.findings == ()


@pytest.mark.parametrize(
    ("getter", "setter", "mutation_kind"),
    [
        ("__getattribute__", "__setattr__", "attribute"),
        ("__getitem__", "__setitem__", "item"),
    ],
)
def test_bound_reflective_protocol_methods(
    tmp_path, getter, setter, mutation_kind
):
    result = _analyze_source(
        tmp_path,
        f"""
def assign_path(obj, key, value):
    target = obj.{getter}(key)
    target.{setter}(key, value)
""",
        "assign_path",
    )

    assert len(result.findings) == 1
    assert result.findings[0].mutation_kind == mutation_kind
