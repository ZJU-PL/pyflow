"""Differential and metamorphic checks for the Python semantic layer."""

from __future__ import annotations

import re

import pytest

from pyflow.analysis.alias.kcfa import PointerAnalysis
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import (
    ClassObject,
)


def _concrete_namespace(source: str) -> dict:
    namespace: dict = {}
    exec(compile(source, "<differential>", "exec"), namespace, namespace)
    return namespace


@pytest.mark.parametrize(
    "source",
    (
        """
sentinel = object()

class Descriptor:
    def __get__(self, instance, owner):
        return sentinel

class A:
    field = Descriptor()

result = A().field
""",
        """
sentinel = object()

def make_class(name, bases, namespace):
    return sentinel

class A(metaclass=make_class):
    pass

result = A
""",
        """
sentinel = object()

class Base:
    field = sentinel

class Child(Base):
    field: int

result = Child.field
""",
    ),
)
def test_identity_results_agree_with_cpython(source: str) -> None:
    concrete = _concrete_namespace(source)
    assert concrete["result"] is concrete["sentinel"]

    abstract = PointerAnalysis(source, k=1).run()
    # Differential oracle checks may-soundness: the concrete identity must be
    # represented even where descriptor/plain-value joins deliberately retain
    # additional conservative targets.
    assert abstract.points_to("sentinel") <= abstract.points_to("result")


def _allocation_kinds(values: set[str]) -> set[str]:
    return {
        match.group(1)
        for value in values
        if (match := re.search(r"AllocKind\.([A-Z_]+)", value))
    }


def test_alpha_renaming_preserves_points_to_result() -> None:
    original = """
seed = object()

def identity(argument):
    local = argument
    return local

result = identity(seed)
"""
    renamed = """
source_value = object()

def identity(parameter):
    temporary = parameter
    return temporary

answer = identity(source_value)
"""
    left = PointerAnalysis(original, k=1).run()
    right = PointerAnalysis(renamed, k=1).run()

    assert _allocation_kinds(left.points_to("result")) == {"OBJECT"}
    assert _allocation_kinds(right.points_to("answer")) == {"OBJECT"}


def test_reordering_independent_statements_preserves_result_kinds() -> None:
    first = """
left = object()
right = []
result = (left, right)
"""
    second = """
right = []
left = object()
result = (left, right)
"""
    first_result = PointerAnalysis(first, k=1).run()
    second_result = PointerAnalysis(second, k=1).run()

    assert _allocation_kinds(first_result.points_to("left")) == {"OBJECT"}
    assert _allocation_kinds(second_result.points_to("left")) == {"OBJECT"}
    assert _allocation_kinds(first_result.points_to("right")) == {"LIST"}
    assert _allocation_kinds(second_result.points_to("right")) == {"LIST"}


def test_base_combination_widening_retains_reachable_attribute_facts() -> None:
    declarations = []
    assignments = []
    base_names = []
    for position in range(7):
        left = f"Base{position}Left"
        right = f"Base{position}Right"
        marker = "\n    marker = sentinel" if position == 6 else ""
        declarations.extend((
            f"class {left}:\n    pass",
            f"class {right}:{marker or chr(10) + '    pass'}",
        ))
        variable = f"Choice{position}"
        assignments.extend((f"{variable} = {left}", f"{variable} = {right}"))
        base_names.append(variable)

    source = "\n\n".join((
        "sentinel = object()",
        *declarations,
        "\n".join(assignments),
        f"class Combined({', '.join(base_names)}):\n    pass",
        "result = Combined.marker",
    ))

    results = [
        PointerAnalysis(
            source,
            k=1,
            worklist_policy="random",
            worklist_seed=seed,
        ).run()
        for seed in (1, 7, 31)
    ]

    for result in results:
        assert result.points_to("sentinel") <= result.points_to("result")
        combined = next(
            obj
            for obj in result.state._heap.objects.values()
            if isinstance(obj, ClassObject) and obj.ir.name == "Combined"
        )
        variants = result.state.class_variants(combined)
        assert variants
        assert any(variant.widened for variant in variants)

    assert all(
        result.points_to("result") == results[0].points_to("result")
        for result in results[1:]
    )
