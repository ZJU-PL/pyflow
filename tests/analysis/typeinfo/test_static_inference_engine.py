"""Regression tests for the standalone static type-inference engine."""

from __future__ import annotations

import collections.abc as cabc
import tempfile
from pathlib import Path

from pyflow.analysis.typeinfo import (
    InferenceOptions,
    MappingCallModelProvider,
    ObservedType,
    ProjectTypeInferenceEngine,
    StaticTypeInferenceEngine,
    validate_observed_types,
)
from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    CallableType,
    Instance,
    NoneType,
    TupleType,
    TypeSystem,
    UnionType,
)
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue
from pyflow.language.modules.project_resolution import ProjectContext


def _raw_types(typ) -> set[type]:
    if isinstance(typ, Instance):
        return {typ.type.raw_type}
    if isinstance(typ, UnionType):
        return {
            item.type.raw_type
            for item in typ.items
            if isinstance(item, Instance)
        }
    return set()


def test_domain_keeps_unknown_distinct_from_any() -> None:
    type_system = TypeSystem()
    unknown = AbstractTypeValue.unresolved()
    explicit_any = AbstractTypeValue.from_type(ANY)

    assert unknown.public_type() is None
    assert unknown.unknown is True
    assert explicit_any.public_type() is ANY
    assert explicit_any.unknown is False
    assert unknown.join(explicit_any, type_system).public_type() is ANY


def test_infers_literals_precise_collections_and_subscripts() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
number = 1
text = "value"
items = [1, 2, 3]
mapping = {"key": 1}
pair = (1, "two")
item = items[0]
mapped = mapping["key"]
second = pair[1]
""",
    )

    assert _raw_types(result.type_of("number")) == {int}
    assert _raw_types(result.type_of("text")) == {str}
    assert _raw_types(result.type_of("item")) == {int}
    assert _raw_types(result.type_of("mapped")) == {int}
    assert _raw_types(result.type_of("second")) == {str}
    items = result.type_of("items")
    assert isinstance(items, Instance) and items.type.raw_type is list
    assert _raw_types(items.args[0]) == {int}
    pair = result.type_of("pair")
    assert isinstance(pair, TupleType)
    assert [_raw_types(item) for item in pair.args] == [{int}, {str}]


def test_joins_control_flow_and_narrows_optional_values() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
value: int | None = None
if value is not None:
    narrowed = value
else:
    narrowed = 0

if flag:
    joined = 1
else:
    joined = "text"
""",
    )

    assert _raw_types(result.type_of("narrowed")) == {int}
    assert _raw_types(result.type_of("joined")) == {int, str}


def test_loop_analysis_reaches_a_fixed_point() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
value = 0
while condition:
    value = "changed"
""",
    )

    assert result.converged is True
    assert _raw_types(result.type_of("value")) == {int, str}


def test_interprocedural_inference_preserves_identity_at_each_call_site() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
def identity(value):
    return value

integer = identity(1)
text = identity("text")
""",
    )

    assert _raw_types(result.type_of("integer")) == {int}
    assert _raw_types(result.type_of("text")) == {str}
    summary = result.functions["sample.identity"]
    assert _raw_types(summary.parameters["value"].public_type()) == {int, str}
    assert summary.return_dependencies == frozenset({"value"})


def test_argument_specializations_preserve_constructed_return_types() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
def wrap(value):
    return [value]

integers = wrap(1)
strings = wrap("text")
""",
    )

    integers = result.type_of("integers")
    strings = result.type_of("strings")
    assert isinstance(integers, Instance) and integers.type.raw_type is list
    assert isinstance(strings, Instance) and strings.type.raw_type is list
    assert _raw_types(integers.args[0]) == {int}
    assert _raw_types(strings.args[0]) == {str}

    summary = result.functions["sample.wrap"]
    assert len(summary.specializations) == 2
    assert {
        next(iter(_raw_types(item.parameter_map["value"].public_type())))
        for item in summary.specializations
    } == {int, str}


def test_argument_specializations_keep_correlated_calls_separate() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
def select(condition, left, right):
    if condition:
        return left
    return right

number = select(flag, 1, 2)
text = select(flag, "left", "right")
""",
    )

    assert _raw_types(result.type_of("number")) == {int}
    assert _raw_types(result.type_of("text")) == {str}


def test_recursive_specializations_converge_independently() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
def descend(value, depth):
    if depth <= 0:
        return [value]
    return descend(value, depth - 1)

numbers = descend(1, 3)
texts = descend("text", 3)
""",
    )

    numbers = result.type_of("numbers")
    texts = result.type_of("texts")
    assert isinstance(numbers, Instance) and numbers.type.raw_type is list
    assert isinstance(texts, Instance) and texts.type.raw_type is list
    assert _raw_types(numbers.args[0]) == {int}
    assert _raw_types(texts.args[0]) == {str}
    assert result.converged is True


def test_method_specializations_include_receiver_and_arguments() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
class Wrapper:
    def wrap(self, value):
        return (value,)

wrapper = Wrapper()
numbers = wrapper.wrap(1)
texts = wrapper.wrap("text")
""",
    )

    numbers = result.type_of("numbers")
    texts = result.type_of("texts")
    assert isinstance(numbers, TupleType)
    assert isinstance(texts, TupleType)
    assert _raw_types(numbers.args[0]) == {int}
    assert _raw_types(texts.args[0]) == {str}
    assert len(result.functions["sample.Wrapper.wrap"].specializations) == 2


def test_higher_order_specializations_retain_callable_identity() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
def boxed(value):
    return [value]

def rendered(value):
    return str(value)

def apply(function, value):
    return function(value)

box = apply(boxed, 1)
text = apply(rendered, 1)
""",
    )

    box = result.type_of("box")
    assert isinstance(box, Instance) and box.type.raw_type is list
    assert _raw_types(box.args[0]) == {int}
    assert _raw_types(result.type_of("text")) == {str}
    assert len(result.functions["sample.apply"].specializations) == 2


def test_specialization_budget_uses_a_widened_overflow_context() -> None:
    result = StaticTypeInferenceEngine(
        options=InferenceOptions(max_specializations_per_function=1)
    ).infer_source(
        "sample",
        """
def wrap(value):
    return [value]

first = wrap(1)
second = wrap("text")
third = wrap(1.5)
""",
    )

    summary = result.functions["sample.wrap"]
    assert len(summary.specializations) == 2
    widened = [item for item in summary.specializations if item.widened]
    assert len(widened) == 1
    assert _raw_types(widened[0].parameter_map["value"].public_type()) == {
        str,
        float,
    }
    assert "specialization-budget-exceeded" in {
        item.code for item in result.diagnostics
    }


def test_infers_unannotated_parameters_and_recursive_return() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
def factorial(number):
    if number <= 1:
        return 1
    return number * factorial(number - 1)

answer = factorial(5)
""",
    )

    summary = result.functions["sample.factorial"]
    assert _raw_types(summary.parameters["number"].public_type()) == {int}
    assert _raw_types(summary.return_type) == {int}
    assert _raw_types(result.type_of("answer")) == {int}


def test_generic_type_variables_are_substituted_per_call() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
from typing import TypeVar

T = TypeVar("T")

def first(values: list[T]) -> T:
    return values[0]

integer = first([1])
text = first(["text"])
""",
    )

    assert _raw_types(result.type_of("integer")) == {int}
    assert _raw_types(result.type_of("text")) == {str}


def test_constructor_arguments_and_instance_attributes_propagate() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
class Box:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

box = Box(1)
attribute = box.value
method = box.get()
""",
    )

    assert _raw_types(result.type_of("sample.Box.value")) == {int}
    assert _raw_types(result.type_of("attribute")) == {int}
    assert _raw_types(result.type_of("method")) == {int}
    assert result.value_of("attribute").unknown is False


def test_container_mutation_and_comprehension_element_flow() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
items = [1]
items.append("text")
copied = [item for item in items]
first = copied[0]
""",
    )

    assert _raw_types(result.type_of("first")) == {int, str}
    copied = result.type_of("copied")
    assert isinstance(copied, Instance) and copied.type.raw_type is list
    assert _raw_types(copied.args[0]) == {int, str}


def test_external_callable_facts_are_consumed_without_cpa() -> None:
    type_system = TypeSystem()
    external = CallableType(
        (Instance(type_system.to_class_descriptor(str)),),
        Instance(type_system.to_class_descriptor(int)),
    )

    def resolve(name: str):
        return external if name == "external.parse" else None

    result = StaticTypeInferenceEngine(
        type_system=type_system,
        external_symbol_resolver=resolve,
    ).infer_source(
        "sample",
        """
from external import parse
value = parse("42")
""",
    )

    assert _raw_types(result.type_of("value")) == {int}


def test_argument_sensitive_external_call_models_are_extensible() -> None:
    type_system = TypeSystem()
    provider = MappingCallModelProvider()
    provider.register(
        "external.echo",
        lambda arguments, _keywords: arguments[0],
    )
    engine = StaticTypeInferenceEngine(
        type_system=type_system,
        call_model_providers=(provider,),
    )

    result = engine.infer_source(
        "sample",
        """
from external import echo
integer = echo(1)
text = echo("value")
""",
    )

    assert _raw_types(result.type_of("integer")) == {int}
    assert _raw_types(result.type_of("text")) == {str}


def test_annotation_mismatches_are_diagnostic_not_solver_failures() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        'value: int = "wrong"\n',
    )

    assert _raw_types(result.type_of("value")) == {int}
    assert [item.code for item in result.diagnostics] == ["annotation-mismatch"]


def test_expression_query_prefers_outer_expression_at_same_start() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
def identity(value):
    return value

answer = identity(1)
""",
    )

    # The Name and Call both start at column 9; the query selects the Call.
    assert _raw_types(result.expression_type(5, 9)) == {int}


def test_union_widening_guarantees_termination() -> None:
    source = """
if c0:
    value = 0
elif c1:
    value = "text"
elif c2:
    value = 1.0
elif c3:
    value = b"bytes"
elif c4:
    value = []
elif c5:
    value = {}
else:
    value = None
"""
    result = StaticTypeInferenceEngine(
        options=InferenceOptions(max_union_size=3)
    ).infer_source("sample", source)

    value = result.value_of("value")
    assert value is not None
    assert value.public_type() is ANY
    assert value.unknown is True


def test_generator_summary_keeps_yield_type_separate() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
def values():
    yield 1
    yield 2
""",
    )

    summary = result.functions["sample.values"]
    assert summary.is_generator is True
    assert _raw_types(summary.yield_value.public_type()) == {int}
    assert isinstance(summary.return_type, NoneType)


def test_generator_calls_expose_iterable_element_types() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
def values():
    yield 1

items = list(values())
item = items[0]
""",
    )

    assert _raw_types(result.type_of("item")) == {int}


def test_async_calls_and_await_keep_result_types() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
async def fetch() -> int:
    return 1

async def use():
    return await fetch()

pending = fetch()
""",
    )

    pending = result.type_of("pending")
    assert isinstance(pending, Instance)
    assert pending.type.raw_type is cabc.Coroutine
    assert _raw_types(pending.args[-1]) == {int}
    assert _raw_types(result.functions["sample.use"].return_type) == {int}


def test_varargs_keyword_only_and_kwargs_are_bound_by_python_call_shape() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
def first(*values):
    return values[0]

def select(value, *, enabled):
    return value if enabled else value

def keyword(**values):
    return values["item"]

from_args = first(1, 2)
from_keyword_only = select(value="text", enabled=True)
from_kwargs = keyword(item=1)
""",
    )

    assert _raw_types(result.type_of("from_args")) == {int}
    assert _raw_types(result.type_of("from_keyword_only")) == {str}
    assert _raw_types(result.type_of("from_kwargs")) == {int}


def test_nested_functions_capture_lexical_type_evidence() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
def outer(value):
    def inner():
        return value
    return inner()

answer = outer(1)
""",
    )

    assert _raw_types(result.type_of("answer")) == {int}
    assert _raw_types(result.functions["sample.outer.inner"].return_type) == {int}


def test_inherited_methods_and_attributes_are_resolved() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
class Base:
    label: str

    def value(self) -> int:
        return 1

class Child(Base):
    pass

child = Child()
label = child.label
value = child.value()
""",
    )

    assert _raw_types(result.type_of("label")) == {str}
    assert _raw_types(result.type_of("value")) == {int}


def test_structural_pattern_matching_narrows_and_binds() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        """
value: int | None = None
match value:
    case int() as number:
        result = number
    case None:
        result = 0
""",
    )

    assert _raw_types(result.type_of("result")) == {int}


def test_runtime_observations_form_a_bounded_soundness_oracle() -> None:
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        "value = 1\nunknown = missing\n",
    )

    violations = validate_observed_types(
        result,
        [
            ObservedType(int, symbol="value"),
            ObservedType(str, symbol="value"),
            ObservedType(object, symbol="unknown"),
        ],
    )

    # int is admitted and the unresolved symbol deliberately remains open.
    assert len(violations) == 1
    assert violations[0].observation.raw_type is str


def test_project_engine_discovers_imports_and_solves_cross_module_types() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        package = root / "pkg"
        package.mkdir()
        package.joinpath("__init__.py").write_text("", encoding="utf-8")
        package.joinpath("models.py").write_text(
            "def parse(value: str) -> int:\n"
            "    return int(value)\n\n"
            "class Client:\n"
            "    pass\n",
            encoding="utf-8",
        )
        package.joinpath("service.py").write_text(
            "from .models import Client, parse\n\n"
            "number = parse('42')\n"
            "client = Client()\n",
            encoding="utf-8",
        )

        result = ProjectTypeInferenceEngine(
            ProjectContext(root)
        ).infer_project(["pkg.service"])

    assert result.converged is True
    assert {"pkg.models", "pkg.service"} <= result.modules.keys()
    assert _raw_types(result.type_of("pkg.service.number")) == {int}
    client = result.type_of("pkg.service.client")
    assert isinstance(client, Instance)
    assert client.type.full_name == "pkg.models.Client"
