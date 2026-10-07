"""Concrete execution of generated builtin/protocol MIR; no host callbacks."""

from copy import copy

import pytest

from pyflow.ir.mir.builder import Builder, field
from pyflow.ir.mir.builtins import initialize
from pyflow.ir.mir.interpreter import ListValue, ObjectValue, interpret
from pyflow.ir.mir.model import CFG, DictExpr, ListExpr, Program
from pyflow.ir.mir.runtime import Runtime


@pytest.fixture(scope="module")
def bootstrap():
    program = Program({}, "main")
    builder = Builder(program, "main")
    runtime = Runtime(program)
    initialize(runtime, builder)
    builder.finish()
    program.validate()
    return program, builder, runtime


def execute(bootstrap, emit):
    original, old_builder, old_runtime = bootstrap
    program = Program(dict(original.cfgs), "main")
    old = original.cfgs["main"]
    builder = Builder(program, "main")
    builder.cfg = CFG(
        old.name,
        {key: copy(node) for key, node in old.nodes.items()},
        old.entry,
        old.exit,
        old.is_synthetic,
        old.filename,
    )
    program.cfgs["main"] = builder.cfg
    builder.counter = old_builder.counter
    builder.tails = {key for key, node in builder.cfg.nodes.items() if old.exit in node.successors}
    for key in builder.tails:
        builder.cfg.nodes[key].successors = tuple(
            item for item in builder.cfg.nodes[key].successors if item != old.exit
        )
    runtime = Runtime(program)
    runtime.serial = old_runtime.serial
    runtime.helpers = dict(old_runtime.helpers)
    answer = emit(runtime, builder)
    if answer is not None:
        builder.assign("answer", answer)
    builder.finish()
    program.validate()
    return interpret(program, max_steps=1_000_000)


def unbox(result, value):
    if isinstance(value, ObjectValue):
        return unbox(result, result.memory[value.fields["$value"]])
    if isinstance(value, ListValue):
        return [unbox(result, result.memory[address]) for address in value.items]
    return value


def answer(result):
    return unbox(result, result.value("answer"))


def exception_name(result):
    builtins = result.value("$builtins")
    state = result.memory[builtins.fields["$state"]]
    exception = result.memory[state.fields["exception"]]
    cls = result.memory[exception.fields["__class__"]]
    name = result.memory[cls.fields["__name__"]]
    return result.memory[name.fields["$value"]]


@pytest.mark.parametrize(
    "left,operator,right,expected",
    [
        (4, "+", 7, 11),
        (2, "-", 8, -6),
        (-3, "*", -4, 12),
        (-7, "//", 3, -3),
        (7, "//", -3, -3),
        (-7, "%", 3, 2),
        (7, "%", -3, -2),
        (2, "**", 5, 32),
        (True, "+", 4, 5),
        (True, "==", 1, True),
        (2, "<=", 3, True),
        (4, ">", 7, False),
    ],
)
def test_integer_primitive_models(bootstrap, left, operator, right, expected):
    result = execute(
        bootstrap,
        lambda rt, b: rt.invoke(b, "binary", (rt.box(b, left), rt.box(b, right)), operator),
    )
    assert exception_name(result) == "NoneType"
    assert answer(result) == expected


def test_primitive_constructors_and_truth(bootstrap):
    def emit(rt, b):
        truth = rt.call(b, rt.builtin("bool"), (rt.box(b, 0),))
        integer = rt.call(b, rt.builtin("int"), (rt.box(b, True),))
        b.assign("truth", truth)
        return integer

    result = execute(bootstrap, emit)
    assert exception_name(result) == "NoneType"
    assert answer(result) == 1
    assert unbox(result, result.value("truth")) is False


def test_list_aliasing_mutation_pop_and_length(bootstrap):
    def emit(rt, b):
        values = rt.sequence(b, (rt.box(b, 1), rt.box(b, 2)))
        rt.special(b, values, "__setitem__", (rt.box(b, -1), rt.box(b, 8)))
        append = rt.invoke(b, "getattr", (values, rt.raw(b, "append")))
        rt.call(b, append, (rt.box(b, 9),))
        pop = rt.invoke(b, "getattr", (values, rt.raw(b, "pop")))
        b.assign("popped", rt.call(b, pop))
        b.assign("length", rt.call(b, rt.builtin("len"), (values,)))
        return values

    result = execute(bootstrap, emit)
    assert exception_name(result) == "NoneType"
    assert answer(result) == [1, 8]
    assert unbox(result, result.value("popped")) == 9
    assert unbox(result, result.value("length")) == 2


def test_sequence_iteration_and_stopiteration_default(bootstrap):
    def emit(rt, b):
        values = rt.sequence(b, (rt.box(b, 4), rt.box(b, 5)), "tuple")
        iterator = rt.call(b, rt.builtin("iter"), (values,))
        b.assign("first", rt.call(b, rt.builtin("next"), (iterator,)))
        b.assign("second", rt.call(b, rt.builtin("next"), (iterator,)))
        return rt.call(b, rt.builtin("next"), (iterator, rt.box(b, 99)))

    result = execute(bootstrap, emit)
    assert exception_name(result) == "NoneType"
    assert answer(result) == 99
    assert unbox(result, result.value("first")) == 4
    assert unbox(result, result.value("second")) == 5


def test_list_constructor_consumes_iterator(bootstrap):
    result = execute(
        bootstrap,
        lambda rt, b: rt.call(
            b, rt.builtin("list"), (rt.sequence(b, (rt.box(b, 1), rt.box(b, 3)), "tuple"),)
        ),
    )
    assert exception_name(result) == "NoneType"
    assert answer(result) == [1, 3]


def test_dict_keys_copy_and_deletion(bootstrap):
    def emit(rt, b):
        mapping = rt.call(b, rt.builtin("dict"))
        rt.special(b, mapping, "__setitem__", (rt.box(b, 2), rt.box(b, 7)))
        duplicate = rt.call(b, rt.builtin("dict"), (mapping,))
        rt.special(b, duplicate, "__setitem__", (rt.box(b, 2), rt.box(b, 11)))
        b.assign("original", rt.special(b, mapping, "__getitem__", (rt.box(b, 2),)))
        b.assign("copy", rt.special(b, duplicate, "__getitem__", (rt.box(b, 2),)))
        rt.special(b, duplicate, "__delitem__", (rt.box(b, 2),))
        return rt.special(b, duplicate, "__contains__", (rt.box(b, 2),))

    result = execute(bootstrap, emit)
    assert exception_name(result) == "NoneType"
    assert unbox(result, result.value("original")) == 7
    assert unbox(result, result.value("copy")) == 11
    assert answer(result) is False


def test_dict_constructor_nested_keyword_abi(bootstrap):
    def emit(rt, b):
        key = rt.box(b, "name")
        value = rt.box(b, 42)
        values = b.alloc(DictExpr((("name", value),)))
        keys = b.alloc(ListExpr((key,)))
        kwargs = b.alloc(DictExpr((("$values", values), ("$keys", keys))))
        mapping = rt.call(b, rt.builtin("dict"), kwargs=kwargs)
        return rt.special(b, mapping, "__getitem__", (key,))

    result = execute(bootstrap, emit)
    assert exception_name(result) == "NoneType"
    assert answer(result) == 42


def test_contains_invokes_user_equality(bootstrap):
    def emit(rt, b):
        function = Builder(rt.program, "user_equal")
        rt.prologue(function)
        function.assign(field(rt.builtin("$state"), "compared"), rt.raw(function, True))
        function.ret(rt.box(function, True))
        function.finish()
        cls = rt.obj(b, "type")
        b.assign(field(cls, "$class"), rt.raw(b, True))
        b.assign(field(cls, "__mro__"), b.alloc(ListExpr((cls, rt.builtin("object")))))
        b.assign(field(cls, "__eq__"), rt.function(b, function.name))
        first, second = rt.obj(b, cls), rt.obj(b, cls)
        values = rt.sequence(b, (first,))
        b.assign("found", rt.special(b, values, "__contains__", (second,)))
        return field(rt.builtin("$state"), "compared")

    result = execute(bootstrap, emit)
    assert exception_name(result) == "NoneType"
    assert result.value("answer") is True
    assert unbox(result, result.value("found")) is True


def test_string_metadata_concat_length_and_index(bootstrap):
    def emit(rt, b):
        value = rt.invoke(b, "binary", (rt.box(b, "ab"), rt.box(b, "c")), "+")
        b.assign("length", rt.call(b, rt.builtin("len"), (value,)))
        return rt.special(b, value, "__getitem__", (rt.box(b, -1),))

    result = execute(bootstrap, emit)
    assert exception_name(result) == "NoneType"
    assert answer(result) == "c"
    assert unbox(result, result.value("length")) == 3


def test_explicit_property_descriptor_calls_user_getter(bootstrap):
    def emit(rt, b):
        getter = Builder(rt.program, "user_getter")
        rt.prologue(getter)
        getter.ret(rt.box(getter, 73))
        getter.finish()
        descriptor = rt.call(b, rt.builtin("property"), (rt.function(b, getter.name),))
        cls = rt.obj(b, "type")
        b.assign(field(cls, "$class"), rt.raw(b, True))
        b.assign(field(cls, "__mro__"), b.alloc(ListExpr((cls, rt.builtin("object")))))
        b.assign(field(cls, "answer"), descriptor)
        obj = rt.obj(b, cls)
        return rt.invoke(b, "getattr", (obj, rt.raw(b, "answer")))

    result = execute(bootstrap, emit)
    assert exception_name(result) == "NoneType"
    assert answer(result) == 73


@pytest.mark.parametrize(
    "arguments,expected",
    [((4,), [0, 1, 2, 3]), ((2, 6, 2), [2, 4]), ((5, 0, -2), [5, 3, 1]), ((2, 1), [])],
)
def test_eager_range(bootstrap, arguments, expected):
    result = execute(
        bootstrap,
        lambda rt, b: rt.call(
            b, rt.builtin("range"), tuple(rt.box(b, value) for value in arguments)
        ),
    )
    assert exception_name(result) == "NoneType"
    assert answer(result) == expected


def test_missing_getattr_default_and_hasattr(bootstrap):
    def emit(rt, b):
        obj = rt.obj(b)
        b.assign("present", rt.call(b, rt.builtin("hasattr"), (obj, rt.box(b, "missing"))))
        return rt.call(b, rt.builtin("getattr"), (obj, rt.box(b, "missing"), rt.box(b, 12)))

    result = execute(bootstrap, emit)
    assert exception_name(result) == "NoneType"
    assert answer(result) == 12
    assert unbox(result, result.value("present")) is False


def test_isinstance_and_issubclass_use_raw_mro(bootstrap):
    def emit(rt, b):
        b.assign(
            "isinstance", rt.call(b, rt.builtin("isinstance"), (rt.box(b, True), rt.builtin("int")))
        )
        return rt.call(b, rt.builtin("issubclass"), (rt.builtin("bool"), rt.builtin("int")))

    result = execute(bootstrap, emit)
    assert exception_name(result) == "NoneType"
    assert answer(result) is True
    assert unbox(result, result.value("isinstance")) is True


@pytest.mark.parametrize(
    "operation,expected",
    [
        ("index", "IndexError"),
        ("division", "ZeroDivisionError"),
        ("range", "ValueError"),
        ("keyword", "TypeError"),
    ],
)
def test_unsupported_or_invalid_operations_set_explicit_exception(bootstrap, operation, expected):
    def emit(rt, b):
        if operation == "index":
            return rt.special(b, rt.sequence(b, ()), "__getitem__", (rt.box(b, 0),))
        if operation == "division":
            return rt.invoke(b, "binary", (rt.box(b, 1), rt.box(b, 0)), "//")
        if operation == "range":
            return rt.call(b, rt.builtin("range"), (rt.box(b, 0), rt.box(b, 5), rt.box(b, 0)))
        value = rt.box(b, 1)
        kwargs = b.alloc(DictExpr((("invalid", value),)))
        return rt.call(b, rt.builtin("len"), (rt.sequence(b, ()),), kwargs=kwargs)

    result = execute(bootstrap, emit)
    assert exception_name(result) == expected
