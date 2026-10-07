"""C3 is executed by MIR; parent MROs and bases are runtime references."""

import pytest

from pyflow.ir.mir import (
    Alloc,
    Literal,
    ListExpr,
    ListValue,
    NewObject,
    ObjectValue,
    Program,
    Var,
    interpret,
)
from pyflow.ir.mir.builder import Builder, field
from pyflow.ir.mir.mro import emit_mro
from pyflow.ir.mir.runtime import Runtime


def setup_program():
    program = Program({}, "mro_test")
    b = Builder(program, "mro_test")
    runtime = Runtime(program)
    builtins = b.alloc(NewObject(), "builtins")
    b.assign("$builtins", builtins)
    none = b.alloc(NewObject(), "none")
    b.assign("none", none)
    b.assign(field(builtins, "None"), none)
    error_type = make_class(b, "TypeError")
    b.assign(field(builtins, "TypeError"), error_type)
    state = b.alloc(NewObject(), "state")
    b.assign(field(state, "exception"), none)
    b.assign(field(builtins, "$state"), state)
    return program, b, runtime


def make_class(b, name):
    cls = b.alloc(NewObject(), "class")
    b.assign(name, cls)
    b.assign(field(cls, "$class"), b.alloc(Literal(True)))
    b.assign(field(cls, "__name__"), b.alloc(Literal(name)))
    return cls


def object_fields(execution, address):
    value = execution.memory[address]
    assert isinstance(value, ObjectValue)
    return value.fields


def exception_address(execution):
    builtins = object_fields(execution, execution.address("$builtins"))
    state = object_fields(execution, builtins["$state"])
    return state["exception"]


def mro_names(execution, name):
    cls = object_fields(execution, execution.address(name))
    mro = execution.memory[cls["__mro__"]]
    assert isinstance(mro, ListValue)
    return [
        execution.memory[object_fields(execution, address)["__name__"]] for address in mro.items
    ]


def build_hierarchy(spec):
    program, b, runtime = setup_program()
    classes = {}
    for name, parents in spec:
        cls = classes[name] = make_class(b, name)
        bases = b.alloc(ListExpr(tuple(classes[parent] for parent in parents)))
        mro = emit_mro(b, runtime, cls, bases)
        b.assign(field(cls, "__mro__"), mro)
    b.finish()
    program.validate()
    return program


@pytest.mark.parametrize(
    "spec, target, expected",
    [
        ([("O", ())], "O", ["O"]),
        ([("O", ()), ("A", ("O",)), ("B", ("A",))], "B", ["B", "A", "O"]),
        (
            [("O", ()), ("A", ("O",)), ("B", ("O",)), ("C", ("A", "B"))],
            "C",
            ["C", "A", "B", "O"],
        ),
        (
            [
                ("O", ()),
                ("A", ("O",)),
                ("B", ("O",)),
                ("C", ("A", "B")),
                ("D", ("B",)),
                ("E", ("C", "D")),
            ],
            "E",
            ["E", "C", "A", "D", "B", "O"],
        ),
    ],
)
def test_emitted_c3_order_matches_python(spec, target, expected):
    execution = interpret(build_hierarchy(spec))
    assert exception_address(execution) == execution.address("none")
    assert mro_names(execution, target) == expected

    # Independent CPython oracle for legal dynamic class hierarchies.
    host_classes = {}
    for name, parents in spec:
        host_classes[name] = type(name, tuple(host_classes[parent] for parent in parents), {})
    actual = [cls.__name__ for cls in host_classes[target].__mro__ if cls is not object]
    assert mro_names(execution, target) == actual


def test_c3_preserves_existing_base_mros():
    spec = [
        ("O", ()),
        ("A", ("O",)),
        ("B", ("O",)),
        ("C", ("A", "B")),
        ("D", ("B",)),
        ("E", ("C", "D")),
    ]
    execution = interpret(build_hierarchy(spec))
    assert mro_names(execution, "O") == ["O"]
    assert mro_names(execution, "A") == ["A", "O"]
    assert mro_names(execution, "B") == ["B", "O"]
    assert mro_names(execution, "C") == ["C", "A", "B", "O"]
    assert mro_names(execution, "D") == ["D", "B", "O"]


@pytest.mark.parametrize(
    "spec",
    [
        [("O", ()), ("A", ("O",)), ("B", ("A", "A"))],
        [
            ("O", ()),
            ("A", ("O",)),
            ("B", ("O",)),
            ("X", ("A", "B")),
            ("Y", ("B", "A")),
            ("Z", ("X", "Y")),
        ],
        [("O", ()), ("A", ("O",)), ("B", ("O", "A"))],
    ],
)
def test_invalid_c3_reports_type_error(spec):
    execution = interpret(build_hierarchy(spec))
    exception = object_fields(execution, exception_address(execution))
    assert exception["__class__"] == execution.address("TypeError")


@pytest.mark.parametrize("problem", ["cycle", "empty_mro", "missing_mro", "nonclass"])
def test_invalid_dynamic_base_reports_type_error(problem):
    program, b, runtime = setup_program()
    cls = make_class(b, "C")
    parent = make_class(b, "A") if problem != "nonclass" else b.alloc(NewObject())
    if problem == "cycle":
        b.assign(field(parent, "__mro__"), b.alloc(ListExpr((parent, cls))))
    elif problem == "empty_mro":
        b.assign(field(parent, "__mro__"), b.alloc(ListExpr(())))
    bases = b.alloc(ListExpr((parent,)))
    result = emit_mro(b, runtime, cls, bases)
    b.assign(field(cls, "__mro__"), result)
    b.finish()
    execution = interpret(program)
    exception = object_fields(execution, exception_address(execution))
    assert exception["__class__"] == execution.address("TypeError")


def test_same_mir_merges_bases_selected_at_runtime():
    program, b, runtime = setup_program()
    root = make_class(b, "O")
    b.assign(field(root, "__mro__"), b.alloc(ListExpr((root,))))
    left, right = make_class(b, "A"), make_class(b, "B")
    for cls in (left, right):
        b.assign(field(cls, "__mro__"), b.alloc(ListExpr((cls, root))))
    bases_left = b.alloc(ListExpr((left,)))
    bases_right = b.alloc(ListExpr((right,)))
    holder = b.alloc(NewObject())
    choice_node = b.emit(Alloc("choice", Literal(True)))
    yes, no = b.branch(Var("choice"))
    b.use(yes)
    b.assign(field(holder, "bases"), bases_left)
    yes_tails = set(b.tails)
    b.use(no)
    b.assign(field(holder, "bases"), bases_right)
    b.join(yes_tails, b.tails)
    cls = make_class(b, "C")
    result = emit_mro(b, runtime, cls, field(holder, "bases"))
    b.assign(field(cls, "__mro__"), result)
    b.finish()

    first = interpret(program)
    assert mro_names(first, "C") == ["C", "A", "O"]
    b.cfg.nodes[choice_node].instruction = Alloc("choice", Literal(False))
    second = interpret(program)
    assert mro_names(second, "C") == ["C", "B", "O"]
