"""MIR JSON round trips, strict validation, and analysis without Python source."""

import copy
import json

import pytest

from pyflow.ir.mir import (
    Alloc,
    Assume,
    Attr,
    Binary,
    Bind,
    Call,
    CFG,
    Delete,
    DictExpr,
    Env,
    Lambda,
    Length,
    ListExpr,
    Literal,
    MIRValidationError,
    NewObject,
    Node,
    Not,
    Program,
    Skip,
    Var,
    format_program,
    interpret,
)
from pyflow.ir.mir.serialization import program_from_dict, program_from_json


def sequence(name, instructions, synthetic=False):
    return CFG(
        name,
        {
            index: Node(
                index,
                instruction,
                (index + 1,) if index + 1 < len(instructions) else (),
                index + 1,
            )
            for index, instruction in enumerate(instructions)
        },
        0,
        len(instructions) - 1,
        synthetic,
        "example.py",
    )


def full_program():
    main = sequence(
        "demo",
        [
            Skip(),
            Env("environment"),
            Alloc("x", Literal(7)),
            Alloc("flag", Literal(True)),
            Alloc("key", Literal("answer")),
            Alloc("object", NewObject()),
            Bind(Attr(Var("object"), Var("key")), Var("x")),
            Alloc("items", ListExpr((Var("x"),))),
            Alloc("mapping", DictExpr((("key", Var("x")),))),
            Alloc("sum", Binary("+", Var("x"), Literal(1))),
            Alloc("function", Lambda("args", "kwargs", "parent", "demo.leaf", "result")),
            Alloc("args", ListExpr((Var("x"),))),
            Alloc("kwargs", DictExpr(())),
            Call("out", Var("function"), Var("args"), Var("kwargs")),
            Assume(Not(Binary("<", Length(Var("items")), Literal(1)))),
            Delete(Attr(Var("object"), Var("key"))),
            Skip(),
        ],
    )
    leaf = sequence(
        "demo.leaf",
        [
            Skip(),
            Bind(Var("result"), Attr(Var("args"), Literal(1))),
            Skip(),
        ],
    )
    program = Program({"demo": main, "demo.leaf": leaf}, "demo")
    program.validate()
    return program


def test_roundtrip_all_core_instructions_and_expressions_preserves_semantics():
    program = full_program()
    serialized = format_program(program, format="json")
    restored = program_from_json(serialized)
    assert restored.to_dict() == program.to_dict()
    for format in ("text", "json", "dot"):
        assert format_program(restored, format=format) == format_program(program, format=format)
    execution = interpret(restored)
    assert execution.value("out") == 7
    assert execution.value("sum") == 8
    assert execution.address("out") == execution.address("x")
    assert execution.value("object").fields == {}


def test_deserialized_mir_is_analyzed_without_a_python_frontend(monkeypatch):
    from pyflow.analysis.callgraph.pycg_mir import analyze_program
    from pyflow.ir.mir import lowering

    def no_source(*_args, **_kwargs):
        raise AssertionError("deserialized MIR must not go through source lowering")

    restored = program_from_dict(full_program().to_dict())
    monkeypatch.setattr(lowering, "lower_source", no_source)
    monkeypatch.setattr(lowering, "lower_file", no_source)
    result = analyze_program(restored, raise_on_truncation=True)
    assert result.converged
    assert result.call_graph.get()["demo"] == {"demo.leaf"}


@pytest.mark.parametrize(
    "path, value",
    [
        (("version",), True),
        (("version",), 2),
        (("entry",), "missing"),
        (("cfgs", "demo", "name"), "mismatch"),
        (("cfgs", "demo", "filename"), None),
        (("cfgs", "demo", "is_synthetic"), 1),
        (("cfgs", "demo", "nodes", "0", "id"), True),
        (("cfgs", "demo", "nodes", "0", "id"), 99),
        (("cfgs", "demo", "nodes", "0", "successors"), [999]),
        (("cfgs", "demo", "nodes", "0", "successors"), [True]),
        (("cfgs", "demo", "nodes", "0", "lineno"), "1"),
        (("cfgs", "demo", "nodes", "0", "instruction", "kind"), "os.system"),
        (
            ("cfgs", "demo", "nodes", "2", "instruction", "value"),
            {"kind": "Alloc", "target": "x", "value": {"kind": "Literal", "value": 7}},
        ),
        (("cfgs", "demo", "nodes", "2", "instruction", "value", "value"), 1.5),
        (
            ("cfgs", "demo", "nodes", "6", "instruction", "target"),
            {"kind": "Literal", "value": "invalid l-value"},
        ),
        (("cfgs", "demo", "nodes", "7", "instruction", "value", "items"), {}),
        (("cfgs", "demo", "nodes", "8", "instruction", "value", "items"), [["key"]]),
        (("cfgs", "demo", "nodes", "9", "instruction", "value", "op"), "**"),
        (("cfgs", "demo", "nodes", "10", "instruction", "value", "body"), "missing"),
        (("cfgs", "demo", "nodes", "10", "instruction", "value", "kwargs_param"), "args"),
    ],
)
def test_malformed_schema_or_graph_is_rejected(path, value):
    data = full_program().to_dict()
    parent = data
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(MIRValidationError):
        program_from_dict(data)


def test_unknown_or_missing_fields_and_noncanonical_node_keys_are_rejected():
    original = full_program().to_dict()
    for mutation in ("unknown", "missing", "node_key"):
        data = copy.deepcopy(original)
        if mutation == "unknown":
            data["cfgs"]["demo"]["__module__"] = "os"
        elif mutation == "missing":
            del data["cfgs"]["demo"]["nodes"]["0"]["instruction"]
        else:
            nodes = data["cfgs"]["demo"]["nodes"]
            nodes["00"] = nodes.pop("0")
        with pytest.raises(MIRValidationError):
            program_from_dict(data)


@pytest.mark.parametrize(
    "payload",
    [
        '{"version": 1, "version": 2, "entry": "demo", "cfgs": {}}',
        '{"version": NaN, "entry": "demo", "cfgs": {}}',
        '{"version": Infinity, "entry": "demo", "cfgs": {}}',
        '{"version":',
        json.dumps(["not a program"]),
    ],
)
def test_invalid_or_ambiguous_json_is_rejected(payload):
    with pytest.raises(MIRValidationError):
        program_from_json(payload)
