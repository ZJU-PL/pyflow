"""Conformance tests for the address semantics on IFIP 2026 slides 9--10."""

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
    DictValue,
    Env,
    EnvironmentValue,
    InvalidIndexError,
    Lambda,
    Length,
    ListExpr,
    ListValue,
    Literal,
    MIRInterpreter,
    MIRTypeError,
    MIRValidationError,
    NewObject,
    Node,
    NondeterministicControlFlow,
    Not,
    ObjectValue,
    PathPruned,
    Program,
    Skip,
    StepLimitExceeded,
    UnboundVariableError,
    Var,
    format_program,
    interpret,
)


def sequence(name, *instructions):
    instructions = (Skip(), *instructions, Skip())
    return CFG(
        name,
        {
            index: Node(index, instruction, (index + 1,) if index + 1 < len(instructions) else ())
            for index, instruction in enumerate(instructions)
        },
        0,
        len(instructions) - 1,
    )


def run(*instructions):
    cfg = sequence("main", *instructions)
    return interpret(Program({"main": cfg}, "main"))


def test_allocation_and_binding_have_different_reference_semantics():
    result = run(
        Alloc("x", Literal(1)),
        Bind(Var("y"), Var("x")),
        Alloc("x", Literal(2)),
        Alloc("object", NewObject()),
        Bind(Var("alias"), Var("object")),
        Alloc("copy", Var("object")),
        Bind(Attr(Var("alias"), Literal("field")), Var("y")),
    )
    assert result.value("x") == 2
    assert result.value("y") == 1
    assert result.address("x") != result.address("y")
    assert result.address("object") == result.address("alias")
    assert result.address("copy") != result.address("object")
    assert result.value("object").fields == {"field": result.address("y")}
    assert result.value("copy").fields == {}


def test_deletion_removes_references_without_destroying_aliased_values():
    result = run(
        Alloc("value", Literal(7)),
        Alloc("obj", NewObject()),
        Bind(Attr(Var("obj"), Literal("f")), Var("value")),
        Bind(Var("saved"), Attr(Var("obj"), Literal("f"))),
        Delete(Attr(Var("obj"), Literal("f"))),
        Delete(Var("value")),
    )
    assert result.value("saved") == 7
    assert result.value("obj").fields == {}
    with pytest.raises(UnboundVariableError):
        result.value("value")


def test_environment_is_a_live_first_class_object():
    result = run(
        Env("scope"),
        Alloc("x", Literal(4)),
        Alloc("y", Literal(9)),
        Bind(Attr(Var("scope"), Literal("x")), Var("y")),
        Bind(Var("saved"), Attr(Var("scope"), Literal("x"))),
        Delete(Attr(Var("scope"), Literal("y"))),
    )
    assert result.address("scope") == result.environment
    assert isinstance(result.value("scope"), EnvironmentValue)
    assert result.value("x") == result.value("saved") == 9
    with pytest.raises(UnboundVariableError):
        result.value("y")


def test_containers_hold_references_and_lists_use_one_based_indexes():
    result = run(
        Alloc("one", Literal(1)),
        Alloc("two", Literal(2)),
        Alloc("xs", ListExpr((Var("one"), Var("two"), Var("one")))),
        Alloc("mapping", DictExpr((("a", Var("one")),))),
        Bind(Attr(Var("xs"), Literal(1)), Var("two")),
        Delete(Attr(Var("xs"), Literal(2))),
        Bind(Var("first"), Attr(Var("xs"), Literal(1))),
        Bind(Var("second"), Attr(Var("xs"), Literal(2))),
        Alloc("size", Length(Var("xs"))),
    )
    assert isinstance(result.value("xs"), ListValue)
    assert isinstance(result.value("mapping"), DictValue)
    assert result.address("first") == result.address("two")
    assert result.address("second") == result.address("one")
    assert result.value("size") == 2
    assert result.value("mapping").fields["a"] == result.address("one")


@pytest.mark.parametrize("index", [0, -1, 2])
def test_out_of_range_core_list_index_is_explicit(index):
    with pytest.raises(InvalidIndexError):
        run(
            Alloc("x", Literal(1)),
            Alloc("xs", ListExpr((Var("x"),))),
            Bind(Var("value"), Attr(Var("xs"), Literal(index))),
        )


def test_closure_uses_live_parent_and_return_preserves_identity():
    function = sequence("get", Bind(Var("result"), Attr(Var("parent"), Literal("x"))))
    main = sequence(
        "main",
        Alloc("x", NewObject()),
        Alloc("function", Lambda("args", "kwargs", "parent", "get", "result")),
        Alloc("x", NewObject()),
        Alloc("args", ListExpr(())),
        Alloc("kwargs", DictExpr(())),
        Call("returned", Var("function"), Var("args"), Var("kwargs")),
        Alloc("value", Literal(42)),
        Bind(Attr(Var("returned"), Literal("answer")), Var("value")),
    )
    result = interpret(Program({"main": main, "get": function}, "main"))
    assert result.address("returned") == result.address("x")
    assert result.value("x").fields["answer"] == result.address("value")


def test_call_passes_positional_and_keyword_container_addresses():
    function = sequence(
        "f",
        Bind(Var("argument"), Attr(Var("a"), Literal(1))),
        Bind(Var("keyword"), Attr(Var("k"), Literal("named"))),
        Alloc("result", ListExpr((Var("argument"), Var("keyword")))),
    )
    main = sequence(
        "main",
        Alloc("v", Literal(3)),
        Alloc("w", Literal(8)),
        Alloc("args", ListExpr((Var("v"),))),
        Alloc("kwargs", DictExpr((("named", Var("w")),))),
        Alloc("f", Lambda("a", "k", "p", "f", "result")),
        Call("returned", Var("f"), Var("args"), Var("kwargs")),
    )
    result = interpret(Program({"main": main, "f": function}, "main"))
    assert result.value("returned").items == (result.address("v"), result.address("w"))


def test_primitive_operations_do_not_use_python_truthiness_or_coercion():
    result = run(
        Alloc("one", Literal(1)),
        Alloc("two", Literal(2)),
        Alloc("obj", NewObject()),
        Alloc("dict", DictExpr(())),
        Alloc("sum", Binary("+", Literal(2), Literal(3))),
        Alloc("minus", Binary("-", Literal(9), Literal(4))),
        Alloc("text", Binary("+", Literal("a"), Literal("b"))),
        Alloc("joined", Binary("+", ListExpr((Var("one"),)), ListExpr((Var("two"),)))),
        Alloc("absent", Not(Binary("in", Literal("missing"), Var("obj")))),
        Alloc("truth", Binary("or", Literal(False), Literal(True))),
    )
    assert isinstance(result.value("obj"), ObjectValue)
    assert isinstance(result.value("dict"), DictValue)
    assert result.value("sum") == result.value("minus") == 5
    assert result.value("text") == "ab"
    assert result.value("joined").items == (result.address("one"), result.address("two"))
    assert result.value("absent") is result.value("truth") is True
    with pytest.raises(MIRTypeError):
        run(Assume(Literal(1)))
    with pytest.raises(MIRTypeError):
        run(Alloc("bad", Binary("+", Literal(True), Literal(1))))
    with pytest.raises(TypeError):
        Literal(None)


def test_assume_branches_choose_the_feasible_path():
    cfg = CFG(
        "main",
        {
            0: Node(0, Skip(), (1, 2)),
            1: Node(1, Assume(Literal(False)), (3,)),
            2: Node(2, Assume(Literal(True)), (4,)),
            3: Node(3, Alloc("x", Literal("wrong")), (5,)),
            4: Node(4, Alloc("x", Literal("right")), (5,)),
            5: Node(5, Skip()),
        },
        0,
        5,
    )
    assert interpret(Program({"main": cfg}, "main")).value("x") == "right"
    cfg.nodes[1].instruction = Assume(Literal(True))
    with pytest.raises(NondeterministicControlFlow):
        interpret(Program({"main": cfg}, "main"))
    cfg.nodes[1].instruction = cfg.nodes[2].instruction = Assume(Literal(False))
    with pytest.raises(PathPruned):
        interpret(Program({"main": cfg}, "main"))


def test_instruction_limit_bounds_loops():
    cfg = CFG("main", {0: Node(0, Skip(), (0,)), 1: Node(1, Skip())}, 0, 1)
    interpreter = MIRInterpreter(Program({"main": cfg}, "main"), max_steps=10)
    with pytest.raises(StepLimitExceeded):
        interpreter.run()
    assert interpreter.steps == 10


def test_validation_rejects_missing_graphs_and_noncore_operations():
    cfg = sequence("main", Alloc("f", Lambda("a", "k", "p", "missing", "return")))
    program = Program({"main": cfg}, "main")
    with pytest.raises(MIRValidationError, match="Unknown lambda body"):
        program.validate()
    cfg.nodes[1].instruction = Alloc("x", Binary("*", Literal(2), Literal(3)))
    with pytest.raises(MIRValidationError, match="Unknown primitive operator"):
        program.validate()
    cfg.nodes[1].instruction = Skip()
    cfg.nodes[1].successors = (100,)
    with pytest.raises(MIRValidationError, match="unknown successor"):
        program.validate()


def test_dumps_are_deterministic_and_preserve_reference_syntax():
    first = sequence(
        "a",
        Alloc("x", Literal(1)),
        Alloc("obj", NewObject()),
        Bind(Attr(Var("obj"), Literal("x")), Var("x")),
    )
    second = sequence("b")
    program = Program({"b": second, "a": first}, "a")
    program.validate()
    data = json.loads(format_program(program, format="json"))
    assert list(data["cfgs"]) == ["a", "b"]
    assert data["cfgs"]["a"]["nodes"]["3"]["instruction"]["kind"] == "Bind"
    assert 'BIND obj["x"] = x' in format_program(program)
    assert "digraph MIR" in format_program(program, format="dot")
    assert 'label="a"' in format_program(program, format="dot")
    assert "cfg b" not in format_program(program, scope="a")
    program.cfgs = {"a": first, "b": second}
    assert data == program.to_dict()


def test_expression_evaluation_never_allocates_or_mutates_memory():
    cfg = sequence("main", Alloc("x", Literal(1)))
    interpreter = MIRInterpreter(Program({"main": cfg}, "main"))
    result = interpreter.run()
    before = dict(interpreter.memory)
    value = interpreter.evaluate(ListExpr((Var("x"),)), result.environment)
    assert value.items == (result.address("x"),)
    assert interpreter.memory == before
