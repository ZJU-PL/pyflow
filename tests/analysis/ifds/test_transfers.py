from __future__ import annotations

from pyflow.analysis.ifds.core.transfers import (
    actual_argument_expressions,
    actual_parameters,
    bind_call_arguments,
    collect_locals,
    formal_parameters,
    identity_unless_killed,
)
from pyflow.language.python import ast
from pyflow.language.python.ir_metadata import resolve_call_name


def test_collect_locals_finds_locals_in_expression():
    a = ast.Local("a")
    b = ast.Local("b")
    expr = ast.BinaryOp(a, "+", b)
    found = collect_locals(expr)
    found_names = {f.name for f in found}
    assert found_names == {"a", "b"}


def test_collect_locals_empty_for_leaf():
    found = collect_locals(None)
    assert frozenset() == found


def test_collect_locals_skips_code_boundaries():
    a = ast.Local("a")
    code = ast.Code(
        "inner",
        ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[],
            paramnames=[],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[],
            type_params=None,
        ),
        ast.Suite([ast.Return([a])]),
    )
    found = collect_locals(code)
    assert a not in found


def test_collect_locals_nested_in_assign():
    x = ast.Local("x")
    y = ast.Local("y")
    expr = ast.Assign(ast.BinaryOp(x, "+", y), [ast.Local("target")])
    found = collect_locals(expr)
    found_names = {f.name for f in found}
    assert "x" in found_names
    assert "y" in found_names


def test_identity_unless_killed_passes_unless_killed():
    assert identity_unless_killed("fact", ("other",)) == ("fact",)


def test_identity_unless_killed_kills_matching():
    assert identity_unless_killed("fact", ("fact", "other")) == ()


def test_identity_unless_killed_empty_killed():
    assert identity_unless_killed("fact", ()) == ("fact",)


def test_actual_argument_expressions_positional():
    arg_a = ast.Local("a")
    arg_b = ast.Local("b")
    call = ast.Call(ast.Local("fn"), [arg_a, arg_b], [], None, None)
    args = actual_argument_expressions(call)
    assert len(args) == 2
    assert args[0].name == "a"
    assert args[1].name == "b"


def test_actual_argument_expressions_selfarg():
    self_expr = ast.Local("self")
    call = ast.DirectCall(None, self_expr, [], [], None, None)
    args = actual_argument_expressions(call)
    assert args[0] is self_expr


def test_actual_argument_expressions_keyword_values():
    key_val = ast.Local("val")
    call = ast.Call(ast.Local("fn"), [], [("key", key_val)], None, None)
    args = actual_argument_expressions(call)
    assert any(a is key_val for a in args)


def test_actual_argument_expressions_varargs_and_kwargs():
    v = ast.Local("v")
    k = ast.Local("k")
    call = ast.Call(ast.Local("fn"), [], [], v, k)
    args = actual_argument_expressions(call)
    assert any(a is v for a in args)
    assert any(a is k for a in args)


def test_actual_argument_expressions_empty():
    call = ast.Call(ast.Local("fn"), [], [], None, None)
    args = actual_argument_expressions(call)
    assert args == ()


def test_formal_parameters_selfparam():
    self_param = ast.Local("self")
    params = ast.CodeParameters(
        selfparam=self_param,
        posonlyparams=[],
        posonlynames=[],
        params=[],
        paramnames=[],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    formals = formal_parameters(params)
    assert self_param in formals


def test_formal_parameters_posonly():
    p = ast.Local("p")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[p],
        posonlynames=["p"],
        params=[],
        paramnames=[],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    formals = formal_parameters(params)
    assert p in formals


def test_formal_parameters_regular_params():
    a = ast.Local("a")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[a],
        paramnames=["a"],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    formals = formal_parameters(params)
    assert a in formals


def test_formal_parameters_skips_non_locals():
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[],
        paramnames=[],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    formals = formal_parameters(params)
    assert len(formals) == 0


def test_formal_parameters_empty():
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[],
        paramnames=[],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    formals = formal_parameters(params)
    assert formals == ()


def test_resolve_call_name_direct_call_code():
    inner = ast.Code(
        "target_fn",
        ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[],
            paramnames=[],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[],
            type_params=None,
        ),
        ast.Suite([]),
    )
    call = ast.DirectCall(inner, None, [], [], None, None)
    name = resolve_call_name(call)
    assert name == "target_fn"


def test_resolve_call_name_method_call_local():
    call = ast.MethodCall(ast.Local("obj"), ast.Local("do_thing"), [], [], None, None)
    name = resolve_call_name(call)
    assert name == "do_thing"


def test_resolve_call_name_method_call_existing_str():
    call = ast.MethodCall(
        ast.Local("obj"),
        ast.Existing(ast.program.Object("the_method")),
        [],
        [],
        None,
        None,
    )
    name = resolve_call_name(call)
    assert name == "the_method"


def test_resolve_call_name_call_local():
    call = ast.Call(ast.Local("foo"), [], [], None, None)
    name = resolve_call_name(call)
    assert name == "foo"


def test_resolve_call_name_call_existing_pyobj_str():
    obj = ast.program.Object(None)
    obj.pyobj = "str_func"
    call = ast.Call(ast.Existing(obj), [], [], None, None)
    name = resolve_call_name(call)
    assert name == "str_func"


def test_resolve_call_name_call_existing_no_pyobj():
    obj = ast.program.Object(None)
    call = ast.Call(ast.Existing(obj), [], [], None, None)
    name = resolve_call_name(call)
    assert name is None


def test_resolve_call_name_direct_call_no_code():
    call = ast.DirectCall(None, None, [], [], None, None)
    name = resolve_call_name(call)
    assert name is None


def test_bind_call_arguments_positional_only():
    a = ast.Local("a")
    b = ast.Local("b")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[a],
        posonlynames=["a"],
        params=[b],
        paramnames=["b"],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    arg1 = ast.Local("val1")
    arg2 = ast.Local("val2")
    call = ast.Call(ast.Local("fn"), [arg1, arg2], [], None, None)
    bindings = bind_call_arguments(call, params)
    actual_to_formal = {a: f for a, f in bindings}
    assert actual_to_formal[arg1] == a
    assert actual_to_formal[arg2] == b


def test_bind_call_arguments_selfarg():
    self_param = ast.Local("self")
    params = ast.CodeParameters(
        selfparam=self_param,
        posonlyparams=[],
        posonlynames=[],
        params=[],
        paramnames=[],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    self_expr = ast.Local("self")
    call = ast.DirectCall(None, self_expr, [], [], None, None)
    bindings = bind_call_arguments(call, params)
    actual_to_formal = {a: f for a, f in bindings}
    assert actual_to_formal[self_expr] == self_param


def test_bind_call_arguments_keyword():
    a = ast.Local("a")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[a],
        paramnames=["a"],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    kw_val = ast.Local("kw_val")
    call = ast.Call(ast.Local("fn"), [], [("a", kw_val)], None, None)
    bindings = bind_call_arguments(call, params)
    actual_to_formal = {arg: f for arg, f in bindings}
    assert actual_to_formal[kw_val] == a


def test_bind_call_arguments_extra_kwargs():
    kparam = ast.Local("kwargs")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[],
        paramnames=[],
        defaults=[],
        vparam=None,
        kparam=kparam,
        returnparams=[],
        type_params=None,
    )
    kw_val = ast.Local("extra")
    call = ast.Call(ast.Local("fn"), [], [("unknown", kw_val)], None, None)
    bindings = bind_call_arguments(call, params)
    actual_to_formal = {arg: f for arg, f in bindings}
    assert actual_to_formal[kw_val] == kparam


def test_bind_call_arguments_default_values():
    a = ast.Local("a")
    default_val = ast.Existing(ast.program.Object(42))
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[a],
        paramnames=["a"],
        defaults=(default_val,),
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    call = ast.Call(ast.Local("fn"), [], [], None, None)
    bindings = bind_call_arguments(call, params)
    actual_to_formal = {arg: f for arg, f in bindings}
    assert actual_to_formal[default_val] == a


def test_actual_parameters_without_params():
    a = ast.Local("a")
    call = ast.Call(ast.Local("fn"), [a], [], None, None)
    params = actual_parameters(call)
    assert a in params


def test_actual_parameters_non_local_args():
    call = ast.Call(ast.Local("fn"), [ast.Existing(ast.program.Object(1))], [], None, None)
    params = actual_parameters(call)
    assert len(params) == 0


def test_actual_parameters_with_params():
    a = ast.Local("a")
    b = ast.Local("b")
    code_params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[a, b],
        paramnames=["a", "b"],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    arg1 = ast.Local("arg1")
    arg2 = ast.Local("arg2")
    call = ast.Call(ast.Local("fn"), [arg1, arg2], [], None, None)
    params = actual_parameters(call, code_params)
    assert arg1 in params
    assert arg2 in params


def test_actual_parameters_selfarg_with_params():
    self_param = ast.Local("self")
    code_params = ast.CodeParameters(
        selfparam=self_param,
        posonlyparams=[],
        posonlynames=[],
        params=[],
        paramnames=[],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    self_expr = ast.Local("self")
    call = ast.DirectCall(None, self_expr, [], [], None, None)
    params = actual_parameters(call, code_params)
    assert self_expr in params
