"""Compiler protocol calls whose effects are bounded under primitive assumptions."""

from pyflow.language.python import ast

PRIMITIVE_INTRINSICS = frozenset(
    f"interpreter__{operator}__"
    for operator in (
        "add",
        "sub",
        "mul",
        "truediv",
        "floordiv",
        "mod",
        "pow",
        "and",
        "or",
        "xor",
        "lshift",
        "rshift",
        "lt",
        "le",
        "eq",
        "ne",
        "gt",
        "ge",
        "pos",
        "neg",
        "invert",
        "contains",
    )
) | frozenset(
    {
        "interpreter_getitem",
        "interpreter_setitem",
        "interpreter_delitem",
        "interpreter_getattr",
        "interpreter_getattribute",
        "interpreter_setattr",
        "interpreter_delattr",
        "interpreter_bool",
        "interpreter_len",
    }
)


def has_bounded_effects(call):
    if not isinstance(call, ast.Call):
        return False
    callee = call.expr
    if isinstance(callee, ast.Existing):
        name = getattr(callee.object, "pyobj", None)
        return name in PRIMITIVE_INTRINSICS if isinstance(name, str) else name is isinstance
    if isinstance(callee, ast.GetGlobal):
        return getattr(callee.name.object, "pyobj", None) == "isinstance"
    return False
