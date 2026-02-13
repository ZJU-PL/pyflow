"""
Stub Manager for handling stub functions and built-in operations.

This module manages the creation and handling of stub functions
for built-in Python operations and interpreter functions.
"""

import operator

from pyflow.language.python import ast as pyflow_ast


# Expose makeStubs at module scope so tests can patch it directly.
#
# The decompilation-based stub pipeline has been removed from the frontend.
# The frontend now uses minimal, side-effect free stubs by default.
def makeStubs(compiler):
    raise NotImplementedError(
        "Legacy stub collection requires the removed decompilation frontend; "
        "use StubManager's minimal stubs."
    )


class StubManager:
    """Manages stub functions for built-in operations."""

    def __init__(self, compiler):
        self.compiler = compiler
        self.stubs = self._create_stubs()

    def _create_stubs(self):
        """Create stub functions for built-in operations."""
        return self._create_minimal_stubs()

    def _create_minimal_stubs(self):
        """Create minimal stub functions as fallback.

        These stubs include lightweight dynamic folding so arithmetic and
        comparison operators still propagate concrete return types during
        analysis. The goal is to keep the fallback fast while maintaining
        enough fidelity for downstream tests.
        """

        def params_for(op_name):
            """Return CodeParameters tailored to the stub signature."""
            # Most interpreter_* operations are binary; interpreter_call accepts vargs/kargs.
            if op_name == "interpreter_call":
                return pyflow_ast.CodeParameters(
                    None,
                    [pyflow_ast.Local("func")],
                    [],
                    [],
                    pyflow_ast.Local("vargs"),
                    pyflow_ast.Local("kargs"),
                    [pyflow_ast.Local("internal_return")],
                )

            if op_name in ("convertToBool", "invertedConvertToBool"):
                return pyflow_ast.CodeParameters(
                    None,
                    [pyflow_ast.Local("x")],
                    [],
                    [],
                    None,
                    None,
                    [pyflow_ast.Local("internal_return")],
                )

            if op_name in (
                "interpreter__neg__",
                "interpreter__pos__",
                "interpreter__invert__",
            ):
                return pyflow_ast.CodeParameters(
                    None,
                    [pyflow_ast.Local("a")],
                    [],
                    [],
                    None,
                    None,
                    [pyflow_ast.Local("internal_return")],
                )

            if op_name == "interpreter_setattr":
                return pyflow_ast.CodeParameters(
                    None,
                    [
                        pyflow_ast.Local("obj"),
                        pyflow_ast.Local("name"),
                        pyflow_ast.Local("value"),
                    ],
                    [],
                    [],
                    None,
                    None,
                    [pyflow_ast.Local("internal_return")],
                )

            if op_name == "interpreter_setitem":
                return pyflow_ast.CodeParameters(
                    None,
                    [
                        pyflow_ast.Local("obj"),
                        pyflow_ast.Local("subscript"),
                        pyflow_ast.Local("value"),
                    ],
                    [],
                    [],
                    None,
                    None,
                    [pyflow_ast.Local("internal_return")],
                )

            if op_name == "interpreter_ifexp":
                return pyflow_ast.CodeParameters(
                    None,
                    [
                        pyflow_ast.Local("cond"),
                        pyflow_ast.Local("t"),
                        pyflow_ast.Local("f"),
                    ],
                    [],
                    [],
                    None,
                    None,
                    [pyflow_ast.Local("internal_return")],
                )

            # Default to two positional params so binary ops bind correctly.
            return pyflow_ast.CodeParameters(
                None,
                [pyflow_ast.Local("a"), pyflow_ast.Local("b")],
                [],
                [],
                None,
                None,
                [pyflow_ast.Local("internal_return")],
            )

        # Map stub names to simple Python callables used for dynamic folding.
        dynfold = {
            "interpreter_getattribute": getattr,
            "interpreter_setattr": setattr,
            "interpreter__mul__": operator.mul,
            "interpreter__add__": operator.add,
            "interpreter__sub__": operator.sub,
            "interpreter__div__": operator.truediv,
            "interpreter__mod__": operator.mod,
            "interpreter__pow__": operator.pow,
            "interpreter__and__": operator.and_,
            "interpreter__or__": operator.or_,
            "interpreter__xor__": operator.xor,
            "interpreter__lshift__": operator.lshift,
            "interpreter__rshift__": operator.rshift,
            "interpreter__floordiv__": operator.floordiv,
            "interpreter__eq__": operator.eq,
            "interpreter__ne__": operator.ne,
            "interpreter__lt__": operator.lt,
            "interpreter__le__": operator.le,
            "interpreter__gt__": operator.gt,
            "interpreter__ge__": operator.ge,
            "interpreter__is__": operator.is_,
            "interpreter__is_not__": operator.is_not,
            "interpreter__contains__": operator.contains,
            "interpreter__neg__": operator.neg,
            "interpreter__pos__": operator.pos,
            "interpreter__invert__": operator.invert,
            "interpreter_getitem": operator.getitem,
            "interpreter_setitem": operator.setitem,
            "interpreter_delitem": operator.delitem,
            "interpreter_call": lambda func, *args, **kwargs: func(*args, **kwargs),
            "interpreter_booland": lambda a, b: a and b,
            "interpreter_boolor": lambda a, b: a or b,
            "interpreter_ifexp": lambda cond, t, f: t if cond else f,
            "object__getattribute__": getattr,
            "convertToBool": bool,
            "invertedConvertToBool": lambda x: not bool(x),
        }

        def create_stub_code(name):
            # Create a minimal code object that satisfies the type requirements
            params = params_for(name)
            body = pyflow_ast.Suite([])
            code = pyflow_ast.Code(name, params, body)
            dyn_fold = dynfold.get(name)
            code.annotation = type(
                "Annotation",
                (),
                {
                    "origin": [f"stub_{name}"],
                    "interpreter": True,
                    "runtime": False,
                    "staticFold": None,
                    "dynamicFold": dyn_fold,
                    "primitive": False,
                    "descriptive": False,
                },
            )()
            return code

        return type(
            "Stubs",
            (),
            {
                "exports": {
                    "interpreter_getattribute": create_stub_code(
                        "interpreter_getattribute"
                    ),
                    "interpreter_setattr": create_stub_code("interpreter_setattr"),
                    "interpreter__mul__": create_stub_code("interpreter__mul__"),
                    "interpreter__add__": create_stub_code("interpreter__add__"),
                    "interpreter__sub__": create_stub_code("interpreter__sub__"),
                    "interpreter__div__": create_stub_code("interpreter__div__"),
                    "interpreter__mod__": create_stub_code("interpreter__mod__"),
                    "interpreter__pow__": create_stub_code("interpreter__pow__"),
                    "interpreter__and__": create_stub_code("interpreter__and__"),
                    "interpreter__or__": create_stub_code("interpreter__or__"),
                    "interpreter__xor__": create_stub_code("interpreter__xor__"),
                    "interpreter__lshift__": create_stub_code("interpreter__lshift__"),
                    "interpreter__rshift__": create_stub_code("interpreter__rshift__"),
                    "interpreter__floordiv__": create_stub_code(
                        "interpreter__floordiv__"
                    ),
                    "interpreter__eq__": create_stub_code("interpreter__eq__"),
                    "interpreter__ne__": create_stub_code("interpreter__ne__"),
                    "interpreter__lt__": create_stub_code("interpreter__lt__"),
                    "interpreter__le__": create_stub_code("interpreter__le__"),
                    "interpreter__gt__": create_stub_code("interpreter__gt__"),
                    "interpreter__ge__": create_stub_code("interpreter__ge__"),
                    "interpreter__is__": create_stub_code("interpreter__is__"),
                    "interpreter__is_not__": create_stub_code("interpreter__is_not__"),
                    "interpreter__contains__": create_stub_code(
                        "interpreter__contains__"
                    ),
                    "interpreter__neg__": create_stub_code("interpreter__neg__"),
                    "interpreter__pos__": create_stub_code("interpreter__pos__"),
                    "interpreter__invert__": create_stub_code("interpreter__invert__"),
                    "interpreter_getitem": create_stub_code("interpreter_getitem"),
                    "interpreter_setitem": create_stub_code("interpreter_setitem"),
                    "interpreter_delitem": create_stub_code("interpreter_delitem"),
                    "interpreter_call": create_stub_code("interpreter_call"),
                    "interpreter_booland": create_stub_code("interpreter_booland"),
                    "interpreter_boolor": create_stub_code("interpreter_boolor"),
                    "interpreter_ifexp": create_stub_code("interpreter_ifexp"),
                    "convertToBool": create_stub_code("convertToBool"),
                    "invertedConvertToBool": create_stub_code("invertedConvertToBool"),
                    "object__getattribute__": create_stub_code(
                        "object__getattribute__"
                    ),
                    "object__setattribute__": create_stub_code(
                        "object__setattribute__"
                    ),
                    "object__call__": create_stub_code("object__call__"),
                    "function__get__": create_stub_code("function__get__"),
                    "function__call__": create_stub_code("function__call__"),
                    "method__get__": create_stub_code("method__get__"),
                    "method__call__": create_stub_code("method__call__"),
                    "methoddescriptor__get__": create_stub_code(
                        "methoddescriptor__get__"
                    ),
                    "methoddescriptor__call__": create_stub_code(
                        "methoddescriptor__call__"
                    ),
                }
            },
        )()
