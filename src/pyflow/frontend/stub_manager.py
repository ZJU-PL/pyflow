"""
Stub Manager for handling stub functions and built-in operations.

This module manages the creation and handling of stub functions
for built-in Python operations and interpreter functions.
"""

from pyflow.language.python import ast as pyflow_ast


class StubManager:
    """Manages stub functions for built-in operations."""

    def __init__(self, compiler):
        self.compiler = compiler
        self.stubs = self._create_stubs()

    def _create_stubs(self):
        """Create stub functions for built-in operations."""
        try:
            from pyflow.stubs.stubcollector import makeStubs
            return makeStubs(self.compiler)
        except Exception as e:
            # Fallback to minimal stubs if full system fails
            return self._create_minimal_stubs()

    def _create_minimal_stubs(self):
        """Create minimal stub functions as fallback."""
        def create_stub_code(name):
            # Create a minimal code object that satisfies the type requirements
            params = pyflow_ast.CodeParameters(
                None, [], [], [], None, None, [pyflow_ast.Local("internal_return")]
            )
            body = pyflow_ast.Suite([])
            code = pyflow_ast.Code(name, params, body)
            code.annotation = type(
                "Annotation",
                (),
                {
                    "origin": [f"stub_{name}"],
                    "interpreter": True,
                    "runtime": False,
                    "staticFold": None,
                    "dynamicFold": None,
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
                    "interpreter_getattribute": create_stub_code("interpreter_getattribute"),
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
                    "interpreter__floordiv__": create_stub_code("interpreter__floordiv__"),
                    "interpreter__eq__": create_stub_code("interpreter__eq__"),
                    "interpreter__ne__": create_stub_code("interpreter__ne__"),
                    "interpreter__lt__": create_stub_code("interpreter__lt__"),
                    "interpreter__le__": create_stub_code("interpreter__le__"),
                    "interpreter__gt__": create_stub_code("interpreter__gt__"),
                    "interpreter__ge__": create_stub_code("interpreter__ge__"),
                    "interpreter_getitem": create_stub_code("interpreter_getitem"),
                    "interpreter_call": create_stub_code("interpreter_call"),
                    "object__getattribute__": create_stub_code("object__getattribute__"),
                    "object__setattribute__": create_stub_code("object__setattribute__"),
                    "object__call__": create_stub_code("object__call__"),
                    "function__get__": create_stub_code("function__get__"),
                    "function__call__": create_stub_code("function__call__"),
                    "method__get__": create_stub_code("method__get__"),
                    "method__call__": create_stub_code("method__call__"),
                    "methoddescriptor__get__": create_stub_code("methoddescriptor__get__"),
                    "methoddescriptor__call__": create_stub_code("methoddescriptor__call__"),
                }
            },
        )()
