"""AST-only module indexing primitives used by dependency resolution."""

from __future__ import annotations

import ast
import inspect
from dataclasses import dataclass
from typing import Any, Iterable, Optional


@dataclass(frozen=True)
class FakeCode:
    """Minimal code-object metadata needed by source-based extraction."""

    co_filename: str
    co_firstlineno: int


class ASTFunctionProxy:
    """Callable metadata proxy that never executes analyzed source."""

    def __init__(
        self,
        *,
        name: str,
        qualname: str,
        module: str,
        filename: str,
        firstlineno: int,
        signature: Optional[inspect.Signature],
        docstring: Optional[str] = None,
        decorators: Optional[list[str]] = None,
        is_async: bool = False,
        is_class_method: bool = False,
        type_hints: Optional[dict[str, Any]] = None,
    ):
        self.__name__ = name
        self.__qualname__ = qualname
        self.__module__ = module
        self.__code__ = FakeCode(filename, firstlineno)
        if signature is not None:
            self.__signature__ = signature
        self.__doc__ = docstring
        self._decorators = decorators or []
        self._is_async = is_async
        self._is_class_method = is_class_method
        self._type_hints = type_hints or {}

    def __call__(self, *args, **kwargs):
        return None


def iter_toplevel_function_nodes(tree: ast.AST) -> Iterable[ast.AST]:
    for node in getattr(tree, "body", ()) or ():
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def iter_toplevel_class_nodes(tree: ast.AST) -> Iterable[ast.ClassDef]:
    for node in getattr(tree, "body", ()) or ():
        if isinstance(node, ast.ClassDef):
            yield node


def extract_docstring(node: ast.AST) -> Optional[str]:
    return ast.get_docstring(node, clean=False)


def extract_decorator_names(node: ast.AST) -> list[str]:
    decorators: list[str] = []
    for decorator in getattr(node, "decorator_list", ()) or ():
        expression = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(expression, ast.Name):
            decorators.append(expression.id)
            continue
        if isinstance(expression, ast.Attribute):
            parts: list[str] = []
            current: ast.AST = expression
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            decorators.append(".".join(reversed(parts)))
    return decorators


def is_property_decorator(name: str) -> bool:
    tail = name.rsplit(".", 1)[-1].lower()
    return tail in {"property", "cached_property", "abstractproperty"}


def signature_from_ast(args: ast.arguments) -> inspect.Signature:
    parameters: list[inspect.Parameter] = []

    def add_parameter(
        name: str,
        kind: inspect._ParameterKind,
        default: Any = inspect._empty,
    ) -> None:
        parameters.append(inspect.Parameter(name, kind, default=default))

    posonly = list(getattr(args, "posonlyargs", ()) or ())
    regular = list(getattr(args, "args", ()) or ())
    kwonly = list(getattr(args, "kwonlyargs", ()) or ())
    positional = [*posonly, *regular]
    defaults = list(getattr(args, "defaults", ()) or ())
    default_start = len(positional) - len(defaults)

    for index, argument in enumerate(posonly):
        default = inspect._empty
        if defaults and index >= default_start:
            try:
                default = ast.literal_eval(defaults[index - default_start])
            except Exception:
                default = None
        add_parameter(argument.arg, inspect.Parameter.POSITIONAL_ONLY, default)

    for index, argument in enumerate(regular):
        default = inspect._empty
        position = len(posonly) + index
        if defaults and position >= default_start:
            try:
                default = ast.literal_eval(defaults[position - default_start])
            except Exception:
                default = None
        add_parameter(
            argument.arg, inspect.Parameter.POSITIONAL_OR_KEYWORD, default
        )

    if args.vararg is not None:
        add_parameter(args.vararg.arg, inspect.Parameter.VAR_POSITIONAL)

    kw_defaults = list(getattr(args, "kw_defaults", ()) or ())
    for index, argument in enumerate(kwonly):
        default = inspect._empty
        if index < len(kw_defaults) and kw_defaults[index] is not None:
            try:
                default = ast.literal_eval(kw_defaults[index])
            except Exception:
                default = None
        add_parameter(argument.arg, inspect.Parameter.KEYWORD_ONLY, default)

    if args.kwarg is not None:
        add_parameter(args.kwarg.arg, inspect.Parameter.VAR_KEYWORD)

    return inspect.Signature(parameters)


__all__ = [
    "ASTFunctionProxy",
    "FakeCode",
    "extract_decorator_names",
    "extract_docstring",
    "is_property_decorator",
    "iter_toplevel_class_nodes",
    "iter_toplevel_function_nodes",
    "signature_from_ast",
]
