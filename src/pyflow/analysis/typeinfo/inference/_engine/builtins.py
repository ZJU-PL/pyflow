"""Model builtin calls and methods on builtin values."""

from __future__ import annotations

import ast
import asyncio
import builtins
import collections
import collections.abc as cabc
import concurrent.futures
import contextlib
import contextvars
import datetime
import io
import logging
import os
import queue
import re
import subprocess
import threading
import zipfile
from dataclasses import replace

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NEVER,
    NONE_TYPE,
    CallableType,
    Instance,
    NoneType,
    ProperType,
    TupleType,
    TypeType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference._engine.component import InferenceComponent
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue, join_all
from pyflow.analysis.typeinfo.resolution.typing_syntax import substitute_type_vars

# Methods whose results are joined across receiver union alternatives.
_UNION_JOIN_METHODS = frozenset(
    {
        "copy",
        "count",
        "index",
        "get",
        "keys",
        "values",
        "items",
        "union",
        "intersection",
        "difference",
        "symmetric_difference",
        "issubset",
        "issuperset",
        "isdisjoint",
        "decode",
        "encode",
        "hex",
        "upper",
        "lower",
        "strip",
        "lstrip",
        "rstrip",
        "split",
        "rsplit",
        "splitlines",
        "replace",
        "startswith",
        "endswith",
        "find",
        "rfind",
        "join",
        "format",
        "title",
        "capitalize",
        "casefold",
        "center",
        "ljust",
        "rjust",
        "zfill",
        "removeprefix",
        "removesuffix",
        "partition",
        "rpartition",
        "swapcase",
        "translate",
        "expandtabs",
        "isalnum",
        "isalpha",
        "isdecimal",
        "isdigit",
        "isidentifier",
        "islower",
        "isnumeric",
        "isprintable",
        "isspace",
        "istitle",
        "isupper",
    }
)


class BuiltinInference(InferenceComponent):
    """Model builtin calls and methods on builtin values."""

    def _call_builtin(
        self,
        name: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        *,
        call_node: ast.Call | None = None,
    ) -> AbstractTypeValue | None:
        if name == "open":
            mode = "r"
            if call_node is not None:
                mode_node: ast.expr | None = call_node.args[1] if len(call_node.args) > 1 else None
                if mode_node is None:
                    mode_node = next(
                        (kw.value for kw in call_node.keywords if kw.arg == "mode"),
                        None,
                    )
                if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
                    mode = mode_node.value
            return self.engine._value_rules._instance(
                io.BufferedIOBase if "b" in mode else io.TextIOWrapper
            )

        if name in {"staticmethod", "classmethod"} and arguments:
            # An explicit ``x = staticmethod(f)`` class attribute is exposed
            # as the wrapped callable when accessed through the class.
            return arguments[0]
        constructors: dict[str, type] = {
            "bool": bool,
            "bytes": bytes,
            "complex": complex,
            "dict": dict,
            "float": float,
            "frozenset": frozenset,
            "int": int,
            "list": list,
            "object": object,
            "set": set,
            "str": str,
            "tuple": tuple,
        }
        if name in constructors:
            raw = constructors[name]
            if raw in {list, set, frozenset, tuple} and arguments:
                element = (
                    self.engine._value_rules._iterable_element(arguments[0]).public_type() or ANY
                )
                if raw is tuple:
                    return AbstractTypeValue.from_type(TupleType((element,), unknown_size=True))
                result = self.engine._value_rules._instance(raw, element)
                if raw is list and arguments[0].element_dict_shapes:
                    result = replace(
                        result,
                        element_dict_shapes=arguments[0].element_dict_shapes,
                    )
                return result
            if raw is tuple:
                return AbstractTypeValue.from_type(TupleType(()))
            if raw in {list, set, frozenset}:
                return self.engine._value_rules._instance(raw, NEVER)
            if raw is dict:
                if keywords:
                    value = join_all(
                        (
                            AbstractTypeValue.from_type(
                                self.engine._compatibility_rules._runtime_value_type(keyword_value)
                            )
                            for keyword_value in keywords.values()
                        ),
                        self.engine.type_system,
                        max_union_size=self.engine.options.max_union_size,
                    )
                    return self.engine._value_rules._instance(
                        dict,
                        self.engine._value_rules._proper_instance(str),
                        value.public_type() or ANY,
                    )
                if arguments:
                    for typ in arguments[0].types:
                        if not isinstance(typ, Instance):
                            continue
                        raw_type = typ.type.raw_type
                        if (
                            isinstance(raw_type, type)
                            and issubclass(raw_type, dict)
                            and len(typ.args) >= 2
                        ):
                            return AbstractTypeValue.from_type(typ)
                        if (
                            typ.type.full_name
                            in {
                                "collections.abc.Mapping",
                                "collections.abc.MutableMapping",
                                "typing.Mapping",
                                "typing.MutableMapping",
                            }
                            and len(typ.args) >= 2
                        ):
                            return self.engine._value_rules._instance(
                                dict, typ.args[0], typ.args[1]
                            )
                    element = self.engine._value_rules._iterable_element(arguments[0])
                    for typ in element.types:
                        if isinstance(typ, TupleType) and len(typ.args) >= 2:
                            return self.engine._value_rules._instance(
                                dict, typ.args[0], typ.args[1]
                            )
                        if isinstance(typ, Instance) and typ.type.raw_type is dict:
                            return AbstractTypeValue.from_type(typ)
                    return self.engine._value_rules._instance(dict, ANY, ANY)
                return self.engine._value_rules._instance(dict, NEVER, NEVER)
            return self.engine._value_rules._instance(raw)
        if name in {"len", "hash", "id", "ord"}:
            return self.engine._value_rules._instance(int)
        if name in {"all", "any", "callable", "hasattr", "isinstance", "issubclass"}:
            return self.engine._value_rules._instance(bool)
        if name in {"repr", "ascii", "format", "chr", "input"}:
            return self.engine._value_rules._instance(str)
        if name == "abs" and arguments:
            if self.engine._operator_rules._all_bool_values(arguments[0]):
                return self.engine._value_rules._instance(int)
            if self.engine._operator_rules._contains_any(arguments[0]):
                return AbstractTypeValue.from_type(ANY)
            if any(
                isinstance(part, Instance) and part.type.raw_type is complex
                for part in arguments[0].types
            ):
                return self.engine._value_rules._instance(float)
            numeric = self.engine._operator_rules._numeric_join((arguments[0],))
            return numeric if numeric.public_type() is not None else AbstractTypeValue.unresolved()
        if name == "round" and arguments:
            ndigits = arguments[1] if len(arguments) > 1 else keywords.get("ndigits")
            if ndigits is not None and not (
                ndigits.types and all(isinstance(part, NoneType) for part in ndigits.types)
            ):
                return self.engine._value_rules._instance(float)
            return self.engine._value_rules._instance(int)
        if name == "divmod" and len(arguments) >= 2:
            numeric = self.engine._operator_rules._numeric_join(arguments[:2])
            if numeric.public_type() is None:
                return AbstractTypeValue.unresolved()
            return AbstractTypeValue.from_type(
                TupleType((numeric.public_type() or ANY, numeric.public_type() or ANY))
            )
        if name == "pow" and len(arguments) >= 2:
            if len(arguments) >= 3:
                numeric = self.engine._operator_rules._numeric_join(arguments[:2])
                return (
                    numeric if numeric.public_type() is not None else AbstractTypeValue.unresolved()
                )
            return self.engine._operator_rules._pow_result(arguments[0], arguments[1])
        if name == "getattr" and len(arguments) >= 2:
            if (
                call_node is not None
                and len(call_node.args) >= 2
                and isinstance(call_node.args[1], ast.Constant)
                and isinstance(call_node.args[1].value, str)
            ):
                result = self.engine._member_rules._attribute_value(
                    arguments[0], call_node.args[1].value
                )
                if len(arguments) >= 3:
                    return self.engine._value_rules._join(result, arguments[2])
                return result
            return AbstractTypeValue.unresolved()
        if name == "vars" and arguments:
            return self.engine._value_rules._instance(
                dict, self.engine._value_rules._proper_instance(str), ANY
            )
        if name == "range":
            return self.engine._value_rules._instance(range)
        if name == "iter":
            if len(arguments) > 1:
                callable_return = self.engine._value_rules._callable_return_type(arguments[0])
                return self.engine._value_rules._instance(
                    cabc.Iterator, callable_return.public_type() or ANY
                )
            iterator_element = (
                self.engine._value_rules._iterable_element(arguments[0])
                if arguments
                else AbstractTypeValue.unresolved()
            )
            return self.engine._value_rules._instance(
                cabc.Iterator, iterator_element.public_type() or ANY
            )
        if name == "reversed":
            reversed_element = (
                self.engine._value_rules._iterable_element(arguments[0])
                if arguments
                else AbstractTypeValue.unresolved()
            )
            return self.engine._value_rules._instance(
                cabc.Iterator, reversed_element.public_type() or ANY
            )
        if name == "filter":
            filtered_element = (
                self.engine._value_rules._iterable_element(arguments[1])
                if len(arguments) > 1
                else AbstractTypeValue.unresolved()
            )
            if (
                call_node is not None
                and len(call_node.args) > 1
                and isinstance(call_node.args[0], ast.Constant)
                and call_node.args[0].value is None
            ):
                filtered_element = filtered_element.without_type(NoneType)
            return self.engine._value_rules._instance(
                cabc.Iterator, filtered_element.public_type() or ANY
            )
        if name == "enumerate":
            enumerated_element = (
                self.engine._value_rules._iterable_element(arguments[0])
                if arguments
                else AbstractTypeValue.unresolved()
            )
            pair = TupleType(
                (
                    self.engine._value_rules._proper_instance(int),
                    enumerated_element.public_type() or ANY,
                )
            )
            return self.engine._value_rules._instance(cabc.Iterator, pair)
        if name == "zip":
            elements = tuple(
                self.engine._value_rules._iterable_element(argument).public_type() or ANY
                for argument in arguments
            )
            return self.engine._value_rules._instance(zip, TupleType(elements))
        if name == "map":
            mapped_element = AbstractTypeValue.unresolved()
            if arguments:
                builtin_targets = [
                    target.removeprefix("builtins.")
                    for target in arguments[0].class_targets
                    if target.startswith("builtins.")
                ]
                builtin_target = next(
                    (
                        getattr(builtins, target)
                        for target in builtin_targets
                        if isinstance(getattr(builtins, target, None), type)
                    ),
                    None,
                )
                if builtin_target is not None:
                    mapped_element = self.engine._value_rules._instance(builtin_target)
                elif (
                    call_node is not None
                    and call_node.args
                    and isinstance(call_node.args[0], ast.Lambda)
                    and len(arguments) > 1
                    and arguments[0].callable_targets
                ):
                    element = self.engine._value_rules._iterable_element(arguments[1])
                    mapped_element = join_all(
                        (
                            self.engine._call_rules._apply_function(target, [element], {})
                            for target in arguments[0].callable_targets
                        ),
                        self.engine.type_system,
                        max_union_size=self.engine.options.max_union_size,
                    )
                else:
                    mapped_element = self.engine._value_rules._callable_return_type(arguments[0])
            return self.engine._value_rules._instance(
                cabc.Iterator, mapped_element.public_type() or ANY
            )
        if name in {"min", "max"} and arguments:
            default = keywords.get("default")
            if len(arguments) == 1:
                result = self.engine._value_rules._iterable_element(arguments[0])
            else:
                result = join_all(
                    arguments,
                    self.engine.type_system,
                    max_union_size=self.engine.options.max_union_size,
                )
            if default is not None:
                if self.engine._value_rules._is_never_value(result) or result.is_bottom:
                    return default
                result = self.engine._value_rules._join(result, default)
            return result
        if name == "next" and arguments:
            if len(arguments) > 1:
                return self.engine._value_rules._join(
                    self.engine._value_rules._iterable_element(arguments[0]), arguments[1]
                )
            return self.engine._value_rules._iterable_element(arguments[0])
        if name == "sum":
            if not arguments:
                return self.engine._value_rules._instance(int)
            element = self.engine._value_rules._iterable_element(arguments[0])
            start = (
                arguments[1]
                if len(arguments) > 1
                else keywords.get("start", self.engine._value_rules._instance(int))
            )
            if self.engine._value_rules._is_never_value(element):
                element = AbstractTypeValue.from_type(NONE_TYPE)
            return self.engine._operator_rules._binary_result(start, element, ast.Add())
        if name == "sorted" and arguments:
            sorted_element = self.engine._value_rules._iterable_element(arguments[0])
            return self.engine._value_rules._instance(list, sorted_element.public_type() or ANY)
        if name == "type":
            if len(arguments) == 1:
                return AbstractTypeValue.from_type(TypeType(arguments[0].public_type() or ANY))
            return self.engine._value_rules._instance(type)
        if name == "open":
            import io as _io

            return self.engine._value_rules._instance(_io.TextIOWrapper)
        return None

    def _call_attribute(
        self,
        node: ast.Attribute,
        base: AbstractTypeValue,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        environment: dict[str, AbstractTypeValue],
        call_node: ast.Call | None = None,
    ) -> AbstractTypeValue | None:
        for target in base.callable_targets:
            if node.attr == "__call__":
                return self.engine._call_rules._apply_function(
                    target, arguments, keywords, node=call_node or node
                )

        native_override = self._native_call_attribute(node, base, arguments, keywords, call_node)
        if native_override is not None:
            return native_override

        union_parts = self.engine._operator_rules._flatten_union_parts(base)
        if len(union_parts) > 1 and node.attr in _UNION_JOIN_METHODS:
            results: list[AbstractTypeValue] = []
            for part in union_parts:
                result = self._call_attribute(
                    node,
                    AbstractTypeValue.from_type(part),
                    arguments,
                    keywords,
                    environment,
                    call_node=call_node,
                )
                if result is not None:
                    results.append(result)
            if results:
                joined = join_all(
                    results,
                    self.engine.type_system,
                    max_union_size=self.engine.options.max_union_size,
                )
                return replace(joined, unknown=joined.unknown or base.unknown)

        for typ in base.types:
            pathlib_class: Instance | None = None
            if isinstance(typ, TypeType) and isinstance(typ.item, Instance):
                pathlib_class = typ.item
            elif isinstance(typ, Instance) and base.class_targets:
                pathlib_class = typ
            if (
                pathlib_class is not None
                and self.engine._value_rules._is_pathlib_type(pathlib_class)
                and node.attr in {"home", "cwd"}
            ):
                return AbstractTypeValue.from_type(pathlib_class)

        for typ in base.types:
            if not isinstance(typ, Instance):
                continue
            class_info = self.engine._classes.get(typ.type.full_name)
            if class_info is None or class_info.instance.type.tuple_fields is None:
                continue
            if node.attr in {"_replace", "_make"}:
                return AbstractTypeValue.from_type(typ)
            if node.attr == "_asdict":
                return self.engine._value_rules._instance(
                    dict, self.engine._value_rules._proper_instance(str), ANY
                )
            if node.attr in {"_fields", "__match_args__"}:
                return AbstractTypeValue.from_type(
                    TupleType((self.engine._value_rules._proper_instance(str),), unknown_size=True)
                )
            if node.attr == "_field_defaults":
                return self.engine._value_rules._instance(
                    dict, self.engine._value_rules._proper_instance(str), ANY
                )

        method_targets: list[str] = []
        for typ in base.types:
            if isinstance(typ, TupleType):
                if node.attr in {"count", "index"}:
                    return self.engine._value_rules._instance(int)
                if node.attr in {"sort", "reverse"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                continue
            if not isinstance(typ, Instance):
                continue
            class_info = self.engine._classes.get(typ.type.full_name)
            if class_info is not None:
                getter = self.engine._member_rules._class_property(
                    class_info.qualified_name, node.attr
                )
                if getter is not None:
                    # ``obj.prop(...)`` calls the property's value, not the
                    # getter function itself.
                    function = self.engine._functions[getter]
                    value = function.explicit_return or (
                        function.summary.return_value
                        if function.summary
                        else AbstractTypeValue.unresolved()
                    )
                    return self.engine._member_rules._call_property_value(
                        value, arguments, keywords, call_node or node
                    )
                method = self.engine._member_rules._class_method(
                    class_info.qualified_name, node.attr
                )
                if method is not None:
                    method_targets.append(method)
            else:
                member = typ.type.members.get(node.attr)
                if isinstance(member, CallableType):
                    substitutions = {
                        parameter.name: argument
                        for parameter, argument in zip(typ.type.type_parameters, typ.args)
                    }
                    if substitutions:
                        member = substitute_type_vars(member, substitutions)
                    selected = self.engine._call_rules._select_callable_overload(member, arguments)
                    return AbstractTypeValue.from_type(
                        selected.return_type if selected is not None else member.return_type
                    )
        if method_targets:
            return join_all(
                [
                    self.engine._call_rules._apply_function(
                        target,
                        self._method_arguments(self.engine._functions[target], base, arguments),
                        keywords,
                        node=call_node or node,
                    )
                    for target in method_targets
                ],
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )

        text_results = [
            result
            for typ in base.types
            if isinstance(typ, Instance)
            if (text_base := self.engine._operator_rules._text_base(typ)) is not None
            if (result := self._model_text_method(text_base, node.attr)) is not None
        ]
        if text_results:
            return join_all(
                text_results,
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )

        numeric_results = [
            result
            for typ in base.types
            if isinstance(typ, Instance)
            if typ.type.raw_type in {int, float}
            if (result := self._model_numeric_method(typ.type.raw_type, node.attr)) is not None
        ]
        if numeric_results:
            return join_all(
                numeric_results,
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )

        for typ in base.types:
            if not isinstance(typ, Instance):
                continue
            original_type = typ.type
            if typ.type.typed_dict_fields is None:
                projected = self.engine._value_rules._builtin_projection(typ)
                if projected is not None:
                    typ = projected
            raw = typ.type.raw_type
            args = typ.args
            if raw is cabc.Generator:
                if node.attr == "send" and args:
                    # Generator[Y, S, R].send() returns the next yielded value.
                    return AbstractTypeValue.from_type(args[0])
                if node.attr == "throw" and args:
                    return AbstractTypeValue.from_type(args[0])
                if node.attr == "close":
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is cabc.AsyncGenerator:
                if node.attr == "asend" and args:
                    return self.engine._value_rules._instance(cabc.Coroutine, ANY, ANY, args[0])
                if node.attr == "athrow" and args:
                    return self.engine._value_rules._instance(cabc.Coroutine, ANY, ANY, args[0])
                if node.attr == "aclose":
                    return self.engine._value_rules._instance(cabc.Coroutine, ANY, ANY, NONE_TYPE)
            if isinstance(raw, type) and issubclass(raw, io.IOBase):
                if node.attr == "__enter__":
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"__exit__", "close", "flush", "writelines"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"seek", "tell", "fileno"}:
                    return self.engine._value_rules._instance(int)
                if node.attr == "name":
                    return self.engine._value_rules._instance(str)
                if node.attr == "mode":
                    return self.engine._value_rules._instance(str)
                if node.attr == "encoding":
                    return self.engine._value_rules._join(
                        AbstractTypeValue.from_type(self.engine._value_rules._instance(str)),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                is_binary = issubclass(raw, (io.BufferedIOBase, io.RawIOBase))
                is_text = issubclass(raw, io.TextIOBase)
                if node.attr in {"read", "readline"}:
                    if is_binary:
                        return self.engine._value_rules._instance(bytes)
                    if is_text:
                        return self.engine._value_rules._instance(str)
                    # ``io.IOBase.read`` is overridden by both text and binary
                    # subclasses, so typeshed leaves it unconstrained.  The
                    # line-oriented methods default to binary on the base.
                    if node.attr == "read":
                        return AbstractTypeValue.from_type(ANY)
                    return self.engine._value_rules._instance(bytes)
                if node.attr == "readlines":
                    if is_text:
                        element = self.engine._value_rules._proper_instance(str)
                    else:
                        element = self.engine._value_rules._proper_instance(bytes)
                    return self.engine._value_rules._instance(list, element)
                if node.attr in {"readinto", "write"}:
                    return self.engine._value_rules._instance(int if node.attr == "write" else int)
            if self.engine._value_rules._is_pathlib_type(typ):
                if node.attr == "open":
                    mode = "r"
                    if call_node is not None:
                        mode_node = (
                            call_node.args[0]
                            if call_node.args
                            else next(
                                (
                                    keyword.value
                                    for keyword in call_node.keywords
                                    if keyword.arg == "mode"
                                ),
                                None,
                            )
                        )
                        if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
                            mode = mode_node.value
                    return self.engine._value_rules._instance(
                        io.BufferedIOBase if "b" in mode else io.TextIOWrapper
                    )
                if node.attr == "read_text":
                    return self.engine._value_rules._instance(str)
                if node.attr == "read_bytes":
                    return self.engine._value_rules._instance(bytes)
                if node.attr in {"write_text", "write_bytes"}:
                    return self.engine._value_rules._instance(int)
                if node.attr in {
                    "exists",
                    "is_file",
                    "is_dir",
                    "is_symlink",
                    "is_absolute",
                    "is_relative_to",
                    "match",
                    "samefile",
                    "is_mount",
                    "is_socket",
                    "is_fifo",
                    "is_block_device",
                    "is_char_device",
                }:
                    return self.engine._value_rules._instance(bool)
                if node.attr in {"stat", "lstat"}:
                    return self.engine._value_rules._instance(os.stat_result)
                if node.attr in {"owner", "group", "as_uri"}:
                    return self.engine._value_rules._instance(str)
                if node.attr == "readlink":
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"iterdir", "glob", "rglob"}:
                    return self.engine._value_rules._instance(cabc.Iterator, typ)
                if node.attr == "walk":
                    return self.engine._value_rules._instance(
                        cabc.Iterator,
                        TupleType(
                            (
                                typ,
                                self.engine._value_rules._proper_instance(
                                    list, self.engine._value_rules._proper_instance(str)
                                ),
                                self.engine._value_rules._proper_instance(
                                    list, self.engine._value_rules._proper_instance(str)
                                ),
                            )
                        ),
                    )
                if node.attr in {
                    "resolve",
                    "absolute",
                    "expanduser",
                    "with_name",
                    "with_suffix",
                    "with_stem",
                    "joinpath",
                    "relative_to",
                    "rename",
                    "replace",
                }:
                    return AbstractTypeValue.from_type(typ)
                if node.attr == "open":
                    mode = "r"
                    if call_node is not None:
                        mode_node = call_node.args[0] if call_node.args else None
                        if mode_node is None:
                            mode_node = next(
                                (
                                    keyword.value
                                    for keyword in call_node.keywords
                                    if keyword.arg == "mode"
                                ),
                                None,
                            )
                        if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
                            mode = mode_node.value
                    return self.engine._value_rules._instance(
                        io.BufferedIOBase if "b" in mode else io.TextIOWrapper
                    )
                if node.attr in {
                    "mkdir",
                    "touch",
                    "unlink",
                    "rmdir",
                    "chmod",
                    "symlink_to",
                    "hardlink_to",
                    "write_text",
                }:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is datetime.datetime:
                if node.attr == "date":
                    return self.engine._value_rules._instance(datetime.date)
                if node.attr in {"time", "timetz"}:
                    return self.engine._value_rules._instance(datetime.time)
                if node.attr == "tzinfo":
                    return self.engine._value_rules._join(
                        self.engine._value_rules._instance(datetime.tzinfo),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr == "timestamp":
                    return self.engine._value_rules._instance(float)
                if node.attr in {"isoformat", "strftime", "ctime"}:
                    return self.engine._value_rules._instance(str)
                if node.attr == "utcoffset":
                    return self.engine._value_rules._join(
                        self.engine._value_rules._instance(datetime.timedelta),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr in {"weekday", "isoweekday"}:
                    return self.engine._value_rules._instance(int)
                if node.attr in {"replace", "astimezone", "fromisoformat"}:
                    return AbstractTypeValue.from_type(typ)
            if raw is datetime.date:
                if node.attr in {"isoformat", "strftime", "ctime"}:
                    return self.engine._value_rules._instance(str)
                if node.attr in {"weekday", "isoweekday"}:
                    return self.engine._value_rules._instance(int)
                if node.attr in {
                    "replace",
                    "today",
                    "fromtimestamp",
                    "fromisoformat",
                    "fromordinal",
                }:
                    return AbstractTypeValue.from_type(typ)
            if raw is datetime.timedelta:
                if node.attr == "total_seconds":
                    return self.engine._value_rules._instance(float)
            if raw is collections.deque:
                collection_element = AbstractTypeValue.from_type(args[0] if args else ANY)
                if node.attr in {"append", "appendleft", "extend", "extendleft"}:
                    if arguments:
                        added = (
                            arguments[-1]
                            if node.attr in {"append", "appendleft"}
                            else self.engine._value_rules._iterable_element(arguments[0])
                        )
                        widened = self.engine._value_rules._join(collection_element, added)
                        updated = AbstractTypeValue.from_type(
                            Instance(original_type, (widened.public_type() or ANY,))
                        )
                        self.engine._flow_rules._update_environment_receiver(
                            environment, node.value, updated
                        )
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"pop", "popleft"}:
                    return collection_element
                if node.attr == "copy":
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"count", "index"}:
                    return self.engine._value_rules._instance(int)
                if node.attr in {"clear", "rotate", "reverse", "remove"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is list or raw is set:
                collection_element = AbstractTypeValue.from_type(args[0] if args else ANY)
                if node.attr in {"sort", "reverse"} and raw is list:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if (raw is list and node.attr in {"append", "insert"}) or (
                    raw is set and node.attr == "add"
                ):
                    if arguments:
                        widened = self.engine._value_rules._join(collection_element, arguments[-1])
                        updated = AbstractTypeValue.from_type(
                            Instance(original_type, (widened.public_type() or ANY,))
                        )
                        updated = self.engine._value_rules._augment_element_shapes(
                            updated, arguments[-1]
                        )
                        self.engine._flow_rules._update_environment_receiver(
                            environment, node.value, updated
                        )
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if (raw is list and node.attr == "extend") or (
                    raw is set and node.attr == "update"
                ):
                    if arguments:
                        added = self.engine._value_rules._iterable_element(arguments[0])
                        widened = self.engine._value_rules._join(collection_element, added)
                        updated = AbstractTypeValue.from_type(
                            Instance(original_type, (widened.public_type() or ANY,))
                        )
                        updated = self.engine._value_rules._augment_element_shapes(
                            updated, arguments[0]
                        )
                        self.engine._flow_rules._update_environment_receiver(
                            environment, node.value, updated
                        )
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"pop"}:
                    return collection_element
                if node.attr in {"copy"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"count", "index"}:
                    return self.engine._value_rules._instance(int)
                if node.attr in {
                    "union",
                    "intersection",
                    "difference",
                    "symmetric_difference",
                }:
                    element = collection_element
                    if node.attr == "union" and arguments:
                        element = self.engine._value_rules._join(
                            element, self.engine._value_rules._iterable_element(arguments[0])
                        )
                    return AbstractTypeValue.from_type(
                        Instance(original_type, (element.public_type() or ANY,))
                    )
                if node.attr in {"issubset", "issuperset", "isdisjoint"}:
                    return self.engine._value_rules._instance(bool)
                if node.attr in {"clear", "discard", "remove"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is frozenset:
                collection_element = AbstractTypeValue.from_type(args[0] if args else ANY)
                if node.attr == "copy":
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {
                    "union",
                    "intersection",
                    "difference",
                    "symmetric_difference",
                }:
                    element = collection_element
                    if node.attr == "union" and arguments:
                        element = self.engine._value_rules._join(
                            element, self.engine._value_rules._iterable_element(arguments[0])
                        )
                    return self.engine._value_rules._instance(
                        frozenset, element.public_type() or ANY
                    )
                if node.attr in {"issubset", "issuperset", "isdisjoint"}:
                    return self.engine._value_rules._instance(bool)
            if raw is bytearray:
                if node.attr == "copy":
                    return AbstractTypeValue.from_type(typ)
                if node.attr == "decode":
                    return self.engine._value_rules._instance(str)
                if node.attr == "hex":
                    return self.engine._value_rules._instance(str)
                if node.attr in {"append", "extend"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is re.Pattern:
                text = args[0] if args else ANY
                match_type = self.engine._value_rules._proper_instance(re.Match, text)
                if node.attr in {"match", "search", "fullmatch"}:
                    return self.engine._value_rules._join(
                        AbstractTypeValue.from_type(match_type),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr == "findall":
                    return self.engine._value_rules._instance(list, ANY)
                if node.attr == "finditer":
                    return self.engine._value_rules._instance(cabc.Iterator, match_type)
                if node.attr == "sub":
                    return AbstractTypeValue.from_type(text)
                if node.attr == "subn":
                    return AbstractTypeValue.from_type(
                        TupleType((text, self.engine._value_rules._proper_instance(int)))
                    )
                if node.attr == "split":
                    return self.engine._value_rules._instance(list, ANY)
            if raw is re.Match:
                text = args[0] if args else ANY
                match_or_none = self.engine._value_rules._join(
                    AbstractTypeValue.from_type(text),
                    AbstractTypeValue.from_type(NONE_TYPE),
                )
                if node.attr == "group":
                    return AbstractTypeValue.from_type(text)
                if node.attr == "expand":
                    return AbstractTypeValue.from_type(text)
                if node.attr == "__getitem__":
                    return AbstractTypeValue.from_type(text)
                if node.attr == "groups":
                    return AbstractTypeValue.from_type(
                        TupleType((match_or_none.public_type() or ANY,), unknown_size=True)
                    )
                if node.attr == "groupdict":
                    return self.engine._value_rules._instance(
                        dict,
                        self.engine._value_rules._proper_instance(str),
                        match_or_none.public_type() or ANY,
                    )
                if node.attr in {"start", "end"}:
                    if arguments:
                        return self.engine._value_rules._join(
                            AbstractTypeValue.from_type(
                                self.engine._value_rules._proper_instance(int)
                            ),
                            AbstractTypeValue.from_type(NONE_TYPE),
                        )
                    return self.engine._value_rules._instance(int)
                if node.attr == "span":
                    if arguments:
                        return AbstractTypeValue.from_type(
                            TupleType(
                                (
                                    self.engine._value_rules._join(
                                        AbstractTypeValue.from_type(
                                            self.engine._value_rules._proper_instance(int)
                                        ),
                                        AbstractTypeValue.from_type(NONE_TYPE),
                                    ).public_type()
                                    or ANY,
                                    self.engine._value_rules._join(
                                        AbstractTypeValue.from_type(
                                            self.engine._value_rules._proper_instance(int)
                                        ),
                                        AbstractTypeValue.from_type(NONE_TYPE),
                                    ).public_type()
                                    or ANY,
                                )
                            )
                        )
                    return AbstractTypeValue.from_type(
                        TupleType(
                            (
                                self.engine._value_rules._proper_instance(int),
                                self.engine._value_rules._proper_instance(int),
                            )
                        )
                    )
            if raw in {threading.Lock, threading.RLock}:
                if node.attr in {"__enter__"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"__exit__", "release"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"acquire", "locked"}:
                    return self.engine._value_rules._instance(bool)
            if raw in {
                threading.Event,
                threading.Condition,
                threading.Semaphore,
                threading.BoundedSemaphore,
                threading.Barrier,
            }:
                if node.attr in {
                    "wait",
                    "wait_for",
                    "is_set",
                    "isSet",
                    "acquire",
                }:
                    return self.engine._value_rules._instance(bool)
                if node.attr in {
                    "set",
                    "clear",
                    "release",
                    "notify_all",
                    "notifyAll",
                    "abort",
                    "reset",
                }:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"__enter__"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"__exit__"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is threading.Thread:
                if node.attr in {"start", "join", "run"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"is_alive"}:
                    return self.engine._value_rules._instance(bool)
                if node.attr == "name":
                    return self.engine._value_rules._instance(str)
                if node.attr in {"daemon"}:
                    return self.engine._value_rules._instance(bool)
            if raw in {asyncio.Future, asyncio.Task}:
                item = args[0] if args else ANY
                if node.attr == "result":
                    return AbstractTypeValue.from_type(item)
                if node.attr == "exception":
                    return self.engine._value_rules._join(
                        AbstractTypeValue.from_type(
                            self.engine._value_rules._proper_instance(BaseException)
                        ),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr in {"done", "cancelled", "cancel"}:
                    return self.engine._value_rules._instance(bool)
                if node.attr in {"add_done_callback", "remove_done_callback"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if raw is asyncio.Task and node.attr == "get_name":
                    return self.engine._value_rules._instance(str)
                if raw is asyncio.Task and node.attr == "set_name":
                    return AbstractTypeValue.from_type(NONE_TYPE)
            async_bool = self.engine._value_rules._instance(
                cabc.Coroutine, ANY, ANY, self.engine._value_rules._proper_instance(bool)
            )
            if raw in {asyncio.Lock}:
                if node.attr in {"__aenter__"}:
                    return self.engine._value_rules._instance(cabc.Coroutine, ANY, ANY, typ)
                if node.attr in {"__aexit__", "release"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "acquire":
                    return async_bool
                if node.attr == "locked":
                    return self.engine._value_rules._instance(bool)
            if raw in {asyncio.Event}:
                if node.attr == "wait":
                    return async_bool
                if node.attr in {"set", "clear"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "is_set":
                    return self.engine._value_rules._instance(bool)
            if raw in {asyncio.Semaphore, asyncio.BoundedSemaphore}:
                if node.attr in {"__aenter__"}:
                    return self.engine._value_rules._instance(cabc.Coroutine, ANY, ANY, typ)
                if node.attr in {"__aexit__", "release"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "acquire":
                    return async_bool
                if node.attr == "locked":
                    return self.engine._value_rules._instance(bool)
            if raw is asyncio.Timeout:
                if node.attr == "__aenter__":
                    return self.engine._value_rules._instance(cabc.Coroutine, ANY, ANY, typ)
                if node.attr == "__aexit__":
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is asyncio.TaskGroup:
                if node.attr == "__aenter__":
                    return self.engine._value_rules._instance(cabc.Coroutine, ANY, ANY, typ)
                if node.attr == "__aexit__":
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "create_task" and arguments:
                    awaited = (
                        self.engine._value_rules._await_result(arguments[0])
                        if self.engine._value_rules._is_awaitable_value(arguments[0])
                        else AbstractTypeValue.unresolved()
                    )
                    return self.engine._value_rules._instance(
                        asyncio.Task, awaited.public_type() or ANY
                    )
            if raw in {
                queue.Queue,
                queue.SimpleQueue,
                queue.LifoQueue,
                queue.PriorityQueue,
            }:
                item = args[0] if args else ANY
                if node.attr == "get":
                    return AbstractTypeValue.from_type(item)
                if node.attr in {"put", "put_nowait", "task_done", "join"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "qsize":
                    return self.engine._value_rules._instance(int)
                if node.attr in {"empty", "full"}:
                    return self.engine._value_rules._instance(bool)
            if raw is concurrent.futures.Future:
                item = args[0] if args else ANY
                if node.attr == "result":
                    return AbstractTypeValue.from_type(item)
                if node.attr == "exception":
                    return self.engine._value_rules._join(
                        AbstractTypeValue.from_type(
                            self.engine._value_rules._proper_instance(BaseException)
                        ),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr in {"done", "cancelled", "running", "cancel"}:
                    return self.engine._value_rules._instance(bool)
                if node.attr in {
                    "set_result",
                    "set_exception",
                    "set_running_or_notify_cancel",
                    "add_done_callback",
                }:
                    return AbstractTypeValue.from_type(
                        self.engine._value_rules._proper_instance(bool)
                        if node.attr == "set_running_or_notify_cancel"
                        else NONE_TYPE
                    )
            if raw in {
                concurrent.futures.ThreadPoolExecutor,
                concurrent.futures.ProcessPoolExecutor,
            }:
                if node.attr == "__enter__":
                    return AbstractTypeValue.from_type(typ)
                if node.attr == "__exit__":
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "submit" and arguments:
                    return self.engine._value_rules._instance(
                        concurrent.futures.Future,
                        self.engine._value_rules._callable_return_type(arguments[0]).public_type()
                        or ANY,
                    )
                if node.attr == "map" and arguments:
                    return self.engine._value_rules._instance(
                        cabc.Iterator,
                        self.engine._value_rules._callable_return_type(arguments[0]).public_type()
                        or ANY,
                    )
                if node.attr in {"shutdown"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw in {cabc.Iterator, cabc.AsyncIterator}:
                item = args[0] if args else ANY
                if node.attr in {"__iter__", "__aiter__"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"__next__", "__anext__"}:
                    return AbstractTypeValue.from_type(item)
            if raw in {cabc.Mapping, cabc.MutableMapping}:
                key = args[0] if args else ANY
                item = args[1] if len(args) > 1 else ANY
                key_value = AbstractTypeValue.from_type(key)
                item_value = AbstractTypeValue.from_type(item)
                if node.attr == "get":
                    default = (
                        arguments[1]
                        if len(arguments) > 1
                        else AbstractTypeValue.from_type(NONE_TYPE)
                    )
                    return self.engine._value_rules._join(item_value, default)
                if node.attr in {"__getitem__", "pop"}:
                    if node.attr == "pop" and len(arguments) > 1:
                        return self.engine._value_rules._join(item_value, arguments[1])
                    return item_value
                if node.attr == "keys":
                    return self.engine._value_rules._instance(cabc.KeysView, key)
                if node.attr == "values":
                    return self.engine._value_rules._instance(cabc.ValuesView, item)
                if node.attr == "items":
                    return self.engine._value_rules._instance(cabc.ItemsView, key, item)
                if node.attr in {"copy", "__iter__"}:
                    return (
                        AbstractTypeValue.from_type(typ)
                        if node.attr == "copy"
                        else self.engine._value_rules._instance(cabc.Iterator, key)
                    )
                if node.attr in {"__len__", "count"}:
                    return self.engine._value_rules._instance(int)
                if node.attr in {"clear", "update", "setdefault"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw in {cabc.Sequence, cabc.MutableSequence}:
                item = args[0] if args else ANY
                item_value = AbstractTypeValue.from_type(item)
                if node.attr == "__getitem__":
                    return item_value
                if node.attr in {"count", "index", "__len__"}:
                    return self.engine._value_rules._instance(int)
                if node.attr in {"pop"}:
                    return item_value
                if node.attr in {"copy", "reverse"}:
                    return (
                        AbstractTypeValue.from_type(typ)
                        if node.attr == "copy"
                        else AbstractTypeValue.from_type(NONE_TYPE)
                    )
                if node.attr in {"append", "extend", "insert", "remove", "sort", "clear"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "__iter__":
                    return self.engine._value_rules._instance(cabc.Iterator, item)
            if raw is subprocess.CompletedProcess:
                text = args[0] if args else ANY
                if node.attr == "stdout" or node.attr == "stderr":
                    return self.engine._value_rules._join(
                        AbstractTypeValue.from_type(text),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr == "returncode":
                    return self.engine._value_rules._instance(int)
                if node.attr == "check_returncode":
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is subprocess.Popen:
                text = args[0] if args else ANY
                if node.attr == "wait":
                    return self.engine._value_rules._instance(int)
                if node.attr == "poll":
                    return self.engine._value_rules._join(
                        AbstractTypeValue.from_type(self.engine._value_rules._proper_instance(int)),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr == "communicate":
                    return AbstractTypeValue.from_type(
                        TupleType(
                            (
                                self.engine._value_rules._join(
                                    AbstractTypeValue.from_type(text),
                                    AbstractTypeValue.from_type(NONE_TYPE),
                                ).public_type()
                                or ANY,
                                self.engine._value_rules._join(
                                    AbstractTypeValue.from_type(text),
                                    AbstractTypeValue.from_type(NONE_TYPE),
                                ).public_type()
                                or ANY,
                            )
                        )
                    )
                if node.attr in {"kill", "terminate", "send_signal"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"__enter__"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"__exit__"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"__enter__"}:
                    return AbstractTypeValue.from_type(typ)
            if raw in {logging.Logger, logging.LoggerAdapter}:
                if node.attr in {
                    "debug",
                    "info",
                    "warning",
                    "error",
                    "exception",
                    "critical",
                    "log",
                    "setLevel",
                    "addHandler",
                }:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "isEnabledFor":
                    return self.engine._value_rules._instance(bool)
            if raw is os.DirEntry:
                if node.attr in {"is_dir", "is_file", "is_symlink", "is_junction"}:
                    return self.engine._value_rules._instance(bool)
                if node.attr == "stat":
                    return self.engine._value_rules._instance(os.stat_result)
                if node.attr == "__fspath__":
                    return self.engine._value_rules._instance(str)
            if raw is zipfile.ZipFile:
                if node.attr in {"__enter__"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"__exit__", "close", "write", "extract", "extractall", "printdir"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"namelist"}:
                    return self.engine._value_rules._instance(
                        list, self.engine._value_rules._proper_instance(str)
                    )
                if node.attr in {"read"}:
                    return self.engine._value_rules._instance(bytes)
                if node.attr in {"open", "infolist", "getinfo"}:
                    return AbstractTypeValue.from_type(ANY)
                if node.attr == "testzip":
                    return self.engine._value_rules._join(
                        AbstractTypeValue.from_type(self.engine._value_rules._proper_instance(str)),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
            if raw in {contextlib.ExitStack, contextlib.AsyncExitStack}:
                if node.attr in {"__enter__", "__aenter__", "pop_all"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"enter_context", "enter_async_context"} and arguments:
                    entered: ProperType = ANY
                    for item in arguments[0].types:
                        if (
                            isinstance(item, Instance)
                            and item.type.raw_type
                            in {
                                contextlib.AbstractContextManager,
                                contextlib.AbstractAsyncContextManager,
                            }
                            and item.args
                        ):
                            entered = item.args[0]
                            break
                    return AbstractTypeValue.from_type(entered)
                if node.attr in {
                    "__exit__",
                    "__aexit__",
                    "close",
                    "aclose",
                    "callback",
                    "push",
                    "push_async",
                    "push_async_exit",
                    "push_async_callback",
                }:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is contextvars.ContextVar:
                item = args[0] if args else ANY
                if node.attr == "get":
                    return AbstractTypeValue.from_type(item)
                if node.attr == "set":
                    return self.engine._value_rules._instance(contextvars.Token, item)
                if node.attr == "reset":
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is collections.Counter:
                counter_element = AbstractTypeValue.from_type(args[0] if args else ANY)
                if node.attr == "most_common":
                    pair = TupleType(
                        (
                            counter_element.public_type() or ANY,
                            self.engine._value_rules._proper_instance(int),
                        )
                    )
                    return self.engine._value_rules._instance(list, pair)
                if node.attr == "elements":
                    return self.engine._value_rules._instance(
                        cabc.Iterator, counter_element.public_type() or ANY
                    )
                if node.attr == "total":
                    return self.engine._value_rules._instance(int)
                args = (args[0] if args else ANY, self.engine._value_rules._proper_instance(int))
            if (
                raw
                in {
                    dict,
                    collections.defaultdict,
                    collections.OrderedDict,
                    collections.ChainMap,
                    collections.Counter,
                }
                or typ.type.typed_dict_fields is not None
            ):
                if node.attr == "copy":
                    return AbstractTypeValue.from_type(typ)
                if node.attr == "fromkeys" and arguments:
                    key_value = (
                        self.engine._value_rules._iterable_element(arguments[0]).public_type()
                        or ANY
                    )
                    value = arguments[1] if len(arguments) > 1 else keywords.get("value")
                    value_type = (value.public_type() or ANY) if value is not None else NONE_TYPE
                    return self.engine._value_rules._instance(dict, key_value, value_type)
                if typ.type.typed_dict_fields is not None:
                    fields = typ.type.typed_dict_fields
                    key = self.engine._value_rules._proper_instance(str)
                    field_values = list(fields.values())
                    if not field_values:
                        item = ANY
                    elif len(field_values) == 1:
                        item = field_values[0]
                    else:
                        item = UnionType(tuple(sorted(field_values)))
                    key_name = (
                        call_node.args[0].value
                        if call_node
                        and call_node.args
                        and isinstance(call_node.args[0], ast.Constant)
                        and isinstance(call_node.args[0].value, str)
                        else None
                    )
                    if node.attr == "get":
                        if key_name in fields:
                            result = AbstractTypeValue.from_type(fields[key_name])
                            if key_name in typ.type.required_keys:
                                return result
                            default = (
                                arguments[1]
                                if len(arguments) > 1
                                else AbstractTypeValue.from_type(NONE_TYPE)
                            )
                            return self.engine._value_rules._join(result, default)
                        result = AbstractTypeValue.from_type(item)
                        default = (
                            arguments[1]
                            if len(arguments) > 1
                            else AbstractTypeValue.from_type(NONE_TYPE)
                        )
                        return self.engine._value_rules._join(result, default)
                    if node.attr == "setdefault":
                        default = (
                            arguments[1]
                            if len(arguments) > 1
                            else AbstractTypeValue.from_type(NONE_TYPE)
                        )
                        field = fields.get(key_name) if key_name is not None else None
                        if key_name in typ.type.required_keys and field is not None:
                            return AbstractTypeValue.from_type(field)
                        if field is not None:
                            return self.engine._value_rules._join(
                                AbstractTypeValue.from_type(field), default
                            )
                        return self.engine._value_rules._join(
                            AbstractTypeValue.from_type(item), default
                        )
                    if node.attr == "pop":
                        field = fields.get(key_name) if key_name is not None else None
                        result = AbstractTypeValue.from_type(field if field is not None else item)
                        if key_name in typ.type.required_keys:
                            return result
                        if len(arguments) > 1:
                            return self.engine._value_rules._join(result, arguments[1])
                        return result
                    if node.attr == "popitem":
                        return AbstractTypeValue.from_type(TupleType((key, item)))
                    if node.attr == "keys":
                        return self.engine._value_rules._instance(cabc.KeysView, key)
                    if node.attr == "values":
                        return self.engine._value_rules._instance(cabc.ValuesView, item)
                    if node.attr == "items":
                        return self.engine._value_rules._instance(cabc.ItemsView, key, item)
                    if node.attr == "update":
                        # TypedDict keys and their types are fixed by the
                        # declaration; mutating methods must not project the
                        # receiver to an anonymous dict.
                        if call_node is not None:
                            self.engine._compatibility_rules._check_typed_dict_update(
                                typ, fields, arguments, keywords, call_node
                            )
                        return AbstractTypeValue.from_type(NONE_TYPE)
                    if node.attr == "clear":
                        return AbstractTypeValue.from_type(NONE_TYPE)
                else:
                    key = args[0] if len(args) > 0 else ANY
                    item = args[1] if len(args) > 1 else ANY
                    if node.attr == "get":
                        result = AbstractTypeValue.from_type(item)
                        default = (
                            arguments[1]
                            if len(arguments) > 1
                            else AbstractTypeValue.from_type(NONE_TYPE)
                        )
                        return self.engine._value_rules._join(result, default)
                    if node.attr == "setdefault":
                        default = (
                            arguments[1]
                            if len(arguments) > 1
                            else AbstractTypeValue.from_type(NONE_TYPE)
                        )
                        result = self.engine._value_rules._join(
                            AbstractTypeValue.from_type(item), default
                        )
                        key_type = (
                            arguments[0].public_type()
                            if arguments and arguments[0].public_type() is not None
                            else key
                        )
                        widened_key = self.engine._value_rules._join(
                            AbstractTypeValue.from_type(key), AbstractTypeValue.from_type(key_type)
                        )
                        widened_item = self.engine._value_rules._join(
                            AbstractTypeValue.from_type(item), default
                        )
                        self.engine._flow_rules._update_environment_receiver(
                            environment,
                            node.value,
                            self.engine._value_rules._instance(
                                dict,
                                widened_key.public_type() or ANY,
                                widened_item.public_type() or ANY,
                            ),
                        )
                        return result
                    if node.attr == "pop":
                        result = AbstractTypeValue.from_type(item)
                        if len(arguments) > 1:
                            return self.engine._value_rules._join(result, arguments[1])
                        return result
                    if node.attr == "popitem":
                        return AbstractTypeValue.from_type(TupleType((key, item)))
                    if node.attr == "keys":
                        return self.engine._value_rules._instance(cabc.KeysView, key)
                    if node.attr == "values":
                        return self.engine._value_rules._instance(cabc.ValuesView, item)
                    if node.attr == "items":
                        return self.engine._value_rules._instance(cabc.ItemsView, key, item)
                    if node.attr in {"update", "clear"}:
                        if node.attr == "update":
                            mapping_key: AbstractTypeValue | None = None
                            mapping_item: AbstractTypeValue | None = None
                            if arguments:
                                mapping_key, mapping_item = (
                                    self.engine._value_rules._mapping_key_value(arguments[0])
                                )
                            elif keywords:
                                mapping_key = self.engine._value_rules._instance(str)
                                mapping_item = join_all(
                                    keywords.values(),
                                    self.engine.type_system,
                                    max_union_size=self.engine.options.max_union_size,
                                )
                            if mapping_key is not None and mapping_item is not None:
                                widened_key = self.engine._value_rules._join(
                                    AbstractTypeValue.from_type(key), mapping_key
                                )
                                widened_item = self.engine._value_rules._join(
                                    AbstractTypeValue.from_type(item), mapping_item
                                )
                                self.engine._flow_rules._update_environment_receiver(
                                    environment,
                                    node.value,
                                    self.engine._value_rules._instance(
                                        dict,
                                        widened_key.public_type() or ANY,
                                        widened_item.public_type() or ANY,
                                    ),
                                )
                        return AbstractTypeValue.from_type(NONE_TYPE)
        return None

    def _method_arguments(self, function, base, arguments):
        if function.method_kind == "static":
            return arguments
        if function.method_kind == "class":
            receiver = replace(
                base,
                class_targets=frozenset(
                    typ.type.full_name for typ in base.types if isinstance(typ, Instance)
                ),
            )
            return [receiver, *arguments]
        return arguments if base.class_targets else [base, *arguments]

    def _model_numeric_method(self, receiver: type, attribute: str) -> AbstractTypeValue | None:
        """Model common ``int``/``float`` methods."""
        pair = TupleType(
            (
                self.engine._value_rules._proper_instance(int),
                self.engine._value_rules._proper_instance(int),
            )
        )
        if receiver is int:
            if attribute in {"bit_length", "bit_count"}:
                return self.engine._value_rules._instance(int)
            if attribute == "to_bytes":
                return self.engine._value_rules._instance(bytes)
            if attribute in {"as_integer_ratio"}:
                return AbstractTypeValue.from_type(pair)
            if attribute in {"conjugate", "real", "imag"}:
                return self.engine._value_rules._instance(int)
        if receiver is float:
            if attribute == "is_integer":
                return self.engine._value_rules._instance(bool)
            if attribute == "as_integer_ratio":
                return AbstractTypeValue.from_type(pair)
            if attribute in {"hex"}:
                return self.engine._value_rules._instance(str)
            if attribute in {"conjugate", "real", "imag"}:
                return self.engine._value_rules._instance(float)
        return None

    def _native_call_attribute(
        self,
        node: ast.Attribute,
        base: AbstractTypeValue,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        call_node: ast.Call | None,
    ) -> AbstractTypeValue | None:
        """Receiver-aware overrides that typeshed declarations cannot express."""
        for typ in base.types:
            if not isinstance(typ, Instance):
                continue
            raw = typ.type.raw_type
            if raw is asyncio.TaskGroup and node.attr == "create_task" and arguments:
                awaited = (
                    self.engine._value_rules._await_result(arguments[0])
                    if self.engine._value_rules._is_awaitable_value(arguments[0])
                    else AbstractTypeValue.unresolved()
                )
                return self.engine._value_rules._instance(
                    asyncio.Task, awaited.public_type() or ANY
                )
            if raw is contextvars.ContextVar:
                item = AbstractTypeValue.from_type(typ.args[0]) if typ.args else ANY
                if node.attr == "get":
                    return item
                if node.attr == "set":
                    return self.engine._value_rules._instance(
                        contextvars.Token, item.public_type() or ANY
                    )
                if node.attr == "reset":
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if (
                node.attr == "copy"
                and isinstance(raw, type)
                and raw.__module__.startswith("collections")
            ):
                return AbstractTypeValue.from_type(typ)
            if self.engine._value_rules._is_pathlib_type(typ) and node.attr == "open":
                mode = "r"
                if call_node is not None:
                    mode_node = (
                        call_node.args[0]
                        if call_node.args
                        else next(
                            (
                                keyword.value
                                for keyword in call_node.keywords
                                if keyword.arg == "mode"
                            ),
                            None,
                        )
                    )
                    if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
                        mode = mode_node.value
                return self.engine._value_rules._instance(
                    io.BufferedIOBase if "b" in mode else io.TextIOWrapper
                )
        return None

    def _model_text_method(self, receiver: type, attribute: str) -> AbstractTypeValue | None:
        """Model one ``str`` or ``bytes`` receiver alternative."""
        preserving: dict[type, set[str]] = {
            str: {
                "capitalize",
                "casefold",
                "center",
                "expandtabs",
                "format",
                "format_map",
                "join",
                "ljust",
                "lower",
                "lstrip",
                "removeprefix",
                "removesuffix",
                "replace",
                "rjust",
                "rstrip",
                "strip",
                "swapcase",
                "title",
                "translate",
                "upper",
                "zfill",
            },
            bytes: {
                "capitalize",
                "center",
                "expandtabs",
                "join",
                "ljust",
                "lower",
                "lstrip",
                "removeprefix",
                "removesuffix",
                "replace",
                "rjust",
                "rstrip",
                "strip",
                "swapcase",
                "title",
                "translate",
                "upper",
                "zfill",
            },
        }
        predicates: dict[type, set[str]] = {
            str: {
                "endswith",
                "isalnum",
                "isalpha",
                "isascii",
                "isdecimal",
                "isdigit",
                "isidentifier",
                "islower",
                "isnumeric",
                "isprintable",
                "isspace",
                "istitle",
                "isupper",
                "startswith",
            },
            bytes: {
                "endswith",
                "isalnum",
                "isalpha",
                "isascii",
                "isdigit",
                "islower",
                "isspace",
                "istitle",
                "isupper",
                "startswith",
            },
        }
        if attribute == "encode" and receiver is str:
            return self.engine._value_rules._instance(bytes)
        if attribute == "decode" and receiver is bytes:
            return self.engine._value_rules._instance(str)
        if attribute == "hex" and receiver is bytes:
            return self.engine._value_rules._instance(str)
        if attribute in preserving[receiver]:
            return self.engine._value_rules._instance(receiver)
        if attribute in predicates[receiver]:
            return self.engine._value_rules._instance(bool)
        if attribute in {"count", "find", "index", "rfind", "rindex"}:
            return self.engine._value_rules._instance(int)
        element = self.engine._value_rules._proper_instance(receiver)
        if attribute in {"partition", "rpartition"}:
            return AbstractTypeValue.from_type(TupleType((element, element, element)))
        if attribute in {"split", "rsplit", "splitlines"}:
            return self.engine._value_rules._instance(list, element)
        return None
