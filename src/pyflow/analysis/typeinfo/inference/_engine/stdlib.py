"""Model standard-library globals and function calls."""

from __future__ import annotations

import ast
import asyncio
import builtins
import collections
import collections.abc as cabc
import contextlib
import dataclasses
import datetime
import io
import logging
import os
import re
import subprocess
import time
import types
import weakref

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NONE_TYPE,
    CallableType,
    Instance,
    NeverType,
    ProperType,
    TupleType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference._engine.component import InferenceComponent
from pyflow.analysis.typeinfo.inference._engine.state import _ClassInfo
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue, join_all


class StdlibInference(InferenceComponent):
    """Model standard-library globals and function calls."""

    _STDLIB_FLOAT_GLOBALS = frozenset(
        {
            "math.pi",
            "math.e",
            "math.tau",
            "math.inf",
            "math.nan",
        }
    )

    _STDLIB_TEXT_GLOBALS = frozenset(
        {
            "sys.platform",
            "sys.version",
            "sys.byteorder",
            "sys.executable",
            "sys.prefix",
            "sys.exec_prefix",
            "os.sep",
            "os.linesep",
            "os.name",
            "os.curdir",
            "os.pardir",
            "os.devnull",
            "string.ascii_letters",
            "string.ascii_lowercase",
            "string.ascii_uppercase",
            "string.digits",
            "string.hexdigits",
            "string.octdigits",
            "string.punctuation",
            "string.printable",
            "string.whitespace",
        }
    )

    def _stdlib_global_value(self, qualified_name: str) -> AbstractTypeValue | None:
        """Model common module-level constants without importing analysed code."""

        if qualified_name in {"sys.argv", "sys.path"}:
            return self.engine._value_rules._instance(
                list, self.engine._value_rules._proper_instance(str)
            )
        if qualified_name in self._STDLIB_TEXT_GLOBALS:
            return self.engine._value_rules._instance(str)
        if qualified_name in self._STDLIB_FLOAT_GLOBALS:
            return self.engine._value_rules._instance(float)
        if qualified_name in {"sys.maxsize", "sys.maxunicode"}:
            return self.engine._value_rules._instance(int)
        if qualified_name in {"sys.stdout", "sys.stderr", "sys.stdin"}:
            return self.engine._value_rules._instance(io.TextIOBase)
        if qualified_name == "sys.version_info":
            return AbstractTypeValue.from_type(
                TupleType((self.engine._value_rules._proper_instance(int),) * 5, unknown_size=True)
            )
        if qualified_name == "sys.modules":
            return self.engine._value_rules._instance(
                dict,
                self.engine._value_rules._proper_instance(str),
                self.engine._value_rules._proper_instance(types.ModuleType),
            )
        if qualified_name == "os.altsep":
            return AbstractTypeValue.from_type(
                UnionType((self.engine._value_rules._proper_instance(str), NONE_TYPE))
            )
        if qualified_name in {"os.environ", "os.environb"}:
            return self.engine._value_rules._instance(
                dict,
                self.engine._value_rules._proper_instance(str),
                self.engine._value_rules._proper_instance(str),
            )
        return None

    def _model_stdlib_call(
        self,
        qualified_name: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        *,
        node: ast.Call | None = None,
    ) -> AbstractTypeValue | None:
        """Model common stdlib calls when no stub or call provider is available."""

        def element(value: AbstractTypeValue) -> ProperType:
            return self.engine._value_rules._iterable_element(value).public_type() or ANY

        if qualified_name == "io.open":
            # ``io.open`` is an alias of the builtin with the same signature.
            return self.engine._builtin_rules._call_builtin(
                "open", arguments, keywords, call_node=node
            )
        if qualified_name == "collections.deque":
            return self.engine._value_rules._instance(
                collections.deque, element(arguments[0]) if arguments else ANY
            )
        if qualified_name in {"datetime.datetime", "datetime.date", "datetime.timedelta"}:
            raw = {
                "datetime.datetime": datetime.datetime,
                "datetime.date": datetime.date,
                "datetime.timedelta": datetime.timedelta,
            }[qualified_name]
            return self.engine._value_rules._instance(raw)
        if qualified_name in {"dict.fromkeys", "collections.OrderedDict.fromkeys"} and arguments:
            key_type = element(arguments[0])
            value = arguments[1] if len(arguments) > 1 else keywords.get("value")
            value_type = (value.public_type() or ANY) if value is not None else NONE_TYPE
            return self.engine._value_rules._instance(dict, key_type, value_type)
        if qualified_name == "dataclasses.replace" and arguments:
            return AbstractTypeValue.from_type(arguments[0].public_type() or ANY)
        if qualified_name == "dataclasses.asdict":
            return self.engine._value_rules._instance(
                dict, self.engine._value_rules._proper_instance(str), ANY
            )
        if qualified_name == "dataclasses.astuple":
            return AbstractTypeValue.from_type(TupleType((ANY,), unknown_size=True))
        if qualified_name == "dataclasses.fields":
            return AbstractTypeValue.from_type(
                TupleType(
                    (self.engine._value_rules._proper_instance(dataclasses.Field),),
                    unknown_size=True,
                )
            )
        if qualified_name in {
            "typing.get_type_hints",
            "typing_extensions.get_type_hints",
        }:
            return self.engine._value_rules._instance(
                dict, self.engine._value_rules._proper_instance(str), ANY
            )
        if qualified_name in {"typing.get_origin", "typing_extensions.get_origin"}:
            return AbstractTypeValue.from_type(ANY)
        if qualified_name in {"typing.get_args", "typing_extensions.get_args"}:
            return AbstractTypeValue.from_type(TupleType((ANY,), unknown_size=True))
        if qualified_name == "dataclasses.is_dataclass":
            return self.engine._value_rules._instance(bool)
        if qualified_name in {"bytes.fromhex", "bytearray.fromhex"}:
            return self.engine._value_rules._instance(
                bytearray if qualified_name.startswith("bytearray") else bytes
            )
        if qualified_name == "int.from_bytes":
            return self.engine._value_rules._instance(int)
        if qualified_name == "float.fromhex":
            return self.engine._value_rules._instance(float)
        if qualified_name in {
            "datetime.datetime.now",
            "datetime.datetime.utcnow",
            "datetime.datetime.today",
            "datetime.datetime.fromtimestamp",
            "datetime.datetime.utcfromtimestamp",
            "datetime.datetime.strptime",
            "datetime.datetime.combine",
            "datetime.datetime.fromisoformat",
        }:
            return self.engine._value_rules._instance(datetime.datetime)
        if qualified_name in {
            "datetime.date.today",
            "datetime.date.fromtimestamp",
            "datetime.date.fromisoformat",
            "datetime.date.fromordinal",
        }:
            return self.engine._value_rules._instance(datetime.date)
        if qualified_name.startswith("re."):
            text_raw: type = str
            candidates = (arguments[1].types if len(arguments) > 1 else ()) if arguments else ()
            if not candidates and arguments:
                candidates = arguments[0].types
            for typ in candidates:
                if isinstance(typ, Instance) and typ.type.raw_type is bytes:
                    text_raw = bytes
                    break
                if isinstance(typ, Instance) and typ.type.raw_type is str:
                    text_raw = str
                    break
            text_type = self.engine._value_rules._proper_instance(text_raw)
            match_type = self.engine._value_rules._proper_instance(re.Match, text_type)
            pattern_type = self.engine._value_rules._proper_instance(re.Pattern, text_type)
            if qualified_name == "re.compile":
                return AbstractTypeValue.from_type(pattern_type)
            if qualified_name in {"re.match", "re.search", "re.fullmatch"}:
                return self.engine._value_rules._join(
                    AbstractTypeValue.from_type(match_type),
                    AbstractTypeValue.from_type(NONE_TYPE),
                )
            if qualified_name == "re.findall":
                # Typeshed: ``list[Any]`` -- capture groups may be tuples,
                # unmatched optional groups are ``None``.
                return self.engine._value_rules._instance(list, ANY)
            if qualified_name == "re.finditer":
                return self.engine._value_rules._instance(cabc.Iterator, match_type)
            if qualified_name == "re.sub":
                return self.engine._value_rules._instance(text_raw)
            if qualified_name == "re.subn":
                return AbstractTypeValue.from_type(
                    TupleType((text_type, self.engine._value_rules._proper_instance(int)))
                )
            if qualified_name == "re.split":
                # Typeshed: ``list[str | Any]`` -- unmatched capture groups
                # produce ``None``.
                return self.engine._value_rules._instance(list, ANY)
            if qualified_name == "re.escape":
                return self.engine._value_rules._instance(str)
        if qualified_name == "collections.Counter":
            return self.engine._value_rules._instance(
                collections.Counter, element(arguments[0]) if arguments else ANY
            )
        if qualified_name == "collections.namedtuple" and node is not None:
            if len(node.args) < 2 or not isinstance(node.args[0], ast.Constant):
                return AbstractTypeValue.unresolved()
            name = node.args[0].value
            try:
                fields_node = ast.literal_eval(node.args[1])
            except (ValueError, TypeError, SyntaxError):
                return AbstractTypeValue.unresolved()
            if not isinstance(name, str):
                return AbstractTypeValue.unresolved()
            if isinstance(fields_node, str):
                fields = tuple(part for part in fields_node.replace(",", " ").split() if part)
            elif isinstance(fields_node, (list, tuple)) and all(
                isinstance(part, str) for part in fields_node
            ):
                fields = tuple(fields_node)
            else:
                return AbstractTypeValue.unresolved()
            qualified = f"{self.engine._module_name}.{name}"
            raw = type(
                name,
                (tuple,),
                {"__module__": self.engine._module_name, "_fields": fields},
            )
            instance = self.engine._value_rules._proper_instance(raw)
            descriptor = instance.type
            descriptor.tuple_fields = fields
            for field in fields:
                descriptor.members[field] = ANY
            fields_type = AbstractTypeValue.from_type(
                TupleType((self.engine._value_rules._proper_instance(str),), unknown_size=True)
            )
            self.engine._classes[qualified] = _ClassInfo(
                qualified,
                instance,
                attributes={
                    **{field: AbstractTypeValue.from_type(ANY) for field in fields},
                    "_fields": fields_type,
                },
            )
            self.engine._class_aliases[name] = qualified
            return AbstractTypeValue.from_type(instance, class_target=qualified)
        if qualified_name in {"enum.Enum", "enum.IntEnum"} and node is not None:
            if not node.args or not isinstance(node.args[0], ast.Constant):
                return AbstractTypeValue.unresolved()
            name = node.args[0].value
            if not isinstance(name, str):
                return AbstractTypeValue.unresolved()
            names: tuple[str, ...] = ()
            if len(node.args) > 1:
                try:
                    raw_names = ast.literal_eval(node.args[1])
                except (ValueError, TypeError, SyntaxError):
                    raw_names = None
                if isinstance(raw_names, str):
                    names = tuple(part for part in raw_names.replace(",", " ").split() if part)
                elif isinstance(raw_names, (list, tuple)) and all(
                    isinstance(part, str) for part in raw_names
                ):
                    names = tuple(raw_names)
            qualified = f"{self.engine._module_name}.{name}"
            raw = type(name, (), {"__module__": self.engine._module_name})
            instance = self.engine._value_rules._proper_instance(raw)
            attributes: dict[str, AbstractTypeValue] = {}
            enum_values: dict[str, AbstractTypeValue] = {}
            for index, member in enumerate(names, start=1):
                attributes[member] = AbstractTypeValue.from_type(instance)
                enum_values[member] = self.engine._value_rules._instance(int)
            self.engine._classes[qualified] = _ClassInfo(
                qualified,
                instance,
                bases=(qualified_name,),
                attributes=attributes,
                enum_values=enum_values,
            )
            self.engine._class_aliases[name] = qualified
            return AbstractTypeValue.from_type(instance, class_target=qualified)
        if (
            qualified_name in {"typing.TypedDict", "typing_extensions.TypedDict"}
            and node is not None
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and isinstance(node.args[1], ast.Dict)
        ):
            name = node.args[0].value
            fields: dict[str, ProperType] = {}
            required_fields: set[str] = set()
            total = not any(
                isinstance(keyword, ast.keyword)
                and keyword.arg == "total"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in node.keywords
            )
            for key_node, value_node in zip(node.args[1].keys, node.args[1].values):
                if not (isinstance(key_node, ast.Constant) and isinstance(key_node.value, str)):
                    continue
                key = key_node.value
                fields[key] = (
                    self.engine._declaration_rules._annotation_value(value_node).public_type()
                    or ANY
                )
                wrapper = (
                    self.engine._value_rules._qualified_callee_name(value_node.value)
                    if isinstance(value_node, ast.Subscript)
                    else ""
                ) or ""
                if wrapper.endswith("NotRequired"):
                    continue
                if wrapper.endswith("Required") or total:
                    required_fields.add(key)
            qualified = f"{self.engine._module_name}.{name}"
            raw = type(name, (dict,), {"__module__": self.engine._module_name})
            instance = self.engine._value_rules._proper_instance(raw)
            descriptor = instance.type
            descriptor.typed_dict_fields = fields
            descriptor.required_keys = frozenset(required_fields)
            self.engine._classes[qualified] = _ClassInfo(
                qualified,
                instance,
                attributes={
                    field: AbstractTypeValue.from_type(field_type)
                    for field, field_type in fields.items()
                },
            )
            self.engine._class_aliases[name] = qualified
            return AbstractTypeValue.from_type(instance, class_target=qualified)
        if (
            qualified_name in {"typing.NamedTuple", "typing_extensions.NamedTuple"}
            and node is not None
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and isinstance(node.args[1], (ast.List, ast.Tuple))
        ):
            name = node.args[0].value
            fields: dict[str, ProperType] = {}
            for item in node.args[1].elts:
                if not (
                    isinstance(item, ast.Tuple)
                    and len(item.elts) >= 2
                    and isinstance(item.elts[0], ast.Constant)
                    and isinstance(item.elts[0].value, str)
                ):
                    continue
                fields[item.elts[0].value] = (
                    self.engine._declaration_rules._annotation_value(item.elts[1]).public_type()
                    or ANY
                )
            qualified = f"{self.engine._module_name}.{name}"
            raw = type(name, (tuple,), {"__module__": self.engine._module_name})
            instance = self.engine._value_rules._proper_instance(raw)
            descriptor = instance.type
            descriptor.tuple_fields = tuple(fields)
            for field, field_type in fields.items():
                descriptor.members[field] = field_type
            self.engine._classes[qualified] = _ClassInfo(
                qualified,
                instance,
                attributes={
                    field: AbstractTypeValue.from_type(field_type)
                    for field, field_type in fields.items()
                },
            )
            self.engine._class_aliases[name] = qualified
            return AbstractTypeValue.from_type(instance, class_target=qualified)
        if qualified_name == "collections.defaultdict":
            value_type: ProperType = ANY
            if arguments:
                for target in arguments[0].class_targets:
                    if target.startswith("builtins."):
                        value_type = self.engine._value_rules._proper_instance(
                            getattr(builtins, target.removeprefix("builtins."), object)
                        )
                        break
                else:
                    value_type = (
                        self.engine._value_rules._callable_return_type(arguments[0]).public_type()
                        or ANY
                    )
            return self.engine._value_rules._instance(collections.defaultdict, ANY, value_type)
        if qualified_name in {"collections.OrderedDict", "collections.ChainMap"}:
            if keywords:
                value = join_all(
                    keywords.values(),
                    self.engine.type_system,
                    max_union_size=self.engine.options.max_union_size,
                )
                key_type = self.engine._value_rules._proper_instance(str)
                value_type = value.public_type() or ANY
            else:
                key_parts: list[ProperType] = []
                value_parts: list[ProperType] = []
                for argument in arguments:
                    for typ in argument.types:
                        if (
                            isinstance(typ, Instance)
                            and typ.type.raw_type is dict
                            and len(typ.args) >= 2
                        ):
                            # An empty dict contributes no key/value evidence;
                            # Never would otherwise make the result unusable
                            # as a Mapping[str, Any].
                            if not isinstance(typ.args[0], NeverType):
                                key_parts.append(typ.args[0])
                            if not isinstance(typ.args[1], NeverType):
                                value_parts.append(typ.args[1])
                key_type = (
                    join_all(
                        (AbstractTypeValue.from_type(item) for item in key_parts),
                        self.engine.type_system,
                        max_union_size=self.engine.options.max_union_size,
                    ).public_type()
                    or ANY
                )
                value_type = (
                    join_all(
                        (AbstractTypeValue.from_type(item) for item in value_parts),
                        self.engine.type_system,
                        max_union_size=self.engine.options.max_union_size,
                    ).public_type()
                    or ANY
                )
            raw = (
                collections.OrderedDict
                if qualified_name.endswith("OrderedDict")
                else collections.ChainMap
            )
            return self.engine._value_rules._instance(raw, key_type, value_type)
        if qualified_name == "functools.partial" and arguments:
            signatures: list[CallableType] = [
                typ for typ in arguments[0].types if isinstance(typ, CallableType)
            ]
            if not signatures and arguments[0].class_targets:
                # ``functools.partial(int, base=2)``/``partial(SomeClass, x)``
                # bind constructor arguments like any other callable.
                for typ in arguments[0].types:
                    constructor = self.engine._call_rules._constructor_callable_type(typ)
                    if isinstance(constructor, CallableType):
                        signatures.append(constructor)
            for signature in signatures:
                if signature.arg_types is None:
                    return AbstractTypeValue.from_type(signature)
                bound_positions = set(range(len(arguments) - 1))
                target_name = next(iter(arguments[0].callable_targets), None)
                target = self.engine._functions.get(target_name) if target_name else None
                if target is not None:
                    names = target.parameter_names
                    bound_positions.update(
                        names.index(name)
                        for name in keywords
                        if name in names and names.index(name) < len(signature.arg_types)
                    )
                remaining = tuple(
                    item
                    for index, item in enumerate(signature.arg_types)
                    if index not in bound_positions
                )
                return AbstractTypeValue.from_type(CallableType(remaining, signature.return_type))
            return AbstractTypeValue.unresolved()
        if qualified_name == "functools.reduce" and len(arguments) >= 2:
            reduced = element(arguments[1])
            if len(arguments) >= 3:
                reduced = (
                    self.engine._value_rules._join(
                        AbstractTypeValue.from_type(reduced), arguments[2]
                    ).public_type()
                    or ANY
                )
            return AbstractTypeValue.from_type(reduced)
        if qualified_name.startswith("itertools."):
            if qualified_name == "itertools.chain.from_iterable" and arguments:
                inner = element(arguments[0])
                joined = (
                    self.engine._value_rules._iterable_element(
                        AbstractTypeValue.from_type(inner)
                    ).public_type()
                    or ANY
                )
                return self.engine._value_rules._instance(cabc.Iterator, joined)
            if qualified_name == "itertools.chain":
                values = [element(argument) for argument in arguments]
                joined = (
                    join_all(
                        (AbstractTypeValue.from_type(item) for item in values),
                        self.engine.type_system,
                        max_union_size=self.engine.options.max_union_size,
                    ).public_type()
                    or ANY
                )
                return self.engine._value_rules._instance(cabc.Iterator, joined)
            if qualified_name == "itertools.islice" and arguments:
                return self.engine._value_rules._instance(cabc.Iterator, element(arguments[0]))
            if (
                qualified_name
                in {
                    "itertools.filterfalse",
                    "itertools.dropwhile",
                    "itertools.takewhile",
                }
                and len(arguments) >= 2
            ):
                return self.engine._value_rules._instance(cabc.Iterator, element(arguments[1]))
            if qualified_name == "itertools.starmap" and len(arguments) >= 2:
                tuple_element = element(arguments[1])
                callable_targets = arguments[0].callable_targets
                if isinstance(tuple_element, TupleType) and tuple_element.unknown_size:
                    # ``itertools.product`` yields variadic tuples whose arity
                    # is unknown; applying the callable with the single known
                    # element type would fabricate an arity error.
                    return self.engine._value_rules._instance(cabc.Iterator, ANY)
                if callable_targets and isinstance(tuple_element, TupleType):
                    return self.engine._value_rules._instance(
                        cabc.Iterator,
                        join_all(
                            (
                                self.engine._call_rules._apply_function(
                                    target,
                                    [
                                        AbstractTypeValue.from_type(item)
                                        for item in tuple_element.args
                                    ],
                                    {},
                                )
                                for target in callable_targets
                            ),
                            self.engine.type_system,
                            max_union_size=self.engine.options.max_union_size,
                        ).public_type()
                        or ANY,
                    )
                return self.engine._value_rules._instance(cabc.Iterator, tuple_element)
            if qualified_name == "itertools.accumulate" and arguments:
                accumulated = element(arguments[0])
                if len(arguments) > 1 and arguments[1].callable_targets:
                    target = next(iter(arguments[1].callable_targets))
                    result = self.engine._call_rules._apply_function(
                        target,
                        [
                            AbstractTypeValue.from_type(accumulated),
                            AbstractTypeValue.from_type(accumulated),
                        ],
                        {},
                    ).public_type()
                    if result is not None:
                        accumulated = result
                return self.engine._value_rules._instance(cabc.Iterator, accumulated)
            if qualified_name == "itertools.count" and arguments:
                count_raw = (
                    float
                    if any(
                        isinstance(part, Instance) and part.type.raw_type is float
                        for argument in arguments
                        for part in argument.types
                    )
                    else int
                )
                return self.engine._value_rules._instance(
                    cabc.Iterator, self.engine._value_rules._proper_instance(count_raw)
                )
            if qualified_name == "itertools.cycle" and arguments:
                return self.engine._value_rules._instance(cabc.Iterator, element(arguments[0]))
            if qualified_name == "itertools.tee" and arguments:
                item = element(arguments[0])
                count = 2
                if len(arguments) > 1 or "n" in keywords:
                    try:
                        count_node = next(
                            (keyword.value for keyword in node.keywords if keyword.arg == "n"),
                            node.args[1] if len(node.args) > 1 else None,
                        )
                        count_value = ast.literal_eval(count_node)
                        if isinstance(count_value, int):
                            count = max(0, count_value)
                    except (ValueError, TypeError, SyntaxError):
                        count = 2
                return AbstractTypeValue.from_type(
                    TupleType(
                        tuple(
                            self.engine._value_rules._proper_instance(cabc.Iterator, item)
                            for _ in range(count)
                        )
                    )
                )
            if qualified_name in {"itertools.product", "itertools.zip_longest"}:
                elements = [element(argument) for argument in arguments]
                if qualified_name == "itertools.product":
                    repeat = keywords.get("repeat")
                    literal_repeat = (
                        next(iter(repeat.literal_values), None) if repeat is not None else None
                    )
                    if isinstance(literal_repeat, int) and literal_repeat >= 0:
                        elements = elements * literal_repeat
                return self.engine._value_rules._instance(cabc.Iterator, TupleType(tuple(elements)))
            if qualified_name in {"itertools.combinations", "itertools.permutations"} and arguments:
                return self.engine._value_rules._instance(
                    cabc.Iterator,
                    TupleType((element(arguments[0]),), unknown_size=True),
                )
            if qualified_name == "itertools.repeat" and arguments:
                return self.engine._value_rules._instance(
                    cabc.Iterator, arguments[0].public_type() or ANY
                )
            if qualified_name == "itertools.groupby" and arguments:
                item = element(arguments[0])
                return self.engine._value_rules._instance(
                    cabc.Iterator,
                    TupleType(
                        (item, self.engine._value_rules._proper_instance(cabc.Iterator, item))
                    ),
                )
        if qualified_name in {"weakref.ref", "weakref.WeakMethod"} and arguments:
            return self.engine._value_rules._instance(
                weakref.ReferenceType, arguments[0].public_type() or ANY
            )
        if qualified_name == "weakref.proxy" and arguments:
            # A proxy forwards attribute access to the target object.
            return arguments[0]
        if qualified_name in {"glob.glob", "glob.iglob"} and arguments:
            if qualified_name == "glob.glob":
                return self.engine._value_rules._instance(
                    list, self.engine._value_rules._proper_instance(str)
                )
            return self.engine._value_rules._instance(
                cabc.Iterator, self.engine._value_rules._proper_instance(str)
            )
        if qualified_name == "os.scandir":
            return self.engine._value_rules._instance(
                cabc.Iterator, self.engine._value_rules._proper_instance(os.DirEntry)
            )
        if qualified_name == "os.walk":
            return self.engine._value_rules._instance(
                cabc.Iterator,
                TupleType(
                    (
                        self.engine._value_rules._proper_instance(str),
                        self.engine._value_rules._proper_instance(
                            list, self.engine._value_rules._proper_instance(str)
                        ),
                        self.engine._value_rules._proper_instance(
                            list, self.engine._value_rules._proper_instance(str)
                        ),
                    )
                ),
            )
        if qualified_name in {"os.getcwd", "os.getcwdb"}:
            return self.engine._value_rules._instance(
                bytes if qualified_name.endswith("b") else str
            )
        if qualified_name in {"os.getpid", "os.getppid"}:
            return self.engine._value_rules._instance(int)
        if qualified_name in {"os.getenv", "os.environ.get"}:
            default = arguments[1] if len(arguments) > 1 else keywords.get("default")
            string_value = AbstractTypeValue.from_type(
                self.engine._value_rules._proper_instance(str)
            )
            if default is not None and default.public_type() is not None:
                return self.engine._value_rules._join(string_value, default)
            return self.engine._value_rules._join(
                string_value, AbstractTypeValue.from_type(NONE_TYPE)
            )
        if qualified_name == "os.cpu_count":
            return self.engine._value_rules._join(
                AbstractTypeValue.from_type(self.engine._value_rules._proper_instance(int)),
                AbstractTypeValue.from_type(NONE_TYPE),
            )
        if qualified_name == "os.listdir":
            return self.engine._value_rules._instance(
                list, self.engine._value_rules._proper_instance(str)
            )
        if qualified_name == "os.scandir":
            return self.engine._value_rules._instance(cabc.Iterator, ANY)
        if qualified_name in {"os.stat", "os.lstat"}:
            return self.engine._value_rules._instance(os.stat_result)
        if qualified_name == "os.urandom":
            return self.engine._value_rules._instance(bytes)
        if qualified_name in {
            "os.makedirs",
            "os.remove",
            "os.unlink",
            "os.rmdir",
            "os.rename",
            "os.replace",
            "os.chmod",
            "os.chown",
            "os.chdir",
            "os.symlink",
            "os.link",
        }:
            return AbstractTypeValue.from_type(NONE_TYPE)
        if qualified_name in {"os.path.join", "posixpath.join", "ntpath.join"}:
            return self.engine._value_rules._instance(
                bytes
                if any(
                    self.engine._value_rules._contains_raw(argument, bytes)
                    for argument in arguments
                )
                else str
            )
        if qualified_name in {
            "os.fspath",
            "os.path.basename",
            "os.path.dirname",
            "os.path.abspath",
            "os.path.realpath",
            "os.path.normpath",
            "os.path.expanduser",
            "os.path.expandvars",
            "os.path.relpath",
            "posixpath.basename",
            "posixpath.dirname",
            "posixpath.abspath",
            "posixpath.realpath",
            "ntpath.basename",
            "ntpath.dirname",
            "ntpath.abspath",
            "ntpath.realpath",
        }:
            return self.engine._value_rules._instance(
                bytes
                if any(
                    self.engine._value_rules._contains_raw(argument, bytes)
                    for argument in arguments
                )
                else str
            )
        if qualified_name in {
            "os.path.exists",
            "os.path.isfile",
            "os.path.isdir",
            "os.path.islink",
            "os.path.isabs",
            "os.path.samefile",
            "posixpath.exists",
            "posixpath.isfile",
            "posixpath.isdir",
            "ntpath.exists",
            "ntpath.isfile",
            "ntpath.isdir",
        }:
            return self.engine._value_rules._instance(bool)
        if qualified_name in {"os.path.getsize", "os.path.getmtime"}:
            return self.engine._value_rules._instance(
                int if qualified_name.endswith("getsize") else float
            )
        if qualified_name in {
            "os.path.splitext",
            "os.path.split",
            "posixpath.splitext",
            "posixpath.split",
            "ntpath.splitext",
            "ntpath.split",
        }:
            raw = (
                bytes
                if any(
                    self.engine._value_rules._contains_raw(argument, bytes)
                    for argument in arguments
                )
                else str
            )
            return AbstractTypeValue.from_type(
                TupleType(
                    (
                        self.engine._value_rules._proper_instance(raw),
                        self.engine._value_rules._proper_instance(raw),
                    )
                )
            )
        if qualified_name == "contextlib.nullcontext":
            entered = (arguments[0].public_type() or ANY) if arguments else NONE_TYPE
            return self.engine._value_rules._instance(contextlib.AbstractContextManager, entered)
        if qualified_name == "contextlib.closing" and arguments:
            return self.engine._value_rules._instance(
                contextlib.AbstractContextManager,
                arguments[0].public_type() or ANY,
            )
        if qualified_name in {
            "contextlib.suppress",
            "contextlib.redirect_stdout",
            "contextlib.redirect_stderr",
        }:
            return self.engine._value_rules._instance(contextlib.AbstractContextManager, NONE_TYPE)
        if qualified_name.startswith("asyncio."):
            result_types = [
                (
                    self.engine._value_rules._await_result(argument)
                    if self.engine._value_rules._is_awaitable_value(argument)
                    else AbstractTypeValue.unresolved()
                )
                for argument in arguments
            ]
            if qualified_name == "asyncio.sleep":
                return self.engine._value_rules._instance(cabc.Coroutine, ANY, ANY, NONE_TYPE)
            if qualified_name in {"asyncio.create_task"} and result_types:
                return self.engine._value_rules._instance(
                    asyncio.Task, result_types[0].public_type() or ANY
                )
            if qualified_name in {"asyncio.ensure_future", "asyncio.shield"} and result_types:
                return self.engine._value_rules._instance(
                    asyncio.Future, result_types[0].public_type() or ANY
                )
            if qualified_name == "asyncio.run" and result_types:
                return result_types[0]
            if qualified_name == "asyncio.wait_for" and result_types:
                return self.engine._value_rules._instance(
                    cabc.Coroutine,
                    ANY,
                    ANY,
                    result_types[0].public_type() or ANY,
                )
            if qualified_name == "asyncio.gather" and result_types:
                # typeshed models ``gather`` with a fixed arity up to six
                # arguments as ``tuple[T1, ..., Tn]`` and the variadic form as
                # ``list[T]``.  Collapsing the fixed form to a list loses each
                # position's type (``gather(f(), g())[0]`` becomes ``int|str``).
                return_exceptions = any(
                    keyword.arg == "return_exceptions"
                    and not (
                        isinstance(keyword.value, ast.Constant) and keyword.value.value is False
                    )
                    for keyword in node.keywords
                )
                exception_type = self.engine._value_rules._proper_instance(BaseException)
                item_types: list[ProperType] = []
                for result in result_types:
                    item_type = result.public_type() or ANY
                    item_types.append(
                        UnionType((item_type, exception_type)) if return_exceptions else item_type
                    )
                gathered: ProperType
                if len(item_types) <= 6:
                    gathered = TupleType(tuple(item_types))
                else:
                    gathered = self.engine._value_rules._proper_instance(
                        list,
                        join_all(
                            result_types,
                            self.engine.type_system,
                            max_union_size=self.engine.options.max_union_size,
                        ).public_type()
                        or ANY,
                    )
                return self.engine._value_rules._instance(asyncio.Future, gathered)
            if qualified_name == "asyncio.to_thread" and arguments:
                return self.engine._value_rules._instance(
                    cabc.Coroutine,
                    ANY,
                    ANY,
                    self.engine._value_rules._callable_return_type(arguments[0]).public_type()
                    or ANY,
                )
            if qualified_name == "asyncio.as_completed" and arguments:
                item = self.engine._value_rules._iterable_element(arguments[0])
                awaited = (
                    self.engine._value_rules._await_result(item)
                    if self.engine._value_rules._is_awaitable_value(item)
                    else AbstractTypeValue.from_type(ANY)
                )
                return self.engine._value_rules._instance(
                    cabc.Iterator,
                    self.engine._value_rules._proper_instance(
                        cabc.Awaitable, awaited.public_type() or ANY
                    ),
                )
            if qualified_name in {"asyncio.timeout", "asyncio.timeout_at"}:
                return self.engine._value_rules._instance(asyncio.Timeout)
            if qualified_name in {"asyncio.get_running_loop", "asyncio.get_event_loop"}:
                return self.engine._value_rules._instance(asyncio.AbstractEventLoop)
        if qualified_name in {"subprocess.run", "subprocess.Popen"}:
            text_mode = any(
                keyword.arg in {"text", "universal_newlines", "encoding", "errors"}
                and not (
                    isinstance(keyword.value, ast.Constant) and keyword.value.value in (False, None)
                )
                for keyword in node.keywords
            )
            raw = str if text_mode else bytes
            if qualified_name.endswith("run"):
                return self.engine._value_rules._instance(
                    subprocess.CompletedProcess, self.engine._value_rules._proper_instance(raw)
                )
            return self.engine._value_rules._instance(
                subprocess.Popen, self.engine._value_rules._proper_instance(raw)
            )
        if qualified_name in {"subprocess.check_output", "subprocess.getoutput"}:
            text_mode = any(
                keyword.arg in {"text", "universal_newlines", "encoding", "errors"}
                and not (
                    isinstance(keyword.value, ast.Constant) and keyword.value.value in (False, None)
                )
                for keyword in node.keywords
            )
            return self.engine._value_rules._instance(
                str if text_mode or qualified_name.endswith("getoutput") else bytes
            )
        if qualified_name == "subprocess.getstatusoutput":
            return AbstractTypeValue.from_type(
                TupleType(
                    (
                        self.engine._value_rules._proper_instance(int),
                        self.engine._value_rules._proper_instance(str),
                    )
                )
            )
        if qualified_name in {"subprocess.call", "subprocess.check_call"}:
            return self.engine._value_rules._instance(int)
        if qualified_name == "shutil.which":
            return self.engine._value_rules._join(
                AbstractTypeValue.from_type(self.engine._value_rules._proper_instance(str)),
                AbstractTypeValue.from_type(NONE_TYPE),
            )
        if qualified_name in {
            "shutil.copy",
            "shutil.copy2",
            "shutil.copyfile",
            "shutil.copytree",
            "shutil.move",
            "shutil.make_archive",
        }:
            return self.engine._value_rules._instance(str)
        if qualified_name in {
            "shutil.rmtree",
            "shutil.chown",
            "shutil.copymode",
            "shutil.copystat",
        }:
            return AbstractTypeValue.from_type(NONE_TYPE)
        if qualified_name == "shutil.disk_usage":
            return AbstractTypeValue.from_type(
                TupleType(
                    (
                        self.engine._value_rules._proper_instance(int),
                        self.engine._value_rules._proper_instance(int),
                        self.engine._value_rules._proper_instance(int),
                    )
                )
            )
        if qualified_name == "shutil.get_terminal_size":
            return AbstractTypeValue.from_type(
                TupleType(
                    (
                        self.engine._value_rules._proper_instance(int),
                        self.engine._value_rules._proper_instance(int),
                    )
                )
            )
        if qualified_name in {
            "logging.getLogger",
            "logging.getLoggerClass",
        }:
            return self.engine._value_rules._instance(logging.Logger)
        if qualified_name == "logging.basicConfig":
            return AbstractTypeValue.from_type(NONE_TYPE)
        if qualified_name in {
            "logging.debug",
            "logging.info",
            "logging.warning",
            "logging.error",
            "logging.exception",
            "logging.critical",
            "logging.log",
        }:
            return AbstractTypeValue.from_type(NONE_TYPE)
        if qualified_name == "tempfile.mkdtemp":
            return self.engine._value_rules._instance(str)
        if qualified_name == "tempfile.mkstemp":
            return AbstractTypeValue.from_type(
                TupleType(
                    (
                        self.engine._value_rules._proper_instance(int),
                        self.engine._value_rules._proper_instance(str),
                    )
                )
            )
        if qualified_name == "tempfile.gettempdir":
            return self.engine._value_rules._instance(str)
        if qualified_name in {"tempfile.NamedTemporaryFile", "tempfile.TemporaryFile"}:
            # ``mode`` is the first positional parameter of these factories,
            # unlike the builtin ``open(file, mode)``.  The default is binary.
            mode = "w+b"
            if node is not None:
                mode_node: ast.expr | None = node.args[0] if node.args else None
                if mode_node is None:
                    mode_node = next((kw.value for kw in node.keywords if kw.arg == "mode"), None)
                if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
                    mode = mode_node.value
            return self.engine._value_rules._instance(
                io.BufferedIOBase if "b" in mode else io.TextIOWrapper
            )
        if qualified_name == "tempfile.TemporaryDirectory":
            return self.engine._value_rules._instance(
                contextlib.AbstractContextManager, self.engine._value_rules._proper_instance(str)
            )
        if qualified_name == "json.dumps":
            return self.engine._value_rules._instance(str)
        if qualified_name in {"json.dump"}:
            return AbstractTypeValue.from_type(NONE_TYPE)
        if qualified_name in {"json.loads", "json.load"}:
            return AbstractTypeValue.from_type(ANY)
        if qualified_name == "enum.auto":
            # ``auto()`` assigns increasing integers to enum members.
            return self.engine._value_rules._instance(int)
        if qualified_name.startswith("time."):
            if qualified_name in {
                "time.time",
                "time.perf_counter",
                "time.monotonic",
                "time.process_time",
                "time.mktime",
                "time.clock_gettime",
            }:
                return self.engine._value_rules._instance(float)
            if qualified_name in {
                "time.time_ns",
                "time.perf_counter_ns",
                "time.monotonic_ns",
                "time.process_time_ns",
                "time.clock_gettime_ns",
            }:
                return self.engine._value_rules._instance(int)
            if qualified_name == "time.sleep":
                return AbstractTypeValue.from_type(NONE_TYPE)
            if qualified_name in {"time.strftime", "time.ctime", "time.asctime"}:
                return self.engine._value_rules._instance(str)
            if qualified_name in {
                "time.localtime",
                "time.gmtime",
                "time.strptime",
            }:
                return self.engine._value_rules._instance(time.struct_time)
            if qualified_name in {"time.timezone", "time.altzone", "time.daylight"}:
                return self.engine._value_rules._instance(int)
            if qualified_name == "time.tzname":
                return AbstractTypeValue.from_type(
                    TupleType(
                        (
                            self.engine._value_rules._proper_instance(str),
                            self.engine._value_rules._proper_instance(str),
                        ),
                        unknown_size=True,
                    )
                )
        return None
