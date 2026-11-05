"""Project and join abstract values, containers, iterables, and awaitables."""

from __future__ import annotations

import ast
import asyncio
import builtins
import collections
import collections.abc as cabc
import csv
import io
from dataclasses import replace
from typing import Iterable, cast

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    AnyType,
    NEVER,
    CallableType,
    Instance,
    NeverType,
    NoneType,
    ProperType,
    TupleType,
    TypeType,
    TypeVarType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference._engine.component import InferenceComponent
from pyflow.analysis.typeinfo.inference._engine.state import _expression_name
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue, join_all
from pyflow.analysis.typeinfo.resolution.typing_syntax import substitute_type_vars

# Nested typing forms are resolved as annotations, not runtime subscripts.
_TYPING_SPECIAL_FORM_NAMES = frozenset(
    {
        "Annotated",
        "Any",
        "AnyStr",
        "Callable",
        "ClassVar",
        "Concatenate",
        "Final",
        "Generic",
        "Literal",
        "LiteralString",
        "NamedTuple",
        "Never",
        "NewType",
        "NoReturn",
        "NotRequired",
        "Optional",
        "ParamSpec",
        "Protocol",
        "Required",
        "Self",
        "Type",
        "TypeAlias",
        "TypeGuard",
        "TypeIs",
        "TypedDict",
        "TypeVar",
        "Union",
    }
)


class ValueInference(InferenceComponent):
    """Project and join abstract values, containers, iterables, and awaitables."""

    def _subscript_value(
        self,
        base: AbstractTypeValue,
        slice_node: ast.expr,
        index_value: AbstractTypeValue | None = None,
    ) -> AbstractTypeValue:
        if self.engine._operator_rules._contains_any(base):
            return AbstractTypeValue.from_type(ANY)
        if base.class_targets:
            for target in base.class_targets:
                class_info = self.engine._classes.get(target)
                if class_info is None or not class_info.enum_values:
                    continue
                if (
                    isinstance(slice_node, ast.Constant)
                    and isinstance(slice_node.value, str)
                    and slice_node.value in class_info.enum_values
                ):
                    return AbstractTypeValue.from_type(class_info.instance)
                return AbstractTypeValue.unresolved()
            arguments = slice_node.elts if isinstance(slice_node, ast.Tuple) else [slice_node]
            parameters = tuple(
                self.engine._declaration_rules._annotation_value(item).public_type() or ANY
                for item in arguments
            )
            if "builtins.tuple" in base.class_targets:
                # ``tuple[int, str]`` as a value is a generic alias over the
                # special TupleType representation.
                return replace(base, types=frozenset((TupleType(parameters),)))
            return replace(
                base,
                types=frozenset(
                    Instance(typ.type, parameters) if isinstance(typ, Instance) else typ
                    for typ in base.types
                ),
            )
        values: list[AbstractTypeValue] = []
        for typ in base.types:
            if isinstance(typ, UnionType):
                values.extend(
                    self._subscript_value(
                        AbstractTypeValue.from_type(item), slice_node, index_value=index_value
                    )
                    for item in typ.items
                )
                continue
            if isinstance(typ, Instance) and typ.type.typed_dict_fields is None:
                projected = self._builtin_projection(typ)
                if projected is not None:
                    typ = projected
            if isinstance(typ, Instance) and typ.type.tuple_fields is not None:
                typ = TupleType(
                    tuple(typ.type.members.get(name, ANY) for name in typ.type.tuple_fields)
                )
            if (
                isinstance(typ, Instance)
                and typ.args
                and index_value is not None
                and not isinstance(slice_node, ast.Slice)
                and typ.type.typed_dict_fields is None
            ):
                self._check_subscript_index(typ, index_value, slice_node)
            if isinstance(slice_node, ast.Slice):
                if isinstance(typ, TupleType):
                    try:
                        bounds = [
                            ast.literal_eval(item) if item is not None else None
                            for item in (slice_node.lower, slice_node.upper, slice_node.step)
                        ]
                        result = typ if typ.unknown_size else TupleType(typ.args[slice(*bounds)])
                    except (ValueError, TypeError):
                        result = TupleType(
                            (
                                self._iterable_element(
                                    AbstractTypeValue.from_type(typ)
                                ).public_type()
                                or ANY,
                            ),
                            unknown_size=True,
                        )
                    values.append(AbstractTypeValue.from_type(result))
                elif isinstance(typ, Instance) and typ.type.raw_type in {
                    list,
                    str,
                    bytes,
                    bytearray,
                    range,
                    memoryview,
                    cabc.Sequence,
                    cabc.MutableSequence,
                }:
                    values.append(AbstractTypeValue.from_type(typ))
                continue
            if isinstance(typ, TupleType):
                try:
                    index = ast.literal_eval(slice_node)
                except (ValueError, TypeError):
                    index = None
                if isinstance(index, int):
                    if -len(typ.args) <= index < len(typ.args):
                        values.append(AbstractTypeValue.from_type(typ.args[index]))
                        continue
                values.extend(AbstractTypeValue.from_type(item) for item in typ.args)
            elif isinstance(typ, Instance):
                raw = typ.type.raw_type
                if raw in {cabc.Mapping, cabc.MutableMapping} and len(typ.args) >= 2:
                    values.append(AbstractTypeValue.from_type(typ.args[1]))
                    continue
                if raw in {cabc.Sequence, cabc.MutableSequence} and typ.args:
                    values.append(AbstractTypeValue.from_type(typ.args[0]))
                    continue
                if typ.type.typed_dict_fields is not None:
                    field_key = (
                        slice_node.value
                        if isinstance(slice_node, ast.Constant)
                        and isinstance(slice_node.value, str)
                        else None
                    )
                    if field_key is None and index_value is not None and index_value.literal_values:
                        for lit in index_value.literal_values:
                            if isinstance(lit, str) and lit in typ.type.typed_dict_fields:
                                field_key = lit
                                break
                    if field_key is not None and field_key in typ.type.typed_dict_fields:
                        values.append(
                            AbstractTypeValue.from_type(typ.type.typed_dict_fields.get(field_key))
                        )
                    else:
                        if field_key is not None:
                            self.engine._add_diagnostic(
                                "typed-dict-key",
                                f"TypedDict {typ.type.full_name} has no key {field_key!r}",
                                node=slice_node,
                            )
                        values.append(AbstractTypeValue.unresolved())
                    continue
                getitem = self.engine._member_rules._class_method(typ.type.full_name, "__getitem__")
                if getitem is not None:
                    result = self.engine._call_rules._apply_function(
                        getitem,
                        [
                            AbstractTypeValue.from_type(typ),
                            AbstractTypeValue.unresolved(),
                        ],
                        {},
                    )
                    values.append(self._filter_subscript_result(result, slice_node))
                    continue
                member = typ.type.members.get("__getitem__")
                if isinstance(member, CallableType):
                    substitutions = {
                        parameter.name: argument
                        for parameter, argument in zip(typ.type.type_parameters, typ.args)
                    }
                    returned = (
                        substitute_type_vars(member.return_type, substitutions)
                        if substitutions
                        else member.return_type
                    )
                    values.append(
                        self._filter_subscript_result(
                            AbstractTypeValue.from_type(returned),
                            slice_node,
                        )
                    )
                    continue
                if raw in {list, set, frozenset, collections.deque} and typ.args:
                    values.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw is collections.Counter:
                    values.append(self._instance(int))
                elif (
                    raw
                    in {
                        dict,
                        collections.defaultdict,
                        collections.OrderedDict,
                        collections.ChainMap,
                    }
                    and len(typ.args) > 1
                ):
                    if (
                        base.dict_shapes
                        and isinstance(slice_node, ast.Constant)
                        and isinstance(slice_node.value, str)
                    ):
                        for shape in base.dict_shapes:
                            field = dict(shape).get(slice_node.value)
                            values.append(
                                AbstractTypeValue.from_type(field)
                                if field is not None
                                else AbstractTypeValue.unresolved()
                            )
                    else:
                        values.append(AbstractTypeValue.from_type(typ.args[1]))
                elif raw in {bytes, bytearray}:
                    values.append(self._instance(int))
                elif raw in {memoryview, range}:
                    values.append(self._instance(int))
                elif raw is str:
                    values.append(AbstractTypeValue.from_type(typ))
        return (
            join_all(
                values,
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
            if values
            else AbstractTypeValue.unresolved()
        )

    _MAPPING_LIKE = frozenset(
        {
            dict,
            cabc.Mapping,
            cabc.MutableMapping,
            collections.defaultdict,
            collections.OrderedDict,
            collections.ChainMap,
            collections.Counter,
        }
    )
    _INT_INDEX = frozenset(
        {
            list,
            tuple,
            str,
            bytes,
            bytearray,
            range,
            memoryview,
            collections.deque,
            cabc.Sequence,
            cabc.MutableSequence,
        }
    )

    def _check_subscript_index(
        self,
        typ: Instance,
        index_value: AbstractTypeValue,
        node: ast.expr,
    ) -> None:
        """Report ``index`` when a known container is indexed with a wrong key."""
        actual = index_value.public_type()
        if actual is None or index_value.unknown:
            return
        if isinstance(actual, (AnyType, TypeVarType)):
            return
        if any(isinstance(argument, (AnyType, NeverType)) for argument in typ.args):
            # ``list[Any]`` comes from untyped code; mypy stays gradual there.
            return
        raw = typ.type.raw_type
        expected: ProperType | None = None
        if raw in self._MAPPING_LIKE and typ.args:
            expected = typ.args[0]
        elif raw in self._INT_INDEX:
            expected = self._proper_instance(int)
        if expected is None or isinstance(expected, (AnyType, NeverType)):
            # ``dict[Never, Never]`` is an empty literal: any key is fine.
            return
        if self.engine.type_system.is_subtype(actual, expected):
            return
        self.engine._add_diagnostic(
            "index",
            f'Invalid index type "{actual}" for "{typ}"',
            node=node,
        )

    def _is_widened_container(self, original: AbstractTypeValue, final: AbstractTypeValue) -> bool:
        """Whether *final* widened a mutable container argument in place."""
        if original.unknown or final.unknown or not original.types or not final.types:
            return False
        for before in original.types:
            if not isinstance(before, Instance) or before.type.raw_type not in {
                list,
                set,
                frozenset,
                dict,
            }:
                continue
            for after in final.types:
                if (
                    not isinstance(after, Instance)
                    or after.type.raw_type is not before.type.raw_type
                    or len(after.args) != len(before.args)
                ):
                    continue
                if all(
                    self.engine.type_system.is_subtype(old_arg, new_arg)
                    for old_arg, new_arg in zip(before.args, after.args)
                ) and any(
                    not self.engine.type_system.is_subtype(new_arg, old_arg)
                    for old_arg, new_arg in zip(before.args, after.args)
                ):
                    return True
        return False

    def _dict_key_value(self, value: AbstractTypeValue) -> AbstractTypeValue:
        """Project class-object keys to ``type[...]`` for dictionary literals."""
        parts: list[ProperType] = []
        for item in value.types:
            if isinstance(item, Instance) and item.type.full_name in value.class_targets:
                parts.append(TypeType(item))
            elif isinstance(item, TupleType) and "builtins.tuple" in value.class_targets:
                parts.append(TypeType(item))
            else:
                parts.append(item)
        return replace(value, types=frozenset(parts))

    def _mapping_key_value(
        self, value: AbstractTypeValue
    ) -> tuple[AbstractTypeValue, AbstractTypeValue]:
        """Return the joined key/value types contributed by a mapping value."""
        keys: list[AbstractTypeValue] = []
        items: list[AbstractTypeValue] = []
        for typ in value.types:
            if isinstance(typ, Instance) and typ.type.raw_type is dict and len(typ.args) >= 2:
                keys.append(AbstractTypeValue.from_type(typ.args[0]))
                items.append(AbstractTypeValue.from_type(typ.args[1]))
            elif isinstance(typ, Instance) and typ.type.typed_dict_fields is not None:
                keys.append(self._instance(str))
                fields = list(typ.type.typed_dict_fields.values())
                items.append(
                    join_all(
                        (AbstractTypeValue.from_type(item) for item in fields),
                        self.engine.type_system,
                        max_union_size=self.engine.options.max_union_size,
                    )
                    if fields
                    else AbstractTypeValue.from_type(ANY)
                )
            else:
                keys.append(AbstractTypeValue.from_type(ANY))
                items.append(AbstractTypeValue.from_type(ANY))
        if value.unknown:
            keys.append(AbstractTypeValue.unresolved())
            items.append(AbstractTypeValue.unresolved())
        return (
            (
                join_all(
                    keys,
                    self.engine.type_system,
                    max_union_size=self.engine.options.max_union_size,
                )
                if keys
                else AbstractTypeValue.unresolved()
            ),
            (
                join_all(
                    items,
                    self.engine.type_system,
                    max_union_size=self.engine.options.max_union_size,
                )
                if items
                else AbstractTypeValue.unresolved()
            ),
        )

    @staticmethod
    def _is_container_type(typ: ProperType) -> bool:
        if isinstance(typ, TupleType):
            return True
        return isinstance(typ, Instance) and typ.type.raw_type in {
            list,
            tuple,
            set,
            frozenset,
            dict,
            cabc.Sequence,
            cabc.MutableSequence,
            cabc.Iterable,
        }

    def _filter_subscript_result(
        self, result: AbstractTypeValue, slice_node: ast.expr
    ) -> AbstractTypeValue:
        """Select overload alternatives compatible with an int/slice index."""
        alternatives = [
            part
            for typ in result.types
            for part in (typ.items if isinstance(typ, UnionType) else (typ,))
        ]
        if len(alternatives) < 2:
            return result
        wants_container = isinstance(slice_node, ast.Slice)
        selected = [
            part for part in alternatives if self._is_container_type(part) == wants_container
        ]
        return replace(result, types=frozenset(selected)) if selected else result

    def _join_many_values(self, values: list[AbstractTypeValue]) -> AbstractTypeValue:
        return join_all(
            values,
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )

    def _is_awaitable_value(self, value: AbstractTypeValue) -> bool:
        """Return whether any alternative can be awaited."""
        for typ in value.types:
            if isinstance(typ, UnionType):
                if any(
                    self._is_awaitable_value(AbstractTypeValue.from_type(item))
                    for item in typ.items
                ):
                    return True
            elif isinstance(typ, Instance) and typ.type.raw_type in {
                cabc.Coroutine,
                cabc.Awaitable,
                asyncio.Future,
                asyncio.Task,
            }:
                return True
        return False

    def _await_result(self, value: AbstractTypeValue) -> AbstractTypeValue:
        results: list[AbstractTypeValue] = []
        for typ in value.types:
            if self.engine._operator_rules._contains_any(AbstractTypeValue.from_type(typ)):
                results.append(AbstractTypeValue.from_type(ANY))
                continue
            if isinstance(typ, Instance):
                raw = typ.type.raw_type
                if raw is cabc.Coroutine and len(typ.args) >= 3:
                    results.append(AbstractTypeValue.from_type(typ.args[2]))
                    continue
                if raw in {cabc.Awaitable, asyncio.Future, asyncio.Task} and typ.args:
                    results.append(AbstractTypeValue.from_type(typ.args[0]))
                    continue
            if isinstance(typ, UnionType):
                # ``from_type`` would wrap the union as a single proper type
                # and this method would recurse on the same value forever.
                results.extend(
                    self._await_result(AbstractTypeValue.from_type(item)) for item in typ.items
                )
        if results:
            return join_all(
                results,
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
        return AbstractTypeValue.unresolved() if value.unknown else AbstractTypeValue.from_type(ANY)

    def _iterable_element(self, value: AbstractTypeValue, *, _depth: int = 0) -> AbstractTypeValue:
        if _depth > 4:
            return AbstractTypeValue.unresolved()
        elements: list[AbstractTypeValue] = []
        for typ in value.types:
            if isinstance(typ, UnionType):
                elements.extend(
                    self._iterable_element(AbstractTypeValue.from_type(item), _depth=_depth + 1)
                    for item in typ.items
                )
                continue
            if isinstance(typ, TupleType):
                elements.extend(AbstractTypeValue.from_type(item) for item in typ.args)
            elif isinstance(typ, Instance):
                projected = self._builtin_projection(typ)
                if projected is not None:
                    elements.append(
                        self._iterable_element(
                            AbstractTypeValue.from_type(projected), _depth=_depth + 1
                        )
                    )
                    continue
                raw = typ.type.raw_type
                if typ.type.tuple_fields is not None:
                    elements.extend(
                        AbstractTypeValue.from_type(typ.type.members.get(name, ANY))
                        for name in typ.type.tuple_fields
                    )
                elif (
                    raw
                    in {
                        dict,
                        collections.defaultdict,
                        collections.OrderedDict,
                        collections.ChainMap,
                        collections.Counter,
                    }
                    and typ.args
                ):
                    elements.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw in {list, set, frozenset, collections.deque} and typ.args:
                    elements.append(AbstractTypeValue.from_type(typ.args[0]))
                elif isinstance(raw, type) and issubclass(raw, io.IOBase):
                    # Iterating a file object yields its lines: text for
                    # ``TextIOBase`` streams, bytes for everything else.
                    elements.append(
                        self._instance(str if issubclass(raw, io.TextIOBase) else bytes)
                    )
                elif (
                    raw
                    in {
                        cabc.Iterable,
                        cabc.Iterator,
                        cabc.Generator,
                        zip,
                        cabc.AsyncIterable,
                        cabc.AsyncIterator,
                        cabc.AsyncGenerator,
                    }
                    and typ.args
                ):
                    elements.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw in {cabc.KeysView, cabc.ValuesView} and typ.args:
                    elements.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw is cabc.ItemsView and len(typ.args) >= 2:
                    elements.append(
                        AbstractTypeValue.from_type(TupleType((typ.args[0], typ.args[1])))
                    )
                elif raw is csv.DictReader:
                    elements.append(
                        self._instance(dict, self._proper_instance(str), self._proper_instance(str))
                    )
                elif raw is csv.reader:
                    elements.append(self._instance(list, self._proper_instance(str)))
                elif raw is str:
                    elements.append(self._instance(str))
                elif raw is bytes:
                    elements.append(self._instance(int))
                elif raw is memoryview:
                    elements.append(self._instance(int))
                elif raw is range:
                    elements.append(self._instance(int))
                else:
                    info = self.engine._classes.get(typ.type.full_name)
                    if info is not None and self.engine._member_rules._is_enum_class_info(info):
                        elements.append(AbstractTypeValue.from_type(info.instance))
                    elif info is not None:
                        receiver_substitutions = {
                            parameter.name: argument
                            for parameter, argument in zip(typ.type.type_parameters, typ.args)
                        }
                        receiver_substitutions.update(info.type_var_bindings)
                        iter_method = self.engine._member_rules._class_method(
                            info.qualified_name, "__iter__"
                        )
                        next_method = self.engine._member_rules._class_method(
                            info.qualified_name, "__next__"
                        )
                        getitem_method = self.engine._member_rules._class_method(
                            info.qualified_name, "__getitem__"
                        )
                        aiter_method = self.engine._member_rules._class_method(
                            info.qualified_name, "__aiter__"
                        )
                        anext_method = self.engine._member_rules._class_method(
                            info.qualified_name, "__anext__"
                        )
                        if (
                            iter_method is None
                            and next_method is None
                            and getitem_method is None
                            and (aiter_method is not None or anext_method is not None)
                        ):
                            method = aiter_method or anext_method
                            function = self.engine._functions.get(method)
                            signature = (
                                self.engine._function_rules._function_value(function).public_type()
                                if function is not None
                                else None
                            )
                            if (
                                isinstance(signature, CallableType)
                                and signature.return_type is not None
                            ):
                                returned_type = signature.return_type
                                used_anext = False
                                if (
                                    aiter_method is not None
                                    and anext_method is not None
                                    and isinstance(returned_type, Instance)
                                    and returned_type.type.full_name == info.instance.type.full_name
                                ):
                                    anext_function = self.engine._functions.get(anext_method)
                                    anext_signature = (
                                        self.engine._function_rules._function_value(
                                            anext_function
                                        ).public_type()
                                        if anext_function is not None
                                        else None
                                    )
                                    if (
                                        isinstance(anext_signature, CallableType)
                                        and anext_signature.return_type is not None
                                    ):
                                        returned_type = anext_signature.return_type
                                        used_anext = True
                                        if (
                                            isinstance(returned_type, Instance)
                                            and returned_type.type.raw_type is cabc.Coroutine
                                            and len(returned_type.args) >= 3
                                        ):
                                            returned_type = returned_type.args[2]
                                    else:
                                        returned_type = None
                                if returned_type is not None:
                                    if receiver_substitutions:
                                        returned_type = substitute_type_vars(
                                            returned_type, receiver_substitutions
                                        )
                                    if used_anext:
                                        elements.append(AbstractTypeValue.from_type(returned_type))
                                    else:
                                        elements.append(
                                            self._iterable_element(
                                                AbstractTypeValue.from_type(returned_type),
                                                _depth=_depth + 1,
                                            )
                                        )
                            continue
                        method = iter_method or next_method or getitem_method
                        function = (
                            self.engine._functions.get(method) if method is not None else None
                        )
                        if function is not None:
                            signature = self.engine._function_rules._function_value(
                                function
                            ).public_type()
                            if (
                                isinstance(signature, CallableType)
                                and signature.return_type is not None
                            ):
                                returned_type = signature.return_type
                                used_next_method = False
                                if (
                                    iter_method is not None
                                    and isinstance(returned_type, Instance)
                                    and returned_type.type.full_name == info.instance.type.full_name
                                    and next_method is not None
                                ):
                                    next_function = self.engine._functions.get(next_method)
                                    next_signature = (
                                        self.engine._function_rules._function_value(
                                            next_function
                                        ).public_type()
                                        if next_function is not None
                                        else None
                                    )
                                    if (
                                        isinstance(next_signature, CallableType)
                                        and next_signature.return_type is not None
                                    ):
                                        returned_type = next_signature.return_type
                                        used_next_method = True
                                if receiver_substitutions:
                                    returned_type = substitute_type_vars(
                                        returned_type, receiver_substitutions
                                    )
                                returned = AbstractTypeValue.from_type(returned_type)
                                if iter_method is not None and not used_next_method:
                                    if not (
                                        isinstance(returned_type, Instance)
                                        and returned_type.type.full_name
                                        == info.instance.type.full_name
                                    ):
                                        returned = self._iterable_element(
                                            returned, _depth=_depth + 1
                                        )
                                elements.append(returned)
                    else:
                        # External classes (for example ``_csv.Reader``) are
                        # described by stubs rather than source class infos.
                        external_iter = self.engine._member_rules._external_type(
                            f"{typ.type.full_name}.__iter__"
                        )
                        if (
                            isinstance(external_iter, CallableType)
                            and external_iter.return_type is not None
                        ):
                            returned_type = external_iter.return_type
                            substitutions = {
                                parameter.name: argument
                                for parameter, argument in zip(typ.type.type_parameters, typ.args)
                            }
                            if substitutions:
                                returned_type = substitute_type_vars(returned_type, substitutions)
                            used_next = False
                            if (
                                isinstance(returned_type, Instance)
                                and returned_type.type.full_name == typ.type.full_name
                            ):
                                external_next = self.engine._member_rules._external_type(
                                    f"{typ.type.full_name}.__next__"
                                )
                                if (
                                    isinstance(external_next, CallableType)
                                    and external_next.return_type is not None
                                ):
                                    returned_type = external_next.return_type
                                    used_next = True
                                else:
                                    returned_type = None
                            if returned_type is not None:
                                returned = AbstractTypeValue.from_type(returned_type)
                                if not used_next:
                                    returned = self._iterable_element(returned, _depth=_depth + 1)
                                elements.append(returned)
        return (
            join_all(
                elements,
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
            if elements
            else AbstractTypeValue.unresolved()
        )

    def _builtin_projection(self, typ: Instance) -> Instance | None:
        """Project a user subclass of a builtin container to its generic base."""
        info = self.engine._classes.get(typ.type.full_name)
        if info is None or info.builtin_base is None:
            return None
        raw, args = info.builtin_base
        substitutions: dict[str, ProperType] = {
            name: value
            for name, value in info.type_var_bindings.items()
            if not isinstance(value, TypeVarType)
        }
        template = list(info.type_variables)
        if template and typ.args:
            substitutions.update(zip(template, typ.args))
        if substitutions:
            # ``class MyList(list[T])`` projects to ``list[T]``; when the
            # receiver is ``MyList[int]`` the element type must be substituted
            # instead of leaking ``T`` into indexing results.
            args = tuple(substitute_type_vars(arg, substitutions) for arg in args)
        return Instance(self.engine.type_system.to_class_descriptor(raw), args)

    @staticmethod
    def _is_pathlib_type(typ: Instance) -> bool:
        full_name = typ.type.full_name
        return full_name.startswith("pathlib.") and full_name.rsplit(".", 1)[-1] in {
            "Path",
            "PosixPath",
            "WindowsPath",
            "PurePath",
            "PurePosixPath",
            "PureWindowsPath",
        }

    def _callable_return_type(self, value: AbstractTypeValue) -> AbstractTypeValue:
        returns = [
            AbstractTypeValue.from_type(typ.return_type)
            for typ in value.types
            if isinstance(typ, CallableType)
        ]
        return (
            join_all(
                returns,
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
            if returns
            else AbstractTypeValue.unresolved()
        )

    @staticmethod
    def _augment_element_shapes(
        value: AbstractTypeValue, *sources: AbstractTypeValue
    ) -> AbstractTypeValue:
        shapes = set(value.element_dict_shapes)
        for source in sources:
            shapes.update(source.dict_shapes or ())
            shapes.update(source.element_dict_shapes)
        return replace(value, element_dict_shapes=frozenset(shapes)) if shapes else value

    def _join(self, left: AbstractTypeValue, right: AbstractTypeValue) -> AbstractTypeValue:
        joined = left.join(
            right,
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )
        return self._bound_type_depth(joined)

    def _bound_type_depth(self, value: AbstractTypeValue) -> AbstractTypeValue:
        """Widen recursively nested type structures beyond the configured limit.

        A bounded number of union alternatives does not bound structures such
        as ``tuple[tuple[...]]`` produced by loop-carried assignments.  Keep
        the outer tuple shape and known alternatives, but replace only the
        overly deep suffix with an unknown-size tuple containing Any.
        """
        limit = max(1, self.engine.options.max_type_depth)

        def bound(typ: ProperType, depth: int) -> ProperType:
            if depth >= limit:
                if isinstance(typ, TupleType):
                    return TupleType((ANY,), unknown_size=True)
                return ANY
            if isinstance(typ, TupleType):
                return TupleType(
                    tuple(bound(item, depth + 1) for item in typ.args),
                    unknown_size=typ.unknown_size,
                )
            if isinstance(typ, Instance) and typ.args:
                return Instance(
                    typ.type,
                    tuple(bound(item, depth + 1) for item in typ.args),
                )
            if isinstance(typ, UnionType):
                return UnionType(tuple(bound(item, depth + 1) for item in typ.items))
            if isinstance(typ, CallableType):
                args = (
                    None
                    if typ.arg_types is None
                    else tuple(bound(item, depth + 1) for item in typ.arg_types)
                )
                returned = bound(typ.return_type, depth + 1)
                if args == typ.arg_types and returned == typ.return_type:
                    return typ
                # Overload declarations are part of the callable: dropping
                # them makes every later call fall back to the union return
                # (``urlparse`` -> ``ParseResult | ParseResultBytes``).
                return CallableType(args, returned, overloads=typ.overloads)
            if isinstance(typ, TypeType):
                return TypeType(bound(typ.item, depth + 1))
            return typ

        bounded = frozenset(bound(typ, 0) for typ in value.types)
        if bounded == value.types:
            return value
        return AbstractTypeValue(
            bounded,
            unknown=value.unknown,
            callable_targets=value.callable_targets,
            class_targets=value.class_targets,
            dict_shapes=value.dict_shapes,
        )

    def _join_normal_results(self, values: Iterable[AbstractTypeValue]) -> AbstractTypeValue:
        """Join values from branches that can complete normally."""
        candidates = list(values)
        normal = [value for value in candidates if not self._is_never_value(value)]
        result = join_all(
            normal or candidates,
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )
        return self._bound_type_depth(result)

    def _join_environments(
        self,
        left: dict[str, AbstractTypeValue],
        right: dict[str, AbstractTypeValue],
    ) -> dict[str, AbstractTypeValue]:
        result: dict[str, AbstractTypeValue] = {}
        for name in left.keys() | right.keys():
            left_value = left.get(name, AbstractTypeValue.unresolved())
            right_value = right.get(name, AbstractTypeValue.unresolved())
            result[name] = self._join(left_value, right_value)
        return result

    def _fill_missing_attribute_joins(
        self,
        baseline: dict[str, AbstractTypeValue],
        left: dict[str, AbstractTypeValue],
        right: dict[str, AbstractTypeValue],
    ) -> None:
        """Keep branch-local attribute writes from replacing the old value.

        Attribute writes are represented in the environment as dotted keys
        (``c.x``).  Without a value in the branch that did not write the
        attribute, a join would use only the written branch and report the
        mutation as unconditional.  Seed the missing side with the attribute's
        pre-branch value when it can be resolved.
        """
        for present, missing in ((left, right), (right, left)):
            for key, value in list(present.items()):
                if "." not in key or key in missing:
                    continue
                base_name, _, attribute = key.partition(".")
                if "." in attribute:
                    continue
                base = baseline.get(base_name) or self.engine._module_environment.get(base_name)
                if base is None:
                    continue
                previous = self.engine._member_rules._attribute_value(base, attribute)
                if previous.public_type() is not None:
                    missing[key] = previous

    def _join_many_environments(
        self, environments: Iterable[dict[str, AbstractTypeValue]]
    ) -> dict[str, AbstractTypeValue]:
        iterator = iter(environments)
        try:
            result = dict(next(iterator))
        except StopIteration:
            return {}
        for environment in iterator:
            result = self._join_environments(result, environment)
        return result

    def _instance(self, raw_type: type, *args: ProperType) -> AbstractTypeValue:
        return AbstractTypeValue.from_type(self._proper_instance(raw_type, *args))

    def _proper_instance(self, raw_type: type, *args: ProperType) -> Instance | TupleType:
        if raw_type is tuple:
            return TupleType(tuple(args) or (ANY,), unknown_size=not args)
        self._register_type_hierarchy(raw_type)
        return Instance(self.engine.type_system.to_class_descriptor(raw_type), tuple(args))

    def _register_type_hierarchy(self, raw_type: type) -> None:
        # tuple has a dedicated structural representation and must never be
        # inserted into the nominal class graph.  Tuple subclasses still get
        # registered, but their builtin tuple base is intentionally skipped.
        if raw_type is tuple:
            return
        if raw_type in self.engine._registered_hierarchy:
            return
        self.engine._registered_hierarchy.add(raw_type)
        descriptor = self.engine.type_system.to_class_descriptor(raw_type)
        for base in getattr(raw_type, "__bases__", ()):
            self._register_type_hierarchy(base)
            self.engine.type_system.add_subclass_edge(
                super_class=self.engine.type_system.to_class_descriptor(base),
                sub_class=descriptor,
            )

    def _synthetic_instance(self, full_name: str, *, unresolved=False) -> Instance | TupleType:
        if full_name == "builtins.tuple":
            return TupleType(())
        raw = self.engine._synthetic_types.get(full_name)
        if raw is None:
            module, _, name = full_name.rpartition(".")
            raw = type(
                name, (), {"__module__": module, "__pyflow_unresolved_external__": unresolved}
            )
            self.engine._synthetic_types[full_name] = raw
        # Synthetic source classes are freshly created nominal classes,
        # never the builtin tuple constructor handled above.
        return cast(Instance, self._proper_instance(raw))

    def _contains_raw(self, value: AbstractTypeValue, raw_type: type) -> bool:
        return any(
            isinstance(typ, Instance) and typ.type.raw_type is raw_type for typ in value.types
        )

    @staticmethod
    def _is_never_value(value: AbstractTypeValue) -> bool:
        """Whether evaluating a value cannot complete normally."""
        return not value.unknown and value.types == frozenset((NEVER,))

    def _remove_none(self, value: AbstractTypeValue) -> AbstractTypeValue:
        return value.without_type(NoneType)

    @staticmethod
    def _is_none_literal(node: ast.expr) -> bool:
        return isinstance(node, ast.Constant) and node.value is None

    def _unwrap_single_generic(self, value: AbstractTypeValue) -> AbstractTypeValue:
        values = []
        for typ in value.types:
            if isinstance(typ, Instance) and typ.args:
                values.append(AbstractTypeValue.from_type(typ.args[-1]))
        if values:
            return join_all(values, self.engine.type_system)
        if any(
            isinstance(typ, Instance)
            and typ.type.raw_type in {cabc.Coroutine, cabc.Awaitable, asyncio.Future, asyncio.Task}
            for typ in value.types
        ):
            return AbstractTypeValue.from_type(ANY)
        # ``__aenter__`` may return a plain ``Self`` instance rather than an
        # awaitable; unwrapping must not discard that known type.
        return value if value.types else AbstractTypeValue.unresolved()

    def _resolve_lexical_function(self, name: str, scope: str) -> str | None:
        current = scope
        while current:
            candidate = f"{current}.{name}"
            function = self.engine._functions.get(candidate)
            # Class namespaces are not lexical closures for method bodies:
            # ``render(...)`` inside another method does not mean
            # ``self.render(...)``.  Nested functions have ``owner is None``.
            if function is not None and function.owner is None:
                return candidate
            if "." not in current:
                break
            current = current.rpartition(".")[0]
        candidate = f"{self.engine._module_name}.{name}"
        return candidate if candidate in self.engine._functions else None

    def _is_typing_special_form(self, node: ast.expr) -> bool:
        """Whether ``node`` names a typing construct resolved by annotations."""
        name = _expression_name(node)
        if name is None:
            return False
        resolved = self._resolve_import_name(name) or name
        if resolved.split(".", 1)[0] in {"typing", "typing_extensions"}:
            return True
        if name.rsplit(".", 1)[-1] not in _TYPING_SPECIAL_FORM_NAMES:
            return False
        if name in self.engine._imports:
            return True
        return any(
            module in {"typing", "typing_extensions"} for module in self.engine._star_imports
        )

    def _resolve_import_name(self, name: str) -> str | None:
        direct = self.engine._imports.get(name)
        if direct is not None:
            return direct
        prefix, separator, remainder = name.partition(".")
        if not separator or prefix not in self.engine._imports:
            for star_module in self.engine._star_imports:
                candidate = f"{star_module}.{name}"
                if self.engine._member_rules._external_type(candidate) is not None:
                    return candidate
            return None
        target = self.engine._imports[prefix]
        if name == target or name.startswith(f"{target}."):
            return name
        return f"{target}.{remainder}"

    def _qualified_callee_name(self, node: ast.expr) -> str | None:
        name = _expression_name(node)
        if name is None:
            return None
        return self._resolve_import_name(name) or name

    def _resolve_class_expression(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Subscript):
            node = node.value
        name = _expression_name(node)
        if name is None:
            return None
        local = self.engine._class_aliases.get(name)
        if local is not None:
            return local
        imported = self._resolve_import_name(name)
        if imported is not None:
            return imported
        qualified = f"{self.engine._module_name}.{name}"
        if qualified in self.engine._classes:
            return qualified
        if hasattr(builtins, name) and isinstance(getattr(builtins, name), type):
            return f"builtins.{name}"
        return name
