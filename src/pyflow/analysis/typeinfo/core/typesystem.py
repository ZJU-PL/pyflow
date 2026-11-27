# This file is part of PyFlow.
#
# SPDX-FileCopyrightText: 2019–2026 Pynguin Contributors
# SPDX-License-Identifier: MIT
#
"""Type system registry, subtyping graph, and runtime type-hint conversion.

Core immutable type nodes live in :mod:`.types`, class descriptors in
:mod:`.descriptors`, visitors/subtyping in :mod:`.visitors`, and usage-trace
signature guessing in :mod:`.signatures`.  This module exposes :class:`TypeSystem`
and re-exports all core symbols for backward compatibility.
"""

from __future__ import annotations

import collections.abc as cabc
import functools
import inspect
import logging
import re
import types
import typing
from collections import defaultdict
from typing import (
    Any,
    ForwardRef,
    _BaseGenericAlias,  # noqa: PLC2701
    _eval_type,  # noqa: PLC2701
    cast,
    get_args,
    get_origin,
)

import networkx as nx
from typing_inspect import is_union_type

from pyflow.analysis.typeinfo.core.runtime import (
    COLLECTIONS,
    PRIMITIVES,
    get_method_for_signature,
)
from pyflow.util.orderedset import OrderedSet

from .descriptors import (
    ClassDescriptor,
    _is_signatureless_member,
    _typeshed_class_members,
)
from .signatures import (
    STRING_SUBTYPES,
    InferredSignature,
    NamedDefaultDict,
    _ARGUMENT_ATTRIBUTES,
    _DICT_KEY_ATTRIBUTES,
    _DICT_KEY_FROM_ARGUMENT_TYPES,
    _DICT_VALUE_ATTRIBUTES,
    _DICT_VALUE_FROM_ARGUMENT_TYPES,
    _EMPTY_SET,
    _LIST_ELEMENT_ATTRIBUTES,
    _LIST_ELEMENT_FROM_ARGUMENT_TYPES,
    _LIST_ELEMENT_FROM_ARGUMENT_TYPES_PATH,
    _SET_ELEMENT_ATTRIBUTES,
    _SET_ELEMENT_FROM_ARGUMENT_TYPES,
    _SET_ELEMENT_FROM_ARGUMENT_TYPES_PATH,
    _STRING_SUBTYPE_ATTRIBUTES,
    _TUPLE_ELEMENT_ATTRIBUTES,
    _TUPLE_ELEMENT_FROM_ARGUMENT_TYPES,
)
from .types import (
    ANY,
    NEVER,
    NONE_TYPE,
    UNSUPPORTED,
    AnyType,
    CallableType,
    CSVString,
    EmailString,
    HexadecimalString,
    Instance,
    IPv4String,
    IPv6String,
    ISOColorString,
    ISODateString,
    ISOTimeString,
    LiteralType,
    NeverType,
    NoneType,
    NumericString,
    PhoneNumberString,
    ProperType,
    SHA256String,
    SignatureInfo,
    StringSubtype,
    TupleType,
    TypeGuessingStats,
    TypeType,
    TypeVarType,
    UnionType,
    Unsupported,
    URLString,
    UUIDString,
    Variance,
    make_union,
    normalize_generic_args,
)
from .visitors import (
    TypeReprVisitor,
    TypeStringVisitor,
    TypeVisitor,
    _CollectionTypeVisitor,
    _is_partial_type_match,
    _MaybeSubtypeVisitor,
    _PartialTypeMatch,
    _PrimitiveTypeVisitor,
    _SubtypeDistanceVisitor,
    _SubtypeVisitor,
    _sum_distances,
    is_collection_type,
    is_primitive_type,
)

if typing.TYPE_CHECKING:
    from collections.abc import Callable

    from pyflow.analysis.typeinfo.inference.providers import InferenceProvider

_LOGGER = logging.getLogger(__name__)

_TRANSPARENT_WRAPPERS = frozenset(
    origin
    for origin in (
        getattr(typing, "Annotated", None),
        getattr(typing, "Final", None),
        getattr(typing, "ClassVar", None),
    )
    if origin is not None
)


class TypeSystem:  # noqa: PLR0904
    """Central type registry, inheritance graph, and subtyping engine."""

    def __init__(self):  # noqa: D107
        self._structural_checks: set[tuple[ProperType, ProperType]] = set()
        # Memo for ``domain._normalize_types``; cleared with the subtype
        # caches so class-graph mutations cannot produce stale unions.
        self._normalize_cache: dict[frozenset[ProperType], frozenset[ProperType]] = {}
        # Memo for runtime MRO/inspect.signature member extraction, keyed by
        # raw runtime type (immutable; overlaid with dynamic descriptor members).
        self._runtime_members_cache: dict[type | types.UnionType, dict[str, ProperType]] = {}
        self._graph: nx.DiGraph[ClassDescriptor] = nx.DiGraph()
        self._types: dict[str, ClassDescriptor] = {}
        self._attribute_map: dict[str, OrderedSet[ClassDescriptor]] = defaultdict(OrderedSet)
        self.primitive_proper_types = [self.convert_type_hint(prim) for prim in PRIMITIVES]
        self.collection_proper_types = [self.convert_type_hint(coll) for coll in COLLECTIONS]
        numeric = [complex, float, int, bool]
        self.numeric_tower: dict[Instance, list[Instance]] = cast(
            "dict[Instance, list[Instance]]",
            {
                self.convert_type_hint(typ): [self.convert_type_hint(tp) for tp in numeric[idx:]]
                for idx, typ in enumerate(numeric)
            },
        )
        for subtype in STRING_SUBTYPES:
            type_info = ClassDescriptor(subtype)
            self.add_subclass_edge(super_class=self.to_class_descriptor(str), sub_class=type_info)

    def enable_numeric_tower(self):
        """Enable the PEP 484 numeric tower (``bool <: int <: float <: complex``)."""
        bool_info = self.to_class_descriptor(bool)
        int_info = self.to_class_descriptor(int)
        float_info = self.to_class_descriptor(float)
        complex_info = self.to_class_descriptor(complex)
        self.add_subclass_edge(super_class=int_info, sub_class=bool_info)
        self.add_subclass_edge(super_class=float_info, sub_class=int_info)
        self.add_subclass_edge(super_class=complex_info, sub_class=float_info)

    def add_subclass_edge(
        self, *, super_class: ClassDescriptor, sub_class: ClassDescriptor
    ) -> None:
        """Add a subclass edge ``super_class -> sub_class``."""
        if self._graph.has_edge(super_class, sub_class):
            return
        self._graph.add_edge(super_class, sub_class)
        type(self).is_subclass.cache_clear()
        type(self).get_subclasses.cache_clear()
        type(self).get_superclasses.cache_clear()
        type(self).subtype_distance.cache_clear()
        type(self).is_subtype.cache_clear()
        type(self).is_maybe_subtype.cache_clear()
        self._normalize_cache.clear()

    @functools.lru_cache(maxsize=1024)
    def get_subclasses(self, klass: ClassDescriptor) -> OrderedSet[ClassDescriptor]:
        """Return all descendants of *klass* including *klass* itself."""
        if klass not in self._graph:
            return OrderedSet([klass])
        result: OrderedSet[ClassDescriptor] = OrderedSet(nx.descendants(self._graph, klass))
        result.add(klass)
        return result

    @functools.lru_cache(maxsize=1024)
    def get_superclasses(self, klass: ClassDescriptor) -> OrderedSet[ClassDescriptor]:
        """Return all ancestors of *klass* including *klass* itself."""
        if klass not in self._graph:
            return OrderedSet([klass])
        result: OrderedSet[ClassDescriptor] = OrderedSet(nx.ancestors(self._graph, klass))
        result.add(klass)
        return result

    def get_type_outside_of(
        self, klasses: OrderedSet[ClassDescriptor]
    ) -> OrderedSet[ClassDescriptor]:
        """Find registered types that do not belong to *klasses* or any of their subclasses."""
        results = OrderedSet(self._types.values())
        for info in klasses:
            results.difference_update(self.get_subclasses(info))
        return results

    @functools.lru_cache(maxsize=16384)
    def is_subclass(self, left: ClassDescriptor, right: ClassDescriptor) -> bool:
        """Return whether *left* is a subclass of *right*."""
        if left in self._graph:
            if right in self._graph and nx.has_path(self._graph, right, left):
                return True
            for ancestor in nx.ancestors(self._graph, left):
                try:
                    if issubclass(ancestor.raw_type, right.raw_type):
                        return True
                except TypeError:
                    continue
        try:
            return issubclass(left.raw_type, right.raw_type)
        except TypeError:
            return False

    @functools.lru_cache(maxsize=16384)
    def is_subtype(self, left: ProperType, right: ProperType) -> bool:
        """Return whether ``left <: right``."""
        if left == right:
            return True
        if isinstance(right, AnyType):
            return True
        if isinstance(left, LiteralType):
            if isinstance(right, LiteralType):
                return left.value == right.value and left.base == right.base
            if isinstance(right, UnionType):
                return any(self.is_subtype(left, item) for item in right.items)
            return self.is_subtype(left.base, right)
        if isinstance(right, LiteralType):
            return False
        if isinstance(right, UnionType) and not isinstance(left, UnionType):
            return any(self.is_subtype(left, right_elem) for right_elem in right.items)
        return left.accept(_SubtypeVisitor(self, right, self.is_subtype))

    @functools.lru_cache(maxsize=16384)
    def is_maybe_subtype(self, left: ProperType, right: ProperType) -> bool:
        """Return whether *left* may be a subtype of *right* (existential on left unions)."""
        if isinstance(right, AnyType):
            return True
        if isinstance(left, LiteralType):
            if isinstance(right, LiteralType):
                return left.value == right.value and left.base == right.base
            return self.is_maybe_subtype(left.base, right)
        if isinstance(right, LiteralType):
            return False
        if isinstance(right, UnionType) and not isinstance(left, UnionType):
            return any(self.is_maybe_subtype(left, right_elem) for right_elem in right.items)
        return left.accept(_MaybeSubtypeVisitor(self, right, self.is_maybe_subtype))

    def invalidate_subtype_caches(self) -> None:
        """Discard memoized subtype answers after descriptors were mutated."""
        type(self).is_subtype.cache_clear()
        type(self).is_maybe_subtype.cache_clear()
        self._normalize_cache.clear()

    def class_descriptor(self, full_name: str) -> ClassDescriptor | None:
        """Return the descriptor registered for a fully qualified class name."""
        return self._types.get(full_name)

    def forget_class_descriptor(self, full_name: str) -> None:
        """Drop a descriptor so a later analysis can recreate fresh state."""
        descriptor = self._types.pop(full_name, None)
        if descriptor is None:
            return
        if self._graph.has_node(descriptor):
            self._graph.remove_node(descriptor)
        for descriptors in self._attribute_map.values():
            descriptors.discard(descriptor)
        self.invalidate_subtype_caches()

    @property
    def dot(self) -> str:
        """Return a string representation of the class graph."""
        return str(self._graph)

    def to_class_descriptor(self, typ: type | types.UnionType) -> ClassDescriptor:  # noqa: D417
        """Find or create a :class:`ClassDescriptor` for *typ*."""
        full_name = ClassDescriptor.to_full_name(typ)
        found = self._types.get(full_name)
        if found is not None:
            if found.raw_type is typ:
                return found
            existing_unresolved = bool(
                getattr(found.raw_type, "__pyflow_unresolved_external__", False)
            )
            new_unresolved = bool(getattr(typ, "__pyflow_unresolved_external__", False))
            if not (new_unresolved and not existing_unresolved):
                found.refresh(typ)
            return found
        info = ClassDescriptor(typ)
        self._types[info.full_name] = info
        self._graph.add_node(info)
        return info

    def find_class_descriptor(self, full_name: str) -> ClassDescriptor | None:
        """Find a registered :class:`ClassDescriptor` by full name."""
        return self._types.get(full_name)

    def get_members(self, descriptor: ClassDescriptor) -> dict[str, ProperType]:
        """Return static declarations, safely inspected runtime members, and typeshed fills."""
        raw = descriptor.raw_type
        runtime_members = self._runtime_members_cache.get(raw)
        if runtime_members is None:
            runtime_members = {}

            def convert(annotation):
                if isinstance(annotation, str):
                    from pyflow.analysis.typeinfo.resolution.annotations import (
                        BuiltinTypeLookup,
                        resolve_annotation,
                    )

                    return resolve_annotation(annotation, BuiltinTypeLookup()) or ANY
                return (
                    ANY
                    if annotation is inspect.Signature.empty
                    else self.convert_type_hint(annotation)
                )

            for parent in reversed(getattr(raw, "__mro__", ())):
                if parent in {object, typing.Protocol, typing.Generic}:
                    continue
                annotations = vars(parent).get("__annotations__")
                if isinstance(annotations, dict):
                    for name, annotation in annotations.items():
                        runtime_members[name] = convert(annotation)
                for name, member in vars(parent).items():
                    if name in {
                        "__init__",
                        "__init_subclass__",
                        "__subclasshook__",
                        "__dict__",
                        "__weakref__",
                        "__doc__",
                        "__module__",
                        "__qualname__",
                        "__annotations__",
                        "__slots__",
                    }:
                        continue
                    if isinstance(member, property) and member.fget is not None:
                        annotation = member.fget.__annotations__.get("return")
                        runtime_members[name] = convert(annotation)
                    elif inspect.isdatadescriptor(member):
                        runtime_members[name] = ANY
                    elif inspect.isroutine(member) or callable(member):
                        try:
                            signature = inspect.signature(member)
                            arguments = tuple(signature.parameters.values())[1:]
                            runtime_members[name] = CallableType(
                                tuple(convert(arg.annotation) for arg in arguments),
                                convert(signature.return_annotation),
                            )
                        except (ValueError, TypeError):
                            runtime_members[name] = CallableType(None, ANY)
            self._runtime_members_cache[raw] = runtime_members

        members = dict(runtime_members)
        for parent in self.get_superclasses(descriptor):
            members.update(parent.members)
        members.update(descriptor.members)
        stub_members = _typeshed_class_members(descriptor.full_name)
        if stub_members:
            for name, member in stub_members.items():
                existing = members.get(name)
                if existing is None or _is_signatureless_member(existing):
                    members[name] = member
        return members

    def find_by_attribute(self, attr: str) -> OrderedSet[ClassDescriptor]:
        """Search for all registered types that define *attr*."""
        return self._attribute_map[attr]

    def get_all_types(self) -> list[ClassDescriptor]:
        """Return all registered class descriptors."""
        return list(self._types.values())

    def get_shortest_path_length(self, start: ClassDescriptor, end: ClassDescriptor) -> int | None:
        """Return the shortest subclassing path length from *start* to *end*."""
        if start in self._graph and end in self._graph:
            try:
                length = int(nx.shortest_path_length(self._graph, start, end))
                if length >= 0:
                    return length
            except nx.NetworkXNoPath:
                pass

        try:
            if not issubclass(end.raw_type, start.raw_type):
                return None
            if start.raw_type in end.raw_type.__mro__:
                return end.raw_type.__mro__.index(start.raw_type)
            return 1
        except (AttributeError, TypeError, ValueError):
            return None

    def push_attributes_down(self) -> None:
        """Deduplicate inherited attributes so only defining ancestors retain them."""
        reach_in_sets: dict[ClassDescriptor, set[str]] = defaultdict(set)
        reach_out_sets: dict[ClassDescriptor, set[str]] = defaultdict(set)

        object_info = self.find_class_descriptor("builtins.object")
        assert object_info is not None
        object_info.attributes.difference_update({"__lt__", "__le__", "__gt__", "__ge__"})

        work_list = list(self._graph.nodes)
        while len(work_list) > 0:
            current = work_list.pop()
            old_val = set(reach_out_sets[current])
            for pred in self._graph.predecessors(current):
                reach_in_sets[current].update(reach_out_sets[pred])
            current.attributes.difference_update(reach_in_sets[current])
            reach_out_sets[current] = set(reach_in_sets[current])
            reach_out_sets[current].update(current.attributes)
            if old_val != reach_out_sets[current]:
                work_list.extend(self._graph.successors(current))
        for type_info in self._graph.nodes:
            for attribute in type_info.attributes:
                self._attribute_map[attribute].add(type_info)

    def wrap_var_param_type(self, typ: ProperType, param_kind) -> ProperType:
        """Wrap ``*args`` / ``**kwargs`` element types in ``list`` / ``dict``."""
        if param_kind == inspect.Parameter.VAR_POSITIONAL:
            return Instance(self.to_class_descriptor(list), (typ,))
        if param_kind == inspect.Parameter.VAR_KEYWORD:
            return Instance(self.to_class_descriptor(dict), (self.convert_type_hint(str), typ))
        return typ

    def infer_signature_with_provider(
        self,
        method: Callable,
        type_inference_provider: InferenceProvider,
    ) -> InferredSignature:
        """Infer a callable's signature using *type_inference_provider*."""
        return self.infer_signature(method, type_inference_provider.provide)

    @staticmethod
    def type_hints_provider(method: Callable) -> dict[str, Any]:
        """Provide PEP 484 runtime type hints for *method*, if available."""
        try:
            hints = typing.get_type_hints(method)
        except (AttributeError, NameError, TypeError) as exc:
            _LOGGER.debug("Could not retrieve type hints for %s", method)
            _LOGGER.debug(exc)
            hints = {}
        return hints

    def infer_signature(
        self,
        method: Callable,
        type_hint_provider: Callable[[Callable], dict],
    ) -> InferredSignature:
        """Infer a callable's signature using *type_hint_provider*."""
        method_for_signature = get_method_for_signature(method)
        try:
            method_signature = inspect.signature(method_for_signature)
        except (ValueError, TypeError):
            method_signature = inspect.Signature(
                parameters=[
                    inspect.Parameter(
                        name="args",
                        kind=inspect.Parameter.VAR_POSITIONAL,
                        annotation=inspect.Signature.empty,
                    ),
                    inspect.Parameter(
                        name="kwargs",
                        kind=inspect.Parameter.VAR_KEYWORD,
                        annotation=inspect.Signature.empty,
                    ),
                ],
                return_annotation=inspect.Signature.empty,
            )

        hints = type_hint_provider(method)
        parameters: dict[str, ProperType] = {}

        from pyflow.analysis.typeinfo.inference.providers import HintInference  # lazy: break cycle

        hints_provider_for_statistics = HintInference()
        hints_for_statistics: dict = hints_provider_for_statistics.provide(method)
        parameters_for_statistics: dict[str, ProperType] = {}
        for param_name in method_signature.parameters:
            if param_name == "self":
                continue
            parameters[param_name] = self.convert_type_hint(hints.get(param_name))
            parameters_for_statistics[param_name] = self.convert_type_hint(
                hints_for_statistics.get(param_name), unsupported=UNSUPPORTED
            )

        return_type: ProperType = self.convert_type_hint(hints.get("return"))
        return_type_for_statistics: ProperType = self.convert_type_hint(
            hints_for_statistics.get("return"), unsupported=UNSUPPORTED
        )

        return InferredSignature(
            signature=method_signature,
            original_parameters=parameters,
            original_return_type=return_type,
            type_system=self,
            parameters_for_statistics=parameters_for_statistics,
            return_type_for_statistics=return_type_for_statistics,
        )

    _FIND_DOT_SEPARATED_IDENTIFIERS = re.compile(r"[.a-zA-Z0-9_]+\.[a-zA-Z0-9_]+")

    def try_to_load_type(self, candidate: str, globs) -> ProperType:
        """Try to evaluate a string type expression in *globs*."""
        glob: dict[str, Any] = {}
        exec("from typing import *", glob)  # noqa: S102
        glob.update(globs)
        for potential_type in self._FIND_DOT_SEPARATED_IDENTIFIERS.finditer(candidate):
            potential_import = potential_type.group(0).rpartition(".")[0]
            _LOGGER.info("Try to import %s", potential_import)
            try:
                exec("import " + potential_import, glob)  # noqa: S102
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug(err)
        try:
            ref = ForwardRef(candidate)
            return self.convert_type_hint(_eval_type(ref, glob, glob))
        except Exception:  # noqa: BLE001
            return ANY

    def convert_type_hint(self, hint: Any, unsupported: ProperType = ANY) -> ProperType:
        """Convert a Python runtime type hint to a :class:`ProperType`."""
        if hint is Any or hint is None:
            return ANY
        if hint is type(None):
            return NONE_TYPE
        if hint in {typing.NoReturn, getattr(typing, "Never", None)}:
            return NEVER
        if hint is tuple:
            return TupleType((ANY,), unknown_size=True)
        origin = get_origin(hint)
        if origin in _TRANSPARENT_WRAPPERS:
            raw_args = get_args(hint)
            return (
                self.convert_type_hint(raw_args[0], unsupported=unsupported)
                if raw_args
                else unsupported
            )
        if origin is typing.Literal:
            raw_args = get_args(hint)
            if not raw_args:
                return unsupported
            items: list[ProperType] = []
            for value in raw_args:
                if value is None:
                    items.append(NONE_TYPE)
                else:
                    base = Instance(self.to_class_descriptor(type(value)))
                    items.append(LiteralType(value, base))
            return make_union(items)
        if origin is tuple:
            raw_args = get_args(hint)
            if len(raw_args) == 2 and raw_args[1] is Ellipsis:
                return TupleType(
                    (self.convert_type_hint(raw_args[0], unsupported=unsupported),),
                    unknown_size=True,
                )
            args = self.__convert_args_if_exists(hint, unsupported=unsupported)
            if not args:
                return TupleType((ANY,), unknown_size=True)
            return TupleType(args)
        if origin is type:
            type_args = get_args(hint)
            return TypeType(
                self.convert_type_hint(type_args[0], unsupported=unsupported) if type_args else ANY
            )
        if origin is cabc.Callable:
            callable_args = get_args(hint)
            if len(callable_args) != 2:
                return CallableType(None, ANY)
            parameters, returned = callable_args
            return_type = self.convert_type_hint(returned, unsupported=unsupported)
            if parameters is Ellipsis or not isinstance(parameters, list | tuple):
                return CallableType(None, return_type)
            return CallableType(
                tuple(
                    self.convert_type_hint(parameter, unsupported=unsupported)
                    for parameter in parameters
                ),
                return_type,
            )
        if is_union_type(hint) or isinstance(hint, types.UnionType):
            return make_union(self.__convert_args_if_exists(hint, unsupported=unsupported))
        if isinstance(hint, _BaseGenericAlias | types.GenericAlias):
            descriptor = self.to_class_descriptor(hint.__origin__)
            args = normalize_generic_args(
                descriptor,
                self.__convert_args_if_exists(hint, unsupported=unsupported),
            )
            return Instance(descriptor, args)
        if isinstance(hint, type):
            descriptor = self.to_class_descriptor(hint)
            return Instance(descriptor, normalize_generic_args(descriptor, ()))
        _LOGGER.debug("Unknown type hint: %s", hint)
        return unsupported

    def __convert_args_if_exists(
        self, hint: Any, unsupported: ProperType
    ) -> tuple[ProperType, ...]:
        if hasattr(hint, "__args__"):
            return tuple(self.convert_type_hint(t, unsupported=unsupported) for t in hint.__args__)
        return ()

    def make_instance(self, typ: ClassDescriptor) -> Instance | TupleType | NoneType:
        """Create an instance type from *typ*, normalizing tuple/None/builtin generics."""
        if typ.full_name == "builtins.tuple":
            return TupleType((ANY,), unknown_size=True)
        if typ.full_name == "builtins.NoneType":
            return NONE_TYPE
        return Instance(typ, normalize_generic_args(typ, ()))

    @staticmethod
    def _fixup_known_generics(result: Instance) -> Instance:
        normalized = normalize_generic_args(result.type, result.args)
        if normalized == result.args:
            return result
        return Instance(result.type, normalized)

    @functools.lru_cache(maxsize=16384)
    def subtype_distance(self, supertype: ProperType, subtype: ProperType) -> int | None:
        """Compute the shortest subclassing distance from *supertype* to *subtype*."""
        if not self.is_maybe_subtype(subtype, supertype):
            return None
        return supertype.accept(_SubtypeDistanceVisitor(self, subtype))


__all__ = [
    "ANY",
    "AnyType",
    "CSVString",
    "CallableType",
    "ClassDescriptor",
    "EmailString",
    "HexadecimalString",
    "IPv4String",
    "IPv6String",
    "ISOColorString",
    "ISODateString",
    "ISOTimeString",
    "InferredSignature",
    "Instance",
    "LiteralType",
    "NEVER",
    "NONE_TYPE",
    "NamedDefaultDict",
    "NeverType",
    "NoneType",
    "NumericString",
    "PhoneNumberString",
    "ProperType",
    "SHA256String",
    "STRING_SUBTYPES",
    "SignatureInfo",
    "StringSubtype",
    "TupleType",
    "TypeGuessingStats",
    "TypeReprVisitor",
    "TypeStringVisitor",
    "TypeSystem",
    "TypeType",
    "TypeVarType",
    "TypeVisitor",
    "UNSUPPORTED",
    "URLString",
    "UUIDString",
    "UnionType",
    "Unsupported",
    "Variance",
    "_ARGUMENT_ATTRIBUTES",
    "_CollectionTypeVisitor",
    "_DICT_KEY_ATTRIBUTES",
    "_DICT_KEY_FROM_ARGUMENT_TYPES",
    "_DICT_VALUE_ATTRIBUTES",
    "_DICT_VALUE_FROM_ARGUMENT_TYPES",
    "_EMPTY_SET",
    "_LIST_ELEMENT_ATTRIBUTES",
    "_LIST_ELEMENT_FROM_ARGUMENT_TYPES",
    "_LIST_ELEMENT_FROM_ARGUMENT_TYPES_PATH",
    "_MaybeSubtypeVisitor",
    "_PartialTypeMatch",
    "_PrimitiveTypeVisitor",
    "_SET_ELEMENT_ATTRIBUTES",
    "_SET_ELEMENT_FROM_ARGUMENT_TYPES",
    "_SET_ELEMENT_FROM_ARGUMENT_TYPES_PATH",
    "_STRING_SUBTYPE_ATTRIBUTES",
    "_SubtypeDistanceVisitor",
    "_SubtypeVisitor",
    "_TUPLE_ELEMENT_ATTRIBUTES",
    "_TUPLE_ELEMENT_FROM_ARGUMENT_TYPES",
    "_is_partial_type_match",
    "_is_signatureless_member",
    "_sum_distances",
    "_typeshed_class_members",
    "is_collection_type",
    "is_primitive_type",
    "make_union",
    "normalize_generic_args",
]
