"""Resolve names, class hierarchies, attributes, properties, and constructors."""

from __future__ import annotations

import ast
import asyncio
import builtins
import collections.abc as cabc
import contextvars
import dataclasses
import datetime
import io
import logging
import os
import re
import subprocess
import threading
import types
from dataclasses import replace
from typing import Iterable

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NONE_TYPE,
    CallableType,
    Instance,
    ProperType,
    TupleType,
    TypeType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference._engine.component import InferenceComponent
from pyflow.analysis.typeinfo.inference._engine.state import _ClassInfo, _FunctionInfo
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue, join_all
from pyflow.analysis.typeinfo.resolution.annotations import BuiltinTypeLookup
from pyflow.analysis.typeinfo.resolution.typing_syntax import substitute_type_vars

# Imported aliases such as MappingProxyType differ from runtime class names.
_STDLIB_CLASS_ALIASES = {
    name: f"{value.__module__}.{value.__name__}"
    for name, value in vars(types).items()
    if isinstance(value, type) and value.__name__ != name
}


class MemberInference(InferenceComponent):
    """Resolve names, class hierarchies, attributes, properties, and constructors."""

    _ENUM_KIND_NAMES = {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"}

    def _name_value(
        self,
        name: str,
        environment: dict[str, AbstractTypeValue],
        scope: str,
    ) -> AbstractTypeValue:
        if name in environment:
            return environment[name]
        if scope != self.engine._module_name:
            module_value = self.engine._module_environment.get(name)
            if module_value is not None:
                return module_value
        qualified = self.engine._value_rules._resolve_lexical_function(name, scope)
        if qualified is not None:
            return self.engine._function_rules._function_value(self.engine._functions[qualified])
        class_name = self.engine._class_aliases.get(name)
        if class_name is not None:
            return AbstractTypeValue.from_type(
                self.engine._classes[class_name].instance,
                class_target=class_name,
            )
        imported = self.engine._value_rules._resolve_import_name(name)
        if imported is not None:
            if imported in self.engine._module_names:
                # ``import time`` binds the module, not a class that happens
                # to share its name (``time`` -> ``datetime.time``).  Module
                # objects themselves are unmodelled; member access resolves
                # through qualified names instead.
                external = self._external_type(imported)
                if external is None:
                    return AbstractTypeValue.unresolved()
                if isinstance(external, TypeType):
                    external = external.item
                return AbstractTypeValue.from_type(external)
            external = BuiltinTypeLookup()(imported)
            builtin_class = external is not None
            if external is None:
                external = self._external_type(imported)
            if external is None:
                global_value = self.engine._stdlib_rules._stdlib_global_value(imported)
                if global_value is not None:
                    return global_value
            if isinstance(external, TypeType):
                # External class facts are exposed as the runtime type
                # ``type[T]``.  Internally a class object is represented by
                # ``T`` plus a class target so calls can construct ``T``.
                external = external.item
            return AbstractTypeValue.from_type(
                external,
                unknown=external is None,
                class_target=self._external_class_target(
                    external,
                    imported.rsplit(".", 1)[-1],
                    builtin_class=builtin_class,
                ),
            )
        builtin = getattr(builtins, name, None)
        if isinstance(builtin, type):
            return AbstractTypeValue.from_type(
                self.engine._value_rules._proper_instance(builtin), class_target=f"builtins.{name}"
            )
        if builtin is not None and callable(builtin):
            value = self._builtin_callable_value(name)
            if value is not None:
                return value
        return AbstractTypeValue.unresolved()

    def _builtin_callable_value(self, name: str) -> AbstractTypeValue | None:
        """Model builtin functions used as values (``f = len; f(x)``)."""
        int_type = self.engine._value_rules._proper_instance(int)
        str_type = self.engine._value_rules._proper_instance(str)
        bool_type = self.engine._value_rules._proper_instance(bool)
        iterator = self.engine._value_rules._proper_instance(cabc.Iterator, ANY)
        table: dict[str, CallableType] = {
            "len": CallableType((self.engine._value_rules._proper_instance(cabc.Sized),), int_type),
            "abs": CallableType((ANY,), ANY),
            "repr": CallableType((ANY,), str_type),
            "ascii": CallableType((ANY,), str_type),
            "format": CallableType((ANY, str_type), str_type),
            "print": CallableType(None, NONE_TYPE),
            "isinstance": CallableType((ANY, ANY), bool_type),
            "issubclass": CallableType((ANY, ANY), bool_type),
            "callable": CallableType((ANY,), bool_type),
            "hasattr": CallableType((ANY, str_type), bool_type),
            "getattr": CallableType((ANY, str_type), ANY),
            "setattr": CallableType((ANY, str_type, ANY), NONE_TYPE),
            "delattr": CallableType((ANY, str_type), NONE_TYPE),
            "hash": CallableType((ANY,), int_type),
            "id": CallableType((ANY,), int_type),
            "ord": CallableType((str_type,), int_type),
            "chr": CallableType((int_type,), str_type),
            "bin": CallableType((int_type,), str_type),
            "hex": CallableType((int_type,), str_type),
            "oct": CallableType((int_type,), str_type),
            "input": CallableType((str_type,), str_type),
            "open": CallableType(None, self.engine._value_rules._proper_instance(io.TextIOWrapper)),
            "iter": CallableType((ANY,), iterator),
            "next": CallableType((ANY,), ANY),
            "reversed": CallableType((ANY,), iterator),
            "enumerate": CallableType(
                None,
                self.engine._value_rules._proper_instance(
                    cabc.Iterator, TupleType((int_type, ANY))
                ),
            ),
            "zip": CallableType(
                None,
                self.engine._value_rules._proper_instance(
                    cabc.Iterator, TupleType((ANY,), unknown_size=True)
                ),
            ),
            "map": CallableType(None, iterator),
            "filter": CallableType(None, iterator),
            "sum": CallableType((ANY,), ANY),
            "min": CallableType(None, ANY),
            "max": CallableType(None, ANY),
            "any": CallableType((ANY,), bool_type),
            "all": CallableType((ANY,), bool_type),
            "round": CallableType(None, ANY),
            "divmod": CallableType((ANY, ANY), TupleType((ANY, ANY))),
            "pow": CallableType(None, ANY),
            "vars": CallableType(
                (ANY,), self.engine._value_rules._proper_instance(dict, str_type, ANY)
            ),
            "dir": CallableType((ANY,), self.engine._value_rules._proper_instance(list, str_type)),
            "sorted": CallableType((ANY,), self.engine._value_rules._proper_instance(list, ANY)),
            "slice": CallableType(None, ANY),
            "breakpoint": CallableType(None, NONE_TYPE),
        }
        signature = table.get(name)
        return None if signature is None else AbstractTypeValue.from_type(signature)

    def _enum_base_kind(self, base: str, seen: set[str] | None = None) -> str | None:
        """Return the enum base kind for a direct or inherited enum base."""
        short = base.rsplit(".", 1)[-1]
        if short in self._ENUM_KIND_NAMES:
            return short
        seen = set() if seen is None else seen
        if base in seen:
            return None
        seen.add(base)
        info = self.engine._classes.get(base)
        if info is None:
            alias = self.engine._class_aliases.get(short)
            if alias is not None:
                info = self.engine._classes.get(alias)
        if info is None:
            descriptor = self.engine.type_system.class_descriptor(base)
            if descriptor is not None and descriptor.enum_kind is not None:
                return descriptor.enum_kind
            return None
        for parent in info.bases:
            kind = self._enum_base_kind(parent, seen)
            if kind is not None:
                return kind
        return None

    def _is_enum_class_info(self, info: _ClassInfo | None) -> bool:
        return info is not None and any(
            self._enum_base_kind(base) is not None for base in info.bases
        )

    def _mro_names(self, class_name: str) -> list[str]:
        """Approximate C3 linearization over classes known to this engine."""
        if class_name in self.engine._mro_cache:
            return list(self.engine._mro_cache[class_name])
        info = self.engine._classes.get(class_name)
        if info is None:
            return [class_name]
        bases = [base for base in info.bases if base in self.engine._classes]
        if not bases:
            result = [class_name]
        else:
            sequences = [self._mro_names(base) for base in bases] + [list(bases)]
            result = [class_name]
            while sequences:
                for sequence in sequences:
                    head = sequence[0]
                    if not any(head in other[1:] for other in sequences):
                        break
                else:
                    result.extend(base for base in bases if base not in result)
                    break
                result.append(head)
                for sequence in sequences:
                    if sequence and sequence[0] == head:
                        sequence.pop(0)
                sequences = [sequence for sequence in sequences if sequence]
        self.engine._mro_cache[class_name] = result
        return list(result)

    def _super_value(
        self,
        node: ast.Call,
        environment: dict[str, AbstractTypeValue],
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue | None:
        if current_function is None or current_function.owner is None:
            return None
        owner = current_function.owner
        receiver_class: str | None = None
        if current_function.parameter_names:
            receiver = environment.get(current_function.parameter_names[0])
            if receiver is not None:
                for typ in receiver.types:
                    if isinstance(typ, Instance):
                        receiver_class = typ.type.full_name
                        break
        # ``super(SomeBase, self)`` starts the MRO after ``SomeBase`` rather
        # than after the enclosing class.
        start_class = owner
        if len(node.args) >= 2:
            start_value = self.engine._expression_rules._evaluate_expression(
                node.args[0],
                environment,
                scope=owner,
                current_function=current_function,
            )
            explicit = next(iter(start_value.class_targets), None)
            if explicit is None:
                for typ in start_value.types:
                    if isinstance(typ, Instance):
                        explicit = typ.type.full_name
                        break
            if explicit is not None:
                start_class = explicit
        mro = self._mro_names(receiver_class or owner)
        if start_class in mro:
            for candidate in mro[mro.index(start_class) + 1 :]:
                info = self.engine._classes.get(candidate)
                if info is not None:
                    return AbstractTypeValue.from_type(info.instance)
        info = self.engine._classes.get(start_class)
        if info is not None:
            for base in info.bases:
                base_info = self.engine._classes.get(base)
                if base_info is not None:
                    return AbstractTypeValue.from_type(base_info.instance)
            for superclass in self.engine.type_system.get_superclasses(info.instance.type):
                if superclass.full_name in {info.instance.type.full_name, "builtins.object"}:
                    continue
                if superclass.raw_type is tuple:
                    # ``tuple`` is represented by ``TupleType``; constructing
                    # an ``Instance`` for it is rejected by the type system.
                    return AbstractTypeValue.from_type(TupleType(()))
                return AbstractTypeValue.from_type(Instance(superclass))
        return None

    def _external_class_target(
        self,
        external: ProperType | None,
        name: str,
        *,
        builtin_class: bool = False,
    ) -> str | None:
        """Return the defining class name when an external symbol is a class."""
        if not isinstance(external, Instance):
            return None
        if not builtin_class and not self._looks_like_class(name):
            return None
        raw = external.type.raw_type
        module = getattr(raw, "__module__", "")
        if not builtin_class and module in {"builtins", "typing", "typing_extensions"}:
            return None
        # The external value is a class object only if the requested member is
        # the class itself, not an enum member or other uppercase attribute.
        if external.type.full_name.rsplit(".", 1)[-1] != name:
            aliased = _STDLIB_CLASS_ALIASES.get(name)
            if aliased is None or external.type.full_name != aliased:
                return None
        return external.type.full_name

    def _name_is_shadowed(
        self,
        name: str,
        environment: dict[str, AbstractTypeValue],
        scope: str,
    ) -> bool:
        """Whether a bare name resolves locally rather than to a builtin."""
        if name in environment:
            return True
        if self.engine._value_rules._resolve_lexical_function(name, scope) is not None:
            return True
        if self.engine._class_aliases.get(name) is not None:
            return True
        return self.engine._value_rules._resolve_import_name(name) is not None

    def _inherited_member(self, instance: Instance, attribute: str) -> AbstractTypeValue | None:
        """Resolve a member provided by a builtin or stdlib base class.

        Source classes are synthetic and only carry the members declared in
        their own body.  Subclasses of ``dict``/``list``/``Exception`` must
        still expose the inherited API (``get``, ``append``, ``args``, ...).
        """
        descriptor = instance.type
        cache_key = (descriptor.full_name, attribute)
        if cache_key in self.engine._inherited_members:
            cached = self.engine._inherited_members[cache_key]
            return None if cached is None else AbstractTypeValue.from_type(cached)
        found: ProperType | None = None
        for ancestor in self.engine.type_system.get_superclasses(descriptor):
            if ancestor is descriptor:
                continue
            raw = ancestor.raw_type
            if not isinstance(raw, type):
                continue
            if "__pyflow_unresolved_external__" in vars(raw):
                # Synthetic source classes are handled by the per-module class
                # tables; only real builtin/stdlib classes are inspected here.
                continue
            member = self.engine.type_system.get_members(ancestor).get(attribute)
            if member is not None:
                found = member
                break
        if found is None:
            # ``get_superclasses`` only knows classes registered with this
            # type system.  Builtins such as ``BaseException`` are not, so
            # consult the real MRO members (``args``, ``errno``, ...).
            found = self.engine.type_system.get_members(descriptor).get(attribute)
        self.engine._inherited_members[cache_key] = found
        return None if found is None else AbstractTypeValue.from_type(found)

    def _attribute_value(self, base: AbstractTypeValue, attribute: str) -> AbstractTypeValue:
        if self.engine._operator_rules._contains_any(base):
            return AbstractTypeValue.from_type(ANY)
        values: list[AbstractTypeValue] = []
        for typ in base.types:
            if attribute == "__class__":
                values.append(AbstractTypeValue.from_type(TypeType(typ)))
                continue
            class_object = (
                typ.item
                if isinstance(typ, TypeType) and isinstance(typ.item, Instance)
                else typ if isinstance(typ, Instance) and base.class_targets else None
            )
            if class_object is not None:
                nested_name = f"{class_object.type.full_name}.{attribute}"
                nested = self.engine._classes.get(nested_name)
                if nested is not None:
                    values.append(
                        AbstractTypeValue.from_type(
                            nested.instance, class_target=nested.qualified_name
                        )
                    )
                    continue
            if isinstance(typ, UnionType):
                values.extend(
                    self._attribute_value(AbstractTypeValue.from_type(item), attribute)
                    for item in typ.items
                )
                continue
            if not isinstance(typ, Instance):
                continue
            class_info = self.engine._classes.get(typ.type.full_name)
            if self._is_enum_class_info(class_info):
                if attribute in class_info.enum_values:
                    values.append(
                        AbstractTypeValue.from_type(
                            class_info.instance,
                            literal_values=frozenset(
                                (("enum", class_info.qualified_name, attribute),)
                            ),
                        )
                    )
                    continue
                if attribute == "name":
                    return self.engine._value_rules._instance(str)
                if attribute == "value":
                    enum_values = list(class_info.enum_values.values())
                    return (
                        join_all(
                            enum_values,
                            self.engine.type_system,
                            max_union_size=self.engine.options.max_union_size,
                        )
                        if enum_values
                        else AbstractTypeValue.from_type(ANY)
                    )
            if class_info is not None:
                if attribute == "__members__" and self._is_enum_class_info(class_info):
                    values.append(
                        self.engine._value_rules._instance(
                            dict, self.engine._value_rules._proper_instance(str), typ
                        )
                    )
                    continue
                if class_info.instance.type.tuple_fields is not None:
                    if attribute in {"_fields", "__match_args__"}:
                        values.append(
                            AbstractTypeValue.from_type(
                                TupleType(
                                    (self.engine._value_rules._proper_instance(str),),
                                    unknown_size=True,
                                )
                            )
                        )
                        continue
                    if attribute == "_field_defaults":
                        values.append(
                            self.engine._value_rules._instance(
                                dict, self.engine._value_rules._proper_instance(str), ANY
                            )
                        )
                        continue
                getter = self._class_property(class_info.qualified_name, attribute)
                if getter is not None:
                    function = self.engine._functions[getter]
                    property_value = function.explicit_return or (
                        function.summary.return_value
                        if function.summary
                        else AbstractTypeValue.unresolved()
                    )
                    substitutions = {
                        parameter.name: argument
                        for parameter, argument in zip(typ.type.type_parameters, typ.args)
                    }
                    substitutions.update(class_info.type_var_bindings)
                    substitutions.setdefault("Self", typ)
                    if substitutions and property_value.types:
                        property_value = replace(
                            property_value,
                            types=frozenset(
                                substitute_type_vars(item, substitutions)
                                for item in property_value.types
                            ),
                        )
                    values.append(property_value)
                    continue
                has_known_attribute = False
                member = self._class_attribute(class_info.qualified_name, attribute)
                if member is not None:
                    substitutions = {
                        parameter.name: argument
                        for parameter, argument in zip(typ.type.type_parameters, typ.args)
                    }
                    substitutions.update(class_info.type_var_bindings)
                    if substitutions:
                        member = replace(
                            member,
                            types=frozenset(
                                substitute_type_vars(item, substitutions) for item in member.types
                            ),
                        )
                    descriptor_values: list[AbstractTypeValue] = []
                    for member_type in member.types:
                        if not isinstance(member_type, Instance):
                            continue
                        descriptor = self._class_method(member_type.type.full_name, "__get__")
                        if descriptor is None:
                            continue
                        descriptor_values.append(
                            self.engine._call_rules._apply_function(
                                descriptor,
                                [
                                    member,
                                    base,
                                    AbstractTypeValue.from_type(TypeType(typ)),
                                ],
                                {},
                            )
                        )
                    if descriptor_values:
                        values.extend(descriptor_values)
                    else:
                        values.append(member)
                    has_known_attribute = True
                method = self._class_method(class_info.qualified_name, attribute)
                if method is not None:
                    values.append(self._bound_method_value(self.engine._functions[method], base))
                    has_known_attribute = True
                if not has_known_attribute and not base.class_targets:
                    # ``__getattr__`` is an instance protocol; on a class
                    # object the lookup goes through the metaclass instead.
                    dynamic_getter = self._class_method(class_info.qualified_name, "__getattr__")
                    key = (class_info.qualified_name, attribute)
                    if dynamic_getter is not None and key not in self.engine._resolving_attributes:
                        self.engine._resolving_attributes.add(key)
                        try:
                            values.append(
                                self.engine._call_rules._apply_function(
                                    dynamic_getter,
                                    [base, self.engine._value_rules._instance(str)],
                                    {},
                                )
                            )
                        finally:
                            self.engine._resolving_attributes.remove(key)
                if not has_known_attribute:
                    inherited = self._inherited_member(typ, attribute)
                    if inherited is not None:
                        values.append(inherited)
            else:
                if isinstance(typ.type.raw_type, type) and issubclass(
                    typ.type.raw_type, BaseException
                ):
                    if attribute == "args":
                        values.append(
                            AbstractTypeValue.from_type(TupleType((ANY,), unknown_size=True))
                        )
                        continue
                    if attribute in {"__cause__", "__context__"}:
                        values.append(
                            self.engine._value_rules._join(
                                AbstractTypeValue.from_type(
                                    self.engine._value_rules._proper_instance(BaseException)
                                ),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                    if attribute in {"errno", "winerror"}:
                        values.append(
                            self.engine._value_rules._join(
                                AbstractTypeValue.from_type(
                                    self.engine._value_rules._proper_instance(int)
                                ),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                    if attribute in {"filename", "filename2", "strerror"}:
                        values.append(
                            self.engine._value_rules._join(
                                AbstractTypeValue.from_type(
                                    self.engine._value_rules._proper_instance(str)
                                ),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                if typ.type.raw_type is subprocess.CompletedProcess:
                    text = typ.args[0] if typ.args else ANY
                    if attribute in {"stdout", "stderr"}:
                        values.append(
                            self.engine._value_rules._join(
                                AbstractTypeValue.from_type(text),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                    if attribute == "returncode":
                        values.append(self.engine._value_rules._instance(int))
                        continue
                if typ.type.raw_type is subprocess.Popen:
                    if attribute == "returncode":
                        values.append(
                            self.engine._value_rules._join(
                                AbstractTypeValue.from_type(
                                    self.engine._value_rules._proper_instance(int)
                                ),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                    if attribute == "pid":
                        values.append(self.engine._value_rules._instance(int))
                        continue
                    if attribute in {"stdout", "stderr", "stdin"}:
                        values.append(
                            self.engine._value_rules._join(
                                AbstractTypeValue.from_type(
                                    self.engine._value_rules._proper_instance(io.IOBase)
                                ),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                if typ.type.raw_type is logging.Logger:
                    if attribute == "name":
                        values.append(self.engine._value_rules._instance(str))
                        continue
                    if attribute == "level":
                        values.append(self.engine._value_rules._instance(int))
                        continue
                if typ.type.raw_type is logging.LoggerAdapter:
                    if attribute == "logger":
                        values.append(self.engine._value_rules._instance(logging.Logger))
                        continue
                    if attribute == "extra":
                        values.append(
                            self.engine._value_rules._instance(
                                dict, self.engine._value_rules._proper_instance(str), ANY
                            )
                        )
                        continue
                if typ.type.raw_type is os.DirEntry:
                    if attribute in {"name", "path"}:
                        values.append(self.engine._value_rules._instance(str))
                        continue
                if typ.type.raw_type is dataclasses.Field:
                    if attribute in {"name"}:
                        values.append(self.engine._value_rules._instance(str))
                        continue
                    if attribute in {"type", "default", "default_factory"}:
                        values.append(AbstractTypeValue.from_type(ANY))
                        continue
                    if attribute in {"metadata"}:
                        values.append(self.engine._value_rules._instance(dict, ANY, ANY))
                        continue
                if typ.type.raw_type is os.stat_result:
                    if attribute in {
                        "st_size",
                        "st_mode",
                        "st_ino",
                        "st_dev",
                        "st_nlink",
                        "st_uid",
                        "st_gid",
                        "st_atime",
                        "st_mtime",
                        "st_ctime",
                        "st_atime_ns",
                        "st_mtime_ns",
                        "st_ctime_ns",
                    }:
                        values.append(self.engine._value_rules._instance(int))
                        continue
                if typ.type.raw_type is threading.Thread:
                    if attribute == "name":
                        values.append(self.engine._value_rules._instance(str))
                        continue
                    if attribute == "daemon":
                        values.append(self.engine._value_rules._instance(bool))
                        continue
                    if attribute in {"ident", "native_id"}:
                        values.append(
                            self.engine._value_rules._join(
                                AbstractTypeValue.from_type(
                                    self.engine._value_rules._proper_instance(int)
                                ),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                if isinstance(typ.type.raw_type, type) and issubclass(typ.type.raw_type, io.IOBase):
                    if attribute == "name":
                        values.append(self.engine._value_rules._instance(str))
                        continue
                    if attribute == "mode":
                        values.append(self.engine._value_rules._instance(str))
                        continue
                    if attribute == "encoding":
                        values.append(
                            self.engine._value_rules._join(
                                AbstractTypeValue.from_type(
                                    self.engine._value_rules._proper_instance(str)
                                ),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                if typ.type.raw_type in {
                    asyncio.Lock,
                    asyncio.Event,
                    asyncio.Semaphore,
                    asyncio.BoundedSemaphore,
                    asyncio.TaskGroup,
                    asyncio.Timeout,
                }:
                    if attribute == "__aenter__":
                        values.append(
                            self.engine._value_rules._instance(cabc.Coroutine, ANY, ANY, typ)
                        )
                        continue
                    if attribute == "__aexit__":
                        values.append(AbstractTypeValue.from_type(NONE_TYPE))
                        continue
                if typ.type.raw_type is contextvars.ContextVar and attribute == "name":
                    values.append(self.engine._value_rules._instance(str))
                    continue
                if typ.type.raw_type is re.Pattern:
                    text = typ.args[0] if typ.args else ANY
                    if attribute == "pattern":
                        values.append(AbstractTypeValue.from_type(text))
                        continue
                    if attribute in {"flags", "groups"}:
                        values.append(self.engine._value_rules._instance(int))
                        continue
                    if attribute == "groupindex":
                        values.append(
                            self.engine._value_rules._instance(
                                dict,
                                self.engine._value_rules._proper_instance(str),
                                self.engine._value_rules._proper_instance(int),
                            )
                        )
                        continue
                if typ.type.raw_type is re.Match:
                    text = typ.args[0] if typ.args else ANY
                    if attribute == "string":
                        values.append(AbstractTypeValue.from_type(text))
                        continue
                    if attribute == "re":
                        values.append(self.engine._value_rules._instance(re.Pattern, text))
                        continue
                    if attribute in {"pos", "endpos"}:
                        values.append(self.engine._value_rules._instance(int))
                        continue
                    if attribute in {"lastindex", "lastgroup"}:
                        values.append(
                            self.engine._value_rules._join(
                                (
                                    AbstractTypeValue.from_type(text)
                                    if attribute == "lastgroup"
                                    else self.engine._value_rules._instance(int)
                                ),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                if typ.type.raw_type is datetime.timedelta and attribute in {
                    "days",
                    "seconds",
                    "microseconds",
                }:
                    values.append(self.engine._value_rules._instance(int))
                    continue
                if typ.type.raw_type in {datetime.datetime, datetime.date} and attribute in {
                    "year",
                    "month",
                    "day",
                    "hour",
                    "minute",
                    "second",
                    "microsecond",
                }:
                    values.append(self.engine._value_rules._instance(int))
                    continue
                if typ.type.raw_type is datetime.datetime and attribute == "tzinfo":
                    values.append(
                        self.engine._value_rules._join(
                            self.engine._value_rules._instance(datetime.tzinfo),
                            AbstractTypeValue.from_type(NONE_TYPE),
                        )
                    )
                    continue
                if typ.type.raw_type is datetime.datetime and attribute == "fold":
                    values.append(self.engine._value_rules._instance(int))
                    continue
                if self.engine._value_rules._is_pathlib_type(typ):
                    if attribute in {"name", "stem", "suffix", "drive", "root", "anchor"}:
                        values.append(self.engine._value_rules._instance(str))
                        continue
                    if attribute in {"suffixes", "parts"}:
                        if attribute == "parts":
                            values.append(
                                AbstractTypeValue.from_type(
                                    TupleType(
                                        (self.engine._value_rules._proper_instance(str),),
                                        unknown_size=True,
                                    )
                                )
                            )
                        else:
                            values.append(
                                self.engine._value_rules._instance(
                                    list, self.engine._value_rules._proper_instance(str)
                                )
                            )
                        continue
                    if attribute in {"parent", "parents"}:
                        values.append(AbstractTypeValue.from_type(typ))
                        continue
                member_type = typ.type.members.get(attribute)
                if member_type is not None:
                    substitutions = {
                        parameter.name: argument
                        for parameter, argument in zip(typ.type.type_parameters, typ.args)
                    }
                    if substitutions:
                        member_type = substitute_type_vars(member_type, substitutions)
                    values.append(AbstractTypeValue.from_type(member_type))
                    continue
                external = self._external_type(f"{typ.type.full_name}.{attribute}")
                if external is not None:
                    if (
                        isinstance(external, CallableType)
                        and not base.class_targets
                        and external.arg_types
                    ):
                        external = CallableType(external.arg_types[1:], external.return_type)
                    values.append(AbstractTypeValue.from_type(external))
                    continue
            raw = typ.type.raw_type
            member = getattr(raw, attribute, None) if isinstance(raw, type) else None
            if callable(member):
                try:
                    annotation = getattr(member, "__annotations__", {}).get("return")
                    returned = self.engine.type_system.convert_type_hint(annotation)
                except (AttributeError, TypeError, ValueError):
                    returned = ANY
                values.append(AbstractTypeValue.from_type(CallableType(None, returned)))
            elif member is not None:
                # Data descriptors on builtins (``BaseException.args``,
                # ``OSError.errno``) are not callable, but they are still
                # typed members and should not degrade to unknown.
                inherited = self._inherited_member(typ, attribute)
                if inherited is not None:
                    values.append(inherited)
        return (
            join_all(
                values,
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
            if values
            else AbstractTypeValue.unresolved()
        )

    def _bound_method_value(
        self,
        function: _FunctionInfo,
        base: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Project a method lookup to a runtime callable value.

        Accessing an instance method through an instance binds ``self`` and
        removes it from the callable's public parameter list.  The same applies
        to ``classmethod`` through either a class or an instance.  Accessing an
        instance method through the class keeps the unbound signature.
        """

        value = self.engine._function_rules._function_value(function)
        signature = value.public_type()
        if not isinstance(signature, CallableType) or function.method_kind == "static":
            return value
        if signature.arg_types is None:
            if function.method_kind == "instance" and base.class_targets:
                # Unbound access through the class: keep the raw function
                # target so ``C.m(obj, ...)`` still passes ``self``.
                return value
            # The parameter list is projected to ``...`` (keyword-only or
            # variadic parameters), so ``self``/``cls`` cannot be sliced off.
            # The value is still bound, though: dropping the raw target
            # prevents a later call from binding an explicit argument to
            # ``self`` and reporting a spurious arity mismatch.
            return AbstractTypeValue.from_type(CallableType(None, signature.return_type))
        if function.method_kind == "instance" and base.class_targets:
            return value
        arguments = signature.arg_types
        return AbstractTypeValue.from_type(
            CallableType(
                arguments[1:] if arguments else (),
                signature.return_type,
            )
        )

    def _call_property_value(
        self,
        value: AbstractTypeValue,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        node: ast.Call | ast.Attribute,
    ) -> AbstractTypeValue:
        """Apply a call to the value produced by a property getter."""
        if self.engine._operator_rules._contains_any(value) or value.unknown:
            return AbstractTypeValue.from_type(ANY)
        results: list[AbstractTypeValue] = []
        for class_target in value.class_targets:
            results.append(
                self._instantiate_class_target(class_target, value.types, arguments, keywords, node)
            )
        if not value.class_targets:
            for typ in value.types:
                if not isinstance(typ, CallableType):
                    continue
                selected = self.engine._call_rules._select_callable_overload(typ, arguments)
                results.append(
                    AbstractTypeValue.from_type(
                        selected.return_type if selected is not None else typ.return_type
                    )
                )
        if results:
            return join_all(
                results,
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
        return AbstractTypeValue.unresolved()

    def _instantiate_class_target(
        self,
        class_target: str,
        callee_types: Iterable[ProperType],
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        node: ast.AST,
    ) -> AbstractTypeValue:
        """Apply a call to a class object represented by a class target."""
        class_info = self.engine._classes.get(class_target)
        if class_info is None:
            external_instances = [
                typ
                for typ in callee_types
                if isinstance(typ, Instance) and typ.type.full_name == class_target
            ]
            return AbstractTypeValue.from_type(
                external_instances[0]
                if external_instances
                else self.engine._value_rules._synthetic_instance(class_target, unresolved=True)
            )

        specialized = next(
            (
                typ
                for typ in callee_types
                if isinstance(typ, Instance) and typ.type == class_info.instance.type
            ),
            class_info.instance,
        )
        instance = AbstractTypeValue.from_type(specialized)
        initializer = self._class_method(class_target, "__init__")
        if class_info.type_variables and not (
            isinstance(specialized, Instance) and specialized.args
        ):
            if initializer is not None:
                initializer_info = self.engine._functions[initializer]
                bound = self.engine._call_rules._bind_call_arguments(
                    initializer_info, [instance, *arguments], keywords
                )
                substitutions = self.engine._call_rules._generic_substitutions(
                    initializer_info, bound
                )
                inferred_args = tuple(
                    substitutions.get(name, ANY) for name in class_info.type_variables
                )
            else:
                inferred_args = self.engine._call_rules._generic_constructor_args(
                    class_info, arguments, keywords
                )
            if inferred_args is not None:
                specialized = Instance(class_info.instance.type, inferred_args)
                instance = AbstractTypeValue.from_type(specialized)
        if class_info.instance.type.typed_dict_fields is not None:
            for name, expected in class_info.instance.type.typed_dict_fields.items():
                if name in keywords:
                    self.engine._compatibility_rules._check_annotation_compatibility(
                        keywords[name],
                        AbstractTypeValue.from_type(expected),
                        node,
                        context=f"TypedDict key {name}",
                    )
        if initializer is not None:
            self.engine._call_rules._apply_function(
                initializer, [instance, *arguments], keywords, node=node
            )
        if self.engine._function_rules._class_is_metaclass(class_info):
            return AbstractTypeValue.from_type(
                TypeType(self.engine._value_rules._proper_instance(object))
            )
        return instance

    def _class_method(
        self,
        class_name: str,
        method: str,
        seen: set[str] | None = None,
    ) -> str | None:
        seen = set() if seen is None else seen
        if class_name in seen:
            return None
        seen.add(class_name)
        class_info = self.engine._classes.get(class_name)
        if class_info is None:
            return None
        if method in class_info.methods:
            return class_info.methods[method]
        for base in class_info.bases:
            found = self._class_method(base, method, seen)
            if found is not None:
                return found
        return None

    def _class_property(self, class_name, name, seen=frozenset()):
        if class_name in seen:
            return None
        info = self.engine._classes.get(class_name)
        if info is None:
            return None
        if name in info.properties:
            return info.properties[name]
        if name in info.methods:
            return None
        for base in info.bases:
            result = self._class_property(base, name, seen | {class_name})
            if result is not None:
                return result
        return None

    def _class_attribute(
        self,
        class_name: str,
        attribute: str,
        seen: set[str] | None = None,
    ) -> AbstractTypeValue | None:
        seen = set() if seen is None else seen
        if class_name in seen:
            return None
        seen.add(class_name)
        class_info = self.engine._classes.get(class_name)
        if class_info is None:
            return None
        if attribute in class_info.attributes:
            return class_info.attributes[attribute]
        if attribute in class_info.attribute_templates:
            return class_info.attribute_templates[attribute]
        for base in class_info.bases:
            found = self._class_attribute(base, attribute, seen)
            if found is not None:
                return found
        return None

    def _external_type(self, qualified_name: str) -> ProperType | None:
        if self.engine.external_symbol_resolver is None:
            return None
        try:
            return self.engine.external_symbol_resolver(qualified_name)
        except (ImportError, LookupError, OSError, RuntimeError):
            return None

    @staticmethod
    def _looks_like_class(name: str) -> bool:
        final = name.rsplit(".", 1)[-1]
        return bool(final) and final[0].isupper()
