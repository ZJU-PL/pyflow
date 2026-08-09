"""object support for the AST executor."""

from __future__ import annotations

import ast

import math

import posixpath

import re

from typing import Any

from .runtime import (
    ConcolicError,
    FunctionNode,
    UnsupportedSyntaxError,
    _BuiltinFunction,
    _ClassValue,
    _ContextManagerFactory,
    _DateTimeValue,
    _DictValue,
    _EnumClass,
    _EnumMember,
    _ExceptionType,
    _FloatValue,
    _FunctionValue,
    _GeneratorContext,
    _IdentityDecorator,
    _InstanceValue,
    _IntValue,
    _IteratorValue,
    _ListValue,
    _ModuleValue,
    _NamedTupleClass,
    _NamedTupleValue,
    _OperatorAttrGetter,
    _OperatorItemGetter,
    _OperatorMethodCaller,
    _PartialValue,
    _PathValue,
    _RegexModule,
    _SetValue,
    _StringValue,
    _SummaryFunction,
    _SummaryModule,
    _TargetException,
    _TimedeltaValue,
    _TupleValue,
    _URLParseValue,
)

from .support import _concrete


class _ObjectMixin:
    def _call_value(self, value: Any, args: list[Any], keywords: dict[str, Any]) -> Any:
        if isinstance(value, _FunctionValue):
            return self._call_function_value(value, args, keywords)
        if isinstance(value, _ClassValue):
            return self._construct(value, args, keywords)
        if isinstance(value, _NamedTupleClass):
            return self._construct_namedtuple(value, args, keywords)
        if isinstance(value, _EnumClass):
            return self._construct_enum(value, args, keywords)
        if isinstance(value, _SummaryFunction):
            return self._call_summary(value.module, value.name, args, keywords)
        if isinstance(value, _ContextManagerFactory):
            iterator = self._call_value(value.function, args, keywords)
            if not isinstance(iterator, _IteratorValue):
                raise UnsupportedSyntaxError(
                    "contextmanager function must yield a value"
                )
            return _GeneratorContext(iterator)
        if isinstance(value, _OperatorItemGetter):
            if len(args) != 1 or keywords:
                raise ConcolicError("operator.itemgetter() expects one argument")
            results = tuple(
                self._subscript(args[0], ast.Constant(value=_concrete(item)))
                for item in value.items
            )
            return results[0] if len(results) == 1 else _TupleValue(results)
        if isinstance(value, _OperatorAttrGetter):
            if len(args) != 1 or keywords:
                raise ConcolicError("operator.attrgetter() expects one argument")
            results: list[Any] = []
            for attribute in value.attributes:
                result = args[0]
                for component in attribute.split("."):
                    result = self._attribute(result, component)
                results.append(result)
            return results[0] if len(results) == 1 else _TupleValue(tuple(results))
        if isinstance(value, _OperatorMethodCaller):
            if len(args) != 1 or keywords:
                raise ConcolicError("operator.methodcaller() expects one argument")
            return self._call_attribute(
                args[0], value.name, list(value.args), value.keywords
            )
        if isinstance(value, _PartialValue):
            overlapping = set(value.keywords) & set(keywords)
            if overlapping:
                name = next(iter(overlapping))
                raise ConcolicError(f"multiple values for keyword argument {name!r}")
            return self._call_value(
                value.function,
                [*value.args, *args],
                {**value.keywords, **keywords},
            )
        if isinstance(value, _IdentityDecorator) and len(args) == 1 and not keywords:
            return args[0]
        if isinstance(value, _ExceptionType):
            if keywords or len(args) > 1:
                raise ConcolicError(f"{value.name}() expects at most one argument")
            message = str(_concrete(args[0])) if args else ""
            return _TargetException(value.name, message)
        if isinstance(value, _BuiltinFunction):
            if keywords:
                raise UnsupportedSyntaxError(
                    f"{value.name} factory does not support keyword arguments"
                )
            if value.name == "list" and not args:
                return _ListValue([])
            if value.name == "dict" and not args:
                return _DictValue({})
            if value.name == "set" and not args:
                return _SetValue([])
            if value.name == "int" and not args:
                return self._literal(0)
            if value.name == "str" and not args:
                return _StringValue("", self._z3.StringVal(""))
        raise UnsupportedSyntaxError("value is not callable in the concolic subset")

    def _attribute(self, value: Any, name: str) -> Any:
        if isinstance(value, _URLParseValue) and name in {
            "fragment",
            "hostname",
            "netloc",
            "params",
            "password",
            "path",
            "port",
            "query",
            "scheme",
            "username",
        }:
            try:
                return self._constant_value(getattr(value.concrete, name))
            except ValueError as error:
                raise ConcolicError(str(error)) from error
        if isinstance(value, _EnumClass) and name in value.members:
            return _EnumMember(value, name, value.members[name])
        if isinstance(value, _EnumMember):
            if name == "name":
                return _StringValue(value.name, self._z3.StringVal(value.name))
            if name == "value":
                return self._constant_value(value.value)
        if isinstance(value, _NamedTupleValue):
            try:
                return value.values[value.class_value.fields.index(name)]
            except ValueError:
                pass
        if isinstance(value, _NamedTupleClass) and name == "_fields":
            return _TupleValue(
                tuple(
                    _StringValue(field, self._z3.StringVal(field))
                    for field in value.fields
                )
            )
        if isinstance(value, _DateTimeValue):
            attributes = {
                "year",
                "month",
                "day",
                "hour",
                "minute",
                "second",
                "microsecond",
            }
            if name in attributes and hasattr(value.concrete, name):
                concrete = getattr(value.concrete, name)
                return _IntValue(concrete, self._z3.IntVal(concrete))
        if isinstance(value, _TimedeltaValue) and name in {
            "days",
            "seconds",
            "microseconds",
        }:
            concrete = getattr(value.concrete, name)
            return _IntValue(concrete, self._z3.IntVal(concrete))
        if (
            isinstance(value, _SummaryModule)
            and value.name == "datetime"
            and name in {"date", "datetime"}
        ):
            return _SummaryFunction("datetime", name)
        if isinstance(value, _PathValue):
            if name == "name":
                concrete = posixpath.basename(value.concrete)
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if name == "suffix":
                concrete = posixpath.splitext(value.concrete)[1]
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if name == "stem":
                concrete = posixpath.splitext(posixpath.basename(value.concrete))[0]
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if name == "parent":
                return _PathValue(posixpath.dirname(value.concrete) or ".")
            if name == "parts":
                parts = tuple(part for part in value.concrete.split("/") if part)
                if value.concrete.startswith("/"):
                    parts = ("/", *parts)
                return _TupleValue(
                    tuple(
                        _StringValue(part, self._z3.StringVal(part)) for part in parts
                    )
                )
        if isinstance(value, _InstanceValue):
            if name in value.fields:
                return value.fields[name]
            found, class_attribute = self._class_attribute_value(
                value.class_value, name
            )
            if found:
                return class_attribute
            method_with_owner = self._method_with_owner(value.class_value, name)
            method_kind = (
                self._method_kind(method_with_owner[0])
                if method_with_owner is not None
                else None
            )
            if method_with_owner is not None and method_kind in {
                "property",
                "cached_property",
            }:
                method, owner = method_with_owner
                result = self._call_scoped_function(
                    method,
                    [value],
                    {},
                    owner.module,
                    current_class=owner,
                    current_instance=value,
                )
                if method_kind == "cached_property":
                    value.fields[name] = result
                return result
            if method_with_owner is not None:
                return value
            fallback = self._method_with_owner(value.class_value, "__getattr__")
            if fallback is not None:
                method, owner = fallback
                return self._call_method(
                    method,
                    owner,
                    value,
                    [_StringValue(name, self._z3.StringVal(name))],
                    {},
                )
        if isinstance(value, _ClassValue):
            found, class_attribute = self._class_attribute_value(value, name)
            if found:
                return class_attribute
            if self._method_with_owner(value, name) is not None:
                return value
        if isinstance(value, _SummaryModule) and value.name == "os" and name == "path":
            return _SummaryModule("os.path")
        if isinstance(value, _SummaryModule) and value.name == "math" and name in {
            "e",
            "pi",
            "tau",
        }:
            concrete = getattr(math, name)
            return _FloatValue(concrete, self._z3.RealVal(str(concrete)))
        if (
            isinstance(value, _SummaryModule)
            and value.name == "urllib"
            and name == "parse"
        ):
            return _SummaryModule("urllib.parse")
        if isinstance(value, _RegexModule) and name in {
            "I",
            "IGNORECASE",
            "M",
            "MULTILINE",
            "S",
            "DOTALL",
        }:
            flag_name = {
                "I": "IGNORECASE",
                "M": "MULTILINE",
                "S": "DOTALL",
            }.get(name, name)
            concrete = int(getattr(re, flag_name))
            return _IntValue(concrete, self._z3.IntVal(concrete))
        if isinstance(value, _ModuleValue):
            if name in value.globals:
                return self._constant_value(value.globals[name])
            if name in value.classes:
                return self._class_value(value.classes[name])
            if value.loading:
                raise ConcolicError(
                    "circular import accessed unavailable attribute "
                    f"{name!r} in {value.path}"
                )
        raise UnsupportedSyntaxError(f"unsupported attribute {name!r}")

    def _construct(
        self,
        class_value: _ClassValue,
        args: list[Any],
        keywords: dict[str, Any] | None = None,
    ) -> _InstanceValue:
        instance = _InstanceValue(class_value, {})
        initializer = self._method_with_owner(class_value, "__init__")
        if initializer is not None:
            method, owner = initializer
            self._call_method(method, owner, instance, args, keywords or {})
        elif self._is_dataclass(class_value):
            self._construct_dataclass(instance, args, keywords or {})
        elif args or keywords:
            raise ConcolicError(f"{class_value.definition.name}() takes no arguments")
        return instance

    def _construct_namedtuple(
        self, class_value: _NamedTupleClass, args: list[Any], keywords: dict[str, Any]
    ) -> _NamedTupleValue:
        if len(args) > len(class_value.fields):
            raise ConcolicError(f"{class_value.name}() received too many arguments")
        values = list(args)
        remaining = dict(keywords)
        for field in class_value.fields[len(args) :]:
            if field not in remaining:
                raise ConcolicError(f"missing required argument {field!r}")
            values.append(remaining.pop(field))
        if remaining:
            name = next(iter(remaining))
            raise ConcolicError(f"unexpected keyword argument {name!r}")
        return _NamedTupleValue(class_value, tuple(values))

    def _construct_enum(
        self, class_value: _EnumClass, args: list[Any], keywords: dict[str, Any]
    ) -> _EnumMember:
        if keywords or len(args) != 1:
            raise ConcolicError(f"{class_value.name}() expects one value")
        concrete = _concrete(args[0])
        for name, value in class_value.members.items():
            if value == concrete:
                return _EnumMember(class_value, name, value)
        raise ConcolicError(f"{concrete!r} is not a valid {class_value.name}")

    def _call_method(
        self,
        method: FunctionNode,
        owner: _ClassValue,
        instance: _InstanceValue | None,
        args: list[Any],
        keywords: dict[str, Any],
    ) -> Any:
        kind = self._method_kind(method)
        if kind == "staticmethod":
            return self._call_scoped_function(
                method, args, keywords, owner.module, owner, instance
            )
        if kind == "classmethod":
            return self._call_scoped_function(
                method, [owner, *args], keywords, owner.module, owner, instance
            )
        if instance is None:
            raise ConcolicError(
                f"{owner.definition.name}.{method.name} requires an instance"
            )
        return self._call_scoped_function(
            method, [instance, *args], keywords, owner.module, owner, instance
        )

    def _method_with_owner(
        self, class_value: _ClassValue, name: str
    ) -> tuple[FunctionNode, _ClassValue] | None:
        for candidate in self._mro(class_value):
            for statement in candidate.definition.body:
                if (
                    isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and statement.name == name
                ):
                    return statement, candidate
        return None

    def _class_attribute_value(
        self, class_value: _ClassValue, name: str
    ) -> tuple[bool, Any]:
        """Return an inherited class variable declared with a simple assignment."""
        for candidate in self._mro(class_value):
            attributes = self._materialize_class_attributes(candidate)
            if name in attributes:
                return True, attributes[name]
        return False, None

    def _materialize_class_attributes(
        self, class_value: _ClassValue
    ) -> dict[str, Any]:
        """Lazily execute simple class-variable declarations in class-body order."""
        key = id(class_value)
        if key in self._class_attributes:
            return self._class_attributes[key]

        attributes: dict[str, Any] = {}
        self._class_attributes[key] = attributes
        previous_env = self.env
        previous_functions = self._functions
        previous_classes = self._classes
        previous_globals = self._globals
        previous_module = self._current_module
        self.env = {**class_value.closure}
        if class_value.module is not None:
            self._functions = class_value.module.functions
            self._classes = class_value.module.classes
            self._globals = class_value.module.globals
            self._current_module = class_value.module
        try:
            for statement in class_value.definition.body:
                targets: list[ast.expr]
                value: ast.expr | None
                if isinstance(statement, ast.Assign):
                    targets = statement.targets
                    value = statement.value
                elif isinstance(statement, ast.AnnAssign):
                    targets = [statement.target]
                    value = statement.value
                else:
                    continue
                if value is None:
                    continue
                result = self._evaluate(value)
                for target in targets:
                    if isinstance(target, ast.Name):
                        attributes[target.id] = result
                        self.env[target.id] = result
            return attributes
        finally:
            self.env = previous_env
            self._functions = previous_functions
            self._classes = previous_classes
            self._globals = previous_globals
            self._current_module = previous_module

    def _method_after(
        self, class_value: _ClassValue, start_class: _ClassValue, name: str
    ) -> tuple[FunctionNode, _ClassValue] | None:
        mro = self._mro(class_value)
        try:
            start = mro.index(start_class) + 1
        except ValueError as error:
            raise ConcolicError(
                "super() start class is not in the instance MRO"
            ) from error
        for candidate in mro[start:]:
            for statement in candidate.definition.body:
                if (
                    isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and statement.name == name
                ):
                    return statement, candidate
        return None

    def _property_setter_with_owner(
        self, class_value: _ClassValue, name: str
    ) -> tuple[FunctionNode, _ClassValue] | None:
        for candidate in self._mro(class_value):
            for statement in candidate.definition.body:
                if (
                    isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and statement.name == name
                    and any(
                        isinstance(decorator, ast.Attribute)
                        and decorator.attr == "setter"
                        and isinstance(decorator.value, ast.Name)
                        and decorator.value.id == name
                        for decorator in statement.decorator_list
                    )
                ):
                    return statement, candidate
        return None

    def _mro(self, class_value: _ClassValue) -> tuple[_ClassValue, ...]:
        bases = self._class_bases(class_value)
        if not bases:
            return (class_value,)
        sequences = [list(self._mro(base)) for base in bases] + [list(bases)]
        merged: list[_ClassValue] = [class_value]
        while any(sequences):
            candidate = next(
                (
                    sequence[0]
                    for sequence in sequences
                    if sequence
                    and not any(sequence[0] in other[1:] for other in sequences)
                ),
                None,
            )
            if candidate is None:
                raise ConcolicError(
                    "inconsistent inheritance hierarchy for "
                    f"{class_value.definition.name}"
                )
            merged.append(candidate)
            for sequence in sequences:
                if sequence and sequence[0] == candidate:
                    sequence.pop(0)
        return tuple(merged)

    def _class_bases(self, class_value: _ClassValue) -> tuple[_ClassValue, ...]:
        bases: list[_ClassValue] = []
        for node in class_value.definition.bases:
            base = self._evaluate(node)
            if not isinstance(base, _ClassValue):
                raise UnsupportedSyntaxError("class bases must be local classes")
            bases.append(base)
        return tuple(bases)

    @staticmethod
    def _method_kind(method: FunctionNode) -> str:
        names = {
            decorator.id
            for decorator in method.decorator_list
            if isinstance(decorator, ast.Name)
        }
        attribute_names = {
            decorator.attr
            for decorator in method.decorator_list
            if isinstance(decorator, ast.Attribute)
        }
        if "staticmethod" in names:
            return "staticmethod"
        if "classmethod" in names:
            return "classmethod"
        if "property" in names or "property" in attribute_names:
            return "property"
        if "cached_property" in names or "cached_property" in attribute_names:
            return "cached_property"
        return "instance"

    @staticmethod
    def _is_dataclass(class_value: _ClassValue) -> bool:
        return any(
            _ObjectMixin._is_dataclass_decorator(decorator)
            for decorator in class_value.definition.decorator_list
        )

    @staticmethod
    def _is_dataclass_decorator(decorator: ast.expr) -> bool:
        return (
            isinstance(decorator, ast.Name) and decorator.id == "dataclass"
        ) or (
            isinstance(decorator, ast.Attribute) and decorator.attr == "dataclass"
        ) or (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Name)
            and decorator.func.id == "dataclass"
        ) or (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "dataclass"
        )

    def _construct_dataclass(
        self,
        instance: _InstanceValue,
        args: list[Any],
        keywords: dict[str, Any],
    ) -> None:
        fields = self._dataclass_fields(instance.class_value)
        names = [field.target.id for field in fields]
        if len(args) > len(names):
            raise ConcolicError(
                f"{instance.class_value.definition.name}() received too many arguments"
            )
        for name, value in zip(names, args):
            instance.fields[name] = value
        for field in fields[len(args) :]:
            name = field.target.id
            if name in keywords:
                instance.fields[name] = keywords.pop(name)
            elif field.value is not None:
                instance.fields[name] = self._dataclass_default(field.value)
            else:
                raise ConcolicError(f"missing required argument {name!r}")
        if keywords:
            name = next(iter(keywords))
            raise ConcolicError(f"unexpected keyword argument {name!r}")

    def _dataclass_fields(self, class_value: _ClassValue) -> list[ast.AnnAssign]:
        fields: list[ast.AnnAssign] = []
        for candidate in reversed(self._mro(class_value)):
            if not self._is_dataclass(candidate):
                continue
            fields.extend(
                statement
                for statement in candidate.definition.body
                if isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
            )
        return fields

    def _match_args(self, class_value: _ClassValue) -> tuple[str, ...]:
        """Return the class-pattern attribute names for a local class.

        Dataclasses synthesize ``__match_args__`` from their constructor
        fields.  For ordinary local classes, support the usual explicit tuple
        declaration while keeping evaluation side-effect free.
        """
        for candidate in self._mro(class_value):
            for statement in candidate.definition.body:
                value: ast.expr | None = None
                if (
                    isinstance(statement, ast.Assign)
                    and len(statement.targets) == 1
                    and isinstance(statement.targets[0], ast.Name)
                    and statement.targets[0].id == "__match_args__"
                ):
                    value = statement.value
                elif (
                    isinstance(statement, ast.AnnAssign)
                    and isinstance(statement.target, ast.Name)
                    and statement.target.id == "__match_args__"
                ):
                    value = statement.value
                if value is not None:
                    if not isinstance(value, (ast.Tuple, ast.List)):
                        raise UnsupportedSyntaxError(
                            "__match_args__ must be a literal tuple or list of strings"
                        )
                    names = []
                    for node in value.elts:
                        if not isinstance(node, ast.Constant) or not isinstance(
                            node.value, str
                        ):
                            raise UnsupportedSyntaxError(
                                "__match_args__ must contain only strings"
                            )
                        names.append(node.value)
                    return tuple(names)
        if self._is_dataclass(class_value):
            return tuple(
                field.target.id for field in self._dataclass_fields(class_value)
            )
        return ()

    def _dataclass_default(self, node: ast.expr) -> Any:
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "field"
        ):
            keywords = {keyword.arg: keyword.value for keyword in node.keywords}
            if "default" in keywords:
                return self._evaluate(keywords["default"])
            if "default_factory" in keywords:
                factory = keywords["default_factory"]
                if isinstance(factory, ast.Name) and factory.id in {
                    "dict",
                    "list",
                    "set",
                }:
                    return self._call(ast.Call(factory, [], []))
                if isinstance(factory, ast.Lambda):
                    return self._call_function_value(
                        _FunctionValue(factory, self.env), [], {}
                    )
                raise UnsupportedSyntaxError("unsupported dataclass default factory")
            raise UnsupportedSyntaxError("dataclasses.field() needs a default")
        return self._evaluate(node)

    def _dataclass_serialized(self, value: Any) -> Any:
        if isinstance(value, _InstanceValue) and self._is_dataclass(value.class_value):
            return _DictValue(
                {
                    field.target.id: self._dataclass_serialized(
                        value.fields[field.target.id]
                    )
                    for field in self._dataclass_fields(value.class_value)
                }
            )
        if isinstance(value, _ListValue):
            return _ListValue(
                [self._dataclass_serialized(item) for item in value.values]
            )
        if isinstance(value, _TupleValue):
            return _TupleValue(
                tuple(self._dataclass_serialized(item) for item in value.values)
            )
        if isinstance(value, _DictValue):
            return _DictValue(
                {
                    key: self._dataclass_serialized(item)
                    for key, item in value.values.items()
                }
            )
        return value
