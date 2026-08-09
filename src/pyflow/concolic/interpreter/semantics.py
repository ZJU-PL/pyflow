"""semantic support for the AST executor."""

from __future__ import annotations

import ast

from typing import Any

from ..core.runtime import (
    ConcolicError,
    UnsupportedSyntaxError,
    _BoolValue,
    _BuiltinFunction,
    _BytesValue,
    _ClassValue,
    _ContextManagerFactory,
    _DictValue,
    _EnumClass,
    _EnumMember,
    _ExceptionType,
    _FloatValue,
    _FunctionValue,
    _GeneratorContext,
    _IdentityDecorator,
    _ImportlibFunction,
    _ImportlibModule,
    _InstanceValue,
    _IntValue,
    _ListValue,
    _ModuleValue,
    _NamedTupleClass,
    _NamedTupleValue,
    _NullContext,
    _OperatorAttrGetter,
    _OperatorItemGetter,
    _OperatorMethodCaller,
    _PartialValue,
    _RangeValue,
    _RegexMatch,
    _RegexModule,
    _SetValue,
    _StringValue,
    _SummaryFunction,
    _SummaryModule,
    _SuppressContext,
    _TupleValue,
    _URLParseValue,
)

from ..core.support import _concrete


class _SemanticMixin:
    def _contains(self, container: Any, needle: Any) -> _BoolValue:
        if isinstance(container, _InstanceValue):
            method_with_owner = self._method_with_owner(container.class_value, "__contains__")
            if method_with_owner is not None:
                method, owner = method_with_owner
                return self._truthy(self._call_method(method, owner, container, [needle], {}))
        if isinstance(container, _StringValue):
            item = self._to_string(needle)
            return _BoolValue(
                item.concrete in container.concrete,
                self._z3.Contains(container.symbolic, item.symbolic),
            )
        if isinstance(container, (_ListValue, _TupleValue)):
            matches = [self._equals(item, needle) for item in container.values]
            return _BoolValue(
                any(match.concrete for match in matches),
                self._z3.Or(*(match.symbolic for match in matches)),
            )
        if isinstance(container, _DictValue):
            concrete = self._key(needle) in container.values
            return _BoolValue(concrete, self._z3.BoolVal(concrete))
        raise UnsupportedSyntaxError("membership requires a supported container")

    def _enum_scalar(self, value: Any) -> Any:
        if isinstance(value, _EnumMember) and value.class_value.kind in {
            "IntEnum",
            "StrEnum",
        }:
            return self._constant_value(value.value)
        return value

    def _equals(self, left: Any, right: Any) -> _BoolValue:
        left = self._enum_scalar(left)
        right = self._enum_scalar(right)
        if isinstance(left, _EnumMember) and isinstance(right, _EnumMember):
            concrete = left == right
            return _BoolValue(concrete, self._z3.BoolVal(concrete))
        if isinstance(left, _InstanceValue):
            method_with_owner = self._method_with_owner(left.class_value, "__eq__")
            if method_with_owner is not None:
                method, owner = method_with_owner
                return self._truthy(self._call_method(method, owner, left, [right], {}))
        if isinstance(left, _IntValue) and isinstance(right, _IntValue):
            return _BoolValue(left.concrete == right.concrete, left.symbolic == right.symbolic)
        if isinstance(left, (_IntValue, _FloatValue)) and isinstance(
            right, (_IntValue, _FloatValue)
        ):
            lhs = self._as_real(left)
            rhs = self._as_real(right)
            return _BoolValue(lhs[0] == rhs[0], lhs[1] == rhs[1])
        if isinstance(left, _StringValue) and isinstance(right, _StringValue):
            return _BoolValue(left.concrete == right.concrete, left.symbolic == right.symbolic)
        if isinstance(left, _BoolValue) and isinstance(right, _BoolValue):
            return _BoolValue(left.concrete == right.concrete, left.symbolic == right.symbolic)
        return _BoolValue(
            _concrete(left) == _concrete(right),
            self._z3.BoolVal(_concrete(left) == _concrete(right)),
        )

    def _string_order(
        self, left: _StringValue, right: _StringValue, operator: ast.cmpop
    ) -> tuple[bool, Any]:
        comparisons = {
            ast.Lt: left.concrete < right.concrete,
            ast.LtE: left.concrete <= right.concrete,
            ast.Gt: left.concrete > right.concrete,
            ast.GtE: left.concrete >= right.concrete,
        }
        for kind, result in comparisons.items():
            if isinstance(operator, kind):
                return result, self._z3.BoolVal(result)
        raise UnsupportedSyntaxError(f"unsupported comparison {type(operator).__name__}")

    def _python_floor_div(self, numerator: Any, denominator: Any) -> Any:
        positive = numerator / denominator
        denominator_magnitude = -denominator
        negative_division = numerator / denominator_magnitude
        negative_remainder = numerator % denominator_magnitude
        negative = self._z3.If(negative_remainder == 0, -negative_division, -negative_division - 1)
        return self._z3.If(denominator > 0, positive, negative)

    def _key(self, value: Any) -> int | str | bool:
        concrete = _concrete(value)
        if isinstance(concrete, (int, str, bool)):
            return concrete
        raise UnsupportedSyntaxError("dictionary keys must be integer, string, or Boolean")

    @staticmethod
    def _numeric_concrete(value: Any) -> int | float:
        if isinstance(value, (_IntValue, _FloatValue)):
            return value.concrete
        raise UnsupportedSyntaxError("a numeric expression was required")

    def _as_real(self, value: _IntValue | _FloatValue) -> tuple[float, Any]:
        if isinstance(value, _FloatValue):
            return value.concrete, value.symbolic
        return float(value.concrete), self._z3.ToReal(value.symbolic)

    def _hash(self, value: Any) -> _IntValue:
        if isinstance(value, _IntValue):
            return value
        if isinstance(value, _BoolValue):
            return _IntValue(int(value.concrete), self._z3.If(value.symbolic, 1, 0))
        if isinstance(value, _InstanceValue):
            method_with_owner = self._method_with_owner(value.class_value, "__hash__")
            if method_with_owner is not None:
                method, owner = method_with_owner
                return self._as_int(self._call_method(method, owner, value, [], {}))
        raise UnsupportedSyntaxError("hash() requires an integer, Boolean, or custom __hash__")

    def _literal(self, value: int | str | bool) -> Any:
        if isinstance(value, bool):
            return _BoolValue(value, self._z3.BoolVal(value))
        if isinstance(value, int):
            return _IntValue(value, self._z3.IntVal(value))
        return _StringValue(value, self._z3.StringVal(value))

    @staticmethod
    def _missing_key(key: Any) -> None:
        raise ConcolicError(f"dictionary key not found: {key!r}")

    def _lookup(self, name: str) -> Any:
        if (
            name in self._nonlocal_names
            and self._closure_env is not None
            and name in self._closure_env
        ):
            return self._closure_env[name]
        try:
            return self.env[name]
        except KeyError as error:
            if name in self._global_values:
                return self._global_values[name]
            if name in self._classes:
                return self._class_value(self._classes[name])
            if name in self._functions:
                return self._function_value(self._functions[name])
            if name in {"dict", "int", "list", "set", "str"}:
                return _BuiltinFunction(name)
            if name in {
                "BaseException",
                "Exception",
                "KeyError",
                "LookupError",
                "RuntimeError",
                "TypeError",
                "ValueError",
                "ZeroDivisionError",
            }:
                return _ExceptionType(name)
            if name in self._globals:
                return self._constant_value(self._globals[name])
            raise UnsupportedSyntaxError(f"unknown local name {name!r}") from error

    def _constant_value(self, value: Any) -> Any:
        if isinstance(
            value,
            (
                _ModuleValue,
                _FunctionValue,
                _ClassValue,
                _URLParseValue,
                _RegexModule,
                _SummaryModule,
                _SummaryFunction,
                _OperatorItemGetter,
                _OperatorAttrGetter,
                _OperatorMethodCaller,
                _NamedTupleClass,
                _NamedTupleValue,
                _EnumClass,
                _EnumMember,
                _ImportlibModule,
                _ImportlibFunction,
                _BuiltinFunction,
                _ExceptionType,
                _SuppressContext,
                _NullContext,
                _ContextManagerFactory,
                _GeneratorContext,
                _PartialValue,
                _IdentityDecorator,
            ),
        ):
            return value
        if isinstance(value, bool):
            return _BoolValue(value, self._z3.BoolVal(value))
        if isinstance(value, int):
            return _IntValue(value, self._z3.IntVal(value))
        if isinstance(value, float):
            return _FloatValue(value, self._z3.RealVal(str(value)))
        if isinstance(value, str):
            return _StringValue(value, self._z3.StringVal(value))
        if isinstance(value, bytes):
            return _BytesValue(value)
        if isinstance(value, list):
            return _ListValue([self._constant_value(item) for item in value])
        if isinstance(value, tuple):
            return _TupleValue(tuple(self._constant_value(item) for item in value))
        if isinstance(value, set):
            return _SetValue([self._constant_value(item) for item in value])
        if isinstance(value, dict):
            return _DictValue({key: self._constant_value(item) for key, item in value.items()})
        if value is None:
            return None
        raise UnsupportedSyntaxError(f"unsupported global value {value!r}")

    @staticmethod
    def _as_int(value: Any) -> _IntValue:
        if not isinstance(value, _IntValue):
            raise UnsupportedSyntaxError("an integer expression was required")
        return value

    @staticmethod
    def _as_bool(value: Any) -> _BoolValue:
        if not isinstance(value, _BoolValue):
            raise UnsupportedSyntaxError("a Boolean condition was required")
        return value

    def _truthy(self, value: Any) -> _BoolValue:
        value = self._enum_scalar(value)
        if isinstance(value, _BoolValue):
            return value
        if isinstance(value, _IntValue):
            return _BoolValue(value.concrete != 0, value.symbolic != 0)
        if isinstance(value, _FloatValue):
            return _BoolValue(value.concrete != 0, value.symbolic != 0)
        if isinstance(value, _BytesValue):
            return _BoolValue(bool(value.concrete), self._z3.BoolVal(bool(value.concrete)))
        if isinstance(value, _StringValue):
            return _BoolValue(value.concrete != "", value.symbolic != self._z3.StringVal(""))
        if isinstance(value, (_ListValue, _TupleValue, _SetValue, _RangeValue)):
            return _BoolValue(bool(value.values), self._z3.BoolVal(bool(value.values)))
        if isinstance(value, _DictValue):
            return _BoolValue(bool(value.values), self._z3.BoolVal(bool(value.values)))
        if isinstance(value, _RegexMatch):
            return _BoolValue(True, self._z3.BoolVal(True))
        if isinstance(value, _InstanceValue):
            method_with_owner = self._method_with_owner(value.class_value, "__bool__")
            if method_with_owner is not None:
                method, owner = method_with_owner
                return self._truthy(self._call_method(method, owner, value, [], {}))
            method_with_owner = self._method_with_owner(value.class_value, "__len__")
            if method_with_owner is not None:
                return self._truthy(self._length(value))
        return _BoolValue(value is not None, self._z3.BoolVal(value is not None))
