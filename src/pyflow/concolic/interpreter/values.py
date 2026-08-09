"""value support for the AST executor."""

from __future__ import annotations

import ast

import heapq

import math

import posixpath

from typing import Any

from ..runtime import (
    ConcolicError,
    UnsupportedSyntaxError,
    _BoolValue,
    _Awaiting,
    _BuiltinFunction,
    _BytesValue,
    _ClassValue,
    _CounterValue,
    _DateTimeValue,
    _DefaultDictValue,
    _DequeValue,
    _DictValue,
    _EnumClass,
    _EnumMember,
    _FloatValue,
    _InstanceValue,
    _IntValue,
    _IteratorValue,
    _ListValue,
    _NamedTupleValue,
    _PathValue,
    _RangeValue,
    _Raised,
    _ResumeKind,
    _ResumeOperation,
    _Returned,
    _SequenceIteratorValue,
    _SetValue,
    _StringValue,
    _TimedeltaValue,
    _TupleValue,
    _Yielded,
)

from ..support import _concrete, _unique_values


class _ValueMixin:
    def _binary(
        self,
        left: Any,
        operator: ast.operator,
        right: Any,
    ) -> Any:
        left = self._enum_scalar(left)
        right = self._enum_scalar(right)
        if isinstance(left, _DateTimeValue) and isinstance(right, _TimedeltaValue):
            if isinstance(operator, ast.Add):
                return _DateTimeValue(left.concrete + right.concrete)
            if isinstance(operator, ast.Sub):
                return _DateTimeValue(left.concrete - right.concrete)
        if (
            isinstance(left, _DateTimeValue)
            and isinstance(right, _DateTimeValue)
            and isinstance(operator, ast.Sub)
        ):
            return _TimedeltaValue(left.concrete - right.concrete)
        if isinstance(left, _PathValue) and isinstance(operator, ast.Div):
            return _PathValue(
                posixpath.join(left.concrete, self._to_string(right).concrete)
            )
        if (
            isinstance(left, _DictValue)
            and isinstance(right, _DictValue)
            and isinstance(operator, ast.BitOr)
        ):
            return _DictValue({**left.values, **right.values})
        if isinstance(left, _SetValue) and isinstance(right, _SetValue):
            if isinstance(operator, ast.BitOr):
                return _SetValue(_unique_values([*left.values, *right.values]))
            if isinstance(operator, ast.BitAnd):
                return _SetValue(
                    [
                        value
                        for value in left.values
                        if any(
                            self._equals(value, candidate).concrete
                            for candidate in right.values
                        )
                    ]
                )
            if isinstance(operator, ast.Sub):
                return _SetValue(
                    [
                        value
                        for value in left.values
                        if not any(
                            self._equals(value, candidate).concrete
                            for candidate in right.values
                        )
                    ]
                )
        if isinstance(left, _InstanceValue):
            methods = {
                ast.Add: "__add__",
                ast.Sub: "__sub__",
                ast.Mult: "__mul__",
                ast.FloorDiv: "__floordiv__",
                ast.Mod: "__mod__",
            }
            for kind, name in methods.items():
                if isinstance(operator, kind):
                    method_with_owner = self._method_with_owner(
                        left.class_value, name
                    )
                    if method_with_owner is not None:
                        method, owner = method_with_owner
                        return self._call_method(method, owner, left, [right], {})
        if isinstance(left, _BoolValue) and isinstance(right, _BoolValue):
            if isinstance(operator, ast.BitXor):
                return _BoolValue(
                    left.concrete ^ right.concrete,
                    self._z3.Xor(left.symbolic, right.symbolic),
                )
            if isinstance(operator, ast.BitAnd):
                return _BoolValue(
                    left.concrete and right.concrete,
                    self._z3.And(left.symbolic, right.symbolic),
                )
            if isinstance(operator, ast.BitOr):
                return _BoolValue(
                    left.concrete or right.concrete,
                    self._z3.Or(left.symbolic, right.symbolic),
                )
        if (
            isinstance(operator, ast.Add)
            and isinstance(left, _StringValue)
            and isinstance(right, _StringValue)
        ):
            return _StringValue(
                left.concrete + right.concrete, left.symbolic + right.symbolic
            )
        if isinstance(operator, ast.Mod) and isinstance(left, _StringValue):
            try:
                concrete = left.concrete % _concrete(right)
            except (TypeError, ValueError) as error:
                raise ConcolicError(str(error)) from error
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if (
            isinstance(operator, ast.Add)
            and isinstance(left, _ListValue)
            and isinstance(right, _ListValue)
        ):
            return _ListValue(left.values + right.values)
        if isinstance(left, (_IntValue, _FloatValue)) and isinstance(
            right, (_IntValue, _FloatValue)
        ) and (isinstance(left, _FloatValue) or isinstance(right, _FloatValue)):
            lhs = self._as_real(left)
            rhs = self._as_real(right)
            if isinstance(operator, ast.Add):
                concrete, symbolic = lhs[0] + rhs[0], lhs[1] + rhs[1]
            elif isinstance(operator, ast.Sub):
                concrete, symbolic = lhs[0] - rhs[0], lhs[1] - rhs[1]
            elif isinstance(operator, ast.Mult):
                concrete, symbolic = lhs[0] * rhs[0], lhs[1] * rhs[1]
            elif isinstance(operator, ast.Div):
                if rhs[0] == 0:
                    raise ConcolicError("division by zero")
                concrete, symbolic = lhs[0] / rhs[0], lhs[1] / rhs[1]
            elif isinstance(operator, ast.FloorDiv):
                if rhs[0] == 0:
                    raise ConcolicError("division by zero")
                concrete = lhs[0] // rhs[0]
                symbolic = self._z3.RealVal(str(concrete))
            elif isinstance(operator, ast.Mod):
                if rhs[0] == 0:
                    raise ConcolicError("division by zero")
                concrete = lhs[0] % rhs[0]
                symbolic = self._z3.RealVal(str(concrete))
            else:
                raise UnsupportedSyntaxError(
                    f"unsupported floating-point operator {type(operator).__name__}"
                )
            return _FloatValue(float(concrete), symbolic)
        if isinstance(operator, ast.Mult) and isinstance(left, _StringValue):
            count = self._as_int(right)
            return _StringValue(
                left.concrete * count.concrete,
                self._z3.StringVal(left.concrete * count.concrete),
            )
        if isinstance(operator, ast.Mult) and isinstance(left, _ListValue):
            count = self._as_int(right)
            return _ListValue(left.values * count.concrete)
        if isinstance(operator, ast.Mult) and isinstance(
            right, (_StringValue, _ListValue)
        ):
            return self._binary(right, operator, left)
        lhs, rhs = self._as_int(left), self._as_int(right)
        if isinstance(operator, ast.Add):
            return _IntValue(lhs.concrete + rhs.concrete, lhs.symbolic + rhs.symbolic)
        if isinstance(operator, ast.Sub):
            return _IntValue(lhs.concrete - rhs.concrete, lhs.symbolic - rhs.symbolic)
        if isinstance(operator, ast.Mult):
            return _IntValue(lhs.concrete * rhs.concrete, lhs.symbolic * rhs.symbolic)
        if isinstance(operator, ast.FloorDiv):
            if rhs.concrete == 0:
                raise ConcolicError("division by zero")
            return _IntValue(
                lhs.concrete // rhs.concrete,
                self._python_floor_div(lhs.symbolic, rhs.symbolic),
            )
        if isinstance(operator, ast.Mod):
            if rhs.concrete == 0:
                raise ConcolicError("modulo by zero")
            quotient = self._python_floor_div(lhs.symbolic, rhs.symbolic)
            return _IntValue(
                lhs.concrete % rhs.concrete, lhs.symbolic - rhs.symbolic * quotient
            )
        if isinstance(operator, ast.Div):
            if rhs.concrete == 0:
                raise ConcolicError("division by zero")
            return _FloatValue(
                lhs.concrete / rhs.concrete,
                self._z3.ToReal(lhs.symbolic) / self._z3.ToReal(rhs.symbolic),
            )
        if isinstance(operator, ast.LShift):
            factor = 1 << rhs.concrete
            return _IntValue(lhs.concrete << rhs.concrete, lhs.symbolic * factor)
        if isinstance(operator, ast.RShift):
            factor = 1 << rhs.concrete
            return _IntValue(
                lhs.concrete >> rhs.concrete,
                self._python_floor_div(lhs.symbolic, self._z3.IntVal(factor)),
            )
        if isinstance(operator, (ast.BitAnd, ast.BitOr, ast.BitXor)):
            concrete = (
                lhs.concrete & rhs.concrete
                if isinstance(operator, ast.BitAnd)
                else (
                    lhs.concrete | rhs.concrete
                    if isinstance(operator, ast.BitOr)
                    else lhs.concrete ^ rhs.concrete
                )
            )
            return _IntValue(concrete, self._z3.IntVal(concrete))
        raise UnsupportedSyntaxError(
            f"unsupported binary operator {type(operator).__name__}"
        )

    def _compare(self, comparison: ast.Compare) -> _BoolValue:
        left = self._evaluate(comparison.left)
        pairs = [
            (operator, self._evaluate(node))
            for operator, node in zip(comparison.ops, comparison.comparators)
        ]
        return self._compare_values(left, pairs)

    def _compare_values(
        self, left: Any, pairs: list[tuple[ast.cmpop, Any]]
    ) -> _BoolValue:
        concrete_parts: list[bool] = []
        symbolic_parts: list[Any] = []
        for operator, right in pairs:
            if isinstance(operator, (ast.In, ast.NotIn)):
                membership = self._contains(right, left)
                concrete = membership.concrete
                symbolic = membership.symbolic
                if isinstance(operator, ast.NotIn):
                    concrete, symbolic = not concrete, self._z3.Not(symbolic)
                concrete_parts.append(concrete)
                symbolic_parts.append(symbolic)
                left = right
                continue
            if isinstance(operator, (ast.Is, ast.IsNot)):
                concrete = (
                    left.name == right.name
                    if isinstance(left, _BuiltinFunction)
                    and isinstance(right, _BuiltinFunction)
                    else _concrete(left) is _concrete(right)
                )
                symbolic = self._z3.BoolVal(concrete)
                if isinstance(operator, ast.IsNot):
                    concrete, symbolic = not concrete, self._z3.Not(symbolic)
                concrete_parts.append(concrete)
                symbolic_parts.append(symbolic)
                left = right
                continue
            left = self._enum_scalar(left)
            right = self._enum_scalar(right)
            if isinstance(left, _EnumMember) and isinstance(right, _EnumMember):
                if not isinstance(operator, (ast.Eq, ast.NotEq)):
                    raise UnsupportedSyntaxError(
                        "enum members only support equality comparison"
                    )
                equality = self._equals(left, right)
                concrete, symbolic = equality.concrete, equality.symbolic
                if isinstance(operator, ast.NotEq):
                    concrete, symbolic = not concrete, self._z3.Not(symbolic)
                concrete_parts.append(concrete)
                symbolic_parts.append(symbolic)
                left = right
                continue
            if isinstance(left, _InstanceValue):
                methods = {
                    ast.Eq: "__eq__",
                    ast.NotEq: "__ne__",
                    ast.Lt: "__lt__",
                    ast.LtE: "__le__",
                    ast.Gt: "__gt__",
                    ast.GtE: "__ge__",
                }
                method_name = next(
                    (
                        name
                        for kind, name in methods.items()
                        if isinstance(operator, kind)
                    ),
                    None,
                )
                method_with_owner = (
                    self._method_with_owner(left.class_value, method_name)
                    if method_name is not None
                    else None
                )
                used_equality_fallback = False
                if method_with_owner is None and isinstance(operator, ast.NotEq):
                    method_with_owner = self._method_with_owner(
                        left.class_value, "__eq__"
                    )
                    used_equality_fallback = method_with_owner is not None
                if method_with_owner is not None:
                    method, owner = method_with_owner
                    equality = self._truthy(
                        self._call_method(method, owner, left, [right], {})
                    )
                    concrete, symbolic = equality.concrete, equality.symbolic
                    if isinstance(operator, ast.NotEq) and used_equality_fallback:
                        concrete, symbolic = not concrete, self._z3.Not(symbolic)
                    concrete_parts.append(concrete)
                    symbolic_parts.append(symbolic)
                    left = right
                    continue
            if left is None or right is None:
                if not isinstance(operator, (ast.Eq, ast.NotEq)):
                    raise UnsupportedSyntaxError(
                        "None only supports equality comparison"
                    )
                concrete = _concrete(left) == _concrete(right)
                if isinstance(operator, ast.NotEq):
                    concrete = not concrete
                concrete_parts.append(concrete)
                symbolic_parts.append(self._z3.BoolVal(concrete))
                left = right
                continue
            if isinstance(left, (_IntValue, _FloatValue)) and isinstance(
                right, (_IntValue, _FloatValue)
            ) and (isinstance(left, _FloatValue) or isinstance(right, _FloatValue)):
                lhs = self._as_real(left)
                rhs = self._as_real(right)
                comparisons = {
                    ast.Eq: (lhs[0] == rhs[0], lhs[1] == rhs[1]),
                    ast.NotEq: (lhs[0] != rhs[0], lhs[1] != rhs[1]),
                    ast.Lt: (lhs[0] < rhs[0], lhs[1] < rhs[1]),
                    ast.LtE: (lhs[0] <= rhs[0], lhs[1] <= rhs[1]),
                    ast.Gt: (lhs[0] > rhs[0], lhs[1] > rhs[1]),
                    ast.GtE: (lhs[0] >= rhs[0], lhs[1] >= rhs[1]),
                }
                for kind, result in comparisons.items():
                    if isinstance(operator, kind):
                        concrete_parts.append(result[0])
                        symbolic_parts.append(result[1])
                        left = right
                        break
                else:
                    raise UnsupportedSyntaxError(
                        f"unsupported comparison {type(operator).__name__}"
                    )
                continue
            if isinstance(left, _StringValue) and isinstance(right, _StringValue):
                if isinstance(operator, ast.Eq):
                    concrete, symbolic = (
                        left.concrete == right.concrete,
                        left.symbolic == right.symbolic,
                    )
                elif isinstance(operator, ast.NotEq):
                    concrete, symbolic = (
                        left.concrete != right.concrete,
                        left.symbolic != right.symbolic,
                    )
                else:
                    concrete, symbolic = self._string_order(left, right, operator)
                concrete_parts.append(concrete)
                symbolic_parts.append(symbolic)
                left = right
                continue
            left, right = self._as_int(left), self._as_int(right)
            if isinstance(operator, ast.Eq):
                concrete, symbolic = (
                    left.concrete == right.concrete,
                    left.symbolic == right.symbolic,
                )
            elif isinstance(operator, ast.NotEq):
                concrete, symbolic = (
                    left.concrete != right.concrete,
                    left.symbolic != right.symbolic,
                )
            elif isinstance(operator, ast.Lt):
                concrete, symbolic = (
                    left.concrete < right.concrete,
                    left.symbolic < right.symbolic,
                )
            elif isinstance(operator, ast.LtE):
                concrete, symbolic = (
                    left.concrete <= right.concrete,
                    left.symbolic <= right.symbolic,
                )
            elif isinstance(operator, ast.Gt):
                concrete, symbolic = (
                    left.concrete > right.concrete,
                    left.symbolic > right.symbolic,
                )
            elif isinstance(operator, ast.GtE):
                concrete, symbolic = (
                    left.concrete >= right.concrete,
                    left.symbolic >= right.symbolic,
                )
            else:
                raise UnsupportedSyntaxError(
                    f"unsupported comparison {type(operator).__name__}"
                )
            concrete_parts.append(concrete)
            symbolic_parts.append(symbolic)
            left = right
        return _BoolValue(all(concrete_parts), self._z3.And(*symbolic_parts))

    def _input_value(self, name: str, value: Any) -> Any:
        if isinstance(value, bool):
            return _BoolValue(value, self._z3.Bool(name))
        if isinstance(value, int):
            return _IntValue(value, self._z3.Int(name))
        if isinstance(value, float):
            return _FloatValue(value, self._z3.Real(name))
        if isinstance(value, str):
            return _StringValue(value, self._z3.String(name))
        if isinstance(value, list):
            return _ListValue(
                [
                    self._input_value(f"{name}_{index}", item)
                    for index, item in enumerate(value)
                ]
            )
        if isinstance(value, dict):
            return _DictValue(
                {
                    key: self._input_value(f"{name}_{key}", item)
                    for key, item in value.items()
                    if isinstance(key, (int, str, bool))
                }
            )
        raise ValueError(
            "initial_inputs must contain integers, strings, Booleans, or lists"
        )

    def _assign(self, target: ast.expr, value: Any) -> None:
        if isinstance(target, ast.Name):
            self._assign_name(target.id, value)
            return
        if isinstance(target, ast.Subscript):
            container = self._evaluate(target.value)
            if isinstance(container, _InstanceValue):
                method_with_owner = self._method_with_owner(
                    container.class_value, "__setitem__"
                )
                if method_with_owner is not None:
                    method, owner = method_with_owner
                    key = (
                        self._slice_indices(target.slice, 0)
                        if isinstance(target.slice, ast.Slice)
                        else self._evaluate(target.slice)
                    )
                    self._call_method(method, owner, container, [key, value], {})
                    return
            if isinstance(target.slice, ast.Slice):
                if not isinstance(container, _ListValue):
                    raise UnsupportedSyntaxError("slice assignment requires a list")
                container.values[
                    self._slice_indices(target.slice, len(container.values))
                ] = list(self._iter_values(value))
                return
            index = self._evaluate(target.slice)
            if isinstance(container, _ListValue):
                container.values[self._as_int(index).concrete] = value
                return
            if isinstance(container, _DictValue):
                container.values[self._key(index)] = value
                return
        if isinstance(target, ast.Attribute):
            instance = self._evaluate(target.value)
            if isinstance(instance, _InstanceValue):
                setter = self._property_setter_with_owner(
                    instance.class_value, target.attr
                )
                if setter is not None:
                    method, owner = setter
                    self._call_method(method, owner, instance, [value], {})
                    return
                instance.fields[target.attr] = value
                return
            if isinstance(instance, _ClassValue):
                self._materialize_class_attributes(instance)[target.attr] = value
                return
        if isinstance(target, (ast.Tuple, ast.List)):
            values = self._iter_values(value)
            starred = [
                index
                for index, element in enumerate(target.elts)
                if isinstance(element, ast.Starred)
            ]
            if len(starred) > 1:
                raise UnsupportedSyntaxError(
                    "unpacking assignment has multiple starred targets"
                )
            if not starred:
                if len(target.elts) != len(values):
                    raise UnsupportedSyntaxError(
                        "unpacking assignment has mismatched length"
                    )
                for element, item in zip(target.elts, values):
                    self._assign(element, item)
                return
            star_index = starred[0]
            trailing_count = len(target.elts) - star_index - 1
            if len(values) < star_index + trailing_count:
                raise UnsupportedSyntaxError(
                    "unpacking assignment has mismatched length"
                )
            for element, item in zip(target.elts[:star_index], values):
                self._assign(element, item)
            starred_target = target.elts[star_index]
            assert isinstance(starred_target, ast.Starred)
            self._assign(
                starred_target.value,
                _ListValue(list(values[star_index : len(values) - trailing_count])),
            )
            if trailing_count:
                for element, item in zip(
                    target.elts[-trailing_count:], values[-trailing_count:]
                ):
                    self._assign(element, item)
            return
        raise UnsupportedSyntaxError("unsupported assignment target")

    def _assign_name(self, name: str, value: Any) -> None:
        if name in self._global_names:
            self._global_values[name] = value
        elif name in self._nonlocal_names:
            if self._closure_env is None or name not in self._closure_env:
                raise ConcolicError(
                    f"nonlocal name {name!r} has no enclosing binding"
                )
            self._closure_env[name] = value
        else:
            self.env[name] = value

    def _delete(self, target: ast.expr) -> None:
        if isinstance(target, ast.Name):
            self.env.pop(target.id, None)
            return
        if isinstance(target, ast.Attribute):
            self._delattr(
                self._evaluate(target.value),
                _StringValue(target.attr, self._z3.StringVal(target.attr)),
            )
            return
        if isinstance(target, ast.Subscript):
            container = self._evaluate(target.value)
            if isinstance(target.slice, ast.Slice) and isinstance(
                container, _ListValue
            ):
                del container.values[
                    self._slice_indices(target.slice, len(container.values))
                ]
                return
            index = self._evaluate(target.slice)
            if isinstance(container, _ListValue):
                del container.values[self._as_int(index).concrete]
                return
            if isinstance(container, _DictValue):
                del container.values[self._key(index)]
                return
        raise UnsupportedSyntaxError("unsupported deletion target")

    def _evaluate_target(self, target: ast.expr) -> Any:
        if isinstance(target, ast.Name):
            return self._lookup(target.id)
        if isinstance(target, ast.Attribute):
            return self._attribute(self._evaluate(target.value), target.attr)
        if isinstance(target, ast.Subscript):
            return self._subscript(self._evaluate(target.value), target.slice)
        raise UnsupportedSyntaxError("unsupported augmented-assignment target")

    def _subscript(self, container: Any, slice_node: ast.expr) -> Any:
        if isinstance(container, _InstanceValue):
            method_with_owner = self._method_with_owner(
                container.class_value, "__getitem__"
            )
            if method_with_owner is not None:
                method, owner = method_with_owner
                key = (
                    self._slice_indices(slice_node, 0)
                    if isinstance(slice_node, ast.Slice)
                    else self._evaluate(slice_node)
                )
                return self._call_method(method, owner, container, [key], {})
        if isinstance(slice_node, ast.Slice):
            return self._slice(container, slice_node)
        index = (
            self._as_int(self._evaluate(slice_node))
            if not isinstance(container, _DictValue)
            else self._evaluate(slice_node)
        )
        if isinstance(container, _StringValue):
            return self._string_index(container, index)
        if isinstance(container, _BytesValue):
            return self._literal(container.concrete[index.concrete])
        if isinstance(
            container, (_ListValue, _TupleValue, _NamedTupleValue, _SetValue)
        ):
            return container.values[index.concrete]
        if isinstance(container, _DictValue):
            key = self._key(index)
            if key not in container.values and isinstance(container, _CounterValue):
                return self._literal(0)
            if key not in container.values and isinstance(container, _DefaultDictValue):
                container.values[key] = self._call_value(container.factory, [], {})
            return container.values[key]
        raise UnsupportedSyntaxError("subscripted value is not a supported container")

    def _slice(self, container: Any, slice_node: ast.Slice) -> Any:
        step = self._slice_step(slice_node)
        start = self._slice_bound(slice_node.lower, 0)
        if isinstance(container, _StringValue):
            stop = self._slice_bound(slice_node.upper, len(container.concrete))
            concrete = container.concrete[
                self._slice_indices(slice_node, len(container.concrete))
            ]
            if step.concrete != 1 or start.concrete < 0 or stop.concrete < 0:
                return _StringValue(concrete, self._z3.StringVal(concrete))
            return _StringValue(
                concrete,
                self._z3.SubString(
                    container.symbolic, start.symbolic, stop.symbolic - start.symbolic
                ),
            )
        if isinstance(container, _BytesValue):
            return _BytesValue(
                container.concrete[
                    self._slice_indices(slice_node, len(container.concrete))
                ]
            )
        if isinstance(container, _ListValue):
            return _ListValue(
                container.values[self._slice_indices(slice_node, len(container.values))]
            )
        if isinstance(container, _TupleValue):
            return _TupleValue(
                container.values[self._slice_indices(slice_node, len(container.values))]
            )
        raise UnsupportedSyntaxError("slicing requires a string, list, or tuple")

    def _slice_bound(self, node: ast.expr | None, default: int) -> _IntValue:
        return (
            _IntValue(default, self._z3.IntVal(default))
            if node is None
            else self._as_int(self._evaluate(node))
        )

    def _slice_step(self, node: ast.Slice) -> _IntValue:
        step = self._slice_bound(node.step, 1)
        if step.concrete == 0:
            raise ConcolicError("slice step cannot be zero")
        return step

    def _slice_indices(self, node: ast.Slice, _length: int) -> slice:
        step = self._slice_step(node).concrete
        start = (
            self._as_int(self._evaluate(node.lower)).concrete
            if node.lower is not None
            else None
        )
        stop = (
            self._as_int(self._evaluate(node.upper)).concrete
            if node.upper is not None
            else None
        )
        return slice(start, stop, step)

    def _string_index(self, value: _StringValue, index: _IntValue) -> _StringValue:
        concrete = value.concrete[index.concrete]
        if index.concrete < 0:
            return _StringValue(concrete, self._z3.StringVal(concrete))
        return _StringValue(
            concrete, self._z3.SubString(value.symbolic, index.symbolic, 1)
        )

    def _as_iterator(self, value: Any) -> _IteratorValue:
        if isinstance(value, _IteratorValue):
            return value
        if isinstance(
            value, (_ListValue, _TupleValue, _NamedTupleValue, _SetValue, _RangeValue)
        ):
            return _SequenceIteratorValue(tuple(value.values))
        if isinstance(value, _BytesValue):
            return _SequenceIteratorValue(
                tuple(self._literal(item) for item in value.concrete)
            )
        if isinstance(value, _StringValue):
            return _SequenceIteratorValue(
                tuple(
                    _StringValue(char, self._z3.StringVal(char))
                    for char in value.concrete
                )
            )
        if isinstance(value, _DictValue):
            return _SequenceIteratorValue(
                tuple(self._literal(key) for key in value.values)
            )
        if isinstance(value, _EnumClass):
            return _SequenceIteratorValue(
                tuple(
                    _EnumMember(value, name, member_value)
                    for name, member_value in value.members.items()
                )
            )
        if isinstance(value, _InstanceValue):
            method_with_owner = self._method_with_owner(value.class_value, "__iter__")
            if method_with_owner is not None:
                method, owner = method_with_owner
                return self._as_iterator(
                    self._call_method(method, owner, value, [], {})
                )
        raise UnsupportedSyntaxError("value is not iterable in the concolic subset")

    def _resume_iterator(
        self, iterator: _IteratorValue, operation: _ResumeOperation
    ) -> _Yielded | _Awaiting | _Returned:
        self._resume_steps += 1
        if self._resume_steps > self._max_resume_steps:
            raise ConcolicError(
                "iterator execution exceeded --max-resume-steps "
                f"({self._max_resume_steps})"
            )
        outcome = iterator.resume(self, operation)
        if isinstance(outcome, _Raised):
            raise outcome.exception
        return outcome

    def _iter_values(self, value: Any) -> tuple[Any, ...]:
        iterator = self._as_iterator(value)
        values: list[Any] = []
        while True:
            outcome = self._resume_iterator(
                iterator, _ResumeOperation(_ResumeKind.NEXT)
            )
            if isinstance(outcome, _Returned):
                return tuple(values)
            values.append(outcome.value)

    def _evaluate_comprehension(
        self,
        generators: list[ast.comprehension],
        expression: ast.expr | tuple[ast.expr, ast.expr],
    ) -> list[Any]:
        output: list[Any] = []
        previous_env = self.env
        self.env = dict(self.env)

        def visit(index: int) -> None:
            if index == len(generators):
                if isinstance(expression, tuple):
                    output.append(
                        (self._evaluate(expression[0]), self._evaluate(expression[1]))
                    )
                else:
                    output.append(self._evaluate(expression))
                return
            generator = generators[index]
            for item in self._iter_values(self._evaluate(generator.iter)):
                self._assign(generator.target, item)
                include = True
                for condition_node in generator.ifs:
                    condition = self._truthy(self._evaluate(condition_node))
                    self._record_branch(
                        condition.symbolic,
                        condition.concrete,
                        condition_node,
                        "comprehension_filter",
                    )
                    if not condition.concrete:
                        include = False
                        break
                if include:
                    visit(index + 1)

        try:
            visit(0)
        finally:
            self.env = previous_env
        return output

    def _length(self, value: Any) -> _IntValue:
        if isinstance(value, _StringValue):
            return _IntValue(len(value.concrete), self._z3.Length(value.symbolic))
        if isinstance(
            value, (_ListValue, _TupleValue, _NamedTupleValue, _SetValue, _RangeValue)
        ):
            return _IntValue(len(value.values), self._z3.IntVal(len(value.values)))
        if isinstance(value, _BytesValue):
            return _IntValue(len(value.concrete), self._z3.IntVal(len(value.concrete)))
        if isinstance(value, _DictValue):
            return _IntValue(len(value.values), self._z3.IntVal(len(value.values)))
        if isinstance(value, _InstanceValue):
            method_with_owner = self._method_with_owner(value.class_value, "__len__")
            if method_with_owner is not None:
                method, owner = method_with_owner
                return self._as_int(self._call_method(method, owner, value, [], {}))
        raise UnsupportedSyntaxError("len() requires a supported container")

    def _to_int(self, value: Any) -> _IntValue:
        value = self._enum_scalar(value)
        if isinstance(value, _IntValue):
            return value
        if isinstance(value, _BoolValue):
            return _IntValue(int(value.concrete), self._z3.If(value.symbolic, 1, 0))
        if isinstance(value, _FloatValue):
            symbolic = self._z3.If(
                value.symbolic >= 0,
                self._z3.ToInt(value.symbolic),
                -self._z3.ToInt(-value.symbolic),
            )
            return _IntValue(int(value.concrete), symbolic)
        if isinstance(value, _StringValue):
            try:
                concrete = int(value.concrete)
            except ValueError as error:
                raise ConcolicError(
                    f"invalid literal for int(): {value.concrete!r}"
                ) from error
            if value.concrete.startswith("-"):
                symbolic = -self._z3.StrToInt(
                    self._z3.SubString(
                        value.symbolic, 1, self._z3.Length(value.symbolic) - 1
                    )
                )
            else:
                symbolic = self._z3.StrToInt(value.symbolic)
            return _IntValue(concrete, symbolic)
        raise UnsupportedSyntaxError("int() requires an integer, Boolean, or string")

    def _to_float(self, value: Any) -> _FloatValue:
        if isinstance(value, _FloatValue):
            return value
        if isinstance(value, _IntValue):
            return _FloatValue(float(value.concrete), self._z3.ToReal(value.symbolic))
        if isinstance(value, _BoolValue):
            return _FloatValue(
                float(value.concrete), self._z3.If(value.symbolic, 1.0, 0.0)
            )
        if isinstance(value, _StringValue):
            try:
                concrete = float(value.concrete)
            except ValueError as error:
                raise ConcolicError(str(error)) from error
            if not math.isfinite(concrete):
                raise UnsupportedSyntaxError(
                    "float() does not support non-finite values"
                )
            return _FloatValue(concrete, self._z3.RealVal(str(concrete)))
        raise UnsupportedSyntaxError("float() requires an integer, Boolean, or string")

    def _to_string(self, value: Any) -> _StringValue:
        value = self._enum_scalar(value)
        if isinstance(value, _StringValue):
            return value
        if isinstance(value, _IntValue):
            concrete = str(value.concrete)
            symbolic = (
                self._z3.IntToStr(value.symbolic)
                if value.concrete >= 0
                else self._z3.StringVal(concrete)
            )
            return _StringValue(concrete, symbolic)
        if isinstance(value, _BoolValue):
            concrete = str(value.concrete)
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if isinstance(value, _InstanceValue):
            method_with_owner = self._method_with_owner(value.class_value, "__str__")
            if method_with_owner is not None:
                method, owner = method_with_owner
                return self._to_string(
                    self._call_method(method, owner, value, [], {})
                )
        return _StringValue(
            str(_concrete(value)), self._z3.StringVal(str(_concrete(value)))
        )

    def _format_value(self, value: Any, specification: str) -> _StringValue:
        if isinstance(value, _InstanceValue):
            method_with_owner = self._method_with_owner(
                value.class_value, "__format__"
            )
            if method_with_owner is not None:
                method, owner = method_with_owner
                return self._to_string(
                    self._call_method(
                        method,
                        owner,
                        value,
                        [
                            _StringValue(
                                specification, self._z3.StringVal(specification)
                            )
                        ],
                        {},
                    )
                )
        try:
            concrete = format(_concrete(value), specification)
        except (TypeError, ValueError) as error:
            raise ConcolicError(str(error)) from error
        return _StringValue(concrete, self._z3.StringVal(concrete))

    def _to_bytes(self, value: Any) -> _BytesValue:
        if isinstance(value, _BytesValue):
            return value
        if isinstance(value, (_ListValue, _TupleValue, _RangeValue)):
            return _BytesValue(
                bytes(self._as_int(item).concrete for item in value.values)
            )
        raise UnsupportedSyntaxError(
            "bytes() requires bytes or an iterable of integers"
        )

    def _range(self, args: list[Any]) -> _RangeValue:
        ints = [self._as_int(argument) for argument in args]
        start, stop, step = (
            (
                _IntValue(0, self._z3.IntVal(0)),
                ints[0],
                _IntValue(1, self._z3.IntVal(1)),
            )
            if len(ints) == 1
            else (
                ints[0],
                ints[1],
                ints[2] if len(ints) == 3 else _IntValue(1, self._z3.IntVal(1)),
            )
        )
        if step.concrete == 0:
            raise ConcolicError("range() arg 3 must not be zero")
        return _RangeValue(
            tuple(
                _IntValue(item, start.symbolic + offset * step.symbolic)
                for offset, item in enumerate(
                    range(start.concrete, stop.concrete, step.concrete)
                )
            )
        )

    def _aggregate(self, name: str, args: list[Any]) -> _IntValue | _FloatValue:
        if name == "sum":
            if not 1 <= len(args) <= 2:
                raise ConcolicError("sum() expects an iterable and optional start")
            values = list(self._iter_values(args[0]))
            start = args[1] if len(args) == 2 else self._literal(0)
            values.insert(0, start)
        else:
            values = list(self._iter_values(args[0])) if len(args) == 1 else args
            if not values:
                raise ConcolicError(f"{name}() arg is an empty sequence")

        if not all(isinstance(value, (_IntValue, _FloatValue)) for value in values):
            raise UnsupportedSyntaxError(f"{name}() requires numeric values")
        if not any(isinstance(value, _FloatValue) for value in values):
            integers = [self._as_int(value) for value in values]
            if name == "sum":
                return _IntValue(
                    sum(value.concrete for value in integers),
                    self._z3.Sum(*(value.symbolic for value in integers)),
                )
            selected = integers[0]
            for value in integers[1:]:
                choose = (
                    selected.symbolic >= value.symbolic
                    if name == "max"
                    else selected.symbolic <= value.symbolic
                )
                concrete = (
                    max(selected.concrete, value.concrete)
                    if name == "max"
                    else min(selected.concrete, value.concrete)
                )
                selected = _IntValue(
                    concrete, self._z3.If(choose, selected.symbolic, value.symbolic)
                )
            return selected

        reals = [self._as_real(value) for value in values]
        if name == "sum":
            return _FloatValue(
                sum(value[0] for value in reals),
                self._z3.Sum(*(value[1] for value in reals)),
            )
        selected_concrete, selected_symbolic = reals[0]
        for concrete, symbolic in reals[1:]:
            choose = (
                selected_symbolic >= symbolic
                if name == "max"
                else selected_symbolic <= symbolic
            )
            selected_concrete = (
                max(selected_concrete, concrete)
                if name == "max"
                else min(selected_concrete, concrete)
            )
            selected_symbolic = self._z3.If(
                choose, selected_symbolic, symbolic
            )
        return _FloatValue(selected_concrete, selected_symbolic)

    def _heap_entries(self, values: list[Any]) -> list[tuple[Any, int, Any]]:
        entries = [
            (_concrete(value), index, value) for index, value in enumerate(values)
        ]
        try:
            heapq.heapify(entries)
        except TypeError as error:
            raise ConcolicError(str(error)) from error
        return entries

    def _copy_value(self, value: Any, *, deep: bool) -> Any:
        copy_value = (
            (lambda item: self._copy_value(item, deep=True))
            if deep
            else lambda item: item
        )
        if isinstance(value, _DequeValue):
            return _DequeValue([copy_value(item) for item in value.values])
        if isinstance(value, _ListValue):
            return _ListValue([copy_value(item) for item in value.values])
        if isinstance(value, _TupleValue):
            return _TupleValue(tuple(copy_value(item) for item in value.values))
        if isinstance(value, _SetValue):
            return _SetValue([copy_value(item) for item in value.values])
        if isinstance(value, _DefaultDictValue):
            return _DefaultDictValue(
                {key: copy_value(item) for key, item in value.values.items()},
                value.factory,
            )
        if isinstance(value, _CounterValue):
            return _CounterValue(
                {key: copy_value(item) for key, item in value.values.items()}
            )
        if isinstance(value, _DictValue):
            return _DictValue(
                {key: copy_value(item) for key, item in value.values.items()}
            )
        if isinstance(value, _InstanceValue):
            return _InstanceValue(
                value.class_value,
                {name: copy_value(item) for name, item in value.fields.items()},
            )
        return value
