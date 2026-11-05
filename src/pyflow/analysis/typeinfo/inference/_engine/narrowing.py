"""Refine environments with guards, membership tests, and patterns."""

from __future__ import annotations

import ast
import itertools
import operator
import collections.abc as cabc
from dataclasses import replace
from typing import Callable

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    AnyType,
    NONE_TYPE,
    CallableType,
    Instance,
    LiteralType,
    NoneType,
    ProperType,
    TupleType,
    TypeType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference._engine.component import InferenceComponent
from pyflow.analysis.typeinfo.inference._engine.state import _ClassInfo, _FunctionInfo
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue, join_all
from pyflow.analysis.typeinfo.resolution.literals import narrow_to_literal


class NarrowingInference(InferenceComponent):
    """Refine environments with guards, membership tests, and patterns."""

    def _narrow_environment(
        self,
        condition: ast.expr,
        environment: dict[str, AbstractTypeValue],
        *,
        truthy: bool,
    ) -> dict[str, AbstractTypeValue]:
        result = dict(environment)
        if isinstance(condition, ast.UnaryOp) and isinstance(condition.op, ast.Not):
            return self._narrow_environment(condition.operand, environment, truthy=not truthy)
        if isinstance(condition, ast.BoolOp):
            sequential = (isinstance(condition.op, ast.And) and truthy) or (
                isinstance(condition.op, ast.Or) and not truthy
            )
            if sequential:
                for expression in condition.values:
                    result = self._narrow_environment(expression, result, truthy=truthy)
                return result
            paths = []
            for expression in condition.values:
                paths.append(self._narrow_environment(expression, result, truthy=truthy))
                result = self._narrow_environment(expression, result, truthy=not truthy)
            return self.engine._value_rules._join_many_environments(paths)

        def key(expression):
            if isinstance(expression, ast.NamedExpr):
                expression = expression.target
            return (
                ast.unparse(expression)
                if isinstance(expression, (ast.Name, ast.Attribute, ast.Subscript))
                else None
            )

        def current(expression):
            name = key(expression)
            if name in result:
                return result[name]
            if name in self.engine._module_environment:
                return self.engine._module_environment[name]
            if isinstance(expression, ast.Attribute):
                return self.engine._member_rules._attribute_value(
                    current(expression.value), expression.attr
                )
            if isinstance(expression, ast.Subscript):
                return self.engine._value_rules._subscript_value(
                    current(expression.value), expression.slice
                )
            return AbstractTypeValue.unresolved()

        if isinstance(condition, ast.NamedExpr) and isinstance(condition.target, ast.Name):
            name = condition.target.id
            if name in result:
                result[name] = self.engine._value_rules._remove_none(result[name])
            return result
        if key(condition) is not None and truthy:
            result[key(condition)] = self.engine._value_rules._remove_none(current(condition))
            return result
        if (
            isinstance(condition, ast.Call)
            and isinstance(condition.func, ast.Name)
            and condition.func.id == "isinstance"
            and len(condition.args) >= 2
            and key(condition.args[0]) is not None
        ):
            expression = condition.args[0]
            narrowed = self.engine._expression_rules._evaluate_type_expression(condition.args[1])
            if narrowed.unknown and isinstance(condition.args[1], ast.Name):
                # Local aliases such as ``_Segment = Segment`` are runtime
                # class objects, not annotation aliases.  A tuple of classes
                # (``expected = (str, bytes)``) narrows to the union of its
                # elements rather than to the tuple itself.
                runtime_alias = current(condition.args[1])
                runtime_types = self._runtime_isinstance_types(runtime_alias)
                if runtime_types is not None:
                    narrowed = runtime_types
            if not narrowed.unknown:
                if truthy:
                    old = current(expression)
                    alternatives = [
                        part
                        for typ in old.types
                        for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                    ]
                    if old.unknown or any(isinstance(part, AnyType) for part in alternatives):
                        result[key(expression)] = narrowed
                    else:
                        accepted = set()
                        for part in alternatives:
                            for expected in narrowed.types:
                                if self.engine.type_system.is_subtype(part, expected):
                                    accepted.add(part)
                                elif self.engine.type_system.is_subtype(expected, part):
                                    accepted.add(expected)
                        result[key(expression)] = AbstractTypeValue(types=frozenset(accepted))
                else:
                    old = current(expression)
                    alternatives = [
                        part
                        for typ in old.types
                        for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                    ]
                    result[key(expression)] = replace(
                        old,
                        types=frozenset(
                            part
                            for part in alternatives
                            if isinstance(part, AnyType)
                            or not any(
                                self.engine.type_system.is_subtype(part, accepted)
                                for accepted in narrowed.types
                            )
                        ),
                    )
            return result
        if truthy and isinstance(condition, ast.Compare) and len(condition.ops) == 1:
            if isinstance(condition.ops[0], ast.Eq):
                left, right = condition.left, condition.comparators[0]
                expression = left if key(left) is not None else right
                literal_node = right if expression is left else left
                if (
                    key(expression) is not None
                    and isinstance(literal_node, ast.Constant)
                    and literal_node.value is not None
                ):
                    literal = self.engine._expression_rules._evaluate_expression(
                        literal_node,
                        result,
                        scope=(
                            self.engine._current_function_info.qualified_name
                            if self.engine._current_function_info is not None
                            else self.engine._module_name
                        ),
                        current_function=self.engine._current_function_info,
                    )
                    if literal.literal_values and not literal.unknown:
                        result[key(expression)] = narrow_to_literal(current(expression), literal)
                        return result

        if (
            isinstance(condition, ast.Compare)
            and len(condition.ops) == 1
            and isinstance(condition.ops[0], (ast.Is, ast.IsNot))
        ):
            left, right = condition.left, condition.comparators[0]
            expression, target = (
                (left, right)
                if key(left) is not None
                else (right, left) if key(right) is not None else (None, None)
            )
            if expression is not None and target is not None:
                expected = current(target)
                if expected.class_targets:
                    old = current(expression)
                    positive = truthy == isinstance(condition.ops[0], ast.Is)
                    if old.class_targets:
                        expected_targets = expected.class_targets
                        class_targets = (
                            old.class_targets & expected_targets
                            if positive
                            else old.class_targets - expected_targets
                        )
                        types = frozenset(
                            part
                            for part in old.types
                            if not isinstance(part, Instance)
                            or (part.type.full_name in expected_targets) == positive
                        )
                        result[key(expression)] = replace(
                            old,
                            types=types,
                            class_targets=class_targets,
                        )
                        return result
        if (
            isinstance(condition, ast.Compare)
            and len(condition.ops) == 1
            and isinstance(condition.ops[0], (ast.Is, ast.Eq))
        ):
            left, right = condition.left, condition.comparators[0]
            type_call = (
                left
                if isinstance(left, ast.Call)
                and isinstance(left.func, ast.Name)
                and left.func.id == "type"
                and len(left.args) == 1
                else (
                    right
                    if isinstance(right, ast.Call)
                    and isinstance(right.func, ast.Name)
                    and right.func.id == "type"
                    and len(right.args) == 1
                    else None
                )
            )
            expected_node = right if type_call is left else left
            if type_call is not None and key(type_call.args[0]) is not None:
                expected = self.engine._expression_rules._evaluate_type_expression(expected_node)
                if not expected.unknown:
                    expression = type_call.args[0]
                    old = current(expression)
                    alternatives = [
                        part
                        for typ in old.types
                        for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                    ]
                    expected_raw = {
                        part.type.raw_type for part in expected.types if isinstance(part, Instance)
                    }
                    filtered = [
                        part
                        for part in alternatives
                        if (isinstance(part, Instance) and part.type.raw_type in expected_raw)
                        == truthy
                    ]
                    result[key(expression)] = AbstractTypeValue(
                        types=frozenset(filtered), unknown=old.unknown
                    )
                    return result
        if (
            isinstance(condition, ast.Compare)
            and len(condition.ops) == 1
            and isinstance(condition.ops[0], (ast.Is, ast.IsNot, ast.Eq, ast.NotEq))
        ):
            left, right = condition.left, condition.comparators[0]
            expression = (
                left
                if key(left) is not None and self.engine._value_rules._is_none_literal(right)
                else (
                    right
                    if key(right) is not None and self.engine._value_rules._is_none_literal(left)
                    else None
                )
            )
            if expression is not None:
                keep_none = truthy == isinstance(condition.ops[0], (ast.Is, ast.Eq))
                old = current(expression)
                if keep_none:
                    alternatives = [
                        part
                        for typ in old.types
                        for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                    ]
                    possible = old.unknown or any(
                        isinstance(part, (NoneType, AnyType))
                        or isinstance(part, Instance)
                        and part.type.raw_type is object
                        for part in alternatives
                    )
                    result[key(expression)] = (
                        AbstractTypeValue.from_type(NONE_TYPE)
                        if possible
                        else AbstractTypeValue.bottom()
                    )
                else:
                    result[key(expression)] = self.engine._value_rules._remove_none(old)
        if (
            isinstance(condition, ast.Compare)
            and len(condition.ops) == 1
            and isinstance(condition.ops[0], (ast.Eq, ast.NotEq))
        ):
            left, right = condition.left, condition.comparators[0]
            expression = (
                left
                if key(left) is not None
                and isinstance(right, ast.Constant)
                and right.value is not None
                else (
                    right
                    if key(right) is not None
                    and isinstance(left, ast.Constant)
                    and left.value is not None
                    else None
                )
            )
            value_node = right if expression is left else left
            if expression is not None and isinstance(value_node, ast.Constant):
                value = value_node.value
                base = self.engine._value_rules._proper_instance(type(value))
                if isinstance(base, Instance):
                    old = current(expression)
                    literal = AbstractTypeValue.from_type(base, literal_values=frozenset((value,)))
                    old_literals = old.literal_values or frozenset(
                        part.value
                        for typ in old.types
                        for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                        if isinstance(part, LiteralType)
                    )
                    equal_branch = truthy == isinstance(condition.ops[0], ast.Eq)
                    if equal_branch:
                        if old_literals:
                            possible = value in old_literals
                        else:
                            possible = old.unknown or any(
                                isinstance(part, AnyType)
                                or self.engine.type_system.is_subtype(
                                    base,
                                    part.base if isinstance(part, LiteralType) else part,
                                )
                                for part in old.types
                            )
                        result[key(expression)] = (
                            literal if possible else AbstractTypeValue.bottom()
                        )
                    elif value in old_literals:
                        remaining = old_literals - {value}
                        if remaining:
                            result[key(expression)] = replace(
                                old, literal_values=frozenset(remaining)
                            )
        if (
            isinstance(condition, ast.Call)
            and isinstance(condition.func, ast.Name)
            and condition.func.id == "hasattr"
            and len(condition.args) >= 2
            and isinstance(condition.args[1], ast.Constant)
            and isinstance(condition.args[1].value, str)
            and key(condition.args[0]) is not None
        ):
            expression = condition.args[0]
            attribute = condition.args[1].value
            old = current(expression)
            alternatives = [
                part
                for typ in old.types
                for part in (typ.items if isinstance(typ, UnionType) else (typ,))
            ]
            if attribute == "__iter__":
                filtered = [part for part in alternatives if self._type_is_iterable(part) == truthy]
            else:
                filtered = [
                    part
                    for part in alternatives
                    if (
                        self.engine._member_rules._attribute_value(
                            AbstractTypeValue.from_type(part), attribute
                        ).public_type()
                        is not None
                    )
                    == truthy
                ]
            result[key(expression)] = AbstractTypeValue(
                types=frozenset(filtered), unknown=old.unknown
            )
        if (
            isinstance(condition, ast.Call)
            and isinstance(condition.func, ast.Name)
            and condition.func.id == "callable"
            and len(condition.args) == 1
            and key(condition.args[0]) is not None
        ):
            expression = condition.args[0]
            old = current(expression)
            alternatives = [
                part
                for typ in old.types
                for part in (typ.items if isinstance(typ, UnionType) else (typ,))
            ]
            filtered = [part for part in alternatives if self._type_is_callable(part) == truthy]
            result[key(expression)] = AbstractTypeValue(
                types=frozenset(filtered), unknown=old.unknown
            )
            return result
        if (
            isinstance(condition, ast.Call)
            and condition.args
            and key(condition.args[0]) is not None
        ):
            callee_name = self.engine._value_rules._qualified_callee_name(condition.func)
            function_info = self.engine._functions.get(callee_name) if callee_name else None
            if function_info is None and isinstance(condition.func, ast.Name):
                function_info = self.engine._functions.get(
                    f"{self.engine._module_name}.{condition.func.id}"
                )
            if function_info is not None and function_info.type_guard_target is not None:
                guard_param, guard_type, is_type_is = function_info.type_guard_target
                expression = condition.args[0]
                if truthy:
                    result[key(expression)] = guard_type
                elif is_type_is:
                    old = current(expression)
                    alternatives = [
                        part
                        for typ in old.types
                        for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                    ]
                    result[key(expression)] = replace(
                        old,
                        types=frozenset(
                            part
                            for part in alternatives
                            if not any(
                                self.engine.type_system.is_subtype(part, accepted)
                                for accepted in guard_type.types
                            )
                        ),
                    )
        if (
            isinstance(condition, ast.Call)
            and isinstance(condition.func, ast.Name)
            and condition.func.id == "callable"
            and condition.args
            and key(condition.args[0]) is not None
        ):
            expression = condition.args[0]
            old = current(expression)
            alternatives = [
                part
                for typ in old.types
                for part in (typ.items if isinstance(typ, UnionType) else (typ,))
            ]
            if truthy:
                callable_parts: set[ProperType] = set()
                for part in alternatives:
                    if isinstance(part, (CallableType, TypeType, AnyType)):
                        callable_parts.add(part)
                    elif isinstance(part, Instance):
                        class_info = self.engine._classes.get(part.type.full_name)
                        has_call = part.type.raw_type is type or "__call__" in part.type.members
                        if class_info is not None:
                            has_call = has_call or (
                                self.engine._member_rules._class_method(
                                    class_info.qualified_name, "__call__"
                                )
                                is not None
                            )
                        if has_call:
                            callable_parts.add(part)
                if old.unknown and not callable_parts:
                    callable_parts.add(CallableType(None, ANY))
                result[key(expression)] = AbstractTypeValue(
                    types=frozenset(callable_parts), unknown=old.unknown
                )
            else:
                non_callable_parts: set[ProperType] = set()
                for part in alternatives:
                    is_call = isinstance(part, (CallableType, TypeType))
                    if isinstance(part, Instance):
                        class_info = self.engine._classes.get(part.type.full_name)
                        has_call = part.type.raw_type is type or "__call__" in part.type.members
                        if class_info is not None:
                            has_call = has_call or (
                                self.engine._member_rules._class_method(
                                    class_info.qualified_name, "__call__"
                                )
                                is not None
                            )
                        is_call = is_call or has_call
                    if not is_call:
                        non_callable_parts.add(part)
                result[key(expression)] = replace(old, types=frozenset(non_callable_parts))
        if (
            isinstance(condition, ast.Compare)
            and len(condition.ops) == 1
            and isinstance(condition.ops[0], ast.In)
            and truthy
            and key(condition.left) is not None
        ):
            allowed = self._membership_element_types(condition.comparators[0], current)
            if allowed is not None:
                result[key(condition.left)] = self._narrow_to_allowed(
                    current(condition.left), allowed
                )
        return result

    def _type_is_iterable(self, typ: ProperType) -> bool:
        if isinstance(typ, TupleType) or isinstance(typ, AnyType):
            return True
        if not isinstance(typ, Instance):
            return False
        raw = typ.type.raw_type
        if raw in {
            str,
            bytes,
            bytearray,
            list,
            set,
            frozenset,
            dict,
            tuple,
            range,
            cabc.Iterable,
            cabc.Iterator,
            cabc.Generator,
            cabc.Sequence,
            cabc.Mapping,
        }:
            return True
        if "__iter__" in typ.type.members:
            return True
        info = self.engine._classes.get(typ.type.full_name)
        return bool(
            info is not None
            and self.engine._member_rules._class_method(info.qualified_name, "__iter__") is not None
        )

    def _type_is_callable(self, typ: ProperType) -> bool:
        if isinstance(typ, (AnyType, CallableType, TypeType)):
            return True
        if not isinstance(typ, Instance):
            return False
        if typ.type.raw_type is type:
            return True
        if "__call__" in typ.type.members:
            return True
        info = self.engine._classes.get(typ.type.full_name)
        return bool(
            info is not None
            and self.engine._member_rules._class_method(info.qualified_name, "__call__") is not None
        )

    def _membership_element_types(
        self,
        container: ast.expr,
        current: Callable[[ast.expr], AbstractTypeValue],
    ) -> AbstractTypeValue | None:
        """Return the element type of a literal membership container."""
        elements: list[ast.expr] | None = None
        if isinstance(container, (ast.Set, ast.List, ast.Tuple)):
            elements = list(container.elts)
        elif isinstance(container, ast.Constant) and isinstance(container.value, (str, bytes)):
            elements = [container]
        elif (
            isinstance(container, ast.Call)
            and isinstance(container.func, ast.Name)
            and container.func.id in {"set", "frozenset"}
            and container.args
        ):
            return self._membership_element_types(container.args[0], current)
        if elements is None:
            return None
        values: list[AbstractTypeValue] = []
        for element in elements:
            if isinstance(element, ast.Constant):
                values.append(
                    AbstractTypeValue.from_type(
                        NONE_TYPE
                        if element.value is None
                        else self.engine._value_rules._proper_instance(type(element.value))
                    )
                )
            else:
                values.append(current(element))
        if any(value.unknown for value in values):
            return None
        return join_all(
            values,
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )

    def _value_may_match(
        self,
        old: AbstractTypeValue,
        expected: AbstractTypeValue,
    ) -> bool:
        if old.literal_values and expected.literal_values:
            return bool(old.literal_values & expected.literal_values)
        for left in old.types:
            for right in expected.types:
                if self.engine.type_system.is_subtype(
                    left, right
                ) or self.engine.type_system.is_subtype(right, left):
                    return True
        return old.unknown or expected.unknown

    def _runtime_isinstance_types(self, value: AbstractTypeValue) -> AbstractTypeValue | None:
        """Convert runtime class objects supplied to ``isinstance`` into types."""
        normalized: list[AbstractTypeValue] = []

        def add(typ: ProperType) -> bool:
            if isinstance(typ, TypeType):
                normalized.append(AbstractTypeValue.from_type(typ.item))
                return True
            if isinstance(typ, TupleType):
                return all(add(item) for item in typ.args)
            if isinstance(typ, UnionType):
                return all(add(item) for item in typ.items)
            if isinstance(typ, Instance):
                if typ.type.raw_type in {tuple, list, set, frozenset} and typ.args:
                    return all(add(item) for item in typ.args)
                # Class objects are also represented as instances in some
                # specialized call environments (``cls`` in classmethods).
                normalized.append(AbstractTypeValue.from_type(typ))
                return True
            return False

        if value.unknown or not value.types:
            return None
        if not all(add(typ) for typ in value.types):
            return None
        return join_all(
            normalized,
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )

    def _narrow_to_allowed(
        self,
        old: AbstractTypeValue,
        allowed: AbstractTypeValue,
    ) -> AbstractTypeValue:
        allowed_parts = [
            part
            for typ in allowed.types
            for part in (typ.items if isinstance(typ, UnionType) else (typ,))
        ]
        if not allowed_parts:
            return old
        alternatives = [
            part
            for typ in old.types
            for part in (typ.items if isinstance(typ, UnionType) else (typ,))
        ]
        if not alternatives:
            return (
                AbstractTypeValue(types=frozenset(allowed_parts), unknown=True)
                if old.unknown
                else old
            )
        accepted: set[ProperType] = set()
        for part in alternatives:
            for candidate in allowed_parts:
                if self.engine.type_system.is_subtype(part, candidate):
                    accepted.add(part)
                elif self.engine.type_system.is_subtype(candidate, part):
                    accepted.add(candidate)
        return AbstractTypeValue(
            types=frozenset(accepted),
            unknown=old.unknown,
        )

    def _inherited_match_args(self, info: _ClassInfo, seen: set[str]) -> tuple[str, ...] | None:
        if info.qualified_name in seen:
            return None
        seen.add(info.qualified_name)
        if info.match_args is not None:
            return info.match_args
        for base in info.bases:
            base_info = self.engine._classes.get(base)
            if base_info is not None:
                found = self._inherited_match_args(base_info, seen)
                if found is not None:
                    return found
        return None

    def _class_pattern_fields(
        self, class_type: AbstractTypeValue
    ) -> tuple[dict[str, AbstractTypeValue], list[str]]:
        """Return field types and positional ``__match_args__`` order."""
        fields: dict[str, AbstractTypeValue] = {}
        order: list[str] = []
        match_args: tuple[str, ...] | None = None
        for typ in class_type.types:
            if not isinstance(typ, Instance):
                continue
            info = self.engine._classes.get(typ.type.full_name)
            if info is not None:
                for name, value in info.attributes.items():
                    # ``__match_args__`` and other dunder declarations are not
                    # match fields; single-underscore dataclass fields are.
                    if name.startswith("__") or name in fields:
                        continue
                    fields[name] = value
                    order.append(name)
                if match_args is None:
                    match_args = self._inherited_match_args(info, set())
            for name, value in typ.type.members.items():
                if name.startswith("_") or name in fields:
                    continue
                fields[name] = AbstractTypeValue.from_type(value)
                order.append(name)
        # ``__match_args__`` is the authority for positional class patterns;
        # it is a plain declaration and must never appear as a match field.
        if match_args is not None:
            order = list(match_args)
        return fields, order

    @staticmethod
    def _closed_pattern_values(value):
        """Return exhaustive safe builtin scalars, never mere literal hints."""
        if value.unknown:
            return None
        parts = [
            part
            for typ in value.types
            for part in (typ.items if isinstance(typ, UnionType) else (typ,))
        ]
        if value.literal_values_complete:
            values = tuple(value.literal_values)
        elif parts and all(isinstance(part, (LiteralType, NoneType)) for part in parts):
            values = tuple(part.value if isinstance(part, LiteralType) else None for part in parts)
        elif len(parts) == 1 and isinstance(parts[0], Instance) and parts[0].type.raw_type is bool:
            values = (False, True)
        else:
            return None
        return (
            values
            if all(
                type(item) in {str, bytes, int, bool, float, complex, type(None)} for item in values
            )
            else None
        )

    def _pattern_literal_value(self, literal):
        return AbstractTypeValue.from_type(
            (
                NONE_TYPE
                if literal is None
                else self.engine._value_rules._proper_instance(type(literal))
            ),
            literal_values=frozenset((literal,)),
        )

    @staticmethod
    def _consensus_truth(values):
        values = tuple(values)
        if values and all(item is True for item in values):
            return True
        if values and all(item is False for item in values):
            return False
        return None

    def _sequence_pattern_items(self, pattern, subject):
        items = subject.sequence_items
        if items is None and len(subject.types) == 1:
            typ = next(iter(subject.types))
            if isinstance(typ, TupleType) and not typ.unknown_size:
                items = tuple(AbstractTypeValue.from_type(item) for item in typ.args)
        star = next(
            (i for i, item in enumerate(pattern.patterns) if isinstance(item, ast.MatchStar)), None
        )
        if items is not None:
            minimum = len(pattern.patterns) - (star is not None)
            if len(items) < minimum or star is None and len(items) != minimum:
                return None
            if star is None:
                return list(items)
            tail = len(pattern.patterns) - star - 1
            middle = items[star : len(items) - tail if tail else len(items)]
            element = self.engine._value_rules._join_many_values(list(middle))
            rest = self.engine._value_rules._with_sequence_items(
                self.engine._value_rules._instance(list, element.runtime_type() or ANY), middle
            )
            return [*items[:star], rest, *(items[-tail:] if tail else ())]
        element = self.engine._value_rules._iterable_element(subject)
        return [
            (
                self.engine._value_rules._instance(list, element.runtime_type() or ANY)
                if isinstance(item, ast.MatchStar)
                else element
            )
            for item in pattern.patterns
        ]

    def _pattern_truth(self, pattern, subject, environment, current_function):
        """Three-valued reachability proof; unknown tests retain both paths."""
        if isinstance(pattern, (ast.MatchAs, ast.MatchStar)):
            return (
                self._pattern_truth(pattern.pattern, subject, environment, current_function)
                if isinstance(pattern, ast.MatchAs) and pattern.pattern is not None
                else True
            )
        if isinstance(pattern, ast.MatchOr):
            answers = [
                self._pattern_truth(child, subject, environment, current_function)
                for child in pattern.patterns
            ]
            return (
                True
                if any(item is True for item in answers)
                else False if all(item is False for item in answers) else None
            )
        if subject.unknown:
            return None
        finite = self._closed_pattern_values(subject)
        if isinstance(pattern, ast.MatchSingleton):
            if finite is not None:
                return self._consensus_truth(item is pattern.value for item in finite)
            parts = self.engine._operator_rules._flatten_union_parts(subject)

            def singleton_match(item):
                if isinstance(item, TupleType):
                    return False
                if isinstance(item, Instance) and (
                    not item.type.is_protocol
                    and not item.type.has_unresolved_bases
                    and not issubclass(type(pattern.value), item.type.raw_type)
                    # Numeric annotation compatibility also admits bools.
                    and not (
                        type(pattern.value) is bool and item.type.raw_type in {int, float, complex}
                    )
                ):
                    return False
                return None

            return self._consensus_truth(singleton_match(item) for item in parts)
        if isinstance(pattern, ast.MatchValue):
            try:
                expected = ast.literal_eval(pattern.value)
            except (ValueError, TypeError):
                return None
            if finite is not None:
                return self._consensus_truth(item == expected for item in finite)
            parts = self.engine._operator_rules._flatten_union_parts(subject)
            numeric = {bool, int, float, complex}

            def possible(typ):
                if isinstance(typ, TupleType):
                    return False
                if isinstance(typ, Instance) and typ.type.raw_type in {
                    str,
                    bytes,
                    int,
                    bool,
                    float,
                    complex,
                    list,
                    dict,
                    set,
                }:
                    raw = typ.type.raw_type
                    if raw != type(expected) and not (raw in numeric and type(expected) in numeric):
                        return False
                return None

            return self._consensus_truth(possible(item) for item in parts)
        if isinstance(pattern, ast.MatchSequence):
            if finite is not None:
                # str/bytes/bytearray never participate in sequence patterns.
                return False
            parts = self.engine._operator_rules._flatten_union_parts(subject)
            if parts and all(
                isinstance(item, (NoneType, Instance))
                and (
                    isinstance(item, NoneType)
                    or item.type.raw_type in {str, bytes, bytearray, dict, set, frozenset}
                )
                for item in parts
            ):
                return False
            if subject.sequence_items is None and not any(
                isinstance(item, TupleType) and not item.unknown_size for item in parts
            ):
                return None
            items = self._sequence_pattern_items(pattern, subject)
            if items is None:
                return False
            answers = [
                self._pattern_truth(child, item, environment, current_function)
                for child, item in zip(pattern.patterns, items)
            ]
            return (
                False
                if any(item is False for item in answers)
                else True if all(item is True for item in answers) else None
            )
        if isinstance(pattern, ast.MatchMapping):
            if finite is not None or subject.sequence_items is not None:
                return False
            if subject.mapping_items is None:
                return None
            fields = dict(subject.mapping_items)
            answers = []
            for key, child in zip(pattern.keys, pattern.patterns):
                try:
                    literal = ast.literal_eval(key)
                except (ValueError, TypeError):
                    return None
                if literal not in fields:
                    return False
                answers.append(
                    self._pattern_truth(child, fields[literal], environment, current_function)
                )
            return (
                False
                if any(item is False for item in answers)
                else True if all(item is True for item in answers) else None
            )
        if isinstance(pattern, ast.MatchClass):
            allowed = self.engine._expression_rules._evaluate_type_expression(pattern.cls)
            if allowed.unknown or len(allowed.types) != 1:
                return None
            expected = next(iter(allowed.types))
            if not isinstance(expected, Instance):
                return None
            if finite is not None and expected.type.raw_type.__module__ == "builtins":
                answers = [isinstance(item, expected.type.raw_type) for item in finite]
                if not any(answers):
                    return False
                if not pattern.patterns and not pattern.kwd_patterns:
                    return self._consensus_truth(answers)

            def matches(typ):
                if not isinstance(typ, Instance):
                    return None
                if typ.type.full_name in self.engine._classes:
                    subtype = expected.type.full_name in self.engine._member_rules._mro_names(
                        typ.type.full_name
                    )
                else:
                    subtype = issubclass(typ.type.raw_type, expected.type.raw_type)
                if subtype:
                    return True if not pattern.patterns and not pattern.kwd_patterns else None
                numeric_inputs = {float: {int, bool}, complex: {float, int, bool}}
                if expected.type.raw_type in numeric_inputs.get(typ.type.raw_type, set()):
                    # A numeric annotation can admit a narrower runtime input.
                    # Exact literal evidence was checked above; broad evidence
                    # must keep the subclass-compatible pattern reachable.
                    return None
                if typ.type.raw_type.__module__ == expected.type.raw_type.__module__ == "builtins":
                    return None if issubclass(expected.type.raw_type, typ.type.raw_type) else False
                return None

            return self._consensus_truth(
                matches(item) for item in self.engine._operator_rules._flatten_union_parts(subject)
            )
        return None

    def _partition_pattern(self, pattern, subject, environment, current_function):
        """Split matched and fallthrough evidence only when it is provable."""
        bottom = AbstractTypeValue.bottom()
        if subject.is_bottom:
            return bottom, bottom
        if isinstance(pattern, ast.MatchOr):
            accepted = bottom
            remaining = subject
            for child in pattern.patterns:
                matched, remaining = self._partition_pattern(
                    child, remaining, environment, current_function
                )
                accepted = self.engine._value_rules._join(accepted, matched)
            return accepted, remaining
        truth = self._pattern_truth(pattern, subject, environment, current_function)
        if truth is True:
            return subject, bottom
        if truth is False:
            return bottom, subject
        finite = self._closed_pattern_values(subject)
        if finite is not None:
            matched, remaining = [], []
            for item in finite:
                value = self._pattern_literal_value(item)
                answer = self._pattern_truth(pattern, value, environment, current_function)
                if answer is not False:
                    matched.append(value)
                if answer is not True:
                    remaining.append(value)
            return (
                self.engine._value_rules._join_many_values(matched),
                self.engine._value_rules._join_many_values(remaining),
            )
        parts = self.engine._operator_rules._flatten_union_parts(subject)
        if len(parts) > 1:
            matched, remaining = [], []
            for typ in parts:
                value = replace(
                    subject, types=frozenset((typ,)), unknown=False, literal_values_complete=False
                )
                yes, no = self._partition_pattern(pattern, value, environment, current_function)
                matched.append(yes)
                remaining.append(no)
            if subject.unknown:
                matched.append(AbstractTypeValue.unresolved())
                remaining.append(AbstractTypeValue.unresolved())
            return (
                self.engine._value_rules._join_many_values(matched),
                self.engine._value_rules._join_many_values(remaining),
            )
        if isinstance(pattern, ast.MatchAs) and pattern.pattern is not None:
            return self._partition_pattern(pattern.pattern, subject, environment, current_function)
        if isinstance(pattern, ast.MatchSingleton):
            return self._pattern_literal_value(pattern.value), subject
        if isinstance(pattern, ast.MatchValue) and not subject.unknown:
            try:
                literal = ast.literal_eval(pattern.value)
            except (ValueError, TypeError):
                pass
            else:
                if (
                    len(parts) == 1
                    and isinstance(parts[0], Instance)
                    and parts[0].type.raw_type is type(literal)
                ):
                    return (
                        replace(
                            subject,
                            literal_values=frozenset((literal,)),
                            literal_values_complete=True,
                        ),
                        subject,
                    )
        return subject, subject

    def _match_guard_truth(self, node, environment, inferred=None):
        """Evaluate only finite builtin evidence; never execute guard code."""
        if inferred is not None:
            finite = self._closed_pattern_values(inferred)
            if finite is not None:
                answer = self._consensus_truth(bool(item) for item in finite)
                if answer is not None:
                    return answer

        def values(expression):
            try:
                return (ast.literal_eval(expression),)
            except (ValueError, TypeError):
                if isinstance(expression, ast.Name) and expression.id in environment:
                    return self._closed_pattern_values(environment[expression.id])
                return None

        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            answer = self._match_guard_truth(node.operand, environment)
            return None if answer is None else not answer
        if isinstance(node, ast.BoolOp):
            answers = [self._match_guard_truth(child, environment) for child in node.values]
            if isinstance(node.op, ast.And):
                return (
                    False
                    if False in answers
                    else True if all(item is True for item in answers) else None
                )
            return (
                True
                if True in answers
                else False if all(item is False for item in answers) else None
            )
        if isinstance(node, ast.Compare):
            operands = [values(item) for item in (node.left, *node.comparators)]
            if any(item is None for item in operands):
                return None
            size = 1
            for items in operands:
                size *= len(items)
            if size > 256:
                return None
            operations = {
                ast.Eq: operator.eq,
                ast.NotEq: operator.ne,
                ast.Lt: operator.lt,
                ast.LtE: operator.le,
                ast.Gt: operator.gt,
                ast.GtE: operator.ge,
                ast.In: lambda a, b: a in b,
                ast.NotIn: lambda a, b: a not in b,
            }
            answers = []
            for items in itertools.product(*operands):
                checks = []
                for left, op, right in zip(items, node.ops, items[1:]):
                    if isinstance(op, (ast.Is, ast.IsNot)):
                        if not (
                            left is None
                            or right is None
                            or type(left) is bool
                            or type(right) is bool
                        ):
                            return None
                        check = left is right
                        checks.append(not check if isinstance(op, ast.IsNot) else check)
                    elif type(op) in operations:
                        try:
                            checks.append(bool(operations[type(op)](left, right)))
                        except (TypeError, ValueError):
                            return None
                    else:
                        return None
                answers.append(all(checks))
            return self._consensus_truth(answers)
        finite = values(node)
        return self._consensus_truth(bool(item) for item in finite) if finite is not None else None

    def _narrow_pattern(
        self,
        pattern: ast.pattern,
        subject_node: ast.expr,
        subject: AbstractTypeValue,
        environment: dict[str, AbstractTypeValue],
        current_function: _FunctionInfo | None,
    ) -> dict[str, AbstractTypeValue]:
        result = dict(environment)
        if isinstance(pattern, ast.MatchSingleton):
            if pattern.value is None and isinstance(subject_node, ast.Name):
                result[subject_node.id] = AbstractTypeValue.from_type(NONE_TYPE)
        elif isinstance(pattern, ast.MatchClass):
            narrowed = self.engine._expression_rules._evaluate_type_expression(pattern.cls)
            if isinstance(subject_node, ast.Name) and not narrowed.unknown:
                value = self._narrow_to_allowed(subject, narrowed)
                result[subject_node.id] = subject if value.types == subject.types else value
            fields, field_order = self._class_pattern_fields(narrowed)
            dummy = ast.Constant(value=None)
            for index, child in enumerate(pattern.patterns):
                field_name = field_order[index] if index < len(field_order) else None
                child_value = (
                    fields.get(field_name, AbstractTypeValue.unresolved())
                    if field_name is not None
                    else AbstractTypeValue.unresolved()
                )
                result = self._narrow_pattern(
                    child,
                    dummy,
                    child_value,
                    result,
                    current_function,
                )
            for attribute, child in zip(pattern.kwd_attrs, pattern.kwd_patterns):
                result = self._narrow_pattern(
                    child,
                    dummy,
                    fields.get(attribute, AbstractTypeValue.unresolved()),
                    result,
                    current_function,
                )
        elif isinstance(pattern, ast.MatchValue):
            if isinstance(subject_node, ast.Name):
                result[subject_node.id] = subject
        elif isinstance(pattern, ast.MatchAs):
            if pattern.pattern is not None:
                result = self._narrow_pattern(
                    pattern.pattern, subject_node, subject, result, current_function
                )
            bound = (
                result.get(subject_node.id, subject)
                if isinstance(subject_node, ast.Name)
                else subject
            )
            if pattern.name is not None:
                result[pattern.name] = replace(bound, unknown=bound.unknown or subject.unknown)
        elif isinstance(pattern, ast.MatchStar):
            if pattern.name is not None:
                result[pattern.name] = subject
        elif isinstance(pattern, ast.MatchSequence):
            dummy = ast.Constant(value=None)
            items = self._sequence_pattern_items(pattern, subject)
            if items is not None:
                for child, item in zip(pattern.patterns, items):
                    narrowed, _ = self._partition_pattern(child, item, result, current_function)
                    result = self._narrow_pattern(child, dummy, narrowed, result, current_function)
        elif isinstance(pattern, ast.MatchMapping):
            scope = (
                current_function.qualified_name if current_function else self.engine._module_name
            )
            dummy = ast.Constant(value=None)
            keys = []
            for key, child in zip(pattern.keys, pattern.patterns):
                index = self.engine._expression_rules._evaluate_expression(
                    key, result, scope=scope, current_function=current_function
                )
                item = self.engine._value_rules._subscript_value(subject, key, index)
                matched, _ = self._partition_pattern(child, item, result, current_function)
                result = self._narrow_pattern(child, dummy, matched, result, current_function)
                try:
                    keys.append(ast.literal_eval(key))
                except (ValueError, TypeError):
                    pass
            if pattern.rest is not None:
                key_type, value_type = self.engine._value_rules._mapping_key_value(subject)
                rest = self.engine._value_rules._instance(
                    dict, key_type.runtime_type() or ANY, value_type.runtime_type() or ANY
                )
                if subject.mapping_items is not None and len(keys) == len(pattern.keys):
                    rest = self.engine._value_rules._with_mapping_items(
                        rest,
                        tuple(
                            (key, value) for key, value in subject.mapping_items if key not in keys
                        ),
                    )
                result[pattern.rest] = rest
        elif isinstance(pattern, ast.MatchOr):
            alternatives = []
            for child in pattern.patterns:
                matched, _ = self._partition_pattern(child, subject, result, current_function)
                if not matched.is_bottom:
                    alternatives.append(
                        self._narrow_pattern(child, subject_node, matched, result, current_function)
                    )
            if alternatives:
                result = self.engine._value_rules._join_many_environments(alternatives)
        if subject.unknown and isinstance(subject_node, ast.Name) and subject_node.id in result:
            result[subject_node.id] = replace(
                result[subject_node.id], unknown=True, literal_values_complete=False
            )
        return result
