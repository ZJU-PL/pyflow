"""Refine environments with guards, membership tests, and patterns."""

from __future__ import annotations

import ast
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
                old = result.get(subject_node.id, subject)
                result[subject_node.id] = self._narrow_to_allowed(old, narrowed)
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
            scope = (
                current_function.qualified_name
                if current_function is not None
                else self.engine._module_name
            )
            val = self.engine._expression_rules._evaluate_expression(
                pattern.value, result, scope=scope, current_function=current_function
            )
            if isinstance(subject_node, ast.Name) and not val.unknown:
                old = result.get(subject_node.id, subject)
                if self._value_may_match(old, val):
                    result[subject_node.id] = val
                else:
                    result[subject_node.id] = AbstractTypeValue.bottom()
        elif isinstance(pattern, ast.MatchAs):
            scope = (
                current_function.qualified_name
                if current_function is not None
                else self.engine._module_name
            )
            bound_value = subject
            if pattern.pattern is not None:
                result = self._narrow_pattern(
                    pattern.pattern,
                    subject_node,
                    subject,
                    result,
                    current_function,
                )
                if isinstance(subject_node, ast.Name) and subject_node.id in result:
                    bound_value = result[subject_node.id]
                elif isinstance(pattern.pattern, ast.MatchClass):
                    narrowed = self.engine._expression_rules._evaluate_type_expression(
                        pattern.pattern.cls
                    )
                    if not narrowed.unknown:
                        bound_value = narrowed
                elif isinstance(pattern.pattern, ast.MatchValue):
                    val = self.engine._expression_rules._evaluate_expression(
                        pattern.pattern.value,
                        result,
                        scope=scope,
                        current_function=current_function,
                    )
                    if not val.unknown:
                        bound_value = val
                elif isinstance(pattern.pattern, ast.MatchSingleton):
                    if pattern.pattern.value is None:
                        bound_value = AbstractTypeValue.from_type(NONE_TYPE)
                    elif isinstance(pattern.pattern.value, bool):
                        bound_value = self.engine._value_rules._instance(bool)
            if pattern.name is not None:
                result[pattern.name] = bound_value
        elif isinstance(pattern, ast.MatchStar):
            if pattern.name is not None:
                element = self.engine._value_rules._iterable_element(subject)
                result[pattern.name] = self.engine._value_rules._instance(
                    list, element.public_type() or ANY
                )
        elif isinstance(pattern, ast.MatchSequence):
            star_index = next(
                (
                    index
                    for index, child in enumerate(pattern.patterns)
                    if isinstance(child, ast.MatchStar)
                ),
                None,
            )
            if star_index is None:
                unpacked = self.engine._flow_rules._unpack_value(subject, len(pattern.patterns))
                for child, child_value in zip(pattern.patterns, unpacked):
                    result = self._narrow_pattern(
                        child,
                        subject_node,
                        child_value,
                        result,
                        current_function,
                    )
            else:
                tuple_args: list[ProperType] = []
                if len(subject.types) == 1:
                    only = next(iter(subject.types))
                    if isinstance(only, TupleType) and not only.unknown_size:
                        tuple_args = list(only.args)
                element = self.engine._value_rules._iterable_element(subject)
                for index, child in enumerate(pattern.patterns):
                    if isinstance(child, ast.MatchStar):
                        child_value = self.engine._value_rules._instance(
                            list, element.public_type() or ANY
                        )
                    elif tuple_args:
                        child_value = AbstractTypeValue.from_type(
                            tuple_args[min(index, len(tuple_args) - 1)]
                        )
                    else:
                        child_value = element
                    result = self._narrow_pattern(
                        child,
                        subject_node,
                        child_value,
                        result,
                        current_function,
                    )
        elif isinstance(pattern, ast.MatchMapping):
            item = self.engine._value_rules._subscript_value(subject, ast.Constant(value=""))
            for child in pattern.patterns:
                result = self._narrow_pattern(
                    child,
                    subject_node,
                    item,
                    result,
                    current_function,
                )
            if pattern.rest is not None:
                result[pattern.rest] = subject
        elif isinstance(pattern, ast.MatchOr):
            alternatives = [
                self._narrow_pattern(
                    child,
                    subject_node,
                    subject,
                    result,
                    current_function,
                )
                for child in pattern.patterns
            ]
            result = self.engine._value_rules._join_many_environments(alternatives)
        return result
