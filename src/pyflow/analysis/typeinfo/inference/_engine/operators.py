"""Infer arithmetic, comparisons, and overloaded operator results."""

from __future__ import annotations

import ast
import datetime
import operator
from dataclasses import replace
from typing import Iterable, cast

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    AnyType,
    Instance,
    ProperType,
    TupleType,
    TypeType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference._engine.component import InferenceComponent
from pyflow.analysis.typeinfo.inference._engine.state import _FunctionInfo
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue, join_all


class OperatorInference(InferenceComponent):
    """Infer arithmetic, comparisons, and overloaded operator results."""

    def _check_percent_format(
        self,
        node: ast.BinOp,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
    ) -> None:
        from pyflow.analysis.typeinfo.resolution.format_strings import (
            check_percent_format,
        )

        if not (isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)):
            return
        argument = right.public_type()
        issues = check_percent_format(node.left.value, argument, self.engine.type_system)
        for issue in issues:
            self.engine._add_diagnostic(
                "format-string-mismatch",
                issue,
                node=node,
            )

    def _binary_result(
        self,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
        operator: ast.operator,
    ) -> AbstractTypeValue:
        if any(isinstance(part, UnionType) for part in left.types):
            left = left.join(AbstractTypeValue.bottom(), self.engine.type_system)
        if any(isinstance(part, UnionType) for part in right.types):
            right = right.join(AbstractTypeValue.bottom(), self.engine.type_system)
        if isinstance(operator, (ast.BitOr, ast.BitAnd, ast.BitXor)):
            flag_result = self._flag_bitwise_result(left, right)
            if flag_result is not None:
                return flag_result
        # ``enum.IntEnum``/``enum.StrEnum`` members (and plain subclasses of
        # ``int``/``str``) behave like their scalar base for operators.
        left = self._project_scalar_subclass(left)
        right = self._project_scalar_subclass(right)
        if isinstance(operator, ast.Mod):
            if self.engine._value_rules._contains_raw(
                left, str
            ) or self.engine._value_rules._contains_raw(left, bytes):
                values = [
                    (
                        self.engine._value_rules._instance(part.type.raw_type)
                        if isinstance(part, Instance) and part.type.raw_type in {str, bytes}
                        else self._binary_result(AbstractTypeValue.from_type(part), right, operator)
                    )
                    for part in left.types
                ]
                if left.unknown:
                    values.append(AbstractTypeValue.unresolved())
                return join_all(values, self.engine.type_system)
            numeric = {bool, int, float, complex}
            if (
                not left.unknown
                and not right.unknown
                and left.types
                and right.types
                and all(
                    isinstance(part, Instance) and part.type.raw_type in numeric
                    for part in (*left.types, *right.types)
                )
            ):
                if self._all_bool_values(left, right):
                    return self.engine._value_rules._instance(int)
                return self._numeric_join((left, right))
            if self._contains_any(left) or self._contains_any(right):
                return AbstractTypeValue.from_type(ANY)
            # An unresolved format string does not make the formatting
            # arguments a possible result of the operation.
            return AbstractTypeValue.unresolved()
        if isinstance(operator, ast.BitOr):
            return self._bit_or_result(left, right)
        if isinstance(operator, ast.Div):
            if len(left.types) == 1:
                left_part = next(iter(left.types))
                if isinstance(left_part, Instance) and self.engine._value_rules._is_pathlib_type(
                    left_part
                ):
                    return AbstractTypeValue.from_type(left_part)
            numeric = {bool, int, float, complex}
            if (
                not left.unknown
                and not right.unknown
                and left.types
                and right.types
                and all(
                    isinstance(part, Instance) and part.type.raw_type in numeric
                    for part in (*left.types, *right.types)
                )
            ):
                if any(
                    isinstance(part, Instance) and part.type.raw_type in {float, complex}
                    for part in (*left.types, *right.types)
                ):
                    return self._numeric_join((left, right))
                return self.engine._value_rules._instance(float)
            if self._contains_any(left) or self._contains_any(right):
                return AbstractTypeValue.from_type(ANY)
            # Division is not defined for every object.  When no local or
            # external ``__truediv__`` model produced a result, coercing to
            # float would be unsound (``Path / str``, ``Decimal / int``, ...).
            return AbstractTypeValue.unresolved()
        if isinstance(operator, ast.FloorDiv):
            if (
                not left.unknown
                and not right.unknown
                and self.engine._value_rules._contains_raw(left, int)
                and self.engine._value_rules._contains_raw(right, int)
            ):
                return self.engine._value_rules._instance(int)
        if isinstance(operator, ast.MatMult):
            return AbstractTypeValue.unresolved()
        if isinstance(operator, ast.Add):
            return self._add_result(left, right)
        if isinstance(operator, ast.Sub):
            set_result = self._set_difference_result(left, right)
            if set_result is not None:
                return set_result
            raw_pairs = {
                (datetime.datetime, datetime.datetime): datetime.timedelta,
                (datetime.date, datetime.date): datetime.timedelta,
                (datetime.timedelta, datetime.timedelta): datetime.timedelta,
                (datetime.datetime, datetime.timedelta): datetime.datetime,
                (datetime.date, datetime.timedelta): datetime.date,
            }
            if len(left.types) == 1 and len(right.types) == 1:
                left_part = next(iter(left.types))
                right_part = next(iter(right.types))
                if isinstance(left_part, Instance) and isinstance(right_part, Instance):
                    result = raw_pairs.get((left_part.type.raw_type, right_part.type.raw_type))
                    if result is not None:
                        return self.engine._value_rules._instance(result)
        if isinstance(operator, ast.Mult):
            return self._mult_result(left, right)
        if isinstance(operator, (ast.BitAnd, ast.BitXor)):
            return self._set_bitwise_result(left, right)
        if isinstance(operator, ast.Pow):
            return self._pow_result(left, right)
        if self._contains_any(left) or self._contains_any(right):
            # Gradual typing: arithmetic on Any stays Any.  Narrowing it to a
            # concrete numeric type produces false diagnostics and can prune
            # valid branches in untyped code.
            return AbstractTypeValue.from_type(ANY)
        if left.unknown or right.unknown:
            # ``u * 2`` where u is unmodelled is not necessarily int: u may be
            # a str, list, or an object implementing its own protocol.
            return AbstractTypeValue.unresolved()
        if self._all_bool_values(left, right) and isinstance(
            operator,
            (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod, ast.Pow, ast.LShift, ast.RShift),
        ):
            return self.engine._value_rules._instance(int)
        numeric = self._numeric_join((left, right))
        numeric_type = numeric.public_type()
        if numeric_type is not None:
            if (
                isinstance(numeric_type, Instance)
                and numeric_type.type.raw_type is bool
                and isinstance(
                    operator,
                    (
                        ast.Add,
                        ast.Sub,
                        ast.Mult,
                        ast.FloorDiv,
                        ast.Mod,
                        ast.Pow,
                        ast.LShift,
                        ast.RShift,
                    ),
                )
            ):
                # bool arithmetic produces int even when another union
                # alternative is non-numeric (for example ``bool | None``).
                return self.engine._value_rules._instance(int)
            return numeric
        return self.engine._value_rules._join(left, right).join(
            AbstractTypeValue.unresolved(),
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )

    @staticmethod
    def _flatten_union_parts(value: AbstractTypeValue) -> list[ProperType]:
        parts: list[ProperType] = []
        for typ in value.types:
            if isinstance(typ, UnionType):
                parts.extend(typ.items)
            else:
                parts.append(typ)
        return parts

    def _add_result(
        self,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Add each pair of alternatives without dropping union branches."""
        if self._contains_any(left) or self._contains_any(right):
            return AbstractTypeValue.from_type(ANY)
        raw_pairs = {
            (datetime.datetime, datetime.timedelta): datetime.datetime,
            (datetime.timedelta, datetime.datetime): datetime.datetime,
            (datetime.date, datetime.timedelta): datetime.date,
            (datetime.timedelta, datetime.date): datetime.date,
            (datetime.timedelta, datetime.timedelta): datetime.timedelta,
        }
        numeric = {bool, int, float, complex}
        results: list[ProperType] = []
        unknown = left.unknown or right.unknown
        for left_part in self._flatten_union_parts(left):
            for right_part in self._flatten_union_parts(right):
                if isinstance(left_part, TupleType) and isinstance(right_part, TupleType):
                    if left_part.unknown_size or right_part.unknown_size:
                        element = join_all(
                            (
                                AbstractTypeValue.from_type(item)
                                for item in (*left_part.args, *right_part.args)
                            ),
                            self.engine.type_system,
                            max_union_size=self.engine.options.max_union_size,
                        )
                        results.append(
                            TupleType((element.public_type() or ANY,), unknown_size=True)
                        )
                    else:
                        results.append(
                            TupleType(
                                (*left_part.args, *right_part.args),
                                unknown_size=False,
                            )
                        )
                    continue
                if not isinstance(left_part, Instance) or not isinstance(right_part, Instance):
                    unknown = True
                    continue
                left_raw = left_part.type.raw_type
                right_raw = right_part.type.raw_type
                mapped = raw_pairs.get((left_raw, right_raw))
                if mapped is not None:
                    results.append(self.engine._value_rules._proper_instance(mapped))
                    continue
                if left_raw in {str, bytes} and right_raw is left_raw:
                    results.append(left_part)
                    continue
                if left_raw is list and right_raw is list:
                    element = join_all(
                        (
                            AbstractTypeValue.from_type(
                                left_part.args[0] if left_part.args else ANY
                            ),
                            AbstractTypeValue.from_type(
                                right_part.args[0] if right_part.args else ANY
                            ),
                        ),
                        self.engine.type_system,
                        max_union_size=self.engine.options.max_union_size,
                    )
                    results.append(
                        self.engine._value_rules._proper_instance(
                            list, element.public_type() or ANY
                        )
                    )
                    continue
                if left_raw in numeric and right_raw in numeric:
                    if left_raw is bool and right_raw is bool:
                        results.append(self.engine._value_rules._proper_instance(int))
                    else:
                        joined = self._numeric_join(
                            (
                                AbstractTypeValue.from_type(left_part),
                                AbstractTypeValue.from_type(right_part),
                            )
                        )
                        if joined.public_type() is not None:
                            results.append(joined.public_type())
                        else:
                            unknown = True
                    continue
                unknown = True
        if not results:
            return AbstractTypeValue.unresolved() if unknown else AbstractTypeValue.bottom()
        joined = join_all(
            (AbstractTypeValue.from_type(item) for item in results),
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )
        return replace(joined, unknown=joined.unknown or unknown)

    def _set_difference_result(
        self,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
    ) -> AbstractTypeValue | None:
        """Model set/frozenset subtraction; return None for non-set operands."""
        left_parts = self._flatten_union_parts(left)
        right_parts = self._flatten_union_parts(right)
        has_set = any(
            isinstance(part, Instance) and part.type.raw_type in {set, frozenset}
            for part in (*left_parts, *right_parts)
        )
        if not has_set:
            return None
        results: list[ProperType] = []
        unknown = left.unknown or right.unknown
        for left_part in left_parts:
            for right_part in right_parts:
                if not isinstance(left_part, Instance) or not isinstance(right_part, Instance):
                    unknown = True
                    continue
                left_raw = left_part.type.raw_type
                right_raw = right_part.type.raw_type
                if left_raw in {set, frozenset} and right_raw in {set, frozenset}:
                    element = join_all(
                        (
                            AbstractTypeValue.from_type(
                                left_part.args[0] if left_part.args else ANY
                            ),
                            AbstractTypeValue.from_type(
                                right_part.args[0] if right_part.args else ANY
                            ),
                        ),
                        self.engine.type_system,
                        max_union_size=self.engine.options.max_union_size,
                    )
                    results.append(
                        self.engine._value_rules._proper_instance(
                            left_raw, element.public_type() or ANY
                        )
                    )
                    continue
                unknown = True
        if not results:
            return AbstractTypeValue.unresolved()
        joined = join_all(
            (AbstractTypeValue.from_type(item) for item in results),
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )
        return replace(joined, unknown=joined.unknown or unknown)

    def _set_bitwise_result(
        self,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Model set/frozenset ``&`` and ``^`` without dropping unions."""
        if self._contains_any(left) or self._contains_any(right):
            return AbstractTypeValue.from_type(ANY)
        results: list[ProperType] = []
        unknown = left.unknown or right.unknown
        for left_part in self._flatten_union_parts(left):
            for right_part in self._flatten_union_parts(right):
                if not isinstance(left_part, Instance) or not isinstance(right_part, Instance):
                    unknown = True
                    continue
                left_raw = left_part.type.raw_type
                right_raw = right_part.type.raw_type
                if left_raw in {set, frozenset} and right_raw in {set, frozenset}:
                    element = join_all(
                        (
                            AbstractTypeValue.from_type(
                                left_part.args[0] if left_part.args else ANY
                            ),
                            AbstractTypeValue.from_type(
                                right_part.args[0] if right_part.args else ANY
                            ),
                        ),
                        self.engine.type_system,
                        max_union_size=self.engine.options.max_union_size,
                    )
                    results.append(
                        self.engine._value_rules._proper_instance(
                            left_raw, element.public_type() or ANY
                        )
                    )
                    continue
                if left_raw in {bool, int} and right_raw in {bool, int}:
                    results.append(
                        self.engine._value_rules._proper_instance(
                            bool if left_raw is bool and right_raw is bool else int
                        )
                    )
                    continue
                unknown = True
        if not results:
            return AbstractTypeValue.unresolved() if unknown else AbstractTypeValue.bottom()
        joined = join_all(
            (AbstractTypeValue.from_type(item) for item in results),
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )
        return replace(joined, unknown=joined.unknown or unknown)

    def _bit_or_result(
        self,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Bitwise-or each pair of alternatives (sets, mappings, integers)."""
        if self._contains_any(left) or self._contains_any(right):
            return AbstractTypeValue.from_type(ANY)
        results: list[ProperType] = []
        unknown = left.unknown or right.unknown
        for left_part in self._flatten_union_parts(left):
            for right_part in self._flatten_union_parts(right):
                if not isinstance(left_part, Instance) or not isinstance(right_part, Instance):
                    unknown = True
                    continue
                left_raw = left_part.type.raw_type
                right_raw = right_part.type.raw_type
                if left_raw in {set, frozenset} and right_raw in {set, frozenset}:
                    result_raw = set if left_raw is set else frozenset
                    element = join_all(
                        (
                            (
                                AbstractTypeValue.from_type(left_part.args[0])
                                if left_part.args
                                else AbstractTypeValue.from_type(ANY)
                            ),
                            (
                                AbstractTypeValue.from_type(right_part.args[0])
                                if right_part.args
                                else AbstractTypeValue.from_type(ANY)
                            ),
                        ),
                        self.engine.type_system,
                        max_union_size=self.engine.options.max_union_size,
                    )
                    results.append(
                        self.engine._value_rules._proper_instance(
                            result_raw, element.public_type() or ANY
                        )
                    )
                    continue
                if left_raw is dict and right_raw is dict:
                    parts = (left_part, right_part)
                    arguments = [
                        join_all(
                            (
                                AbstractTypeValue.from_type(
                                    part.args[position] if position < len(part.args) else ANY
                                )
                                for part in parts
                            ),
                            self.engine.type_system,
                        ).public_type()
                        or ANY
                        for position in range(2)
                    ]
                    results.append(self.engine._value_rules._proper_instance(dict, *arguments))
                    continue
                if left_raw in {bool, int} and right_raw in {bool, int}:
                    results.append(
                        self.engine._value_rules._proper_instance(
                            bool if left_raw is bool and right_raw is bool else int
                        )
                    )
                    continue
                unknown = True
        if not results:
            return AbstractTypeValue.unresolved() if unknown else AbstractTypeValue.bottom()
        joined = join_all(
            (AbstractTypeValue.from_type(item) for item in results),
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )
        return replace(joined, unknown=joined.unknown or unknown)

    def _mult_result(
        self,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Multiply all alternatives, preserving numeric and repetition results."""
        if self._contains_any(left) or self._contains_any(right):
            return AbstractTypeValue.from_type(ANY)
        numeric = {bool, int, float, complex}
        results: list[ProperType] = []
        unknown = left.unknown or right.unknown
        sequence_types = {str, bytes, bytearray, list}
        for left_part in self._flatten_union_parts(left):
            for right_part in self._flatten_union_parts(right):
                if (
                    isinstance(left_part, TupleType)
                    and isinstance(right_part, Instance)
                    and right_part.type.raw_type in {int, bool}
                ):
                    element = join_all(
                        (AbstractTypeValue.from_type(arg) for arg in left_part.args),
                        self.engine.type_system,
                    )
                    results.append(TupleType((element.public_type() or ANY,), unknown_size=True))
                    continue
                if (
                    isinstance(right_part, TupleType)
                    and isinstance(left_part, Instance)
                    and left_part.type.raw_type in {int, bool}
                ):
                    element = join_all(
                        (AbstractTypeValue.from_type(arg) for arg in right_part.args),
                        self.engine.type_system,
                    )
                    results.append(TupleType((element.public_type() or ANY,), unknown_size=True))
                    continue
                if (
                    isinstance(left_part, Instance)
                    and left_part.type.raw_type in sequence_types
                    and isinstance(right_part, Instance)
                    and right_part.type.raw_type in {int, bool}
                ):
                    results.append(left_part)
                    continue
                if (
                    isinstance(right_part, Instance)
                    and right_part.type.raw_type in sequence_types
                    and isinstance(left_part, Instance)
                    and left_part.type.raw_type in {int, bool}
                ):
                    results.append(right_part)
                    continue
                if (
                    isinstance(left_part, Instance)
                    and left_part.type.raw_type in numeric
                    and isinstance(right_part, Instance)
                    and right_part.type.raw_type in numeric
                ):
                    if left_part.type.raw_type is bool and right_part.type.raw_type is bool:
                        results.append(self.engine._value_rules._proper_instance(int))
                        continue
                    joined = self._numeric_join(
                        (
                            AbstractTypeValue.from_type(left_part),
                            AbstractTypeValue.from_type(right_part),
                        )
                    )
                    if joined.public_type() is not None:
                        results.append(joined.public_type())
                    else:
                        unknown = True
                    continue
                # An invalid alternative (for example ``str * float``) is not
                # part of the successful result, but must not be reported as a
                # concrete type.
                unknown = True
        if not results:
            return AbstractTypeValue.unresolved() if unknown else AbstractTypeValue.bottom()
        joined = join_all(
            (AbstractTypeValue.from_type(item) for item in results),
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )
        return replace(joined, unknown=joined.unknown or unknown)

    def _text_base(self, typ: Instance) -> type | None:
        """Return the builtin text type a ``str``/``bytes`` subclass behaves as."""
        raw = typ.type.raw_type
        if raw in {str, bytes}:
            return raw
        if not isinstance(raw, type):
            return None
        if self.engine.type_system.is_subtype(typ, self.engine._value_rules._proper_instance(str)):
            return str
        if self.engine.type_system.is_subtype(
            typ, self.engine._value_rules._proper_instance(bytes)
        ):
            return bytes
        return None

    def _flag_bitwise_result(
        self, left: AbstractTypeValue, right: AbstractTypeValue
    ) -> AbstractTypeValue | None:
        """``Flag``/``IntFlag`` bitwise operators return the enum class."""
        for value in (left, right):
            for typ in value.types:
                if not isinstance(typ, Instance):
                    continue
                info = self.engine._classes.get(typ.type.full_name)
                if info is None:
                    continue
                if any(
                    self.engine._member_rules._enum_base_kind(base) in {"Flag", "IntFlag"}
                    for base in info.bases
                ):
                    return AbstractTypeValue.from_type(info.instance)
        return None

    @staticmethod
    def _type_union_value(
        left: AbstractTypeValue, right: AbstractTypeValue
    ) -> AbstractTypeValue | None:
        """``SomeClass | OtherClass`` builds a runtime type union."""
        if not left.class_targets or not right.class_targets:
            return None
        items: list[ProperType] = []
        for value in (left, right):
            for typ in value.types:
                if isinstance(typ, Instance):
                    items.append(typ)
        if not items:
            return None
        return AbstractTypeValue.from_type(UnionType(tuple(items)))

    def _project_scalar_subclass(self, value: AbstractTypeValue) -> AbstractTypeValue:
        """Project scalar subclasses (including enums) onto their builtin base."""
        projected: set[ProperType] = set()
        changed = False
        for typ in value.types:
            replacement = typ
            if isinstance(typ, Instance) and isinstance(typ.type.raw_type, type):
                raw = typ.type.raw_type
                if raw not in {bool, int, float, complex, str, bytes}:
                    for base in (bool, int, float, complex, str, bytes):
                        target = Instance(self.engine.type_system.to_class_descriptor(base))
                        # Source classes are synthetic (their declared bases
                        # live in the type system's subclass graph), so
                        # ``issubclass`` is not sufficient here.
                        if self.engine.type_system.is_subtype(typ, target):
                            replacement = target
                            changed = True
                            break
            projected.add(replacement)
        if not changed:
            return value
        return replace(value, types=frozenset(projected))

    @staticmethod
    def _binary_protocol_names(operator: ast.operator) -> tuple[str | None, str | None]:
        methods = {
            ast.Add: ("__add__", "__radd__"),
            ast.Sub: ("__sub__", "__rsub__"),
            ast.Mult: ("__mul__", "__rmul__"),
            ast.MatMult: ("__matmul__", "__rmatmul__"),
            ast.Div: ("__truediv__", "__rtruediv__"),
            ast.FloorDiv: ("__floordiv__", "__rfloordiv__"),
            ast.Mod: ("__mod__", "__rmod__"),
            ast.Pow: ("__pow__", "__rpow__"),
            ast.LShift: ("__lshift__", "__rlshift__"),
            ast.RShift: ("__rshift__", "__rrshift__"),
            ast.BitOr: ("__or__", "__ror__"),
            ast.BitXor: ("__xor__", "__rxor__"),
            ast.BitAnd: ("__and__", "__rand__"),
        }
        return next(
            (names for kind, names in methods.items() if isinstance(operator, kind)),
            (None, None),
        )

    def _operator_result(
        self,
        node: ast.expr,
        left: AbstractTypeValue,
        right: AbstractTypeValue | None,
        methods: tuple[str | None, str | None],
        environment: dict[str, AbstractTypeValue],
    ) -> AbstractTypeValue | None:
        results: list[AbstractTypeValue] = []
        direct, reflected = methods
        if direct is not None:
            attribute = ast.copy_location(
                ast.Attribute(value=node, attr=direct, ctx=ast.Load()), node
            )
            result = self.engine._builtin_rules._call_attribute(
                attribute,
                left,
                [] if right is None else [right],
                {},
                environment,
            )
            if result is not None:
                results.append(result)
        if reflected is not None and right is not None:
            attribute = ast.copy_location(
                ast.Attribute(value=node, attr=reflected, ctx=ast.Load()), node
            )
            result = self.engine._builtin_rules._call_attribute(
                attribute,
                right,
                [left],
                {},
                environment,
            )
            if result is not None:
                results.append(result)
        if not results:
            return None
        return join_all(
            results,
            self.engine.type_system,
            max_union_size=self.engine.options.max_union_size,
        )

    @staticmethod
    def _comparison_protocol_names(
        operator: ast.cmpop,
    ) -> tuple[str | None, str | None]:
        methods = {
            ast.Eq: ("__eq__", "__eq__"),
            ast.NotEq: ("__ne__", "__ne__"),
            ast.Lt: ("__lt__", "__gt__"),
            ast.LtE: ("__le__", "__ge__"),
            ast.Gt: ("__gt__", "__lt__"),
            ast.GtE: ("__ge__", "__le__"),
        }
        return next(
            (names for kind, names in methods.items() if isinstance(operator, kind)),
            (None, None),
        )

    @staticmethod
    def _static_comparison_truth(
        left: ast.expr, operator_node: ast.cmpop, right: ast.expr
    ) -> bool | None:
        try:
            left_value = ast.literal_eval(left)
            right_value = ast.literal_eval(right)
        except (TypeError, ValueError):
            return None
        operations = {
            ast.Eq: operator.eq,
            ast.NotEq: operator.ne,
            ast.Lt: operator.lt,
            ast.LtE: operator.le,
            ast.Gt: operator.gt,
            ast.GtE: operator.ge,
            ast.Is: operator.is_,
            ast.IsNot: operator.is_not,
            ast.In: lambda left, right: operator.contains(right, left),
            ast.NotIn: lambda left, right: not operator.contains(right, left),
        }
        operation = next(
            (fn for kind, fn in operations.items() if isinstance(operator_node, kind)),
            None,
        )
        if operation is None:
            return None
        try:
            return bool(operation(left_value, right_value))
        except (TypeError, ValueError):
            return None

    def _comparison_result(
        self,
        node: ast.Compare,
        environment: dict[str, AbstractTypeValue],
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue:
        left_node = node.left
        left = self.engine._expression_rules._evaluate_expression(
            left_node,
            environment,
            scope=scope,
            current_function=current_function,
        )
        if self.engine._value_rules._is_never_value(left):
            return left
        results: list[AbstractTypeValue] = []
        last_index = len(node.ops) - 1
        for index, (operator_node, right_node) in enumerate(zip(node.ops, node.comparators)):
            right = self.engine._expression_rules._evaluate_expression(
                right_node,
                environment,
                scope=scope,
                current_function=current_function,
            )
            if self.engine._value_rules._is_never_value(right):
                results.append(right)
                break
            if isinstance(operator_node, (ast.Is, ast.IsNot, ast.In, ast.NotIn)):
                pair = self.engine._value_rules._instance(bool)
            elif isinstance(operator_node, (ast.Eq, ast.NotEq)) and (
                left.class_targets
                or right.class_targets
                or (left.types and all(isinstance(part, TypeType) for part in left.types))
                or (right.types and all(isinstance(part, TypeType) for part in right.types))
            ):
                # Comparing class objects uses metaclass equality (normally
                # identity); it must not dispatch to an instance's __eq__.
                pair = self.engine._value_rules._instance(bool)
            else:
                pair = self._operator_result(
                    node,
                    left,
                    right,
                    self._comparison_protocol_names(operator_node),
                    environment,
                ) or self.engine._value_rules._instance(bool)
            if index == last_index:
                results.append(pair)
                break
            truth = self._static_comparison_truth(left_node, operator_node, right_node)
            if truth is not True:
                results.append(pair)
            if truth is False:
                break
            left_node = right_node
            left = right
        return self.engine._value_rules._join_normal_results(results)

    def _pow_result(
        self,
        base: AbstractTypeValue,
        exponent: AbstractTypeValue,
    ) -> AbstractTypeValue:
        if self._contains_any(base) or self._contains_any(exponent):
            return AbstractTypeValue.from_type(ANY)
        if any(isinstance(part, Instance) and part.type.raw_type is complex for part in base.types):
            return self.engine._value_rules._instance(complex)
        if self._all_bool_values(base, exponent):
            return self.engine._value_rules._instance(int)
        negative_exponent = bool(exponent.literal_values) and all(
            isinstance(value, int) and value < 0 for value in exponent.literal_values
        )
        if negative_exponent:
            return self.engine._value_rules._instance(float)
        fractional_exponent = any(
            isinstance(value, float) and not value.is_integer() for value in exponent.literal_values
        )
        negative_base = any(
            isinstance(value, (int, float)) and not isinstance(value, bool) and value < 0
            for value in base.literal_values
        )
        if negative_base and fractional_exponent:
            return self.engine._value_rules._instance(complex)
        numeric = self._numeric_join((base, exponent))
        if numeric.public_type() is not None:
            return numeric
        return AbstractTypeValue.unresolved()

    @staticmethod
    def _all_bool_values(*values: AbstractTypeValue) -> bool:
        return all(
            value.types
            and all(
                isinstance(part, Instance) and part.type.raw_type is bool for part in value.types
            )
            for value in values
        )

    @staticmethod
    def _contains_any(value: AbstractTypeValue) -> bool:
        def contains(part: ProperType) -> bool:
            if isinstance(part, AnyType):
                return True
            if isinstance(part, UnionType):
                return any(contains(item) for item in part.items)
            return False

        return any(contains(part) for part in value.types)

    def _numeric_join(self, values: Iterable[AbstractTypeValue]) -> AbstractTypeValue:
        ranks = {bool: 0, int: 1, float: 2, complex: 3}
        best: type | None = None
        for value in values:
            for typ in value.types:
                if isinstance(typ, Instance) and typ.type.raw_type in ranks:
                    numeric_raw = cast(type, typ.type.raw_type)
                    if best is None or ranks[numeric_raw] > ranks[best]:
                        best = numeric_raw
        return (
            AbstractTypeValue.bottom() if best is None else self.engine._value_rules._instance(best)
        )
