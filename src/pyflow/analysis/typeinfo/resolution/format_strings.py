"""Static checks for printf-style ``%`` format strings."""

from __future__ import annotations

import re

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    AnyType,
    Instance,
    ProperType,
    TupleType,
    TypeSystem,
    UnionType,
)

_SPEC_RE = re.compile(r"%[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[hlL]?([diouxXeEfFgGcrsa%])")


def percent_conversions(format_string: str) -> list[str]:
    """Return conversion characters in *format_string*, excluding ``%%``."""
    return [match.group(1) for match in _SPEC_RE.finditer(format_string) if match.group(1) != "%"]


def _is_numeric(typ: ProperType) -> bool:
    return isinstance(typ, Instance) and typ.type.raw_type in {bool, int, float}


def _is_int(typ: ProperType) -> bool:
    return isinstance(typ, Instance) and typ.type.raw_type in {bool, int}


def _is_text(typ: ProperType) -> bool:
    return isinstance(typ, Instance) and typ.type.raw_type is str


def _accepts(spec: str, typ: ProperType) -> bool:
    if isinstance(typ, (Instance,)) and typ.type.raw_type is object:
        return True
    if spec in {"d", "i", "o", "u", "x", "X"}:
        return _is_int(typ)
    if spec in {"e", "E", "f", "F", "g", "G"}:
        return _is_numeric(typ)
    if spec == "c":
        return _is_int(typ) or _is_text(typ)
    return True


def check_percent_format(
    format_string: str,
    argument: ProperType | None,
    type_system: TypeSystem,
) -> list[str]:
    """Return human-readable mismatches between a ``%`` format and its RHS."""
    conversions = percent_conversions(format_string)
    if not conversions or argument is None or argument == ANY:
        return []
    if "*" in format_string:
        # Star widths consume extra arguments; leave those to runtime.
        return []
    if isinstance(argument, AnyType):  # pragma: no cover - AnyType is not exported here
        return []
    if isinstance(argument, TupleType) and not argument.unknown_size:
        arguments = list(argument.args)
    else:
        arguments = [argument]
    issues: list[str] = []
    if len(conversions) > 1 and not (isinstance(argument, TupleType) and not argument.unknown_size):
        issues.append("multiple format conversions require a tuple argument")
        return issues
    if len(arguments) != len(conversions):
        issues.append(
            f"format has {len(conversions)} conversion(s) but {len(arguments)} argument(s)"
        )
    for spec, actual in zip(conversions, arguments):
        if isinstance(actual, UnionType):
            if all(_accepts(spec, item) for item in actual.items):
                continue
        elif _accepts(spec, actual):
            continue
        issues.append(f"format conversion %{spec} is incompatible with {actual}")
    return issues
