"""Static checks for printf-style ``%`` format strings."""

from __future__ import annotations

import re

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    AnyType,
    Instance,
    NeverType,
    ProperType,
    TupleType,
    TypeSystem,
    UnionType,
)

_SPEC_RE = re.compile(
    r"%(?:\(([^)]+)\))?[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[hlL]?([diouxXeEfFgGcrsa%])"
)


def percent_conversions(format_string: str) -> list[str]:
    """Return positional conversion characters in *format_string*, excluding ``%%``."""
    return [
        match.group(2)
        for match in _SPEC_RE.finditer(format_string)
        if match.group(2) != "%" and match.group(1) is None
    ]


def _has_percent_mapping_keys(format_string: str) -> bool:
    return any(
        match.group(1) is not None and match.group(2) != "%"
        for match in _SPEC_RE.finditer(format_string)
    )


def _is_numeric(typ: ProperType) -> bool:
    return isinstance(typ, Instance) and typ.type.raw_type in {bool, int, float}


def _is_int(typ: ProperType) -> bool:
    return isinstance(typ, Instance) and typ.type.raw_type in {bool, int}


def _is_text(typ: ProperType) -> bool:
    return isinstance(typ, Instance) and typ.type.raw_type is str


def _accepts(spec: str, typ: ProperType) -> bool:
    if isinstance(typ, AnyType) or typ == ANY:
        return True
    if isinstance(typ, Instance) and typ.type.raw_type is object:
        return True
    if spec in {"d", "i", "u"}:
        # CPython truncates floats via int() for decimal conversions, whereas
        # %o/%x/%X strictly require an integer.
        return _is_numeric(typ)
    if spec in {"o", "x", "X"}:
        return _is_int(typ)
    if spec in {"e", "E", "f", "F", "g", "G"}:
        return _is_numeric(typ)
    if spec == "c":
        return _is_int(typ) or _is_text(typ)
    return True


def str_format_fields(format_string: str) -> list[str]:
    """Return ``str.format`` field names in source order (``""`` for auto).

    Nested replacement fields inside format specifications such as
    ``"{:.{width}f}"`` are extracted alongside their enclosing field.
    """
    fields: list[str] = []
    index = 0
    length = len(format_string)
    while index < length:
        character = format_string[index]
        if character == "{":
            if index + 1 < length and format_string[index + 1] == "{":
                index += 2
                continue
            depth = 1
            cursor = index + 1
            while cursor < length and depth > 0:
                if format_string[cursor] == "{":
                    depth += 1
                elif format_string[cursor] == "}":
                    depth -= 1
                cursor += 1
            if depth != 0:
                break
            inner = format_string[index + 1 : cursor - 1]
            # Split top-level field name from optional !conv and :format_spec.
            spec_split = inner.split(":", 1)
            field_head = spec_split[0].split("!", 1)[0]
            fields.append(field_head)
            if len(spec_split) == 2 and "{" in spec_split[1]:
                fields.extend(str_format_fields(spec_split[1]))
            index = cursor
        elif character == "}" and index + 1 < length and format_string[index + 1] == "}":
            index += 2
        else:
            index += 1
    return fields


def check_str_format(
    format_string: str,
    positional_count: int,
    keyword_names: set[str],
    *,
    has_starred: bool = False,
    has_double_starred: bool = False,
) -> list[str]:
    """Return missing/invalid ``str.format`` fields."""
    fields = str_format_fields(format_string)
    issues: list[str] = []
    auto_index = 0
    auto_used = False
    manual_used = False
    for field in fields:
        head = field.split(".", 1)[0].split("[", 1)[0]
        if head == "":
            auto_used = True
            if not has_starred and auto_index >= positional_count:
                issues.append(f"format is missing positional argument {auto_index}")
            auto_index += 1
            continue
        if head.isdigit():
            manual_used = True
            if not has_starred and int(head) >= positional_count:
                issues.append(f"format references missing positional argument {head}")
        else:
            # Named keyword fields (``{name}``) are valid alongside both
            # automatic (``{}``) and manual (``{0}``) positional fields.
            if not has_double_starred and head not in keyword_names:
                issues.append(f"format references missing keyword argument {head!r}")
    if auto_used and manual_used:
        issues.append("cannot mix automatic and manual field numbering")
    return issues


def _is_dynamic_tuple_or_gradual(typ: ProperType) -> bool:
    if isinstance(typ, (AnyType, NeverType)) or typ == ANY:
        return True
    if isinstance(typ, TupleType) and typ.unknown_size:
        return True
    if isinstance(typ, Instance) and typ.type.raw_type in {tuple, object}:
        return True
    if isinstance(typ, UnionType):
        return any(_is_dynamic_tuple_or_gradual(item) for item in typ.items)
    return False


def check_percent_format(
    format_string: str,
    argument: ProperType | None,
    type_system: TypeSystem,
) -> list[str]:
    """Return human-readable mismatches between a ``%`` format and its RHS."""
    if _has_percent_mapping_keys(format_string):
        return []
    conversions = percent_conversions(format_string)
    if not conversions or argument is None or argument == ANY:
        return []
    if "*" in format_string:
        # Star widths consume extra arguments; leave those to runtime.
        return []
    if isinstance(argument, (AnyType, NeverType)):
        return []
    if isinstance(argument, Instance) and argument.type.tuple_fields is not None:
        argument = TupleType(
            tuple(argument.type.members.get(name, ANY) for name in argument.type.tuple_fields)
        )
    if isinstance(argument, TupleType) and not argument.unknown_size:
        arguments = list(argument.args)
    elif len(conversions) > 1 and _is_dynamic_tuple_or_gradual(argument):
        return []
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
            if any(
                isinstance(item, (AnyType, NeverType)) or item == ANY for item in actual.items
            ) or all(_accepts(spec, item) for item in actual.items):
                continue
        elif _accepts(spec, actual):
            continue
        issues.append(f"format conversion %{spec} is incompatible with {actual}")
    return issues
