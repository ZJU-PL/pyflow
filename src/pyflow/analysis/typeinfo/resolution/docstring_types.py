"""Resolve documented type hints without overriding Python annotations."""

from collections.abc import Callable, Iterable

from pyflow.analysis.typeinfo.core.typesystem import ProperType, UnionType
from pyflow.analysis.typeinfo.resolution.docstrings import expand_typestr


def resolve_documented_type(
    hints: Iterable[str], resolve: Callable[[str], ProperType | None]
) -> ProperType | None:
    """Resolve annotation syntax first, then documentation's ``A or B`` syntax.

    An unresolved alternative invalidates the hint rather than implying that
    the resolved alternatives describe all possible values.
    """
    resolved: list[ProperType] = []
    for hint in hints:
        typ = resolve(hint)
        if typ is not None:
            resolved.append(typ)
            continue
        for alternative in expand_typestr(hint):
            typ = resolve(alternative)
            if typ is None:
                return None
            resolved.append(typ)
    unique = tuple(dict.fromkeys(resolved))
    return None if not unique else unique[0] if len(unique) == 1 else UnionType(unique)
