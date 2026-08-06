"""Small, semantics-preserving source repairs shared by analysis frontends."""

from __future__ import annotations

import re


_LEGACY_EXCEPT_BINDING = re.compile(
    r"^(?P<indent>\s*)except\s+(?P<types>.+?),\s*(?P<name>[A-Za-z_]\w*)\s*:",
    re.MULTILINE,
)


def normalize_legacy_python_syntax(source: str) -> str:
    """Repair syntax whose Python 2 and Python 3 meanings are equivalent."""
    return _LEGACY_EXCEPT_BINDING.sub(
        lambda match: (
            f"{match.group('indent')}except {match.group('types')} "
            f"as {match.group('name')}:"
        ),
        source,
    )


__all__ = ["normalize_legacy_python_syntax"]
