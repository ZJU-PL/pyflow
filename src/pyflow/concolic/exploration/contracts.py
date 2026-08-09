"""Parsing for the supported, side-effect-free contract subset."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from ..core.runtime import ConcolicError, FunctionNode


_POSTCONDITION = re.compile(r"^\s*post(?:\[[^\]]*\])?\s*:\s*(.+?)\s*$")


@dataclass(frozen=True)
class Postcondition:
    """A PEP 316-style postcondition attached to a target function."""

    source: str
    expression: ast.expr


def parse_postconditions(function: FunctionNode) -> tuple[Postcondition, ...]:
    """Return supported ``post:`` clauses from ``function``'s docstring.

    The expression may use function parameters and ``__return__``.  Snapshot
    variables (``post[x]:`` and ``__old__``) are intentionally not modeled yet;
    the bracketed declaration is accepted only for compatibility with simple
    PEP 316 docstrings.
    """

    docstring = ast.get_docstring(function, clean=False)
    if docstring is None:
        return ()
    clauses: list[Postcondition] = []
    for line in docstring.splitlines():
        match = _POSTCONDITION.match(line)
        if match is None:
            continue
        source = match.group(1)
        try:
            expression = ast.parse(source, mode="eval").body
        except SyntaxError as error:
            raise ConcolicError(f"invalid postcondition on {function.name}: {source!r}") from error
        clauses.append(Postcondition(source, expression))
    return tuple(clauses)
