"""Shared activation semantics for context-dependent taint sinks."""

from __future__ import annotations

import re
from typing import Sequence


SINK_BEHAVIOR_JINJA_AUTOESCAPE = "jinja-autoescape"
SUPPORTED_SINK_BEHAVIORS = frozenset({SINK_BEHAVIOR_JINJA_AUTOESCAPE})


def sink_behavior_is_active(
    behavior: str | None,
    positional_constants: Sequence[object] = (),
) -> bool:
    """Return whether a declarative sink behavior is active at one call site."""
    if behavior is None:
        return True
    if behavior != SINK_BEHAVIOR_JINJA_AUTOESCAPE:
        raise ValueError(f"unsupported taint sink behavior {behavior!r}")
    if not positional_constants or not isinstance(positional_constants[0], str):
        return True
    template = positional_constants[0]
    executable_template = re.sub(r"{#.*?#}|<!--.*?-->", "", template, flags=re.S)
    normalized = "".join(executable_template.lower().split())
    return "|safe" in normalized or "{%autoescapefalse" in normalized
