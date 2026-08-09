"""Semantic events emitted while solving pointer constraints.

The pointer graph answers where objects may flow. Security clients also need
to know which program operation caused a load, store, or call and which
abstract object was involved. These immutable events retain that connection
without coupling the pointer solver to a particular detector.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class PointerEventKind(str, Enum):
    LOAD = "load"
    STORE = "store"
    CALL = "call"


@dataclass(frozen=True)
class PointerEvent:
    kind: PointerEventKind
    scope: Any
    context: Any
    constraint: Any
    abstract_object: Any


__all__ = ["PointerEvent", "PointerEventKind"]
