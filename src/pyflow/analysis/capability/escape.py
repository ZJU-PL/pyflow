"""Uniform representation of capability-bearing values crossing boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .model import CapabilityOperation, SourceLocation


class EscapeKind(str, Enum):
    ARGUMENT = "argument"
    RETURN = "return"
    YIELD = "yield"
    RAISE = "raise"
    PUBLIC_EXPORT = "public_export"
    FIELD_STORE = "field_store"
    CLOSURE_CAPTURE = "closure_capture"
    CALLBACK_REGISTRATION = "callback_registration"
    TASK_SPAWN = "task_spawn"
    SERIALIZATION = "serialization"


@dataclass(frozen=True)
class CapabilityEscapeEvent:
    kind: EscapeKind
    objects: tuple[Any, ...]
    location: SourceLocation
    context: str
    operation: CapabilityOperation
    boundary: str
    reason: str
    trace_step: str


__all__ = ["CapabilityEscapeEvent", "EscapeKind"]
