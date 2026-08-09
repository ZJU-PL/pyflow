"""Declarative effects for calls into unanalyzed Python/native libraries."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from fnmatch import fnmatchcase
from typing import Any


class ExternalEffectKind(str, Enum):
    RETURN_ARGUMENT = "return_argument"
    RETURN_RECEIVER = "return_receiver"
    RETAIN_ARGUMENT = "retain_argument"
    INVOKE_CALLBACK = "invoke_callback"
    SPAWN_CALLBACK = "spawn_callback"
    SERIALIZE_ARGUMENT = "serialize_argument"


@dataclass(frozen=True)
class ExternalEffectSummary:
    access_path: str
    kind: ExternalEffectKind
    arguments: tuple[int | str, ...] = ()

    def matches(self, access_path: str) -> bool:
        return fnmatchcase(access_path, self.access_path)

    def to_pointer_effect(self) -> dict[str, Any]:
        return {
            "access_path": self.access_path,
            "kind": self.kind.value,
            "arguments": list(self.arguments),
        }


__all__ = ["ExternalEffectKind", "ExternalEffectSummary"]
