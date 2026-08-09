"""Default defensive capability model for Python builtins and libraries."""

from __future__ import annotations

from pathlib import Path

from .registry import CapabilityRegistry


def default_capability_registry() -> CapabilityRegistry:
    model = Path(__file__).resolve().parents[2] / "config" / "capability" / "stdlib.json"
    return CapabilityRegistry.from_json(model)


__all__ = ["default_capability_registry"]
