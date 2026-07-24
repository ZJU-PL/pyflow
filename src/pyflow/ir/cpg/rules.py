"""Strict-v2 taint-policy loading for the CPG engine."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from pyflow.analysis.ifds.modeling.registry import load_registry
from pyflow.ir.cpg.taint import CPGTaintEngine


def load_rules(
    engine: CPGTaintEngine,
    *,
    frameworks: Sequence[str] | None = None,
    custom_paths: Sequence[str | Path] = (),
) -> CPGTaintEngine:
    """Load the same validated strict-v2 policy used by the IFDS engine.

    ``None`` selects the stdlib pack. A non-empty sequence adds framework
    packs on top of stdlib; an explicit empty sequence selects no bundled
    packs, which is useful for custom-only policies. Custom paths fail closed
    through the central registry validator.
    """
    registry = load_registry()
    if frameworks is None:
        registry.activate("stdlib", type="taint")
    elif frameworks:
        registry.activate("stdlib", *frameworks, type="taint")
    else:
        pass
    if custom_paths:
        registry.load_custom(*custom_paths)
    engine.apply_policy(registry.as_taint_policy())
    return engine


def detect_frameworks(source: str) -> list[str]:
    """Detect strict-v2 taint packs from their declared detection markers."""
    registry = load_registry()
    detected = registry.detect(source.splitlines(), type="taint")
    return sorted(detected or {"stdlib"})
