"""Shared ownership contract for inference components."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyflow.analysis.typeinfo.inference.engine import StaticTypeInferenceEngine


class InferenceComponent:
    """Operate on the solver's state without maintaining a separate copy."""

    def __init__(self, engine: StaticTypeInferenceEngine) -> None:
        self.engine = engine
