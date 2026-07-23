"""Fallback annotation completion for source-loaded IFDS analyses."""

from __future__ import annotations

from .annotations import (
    IFDSAnnotationSynthesizer,
    SyntheticAllocation,
    SyntheticSlot,
)


def ensure_ifds_annotations_complete(codes) -> None:
    """Populate IFDS annotations when the full semantic pipeline leaves gaps."""
    IFDSAnnotationSynthesizer().complete(codes)


__all__ = [
    "SyntheticAllocation",
    "SyntheticSlot",
    "ensure_ifds_annotations_complete",
]
