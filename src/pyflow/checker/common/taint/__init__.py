"""Formal taint domains shared by source and graph checking engines."""

from .locations import AccessSelector, SelectorKind, TaintLocation
from .provenance import (
    ProvenanceEdge,
    ProvenanceNode,
    ProvenanceOperation,
    TaintOrigin,
)
from .state import TaintFact, TaintState
from .strings import AbstractString, AbstractStringKind
from .uncertainty import AnalysisUncertainty, PrecisionLevel

__all__ = [
    "AbstractString",
    "AbstractStringKind",
    "AccessSelector",
    "AnalysisUncertainty",
    "PrecisionLevel",
    "ProvenanceEdge",
    "ProvenanceNode",
    "ProvenanceOperation",
    "SelectorKind",
    "TaintFact",
    "TaintLocation",
    "TaintOrigin",
    "TaintState",
]
