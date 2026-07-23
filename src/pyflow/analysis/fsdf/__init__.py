"""Flow-sensitive data-flow analysis.

The analysis model and implementation are defined in
:mod:`pyflow.analysis.fsdf.analysis`. Canonical collection helpers remain in
their dedicated modules.
"""

from . import canonicalset, canonicaltree
from .analysis import (
    BuildCorrelatedDataflow,
    BuildDataflowNetwork,
    Enviornment,
    FieldName,
    FindMergeSplit,
    HeapSlot,
    LocalName,
    MarkUses,
    Operation,
    ReadModifyInfo,
    Slot,
    checkRecursive,
    evaluate,
    findRecursiveGroups,
    isSCC,
)

__all__ = [
    "BuildCorrelatedDataflow",
    "BuildDataflowNetwork",
    "Enviornment",
    "FieldName",
    "FindMergeSplit",
    "HeapSlot",
    "LocalName",
    "MarkUses",
    "Operation",
    "ReadModifyInfo",
    "Slot",
    "canonicalset",
    "canonicaltree",
    "checkRecursive",
    "evaluate",
    "findRecursiveGroups",
    "isSCC",
]
