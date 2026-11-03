"""Explicit assumptions used by source-backed dependence construction."""

from dataclasses import dataclass


@dataclass(frozen=True)
class DDGConstructionOptions:
    # These defaults favor structural IR inspection. Disable both for
    # arbitrary overloaded Python protocols and potentially aliased arguments.
    assume_primitive_intrinsics: bool = True
    assume_distinct_parameters: bool = True
