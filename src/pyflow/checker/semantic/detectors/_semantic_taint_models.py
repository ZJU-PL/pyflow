"""Data models shared by semantic taint analysis components."""

from dataclasses import dataclass, field
from typing import Dict, Set


@dataclass
class FunctionSummary:
    """Summary of taint analysis for a function."""

    name: str
    has_source: bool = False
    returns_tainted: bool = False
    returns_tainted_unconditional: bool = False
    params_to_sink: Set[str] = field(default_factory=set)
    param_taint_outputs: Set[str] = field(default_factory=set)
    param_key_writes: Dict[str, Set[str]] = field(default_factory=dict)
    param_key_taint_writes: Dict[str, Set[str]] = field(default_factory=dict)
    sinks: Set[str] = field(default_factory=set)
    tainted_sinks: Set[str] = field(default_factory=set)
    tainted_sink: bool = False
    returns_value: bool = True
    return_param_deps: Set[str] = field(default_factory=set)
