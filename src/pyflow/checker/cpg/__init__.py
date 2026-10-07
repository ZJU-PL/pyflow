"""Security analysis over Code Property Graphs built by pyflow.ir.cpg."""

from .taint import CPGTaintEngine, MemoryCell, MemoryLayout, TaintFinding, TaintPath, TaintState
from .rules import detect_frameworks, load_rules
from .profiles import (
    FrameworkProfile,
    FlaskProfile,
    DjangoProfile,
    FastAPIProfile,
    TornadoProfile,
    PythonStdlibProfile,
    detect_profile,
    apply_profile,
    detect_and_apply,
)

__all__ = [
    "CPGTaintEngine",
    "DjangoProfile",
    "FastAPIProfile",
    "FlaskProfile",
    "FrameworkProfile",
    "MemoryCell",
    "MemoryLayout",
    "PythonStdlibProfile",
    "TaintFinding",
    "TaintPath",
    "TaintState",
    "TornadoProfile",
    "apply_profile",
    "detect_and_apply",
    "detect_frameworks",
    "detect_profile",
    "load_rules",
]
