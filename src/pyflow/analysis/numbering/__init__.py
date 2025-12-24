"""Numbering analysis for PyFlow. (value numbering?)

This package provides numbering-based static analysis techniques including
data flow numbering, dominance analysis, read-modify analysis, and Extended
Static Single Assignment (ESSA) form.

Key components:
- DataFlow: Generic data flow analysis framework
- Dominance: Dominance relationship computation
- ReadModify: Read-modify relationship analysis
- SSA: Extended Static Single Assignment form construction

These analyses are used for program optimization, dead code elimination,
and various static analysis tasks that require precise data flow tracking.
"""

from . import dataflow, dominance, readmodify, ssa
