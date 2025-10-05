"""Analysis modules for PyFlow static analysis.

This package contains various analysis modules for static analysis of Python
code, including control flow analysis, data flow analysis, inter-procedural
analysis, constraint-based analysis, and shape analysis.
"""

# Import main analysis modules
from . import shape
from . import ipa
from . import cpa
from . import fsdf
