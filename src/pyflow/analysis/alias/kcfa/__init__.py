# SPDX-FileCopyrightText: 2026 PyFlow Contributors
# SPDX-License-Identifier: MIT
#
"""Pointer analysis for Python — migrated from PythonStAn.

This package provides k-CFA pointer analysis with configurable context
sensitivity. The implementation is based on PythonStAn's constraint-based
k-CFA solver and is migrated as a self-contained module under
``_pythonstan`` to avoid interference with other pyflow subsystems.

Quick start::

    from pyflow.analysis.alias.kcfa import PointerAnalysis

    source = '''
    x = [1, 2, 3]
    y = x
    z = y[0]
    '''

    analysis = PointerAnalysis(source)
    results = analysis.run()
    print(results.points_to("z"))   # -> points-to set for z

Public API
----------
- ``PointerAnalysis`` — main entry point for running pointer analysis
- ``PointerAnalysisResult`` — result container with query methods
"""

from pyflow.analysis.alias.kcfa.bridge import PointerAnalysis, PointerAnalysisResult

__all__ = ["PointerAnalysis", "PointerAnalysisResult"]
