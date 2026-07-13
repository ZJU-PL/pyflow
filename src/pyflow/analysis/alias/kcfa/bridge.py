# SPDX-FileCopyrightText: 2026 PyFlow Contributors
# SPDX-License-Identifier: MIT
"""Bridge between pyflow and the migrated PythonStAn pointer analysis.

This module provides a clean pyflow-facing API that wraps PythonStAn's
k-CFA pointer analysis, hiding the internal ``_pythonstan`` package and
adapting its interfaces to pyflow conventions.
"""

from __future__ import annotations

import ast
import logging
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.analysis import (
    AnalysisResult,
)
from pyflow.analysis.alias.kcfa._pythonstan.world.pipeline import Pipeline

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.points_to_set import (
        PointsToSet,
    )

_LOGGER = logging.getLogger(__name__)

__all__ = ["PointerAnalysis", "PointerAnalysisResult"]


class PointerAnalysisResult:
    """Wraps PythonStAn's AnalysisResult with pyflow-friendly query methods."""

    def __init__(self, inner: AnalysisResult, state) -> None:
        self._inner = inner
        self._state = state
        self._query = inner.query()

    def points_to(self, var_name: str) -> set[str]:
        """Return the set of allocation sites that ``var_name`` may point to."""
        result: set[str] = set()
        for cvar, pts in self._state._env.items():
            content = getattr(cvar, "content", cvar)
            if getattr(content, "name", None) == var_name:
                result.update(str(obj) for obj in pts)
        return result

    def bindings_for_name(self, var_name: str) -> list[tuple[str, set[str]]]:
        """Return all context-qualified bindings matching ``var_name``."""
        bindings: list[tuple[str, set[str]]] = []
        for cvar, pts in self._state._env.items():
            content = getattr(cvar, "content", cvar)
            if getattr(content, "name", None) == var_name:
                bindings.append((str(cvar), {str(obj) for obj in pts}))
        return bindings

    def call_edges(self) -> list[tuple[str, str]]:
        """Return call graph edges as (caller, callee) pairs."""
        cg = self._inner.query().call_graph()
        return [
            (str(edge.callsite), str(edge.callee))
            for edge in cg.get_edges()
        ]

    @property
    def raw(self) -> AnalysisResult:
        """Access the underlying PythonStAn result for advanced queries."""
        return self._inner


class PointerAnalysis:
    """Run k-CFA pointer analysis on Python source code.

    This is the primary pyflow-facing entry point. It orchestrates the
    full PythonStAn lowering pipeline to produce pointer information
    from source text.

    Parameters
    ----------
    source : str
        Python source code to analyze.
    k : int
        Context sensitivity depth for k-CFA (default 1).
    """

    def __init__(self, source: str, *, k: int = 1) -> None:
        self._source = source
        self._k = k

    def run(self) -> PointerAnalysisResult:
        """Execute the pointer analysis and return results.

        Source-string inputs are written to a temporary entry module, then
        analyzed through PythonStAn's migrated Pipeline so import resolution,
        mock stdlib stubs, module graph construction, and transform ordering
        stay aligned with the original backend.
        """
        ast.parse(self._source)
        with tempfile.TemporaryDirectory(prefix="pyflow-pointer-") as tmpdir:
            project_path = Path(tmpdir)
            entry_path = project_path / "__main__.py"
            entry_path.write_text(self._source, encoding="utf-8")

            pipeline = Pipeline(
                config={
                    "filename": str(entry_path),
                    "project_path": str(project_path),
                    "library_paths": [],
                    "mock_libs": True,
                    "prefer_mock_libs": True,
                    "lazy_ir_construction": False,
                    "import_level": -1,
                    "time_count": False,
                    "analysis": [
                        {
                            "name": "pointer-analysis",
                            "id": "PointerAnalysis",
                            "description": "k-CFA pointer analysis",
                            "prev_analysis": ["cfg"],
                            "inter_procedure": True,
                            "options": {
                                "type": "pointer analysis",
                                "k": self._k,
                                "context_policy": f"{self._k}-cfa",
                            },
                        }
                    ],
                }
            )
            pipeline.run()
            result = pipeline.analysis_manager.get_results("pointer-analysis")
            state = result.query()._state
            return PointerAnalysisResult(result, state)
