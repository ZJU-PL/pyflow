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
from typing import TYPE_CHECKING, Sequence

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
    """Expose a stable, pyflow-facing view of a completed analysis.

    The migrated backend represents variables and objects with internal,
    context-qualified classes.  This wrapper deliberately returns strings and
    built-in containers for the common queries, while :attr:`raw` remains
    available to callers that need the backend's richer query interface.
    """

    def __init__(self, inner: AnalysisResult, state) -> None:
        self._inner = inner
        self._state = state
        self._query = inner.query()

    def points_to(self, var_name: str) -> set[str]:
        """Return abstract objects reachable from any binding named ``var_name``.

        Bindings from all analyzed scopes and contexts are combined.  Use
        :meth:`bindings_for_name` when the distinction between those bindings
        matters.
        """
        result: set[str] = set()
        for cvar, pts in self._state._env.items():
            content = getattr(cvar, "content", cvar)
            if getattr(content, "name", None) == var_name:
                result.update(str(obj) for obj in pts)
        return result

    def bindings_for_name(self, var_name: str) -> list[tuple[str, set[str]]]:
        """Return each context-qualified binding matching ``var_name``.

        Each result contains the backend's printable binding identifier and
        the printable abstract objects in that binding's points-to set.
        """
        bindings: list[tuple[str, set[str]]] = []
        for cvar, pts in self._state._env.items():
            content = getattr(cvar, "content", cvar)
            if getattr(content, "name", None) == var_name:
                bindings.append((str(cvar), {str(obj) for obj in pts}))
        return bindings

    def call_edges(self) -> list[tuple[str, str]]:
        """Return discovered call-graph edges as ``(call_site, callee)`` pairs."""
        cg = self._inner.query().call_graph()
        return [
            (str(edge.callsite), str(edge.callee))
            for edge in cg.get_edges()
        ]

    @property
    def semantic_events(self) -> tuple[object, ...]:
        """Return source-attributed load/store/call events from the solver."""
        return self._state.semantic_events

    @property
    def state(self):
        """Return the solved state for semantic analyses built on k-CFA."""
        return self._state

    def unknown_details(self) -> list[dict]:
        """Return fail-visible unresolved-operation diagnostics."""
        return self._query.get_unknown_details()

    @property
    def raw(self) -> AnalysisResult:
        """Return the migrated backend result for advanced queries."""
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

    def __init__(
        self,
        source: str,
        *,
        k: int = 1,
        context_policy: str | None = None,
        native_effects: Sequence[dict] = (),
    ) -> None:
        """Configure an analysis over ``source`` with call-string depth ``k``.

        The source is parsed when :meth:`run` is called.  ``k=0`` gives a
        context-insensitive analysis; positive values retain that many recent
        call sites in each abstract calling context.
        """
        self._source = source
        self._k = k
        self._context_policy = context_policy or f"{k}-cfa"
        self._native_effects = tuple(dict(effect) for effect in native_effects)
        self._entry_file: Path | None = None
        self._project_path: Path | None = None
        self._library_paths: tuple[Path, ...] = ()
        self._import_level = -1

    @classmethod
    def from_project(
        cls,
        entry_file: str | Path,
        *,
        project_path: str | Path | None = None,
        library_paths: Sequence[str | Path] = (),
        k: int = 1,
        context_policy: str | None = None,
        native_effects: Sequence[dict] = (),
        import_level: int = -1,
    ) -> "PointerAnalysis":
        """Configure analysis of a real project and its reachable imports."""
        entry = Path(entry_file).resolve()
        if not entry.is_file():
            raise FileNotFoundError(entry)
        analysis = cls(
            entry.read_text(encoding="utf-8"),
            k=k,
            context_policy=context_policy,
            native_effects=native_effects,
        )
        analysis._entry_file = entry
        analysis._project_path = Path(project_path).resolve() if project_path else entry.parent
        analysis._library_paths = tuple(Path(path).resolve() for path in library_paths)
        analysis._import_level = import_level
        return analysis

    def run(self) -> PointerAnalysisResult:
        """Execute the pointer analysis and return results.

        Source-string inputs are written to a temporary entry module and then
        analyzed through PythonStAn's migrated Pipeline so import resolution,
        mock stdlib stubs, module graph construction, and transform ordering
        stay aligned with the original backend.

        Returns
        -------
        PointerAnalysisResult
            A query wrapper over the solver's fixed-point result.

        Raises
        ------
        SyntaxError
            If ``source`` is not valid Python syntax.
        """
        ast.parse(self._source)
        if self._entry_file is not None:
            return self._run_path(self._entry_file, self._project_path or self._entry_file.parent)
        with tempfile.TemporaryDirectory(prefix="pyflow-pointer-") as tmpdir:
            project_path = Path(tmpdir)
            entry_path = project_path / "__main__.py"
            entry_path.write_text(self._source, encoding="utf-8")

            return self._run_path(entry_path, project_path)

    def _run_path(self, entry_path: Path, project_path: Path) -> PointerAnalysisResult:
        pipeline = Pipeline(
            config={
                    "filename": str(entry_path),
                    "project_path": str(project_path),
                    "library_paths": [str(path) for path in self._library_paths],
                    "mock_libs": True,
                    "prefer_mock_libs": True,
                    "lazy_ir_construction": False,
                    "import_level": self._import_level,
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
                                "context_policy": self._context_policy,
                                # The high-level alias query promises precise
                                # literal container positions/keys.  Keep that
                                # opt-in explicit now that Config.from_dict({})
                                # correctly matches Config()'s False default.
                                "index_sensitive": True,
                                "native_effects": list(self._native_effects),
                            },
                        }
                    ],
                }
        )
        pipeline.run()
        result = pipeline.analysis_manager.get_results("pointer-analysis")
        state = result.query()._state
        return PointerAnalysisResult(result, state)
