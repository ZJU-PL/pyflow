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
import re
import tempfile
import tokenize
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Sequence

from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.analysis import (
    AnalysisResult,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.config import (
    DEFAULT_MAX_ITERATIONS,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import (
    TypeNewObject,
)
from pyflow.analysis.alias.kcfa._pythonstan.world.pipeline import Pipeline

_LOGGER = logging.getLogger(__name__)

#: Statically transparent members of :mod:`typing`.  They have no runtime
#: effect on object identity, but when the typing module is treated as native
#: the generic fallback used to replace their result with a fresh native value.
#: The largest practical losses were ``cast(T, value)`` (returned a native
#: object instead of ``value``) and decorators such as ``@overload`` (dropped
#: the decorated function).
_DEFAULT_NATIVE_EFFECTS = (
    {
        "access_path": "typing.cast",
        "kind": "return_argument",
        "arguments": [1],
        "exhaustive": True,
    },
    {
        "access_path": "typing.overload",
        "kind": "return_argument",
        "arguments": [0],
        "exhaustive": True,
    },
    {
        "access_path": "typing.no_type_check",
        "kind": "return_argument",
        "arguments": [0],
        "exhaustive": True,
    },
    {
        "access_path": "typing.final",
        "kind": "return_argument",
        "arguments": [0],
        "exhaustive": True,
    },
    {
        "access_path": "typing.runtime_checkable",
        "kind": "return_argument",
        "arguments": [0],
        "exhaustive": True,
    },
    {
        # ``copy.copy`` preserves the value's reachable objects for a
        # may-analysis.  ``deepcopy`` is coarser, so it is deliberately not
        # marked exhaustive.
        "access_path": "copy.copy",
        "kind": "return_argument",
        "arguments": [0],
    },
    {
        "access_path": "copy.deepcopy",
        "kind": "return_argument",
        "arguments": [0],
    },
    {
        # ``itertools.chain(*iterables)`` yields the elements of every
        # iterable; represent it as a fresh sequence.
        "access_path": "itertools.chain",
        "kind": "return_sequence",
        "arguments": ["*"],
        "exhaustive": True,
    },
    {
        # ``NewType("Name", T)`` returns a callable that is the identity at
        # runtime; the returned native object is modeled below as well.
        "access_path": "typing.NewType",
        "kind": "return_native",
        "exhaustive": True,
    },
    {
        "access_path": "typing.NewType.<return>",
        "kind": "return_argument",
        "arguments": [0],
        "exhaustive": True,
    },
    {
        # ``asyncio.run(coro)`` returns the awaited coroutine value.
        "access_path": "asyncio.run",
        "kind": "await_argument",
        "arguments": [0],
        "exhaustive": True,
    },
)

__all__ = [
    "AliasStatus",
    "BindingId",
    "PointsToQueryResult",
    "PointerAnalysis",
    "PointerAnalysisResult",
]


def _scope_qualname(scope) -> str | None:
    """Best-effort qualified name for a scope or IR scope."""
    if scope is None:
        return None
    getter = getattr(scope, "get_qualname", None)
    if callable(getter):
        return str(getter())
    inner = getattr(scope, "stmt", None)
    getter = getattr(inner, "get_qualname", None)
    if callable(getter):
        return str(getter())
    return None


class AliasStatus(Enum):
    """Three-valued alias answer that preserves analysis incompleteness."""

    ALIASES = "aliases"
    DOES_NOT_ALIAS = "does_not_alias"
    UNKNOWN = "unknown"


@dataclass(frozen=True, order=True)
class BindingId:
    """Stable public identity for a context-qualified source binding."""

    module: str
    lexical_scope: str
    context: str
    name: str
    kind: str

    def __str__(self) -> str:
        return f"{self.module}:{self.lexical_scope}:{self.context}:" f"{self.kind}:{self.name}"


@dataclass(frozen=True)
class PointsToQueryResult:
    """Points-to values plus completeness and unresolved-reason metadata."""

    objects: frozenset[str]
    complete: bool
    reasons: tuple[dict, ...] = ()


def _summarize_incomplete_reasons(reasons) -> tuple[dict, ...]:
    """Collapse repeated native-effect diagnostics by source scope."""
    other: list[dict] = []
    seen_other = set()
    native: dict[object, dict[str, object]] = {}
    for reason in reasons:
        if reason.get("kind") != "native_effect":
            key = (reason.get("kind"), reason.get("message"), reason.get("scope"))
            if key not in seen_other:
                seen_other.add(key)
                other.append(dict(reason))
            continue

        scope = reason.get("scope")
        group = native.setdefault(scope, {"messages": set()})
        message = str(reason.get("message", "native call has no exhaustive effect summary"))
        messages = group["messages"]
        if message in messages:
            continue
        messages.add(message)

    summaries = []
    for scope, group in native.items():
        count = len(group["messages"])
        summaries.append(
            {
                "kind": "native_effect",
                "message": "native calls in this scope lack exhaustive effect summaries",
                "scope": scope,
                "count": count,
            }
        )
    return tuple((*other, *summaries))


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

    @staticmethod
    def _visible_objects(pts) -> set[str]:
        """Return printable targets, hiding internal construction markers."""
        return {str(obj) for obj in pts if not isinstance(obj, TypeNewObject)}

    @staticmethod
    def _scope_label(scope) -> str:
        stmt = getattr(scope, "stmt", None)
        if stmt is None:
            return "<unknown>"
        get_qualname = getattr(stmt, "get_qualname", None)
        return str(get_qualname() if get_qualname else stmt)

    def _binding_id(self, cvar) -> BindingId:
        content = getattr(cvar, "content", cvar)
        scope = getattr(cvar, "scope", None)
        module = getattr(scope, "module", None) if scope is not None else None
        kind = getattr(getattr(content, "kind", None), "value", "unknown")
        return BindingId(
            module=self._scope_label(module),
            lexical_scope=self._scope_label(scope),
            context=str(getattr(cvar, "context", "<unknown>")),
            name=str(getattr(content, "name", "<unknown>")),
            kind=str(kind),
        )

    def _iter_named_bindings(self, var_name: str):
        seen = set()
        for cvar, pts in self._state._env.items():
            content = getattr(cvar, "content", cvar)
            if getattr(content, "name", None) == var_name and hasattr(cvar, "scope"):
                seen.add(cvar)
                yield self._binding_id(cvar), cvar, pts
        # Empty bindings may never receive an environment entry.  Recover
        # them from constraint definitions so completeness remains queryable
        # even when the points-to result is empty.
        for scope, context, constraint in self._state.constraint_definitions:
            candidates = []
            for attribute in ("target", "source", "base", "callee"):
                variable = getattr(constraint, attribute, None)
                if variable is not None:
                    candidates.append(variable)
            candidates.extend(getattr(constraint, "args", ()))
            candidates.extend(variable for _, variable in getattr(constraint, "kwargs", ()))
            for variable in candidates:
                if getattr(variable, "name", None) != var_name:
                    continue
                cvar = self._state.get_variable(scope, context, variable)
                if cvar in seen:
                    continue
                seen.add(cvar)
                yield (
                    self._binding_id(cvar),
                    cvar,
                    self._state.get_points_to(cvar),
                )

    def points_to(
        self,
        binding: str | BindingId,
        *,
        scope: str | None = None,
        context: str | None = None,
    ) -> set[str]:
        """Return points-to objects for an exact binding or filtered name.

        ``BindingId`` is the precise form.  A bare string retains the legacy
        name-union behavior for compatibility; new clients should call
        :meth:`points_to_name_union` when that union is intentional.
        """
        if isinstance(binding, BindingId):
            return set().union(
                *(
                    PointerAnalysisResult._visible_objects(pts)
                    for binding_id, _, pts in self._iter_named_bindings(binding.name)
                    if binding_id == binding
                )
            )
        return self.points_to_name_union(binding, scope=scope, context=context)

    def points_to_name_union(
        self,
        var_name: str,
        *,
        scope: str | None = None,
        context: str | None = None,
    ) -> set[str]:
        """Explicitly union bindings named ``var_name`` matching the filters."""
        result: set[str] = set()
        for binding_id, _, pts in self._iter_named_bindings(var_name):
            if scope is not None and binding_id.lexical_scope != scope:
                continue
            if context is not None and binding_id.context != context:
                continue
            result.update(PointerAnalysisResult._visible_objects(pts))
        return result

    def binding_ids_for_name(self, var_name: str) -> list[BindingId]:
        """Return stable identifiers for every analyzed binding of a name."""
        return sorted({binding_id for binding_id, _, _ in self._iter_named_bindings(var_name)})

    def bindings_for_name(self, var_name: str) -> list[tuple[str, set[str]]]:
        """Return each context-qualified binding matching ``var_name``.

        Each result contains the backend's printable binding identifier and
        the printable abstract objects in that binding's points-to set.
        """
        bindings: list[tuple[str, set[str]]] = []
        for cvar, pts in self._state._env.items():
            content = getattr(cvar, "content", cvar)
            if getattr(content, "name", None) == var_name:
                bindings.append((str(cvar), PointerAnalysisResult._visible_objects(pts)))
        return bindings

    def points_to_query(
        self,
        binding: str | BindingId,
        *,
        scope: str | None = None,
        context: str | None = None,
    ) -> PointsToQueryResult:
        """Return values together with solver completeness diagnostics."""
        matched = [
            cvar
            for binding_id, cvar, _ in self._iter_named_bindings(
                binding.name if isinstance(binding, BindingId) else binding
            )
            if (
                (not isinstance(binding, BindingId) or binding_id == binding)
                and (scope is None or binding_id.lexical_scope == scope)
                and (context is None or binding_id.context == context)
            )
        ]
        if not matched:
            # Absence of a binding is not evidence that the queried value has
            # no targets.  Calling it "complete" made typos and out-of-scope
            # names indistinguishable from a proven empty points-to set.
            return PointsToQueryResult(
                objects=frozenset(),
                complete=False,
                reasons=(
                    {
                        "kind": "unbound_name",
                        "message": "query did not match an analyzed binding",
                    },
                ),
            )
        complete, reasons = self._query.completeness_for(matched)
        return PointsToQueryResult(
            objects=frozenset(self.points_to(binding, scope=scope, context=context)),
            complete=complete,
            reasons=_summarize_incomplete_reasons(reasons),
        )

    def _binding_exists(self, binding: str | BindingId) -> bool:
        """Whether a query names an analyzed binding at all."""
        if isinstance(binding, BindingId):
            return any(
                candidate == binding for candidate in self.binding_ids_for_name(binding.name)
            )
        return bool(self.binding_ids_for_name(binding))

    def alias_status(
        self,
        left: str | BindingId,
        right: str | BindingId,
    ) -> AliasStatus:
        """Return a sound three-valued alias relation for two queries.

        A name that was never bound is not evidence of non-aliasing.  Typoed
        or out-of-scope names previously produced ``DOES_NOT_ALIAS`` with an
        empty, "complete" points-to set.
        """
        if not self._binding_exists(left) or not self._binding_exists(right):
            return AliasStatus.UNKNOWN
        if self.points_to(left).intersection(self.points_to(right)):
            return AliasStatus.ALIASES
        left_query = self.points_to_query(left)
        right_query = self.points_to_query(right)
        if not left_query.complete or not right_query.complete:
            return AliasStatus.UNKNOWN
        return AliasStatus.DOES_NOT_ALIAS

    def call_edges(self) -> list[tuple[str, str]]:
        """Return discovered call-graph edges as ``(call_site, callee)`` pairs."""
        cg = self._inner.query().call_graph()
        return [(str(edge.callsite), str(edge.callee)) for edge in cg.get_edges()]

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

    def incomplete_reasons(self) -> list[dict]:
        """Return deduplicated reasons the solver marked itself incomplete.

        ``statistics()["complete"]`` only answers yes/no; analyses such as the
        capability inventory need to distinguish "an unmodelled native call"
        (already reported conservatively) from "the frontend dropped code".
        """
        query = self._inner.query() if self._inner is not None else self._query
        reasons: list[dict] = []
        for reason in getattr(query, "_global_incomplete_reasons", ()) or ():
            reasons.append({**reason, "scope": None})
        for scope, scoped in (getattr(query, "_incomplete_scopes", {}) or {}).items():
            name = _scope_qualname(scope)
            for reason in scoped or ():
                reasons.append({**reason, "scope": name})
        for variable, scoped in (getattr(query, "_incomplete_variables", {}) or {}).items():
            name = _scope_qualname(getattr(variable, "scope", None))
            for reason in scoped or ():
                reasons.append({**reason, "scope": name})
        return list(_summarize_incomplete_reasons(reasons))

    def statistics(self) -> dict[str, object]:
        """Return solver statistics, including completeness status."""
        return dict(self._query.get_statistics())

    @property
    def complete(self) -> bool:
        """Whether the solver, frontend, and semantic modeling are complete."""
        return bool(self._query.get_statistics()["complete"])

    @property
    def fixpoint_complete(self) -> bool:
        """Whether all solver work was exhausted before the iteration budget."""
        return bool(self._query.get_statistics()["fixpoint_complete"])

    @property
    def stop_reason(self) -> str:
        """Return the primary reason analysis stopped or remained incomplete."""
        stats = self._query.get_statistics()
        if not stats["fixpoint_complete"]:
            return "solver_budget"
        if not stats["frontend_complete"]:
            return "frontend_incomplete"
        if not stats["semantic_complete"]:
            return "semantic_incomplete"
        return "fixpoint"

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
    k : int or None
        Context sensitivity depth for k-CFA (default 1).
    context_policy : str or None
        Explicit context policy. For ``N-cfa`` policies, its depth must agree
        with ``k``; non-call-string policies replace ``k``.
    max_iterations : int
        Solver work-item budget (default 100,000).
    max_points_to_size : int or None
        Optional threshold that widens growing points-to sets to summary
        objects. Widened queries are reported as incomplete.
    """

    def __init__(
        self,
        source: str,
        *,
        k: int | None = None,
        context_policy: str | None = None,
        native_effects: Sequence[dict] = (),
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        max_points_to_size: int | None = None,
        analyze_all_scopes: bool = False,
        audit_scope_paths: Sequence[str] = (),
        audit_scope_names: Sequence[str] = (),
        worklist_policy: str = "fifo",
        worklist_seed: int = 0,
    ) -> None:
        """Configure an analysis over ``source`` with call-string depth ``k``.

        The source is parsed when :meth:`run` is called.  ``k=0`` gives a
        context-insensitive analysis; positive values retain that many recent
        call sites in each abstract calling context.  Conflicting ``k`` and
        ``N-cfa`` policy depths are rejected when the backend configuration is
        constructed, rather than silently choosing one.
        """
        self._source = source
        if k is None:
            policy_match = (
                re.fullmatch(r"(\d+)-cfa", context_policy) if context_policy is not None else None
            )
            k = int(policy_match.group(1)) if policy_match is not None else 1
        self._k = k
        self._context_policy = context_policy or f"{k}-cfa"
        self._native_effects = tuple(
            dict(effect) for effect in (*_DEFAULT_NATIVE_EFFECTS, *native_effects)
        )
        self._max_iterations = max_iterations
        self._max_points_to_size = max_points_to_size
        self._analyze_all_scopes = bool(analyze_all_scopes)
        self._audit_scope_paths = tuple(audit_scope_paths)
        self._audit_scope_names = tuple(audit_scope_names)
        self._worklist_policy = worklist_policy
        self._worklist_seed = worklist_seed
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
        k: int | None = None,
        context_policy: str | None = None,
        native_effects: Sequence[dict] = (),
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        max_points_to_size: int | None = None,
        analyze_all_scopes: bool = False,
        audit_scope_paths: Sequence[str] = (),
        audit_scope_names: Sequence[str] = (),
        import_level: int = -1,
        max_import_depth: int = -1,
        worklist_policy: str = "fifo",
        worklist_seed: int = 0,
    ) -> "PointerAnalysis":
        """Configure analysis of a real project and its reachable imports.

        ``max_import_depth`` is the preferred spelling for the transitive
        import limit (``0`` analyzes only the entry module and ``-1`` is
        unlimited). ``import_level`` remains available for compatibility.
        """
        entry = Path(entry_file).resolve()
        if not entry.is_file():
            raise FileNotFoundError(entry)
        if max_import_depth != -1:
            if import_level != -1 and import_level != max_import_depth:
                raise ValueError(
                    "import_level and max_import_depth must agree when both " "are provided"
                )
            import_level = max_import_depth
        if import_level < -1:
            raise ValueError(
                "max_import_depth must be >= -1 (-1 = unlimited, " "0 = entry module only)"
            )
        with tokenize.open(entry) as source_file:
            entry_source = source_file.read()
        analysis = cls(
            entry_source,
            k=k,
            context_policy=context_policy,
            native_effects=native_effects,
            max_iterations=max_iterations,
            max_points_to_size=max_points_to_size,
            analyze_all_scopes=analyze_all_scopes,
            audit_scope_paths=audit_scope_paths,
            audit_scope_names=audit_scope_names,
            worklist_policy=worklist_policy,
            worklist_seed=worklist_seed,
        )
        analysis._entry_file = entry
        analysis._project_path = (
            Path(project_path).resolve() if project_path else cls._infer_project_path(entry)
        )
        analysis._library_paths = tuple(Path(path).resolve() for path in library_paths)
        analysis._import_level = import_level
        return analysis

    @staticmethod
    def _infer_project_path(entry: Path) -> Path:
        """Return the nearest enclosing source root for a module path.

        Using only ``entry.parent`` made ``from ..sibling import name`` fail
        whenever the entry was inside a package.  Walking out of contiguous
        packages matches how the module would be imported by Python.
        """
        root = entry.parent
        while (root / "__init__.py").is_file() and root.parent != root:
            root = root.parent
        return root

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
                            "max_iterations": self._max_iterations,
                            "max_points_to_size": self._max_points_to_size,
                            "analyze_all_scopes": self._analyze_all_scopes,
                            "audit_scope_paths": list(self._audit_scope_paths),
                            "audit_scope_names": list(self._audit_scope_names),
                            "worklist_policy": self._worklist_policy,
                            "worklist_seed": self._worklist_seed,
                        },
                    }
                ],
            }
        )
        pipeline.run()
        result = pipeline.analysis_manager.get_results("pointer-analysis")
        state = result.query()._state
        return PointerAnalysisResult(result, state)
