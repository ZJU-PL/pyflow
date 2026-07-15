"""Flow-sensitive heap analysis engine.

:class:`HeapAnalysis` wraps :class:`HeapAbstraction` as a first-class
analysis engine that produces a reusable :class:`PointsToGraph`.  Unlike
IFDS clients that consume the heap model inline during solving,
``HeapAnalysis`` can be run as a standalone pass and queried by
optimization passes and the semantic query API.
"""

from __future__ import annotations

from .abstraction import (
    HeapAbstraction,
)
from .intrinsics import DEFAULT_HEAP_INTRINSICS, HeapIntrinsicModels
from .model import (
    HeapLocation,
    HeapPolicy,
    HeapWrite,
    RawStorageProvider,
)
from .points_to_graph import PointsToGraph, PossibleValues
from .transfer import HeapTransferEngine
from .heap_summary import ProcedureHeapSummary


class HeapAnalysis:
    """Standalone heap alias and escape analysis engine.

    Wraps a single :class:`HeapAbstraction` instance and exposes a
    high-level query API that does not require IFDS solver context.

    Typical pipeline usage::

        analysis = HeapAnalysis()
        graph = analysis.analyze(compiler, program)
        program.set_analysis_result("heap", graph)

    Typical query usage::

        graph = program.heap_analysis
        if graph.never_escapes(location):
            ...  # safe to stack-allocate / eliminate
        if graph.must_alias(a, b):
            ...  # must-alias: load elimination can reuse dominating store
    """

    def __init__(
        self,
        policy: HeapPolicy | None = None,
        raw_storage_provider: RawStorageProvider | None = None,
        intrinsics: HeapIntrinsicModels = DEFAULT_HEAP_INTRINSICS,
    ) -> None:
        self._policy = policy or HeapPolicy()
        self._raw_storage_provider: RawStorageProvider = (
            raw_storage_provider or _empty_raw_storage
        )
        self._intrinsics = intrinsics
        self._heap: HeapAbstraction | None = None
        self._graph: PointsToGraph | None = None
        self._procedure_summaries: dict[object, ProcedureHeapSummary] = {}
        self._precision_degradations: dict[int, frozenset[str]] = {}

    # ── core analysis ──────────────────────────────────────────────────

    def analyze(
        self,
        compiler: object,
        program: object,
        *,
        raw_storage_provider: RawStorageProvider | None = None,
        storage_overrides: dict[tuple[int, int], tuple[object, ...]] | None = None,
        allocation_sites: dict[tuple[int, int], int] | None = None,
        site_storage: dict[int, tuple[object, ...]] | None = None,
        next_site: int = 0,
    ) -> PointsToGraph:
        """Build a heap abstraction and extract the points-to graph.

        If a *raw_storage_provider* is given it replaces the default
        (empty) provider and is used for future live queries.
        """
        provider = raw_storage_provider or self._raw_storage_provider
        self._raw_storage_provider = provider
        self._heap = HeapAbstraction(
            provider,
            policy=self._policy,
            storage_overrides=storage_overrides or {},
            allocation_sites=allocation_sites or {},
            site_storage=site_storage or {},
            next_site=next_site,
        )
        engine = HeapTransferEngine(self._heap, intrinsics=self._intrinsics)
        engine.analyze_program(program)
        self._procedure_summaries = dict(engine.procedure_summaries)
        degradations: dict[int, set[str]] = {}
        for operation, reason in engine.precision_degradations:
            degradations.setdefault(id(operation), set()).add(reason)
        self._precision_degradations = {
            operation_id: frozenset(reasons)
            for operation_id, reasons in degradations.items()
        }
        graph = self._heap.to_points_to_graph(
            state=engine.state,
            program_point_states=engine.program_point_states,
            program_point_outcomes=engine.program_point_outcomes,
            precision_degradations=self._precision_degradations,
        )
        self._graph = graph
        return graph

    @property
    def heap(self) -> HeapAbstraction | None:
        """The underlying :class:`HeapAbstraction`, if :meth:`analyze` has been called."""
        return self._heap

    @property
    def graph(self) -> PointsToGraph | None:
        """The extracted :class:`PointsToGraph`, if :meth:`analyze` has been called."""
        return self._graph

    @property
    def policy(self) -> HeapPolicy:
        """The :class:`HeapPolicy` used by this analysis."""
        return self._policy

    @property
    def intrinsics(self) -> HeapIntrinsicModels:
        """The intrinsic call models used by this analysis."""
        return self._intrinsics

    def reset(self) -> None:
        """Clear internal state so :meth:`analyze` can be called again."""
        self._heap = None
        self._graph = None
        self._procedure_summaries = {}
        self._precision_degradations = {}

    @property
    def procedure_summaries(self) -> dict[object, ProcedureHeapSummary]:
        return dict(self._procedure_summaries)

    @property
    def precision_degradations(self) -> dict[int, frozenset[str]]:
        return dict(self._precision_degradations)

    # ── live heap queries (delegated to HeapAbstraction) ────────────────

    def _require_heap(self) -> HeapAbstraction:
        if self._heap is None:
            raise RuntimeError(
                "HeapAnalysis.analyze() must be called before querying heap state"
            )
        return self._heap

    def location_for(self, raw: object) -> HeapLocation:
        """Canonicalize a raw storage identity into a :class:`HeapLocation`."""
        return self._require_heap().location_for_raw(raw)

    def write_policy(self, location: HeapLocation) -> "HeapWrite":
        """Return a semantic write descriptor for *location*."""
        return self._require_heap().write_for_location(location)

    def mark_escaped(self, location: object) -> None:
        """Mark a location as escaped."""
        self._require_heap().mark_escaped(location)

    def mark_all_escaped(self, locations: tuple[object, ...]) -> None:
        """Mark multiple locations as escaped."""
        self._require_heap().mark_all_escaped(locations)

    def alias_locals(
        self, procedure: object, target: object, source: object
    ) -> None:
        """Declare that two named locals share the same storage."""
        self._require_heap().alias_locals(procedure, target, source)

    def unalias_local(self, procedure: object, local: object) -> None:
        """Break a local alias and allocate a fresh site."""
        self._require_heap().unalias_local(procedure, local)

    # ── graph-backed queries (no live heap required) ────────────────────

    def _require_graph(self) -> PointsToGraph:
        if self._graph is None:
            raise RuntimeError(
                "HeapAnalysis.analyze() must be called before querying the graph"
            )
        return self._graph

    def points_to(self, location: "HeapLocation") -> "frozenset[HeapLocation]":
        """Return all locations in the same alias class as *location*."""
        return self._require_graph().points_to(location)

    def possible_values_at(
        self,
        location: "HeapLocation",
        operation: object | None = None,
        *,
        before: bool = False,
        outcome: str | None = None,
    ) -> PossibleValues:
        """Return values plus unknown/absence state at a program point."""
        return self._require_graph().possible_values_at(
            location,
            operation,
            before=before,
            outcome=outcome,
        )

    def possible_local_values_at(
        self,
        procedure: object,
        local: object,
        operation: object,
        *,
        before: bool = False,
        outcome: str | None = None,
    ) -> PossibleValues:
        return self._require_graph().possible_local_values_at(
            procedure,
            local,
            operation,
            before=before,
            outcome=outcome,
        )

    def outcome_snapshot(self, operation: object, outcome: str):
        return self._require_graph().outcome_snapshot(operation, outcome)

    def never_escapes(self, location: "HeapLocation") -> bool:
        """Return ``True`` if *location* has not been marked escaped."""
        return self._require_graph().never_escapes(location)

    def is_escaped(self, location: "HeapLocation") -> bool:
        """Return ``True`` if *location* has been marked escaped."""
        return self._require_graph().is_escaped(location)

    def single_reference(self, location: "HeapLocation") -> bool:
        """Return ``True`` if *location* has ≤ 1 reference."""
        return self._require_graph().single_reference(location)

    def reference_count(self, location: "HeapLocation") -> int:
        """Return the reference count for *location*."""
        return self._require_graph().reference_count(location)

    def strong_update_possible(self, location: "HeapLocation") -> bool:
        """Return ``True`` if strong updates are safe for *location*."""
        return self._require_graph().strong_update_possible(location)

    def must_alias(self, a: "HeapLocation", b: "HeapLocation") -> bool:
        """Return ``True`` if *a* and *b* are must-aliases."""
        return self._require_graph().must_alias(a, b)

    def may_alias(self, a: "HeapLocation", b: "HeapLocation") -> bool:
        """Return ``True`` if *a* and *b* may alias."""
        return self._require_graph().may_alias(a, b)

    def escaped_locations(self) -> "frozenset[HeapLocation]":
        """Return all escaped root locations."""
        return self._require_graph().escaped_locations()

    def singleton_locations(self) -> "frozenset[HeapLocation]":
        """Return all singleton (strong-update-eligible) root locations."""
        return self._require_graph().singleton_locations()

    def to_dict(self) -> dict[str, object]:
        """Serialize analysis metadata and the points-to graph."""
        graph_dict = {}
        if self._graph is not None:
            graph_dict = self._graph.to_dict()
        return {
            "policy": self._policy.to_dict(),
            "heap_initialized": self._heap is not None,
            "points_to_graph": graph_dict,
        }


def _empty_raw_storage(_procedure: object, _local: object) -> tuple[object, ...]:
    """Default no-op raw-storage provider (returns empty tuple)."""
    return ()
