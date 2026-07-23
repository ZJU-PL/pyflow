"""IFDS and IDE solvers over the reusable interprocedural supergraph."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import threading
import time
import tracemalloc
import re
from typing import (
    DefaultDict,
    Dict,
    FrozenSet,
    Generic,
    Hashable,
    Literal,
    TYPE_CHECKING,
    TypeVar,
)

from .problem import (
    EdgeFunction,
    FactTransition,
    IDEProblem,
    IFDSProblem,
    IdentityEdgeFunction,
)
from .supergraph import NodeT, ProcT

if TYPE_CHECKING:
    from .supergraph import Supergraph


FactT = TypeVar("FactT", bound=Hashable)
ValueT = TypeVar("ValueT")


class SolverLimitExceeded(RuntimeError):
    """Raised when solver propagation exceeds a configured safety cap."""


class AnalysisStatus(str, Enum):
    """Completion state of a solver run."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    FAILED = "failed"


class CancellationToken:
    """Thread-safe cooperative cancellation token for solver runs."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason: str | None = None

    def cancel(self, reason: str = "cancelled") -> None:
        self._reason = reason
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str | None:
        return self._reason


@dataclass(frozen=True)
class SolverOptions:
    """Operational limits and observability controls for IFDS/IDE solving."""

    max_propagated_path_edges: int | None = None
    max_seconds: float | None = None
    max_queue_size: int | None = None
    max_incoming_records: int | None = None
    max_summary_entries: int | None = None
    max_facts_per_node: int | None = None
    max_contexts_per_procedure: int | None = None
    max_memory_bytes: int | None = None
    max_call_string_depth: int | None = None
    cancellation_token: CancellationToken | None = None
    trace_mode: Literal["none", "findings", "all"] = "none"
    limit_behavior: Literal["partial", "raise"] = "partial"
    budget_check_interval: int = 128

    def __post_init__(self) -> None:
        integer_limits = {
            "max_propagated_path_edges": self.max_propagated_path_edges,
            "max_queue_size": self.max_queue_size,
            "max_incoming_records": self.max_incoming_records,
            "max_summary_entries": self.max_summary_entries,
            "max_facts_per_node": self.max_facts_per_node,
            "max_contexts_per_procedure": self.max_contexts_per_procedure,
            "max_memory_bytes": self.max_memory_bytes,
        }
        for name, value in integer_limits.items():
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 1
            ):
                raise ValueError(f"{name} must be a positive integer or None")
        if self.max_seconds is not None and self.max_seconds <= 0:
            raise ValueError("max_seconds must be positive or None")
        if self.budget_check_interval < 1:
            raise ValueError("budget_check_interval must be >= 1")
        if self.trace_mode not in {"none", "findings", "all"}:
            raise ValueError("trace_mode must be 'none', 'findings', or 'all'")
        if self.limit_behavior not in {"partial", "raise"}:
            raise ValueError("limit_behavior must be 'partial' or 'raise'")
        _validate_max_call_string_depth(self.max_call_string_depth)


@dataclass(frozen=True)
class CallContext:
    """Bounded call-string context for context-sensitive IFDS/IDE solving.

    Each call site visited along the current interprocedural path is recorded.
    When ``max_depth`` is exceeded the oldest entries are truncated, keeping
    the context bounded and the analysis polynomial.

    ``CallContext()`` with no arguments represents the empty (entry-point)
    context.
    """

    call_sites: tuple[Hashable, ...] = ()
    max_depth: int = 3

    def __post_init__(self) -> None:
        if not isinstance(self.max_depth, int) or isinstance(self.max_depth, bool):
            raise TypeError("max_depth must be an integer")
        if self.max_depth < 1:
            raise ValueError("max_depth must be >= 1")

    def push(self, call_site: Hashable) -> "CallContext":
        sites = self.call_sites + (call_site,)
        if len(sites) > self.max_depth:
            sites = sites[-self.max_depth :]
        return CallContext(call_sites=sites, max_depth=self.max_depth)

    def pop(self) -> "CallContext":
        if not self.call_sites:
            return self
        return CallContext(call_sites=self.call_sites[:-1], max_depth=self.max_depth)


@dataclass(frozen=True)
class PathEdge(Generic[NodeT, FactT]):
    """A source-relative exploded-graph edge.

    The optional *context* field distinguishes the same (source, node, fact)
    tuple when it is reached through different call strings.  When ``None``
    the solver operates context-insensitively (the default).
    """

    source_node: NodeT
    source_fact: FactT
    node: NodeT
    fact: FactT
    context: Hashable | None = None


@dataclass(frozen=True)
class PropagationTrace(Generic[NodeT, FactT]):
    """One propagation step recorded for debugging/explanation."""

    output_edge: PathEdge[NodeT, FactT]
    kind: str
    predecessor: PathEdge[NodeT, FactT] | None = None
    note: str | None = None


@dataclass(frozen=True)
class SolverStatistics:
    """Lightweight solver statistics."""

    processed_path_edges: int = 0
    propagated_path_edges: int = 0
    normal_flow_steps: int = 0
    call_flow_steps: int = 0
    return_flow_steps: int = 0
    call_to_return_steps: int = 0
    incoming_records: int = 0
    summary_updates: int = 0
    peak_queue_size: int = 0
    peak_facts_at_node: int = 0
    peak_contexts_per_procedure: int = 0
    peak_memory_bytes: int = 0
    budget_checks: int = 0
    elapsed_seconds: float = 0.0


@dataclass(frozen=True)
class _IncomingRecord(Generic[NodeT, FactT]):
    caller_source_node: NodeT
    caller_source_fact: FactT
    caller_source_context: Hashable | None
    call_node: NodeT
    call_fact: FactT
    return_site: NodeT


@dataclass(frozen=True)
class _IDEIncomingRecord(Generic[NodeT, FactT, ValueT]):
    caller_source_node: NodeT
    caller_source_fact: FactT
    caller_source_context: Hashable | None
    call_node: NodeT
    call_fact: FactT
    return_site: NodeT
    call_jump: EdgeFunction[ValueT]


class _SolverBookkeeping(Generic[NodeT, FactT]):
    """Shared statistics/tracing/limit tracking for IFDS and IDE solvers."""

    def __init__(
        self,
        *,
        options: SolverOptions,
        limit_label: str,
    ) -> None:
        self.options = options
        self.record_traces = options.trace_mode == "all"
        self.record_predecessors = options.trace_mode in {"findings", "all"}
        self.limit_label = limit_label
        self.started_at = time.monotonic()
        self.status = AnalysisStatus.COMPLETE
        self.termination_reason: str | None = None
        self._last_budget_check_at = 0
        self._started_tracemalloc = False
        if options.max_memory_bytes is not None and not tracemalloc.is_tracing():
            tracemalloc.start()
            self._started_tracemalloc = True
        self.traces: DefaultDict[
            PathEdge[NodeT, FactT], list[PropagationTrace[NodeT, FactT]]
        ] = defaultdict(list)
        self.predecessors: Dict[
            PathEdge[NodeT, FactT], PropagationTrace[NodeT, FactT]
        ] = {}
        self.stats = {
            "processed_path_edges": 0,
            "propagated_path_edges": 0,
            "normal_flow_steps": 0,
            "call_flow_steps": 0,
            "return_flow_steps": 0,
            "call_to_return_steps": 0,
            "incoming_records": 0,
            "summary_updates": 0,
            "peak_queue_size": 0,
            "peak_facts_at_node": 0,
            "peak_contexts_per_procedure": 0,
            "peak_memory_bytes": 0,
            "budget_checks": 0,
            "elapsed_seconds": 0.0,
        }

    def increment(self, key: str) -> None:
        self.stats[key] += 1

    def observe(self, key: str, value: int) -> None:
        self.stats[key] = max(self.stats[key], value)

    def stop(self, status: AnalysisStatus, reason: str) -> None:
        if self.options.limit_behavior == "raise" and status is AnalysisStatus.PARTIAL:
            self._cleanup_tracing()
            raise SolverLimitExceeded(reason)
        if self.status is AnalysisStatus.COMPLETE:
            self.status = status
            self.termination_reason = reason

    def check_budget(
        self,
        *,
        queue_size: int = 0,
        incoming_records: int = 0,
        summary_entries: int = 0,
        force: bool = False,
    ) -> None:
        if self.status is not AnalysisStatus.COMPLETE:
            return
        self.observe("peak_queue_size", queue_size)
        self.observe("incoming_records", incoming_records)
        limits = (
            ("max_queue_size", queue_size, self.options.max_queue_size),
            (
                "max_incoming_records",
                incoming_records,
                self.options.max_incoming_records,
            ),
            (
                "max_summary_entries",
                summary_entries,
                self.options.max_summary_entries,
            ),
        )
        for name, value, limit in limits:
            if limit is not None and value > limit:
                self.stop(
                    AnalysisStatus.PARTIAL,
                    f"{self.limit_label} exceeded {name}={limit}",
                )
                return

        token = self.options.cancellation_token
        if token is not None and token.is_cancelled:
            self.stop(AnalysisStatus.CANCELLED, token.reason or "cancelled")
            return

        self._last_budget_check_at += 1
        if not force and (
            self._last_budget_check_at % self.options.budget_check_interval
        ):
            return

        self.increment("budget_checks")
        elapsed = time.monotonic() - self.started_at
        self.stats["elapsed_seconds"] = elapsed
        if self.options.max_seconds is not None and elapsed > self.options.max_seconds:
            self.stop(
                AnalysisStatus.PARTIAL,
                f"{self.limit_label} exceeded max_seconds={self.options.max_seconds}",
            )

        if self.options.max_memory_bytes is not None:
            _current, peak = tracemalloc.get_traced_memory()
            self.observe("peak_memory_bytes", peak)
            if peak > self.options.max_memory_bytes:
                self.stop(
                    AnalysisStatus.PARTIAL,
                    f"{self.limit_label} exceeded max_memory_bytes="
                    f"{self.options.max_memory_bytes}",
                )

    def finish(self, *, check_budget: bool = True) -> SolverStatistics:
        if check_budget:
            self.check_budget(force=True)
        self.stats["elapsed_seconds"] = time.monotonic() - self.started_at
        if self._started_tracemalloc:
            _current, peak = tracemalloc.get_traced_memory()
            self.observe("peak_memory_bytes", peak)
            self._cleanup_tracing()
        return SolverStatistics(**self.stats)

    def _cleanup_tracing(self) -> None:
        if self._started_tracemalloc and tracemalloc.is_tracing():
            tracemalloc.stop()
        self._started_tracemalloc = False

    def record_propagation(
        self,
        path_edge: PathEdge[NodeT, FactT],
        *,
        kind: str,
        predecessor: PathEdge[NodeT, FactT] | None = None,
        note: str | None = None,
    ) -> None:
        if self.status is not AnalysisStatus.COMPLETE:
            return
        trace = PropagationTrace(path_edge, kind, predecessor, note)
        if self.record_traces:
            self.traces[path_edge].append(trace)
        elif self.record_predecessors and path_edge not in self.predecessors:
            self.predecessors[path_edge] = trace
        self.stats["propagated_path_edges"] += 1
        if (
            self.options.max_propagated_path_edges is not None
            and self.stats["propagated_path_edges"]
            > self.options.max_propagated_path_edges
        ):
            self.stop(
                AnalysisStatus.PARTIAL,
                f"{self.limit_label} propagation exceeded "
                f"max_propagated_path_edges="
                f"{self.options.max_propagated_path_edges}",
            )

    def frozen_traces(
        self,
    ) -> Dict[PathEdge[NodeT, FactT], tuple[PropagationTrace[NodeT, FactT], ...]]:
        if self.record_traces:
            return {edge: tuple(records) for edge, records in self.traces.items()}
        return {edge: (record,) for edge, record in self.predecessors.items()}

    def statistics(self, *, check_budget: bool = True) -> SolverStatistics:
        return self.finish(check_budget=check_budget)


def _normalize_ifds_transitions(outputs) -> tuple[FactTransition[FactT], ...]:
    """Accept raw IFDS facts or explicit FactTransition wrappers."""
    normalized: list[FactTransition[FactT]] = []
    for output in outputs:
        if isinstance(output, FactTransition):
            normalized.append(output)
        else:
            normalized.append(FactTransition(output))
    return tuple(
        sorted(normalized, key=lambda transition: _stable_value_key(transition.fact))
    )


def _stable_value_key(value: object):
    """Best-effort semantic ordering key without relying on hash iteration."""
    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return (type(value).__qualname__, value)
    if isinstance(value, tuple):
        return ("tuple", tuple(_stable_value_key(item) for item in value))
    if is_dataclass(value):
        return (
            type(value).__qualname__,
            tuple(
                (field.name, _stable_value_key(getattr(value, field.name)))
                for field in fields(value)
            ),
        )
    for attribute in ("name", "label", "state", "protocol"):
        candidate = getattr(value, attribute, None)
        if isinstance(candidate, (str, int)):
            return (type(value).__qualname__, attribute, candidate)
    rendered = re.sub(r"0x[0-9a-fA-F]+|/\d+", "<id>", repr(value))
    return (type(value).__qualname__, rendered)


def _ordered_value_transitions(outputs):
    return tuple(
        sorted(
            outputs,
            key=lambda transition: (
                _stable_value_key(transition.fact),
                _stable_value_key(transition.edge_function),
            ),
        )
    )


def _validate_max_call_string_depth(depth: int | None) -> None:
    if depth is None:
        return
    if not isinstance(depth, int) or isinstance(depth, bool):
        raise TypeError("max_call_string_depth must be an integer or None")
    if depth < 1:
        raise ValueError("max_call_string_depth must be >= 1")


def _solver_options(
    *,
    options: SolverOptions | None,
    record_traces: bool,
    max_propagated_path_edges: int | None,
    max_call_string_depth: int | None,
) -> SolverOptions:
    if options is not None:
        if (
            record_traces
            or max_propagated_path_edges is not None
            or max_call_string_depth is not None
        ):
            raise ValueError(
                "Pass either SolverOptions or legacy solver keyword arguments, not both"
            )
        return options
    return SolverOptions(
        max_propagated_path_edges=max_propagated_path_edges,
        max_call_string_depth=max_call_string_depth,
        trace_mode="all" if record_traces else "none",
        # Preserve the exception behavior of the original public constructor.
        limit_behavior="raise",
    )


class IFDSResult(Generic[NodeT, FactT]):
    """Reachability result for an IFDS problem."""

    def __init__(
        self,
        reached: Dict[NodeT, set[FactT]],
        path_edges: FrozenSet[PathEdge[NodeT, FactT]],
        statistics: SolverStatistics,
        traces: Dict[
            PathEdge[NodeT, FactT], tuple[PropagationTrace[NodeT, FactT], ...]
        ],
        incoming: Dict[tuple[NodeT, FactT], tuple[_IncomingRecord[NodeT, FactT], ...]],
        end_summary: Dict[tuple[NodeT, FactT, NodeT], FrozenSet[FactT]],
        *,
        status: AnalysisStatus = AnalysisStatus.COMPLETE,
        termination_reason: str | None = None,
    ) -> None:
        self._reached = reached
        self._path_edges = path_edges
        self.statistics = statistics
        self._traces = traces
        self._incoming = incoming
        self._end_summary = end_summary
        self.status = status
        self.termination_reason = termination_reason
        unique_facts = {fact for facts in reached.values() for fact in facts}
        self._fact_ids = {
            fact: index
            for index, fact in enumerate(sorted(unique_facts, key=_stable_value_key))
        }

    @property
    def is_complete(self) -> bool:
        return self.status is AnalysisStatus.COMPLETE

    def facts_at(self, node: NodeT) -> FrozenSet[FactT]:
        return frozenset(self._reached.get(node, ()))

    def fact_id(self, fact: FactT) -> int:
        return self._fact_ids[fact]

    def facts_with_ids_at(self, node: NodeT) -> tuple[tuple[int, FactT], ...]:
        return tuple(
            sorted(
                ((self.fact_id(fact), fact) for fact in self._reached.get(node, ())),
                key=lambda pair: pair[0],
            )
        )

    def is_reached(self, node: NodeT, fact: FactT) -> bool:
        return fact in self._reached.get(node, ())

    def path_edges(self) -> FrozenSet[PathEdge[NodeT, FactT]]:
        return self._path_edges

    def traces_for(self, path_edge: PathEdge[NodeT, FactT]):
        return self._traces.get(path_edge, ())

    def explain_fact(self, node: NodeT, fact: FactT):
        return {
            edge: traces
            for edge in self._path_edges
            for traces in (self._traces.get(edge, ()),)
            if edge.node == node and edge.fact == fact
            if traces
        }

    def explain_path(
        self, node: NodeT, fact: FactT, *, max_steps: int = 256
    ) -> tuple[PropagationTrace[NodeT, FactT], ...]:
        """Return one deterministic predecessor chain for a reached fact."""
        candidates = sorted(
            (
                edge
                for edge in self._path_edges
                if edge.node == node and edge.fact == fact and edge in self._traces
            ),
            key=repr,
        )
        if not candidates:
            return ()
        chain: list[PropagationTrace[NodeT, FactT]] = []
        current = candidates[0]
        visited: set[PathEdge[NodeT, FactT]] = set()
        while current not in visited and len(chain) < max_steps:
            visited.add(current)
            records = self._traces.get(current, ())
            if not records:
                break
            record = records[0]
            chain.append(record)
            if record.predecessor is None:
                break
            current = record.predecessor
        chain.reverse()
        return tuple(chain)

    def incoming_records(self, start_node: NodeT, start_fact: FactT):
        return self._incoming.get((start_node, start_fact), ())

    def end_summaries(self, start_node: NodeT, start_fact: FactT, exit_node: NodeT):
        return self._end_summary.get((start_node, start_fact, exit_node), frozenset())

    # ── access-path-aware queries ──────────────────────────────────────

    def is_reached_prefix(self, node: NodeT, fact: FactT) -> bool:
        """Check if *fact* or a prefix-matched stored fact reaches *node*."""
        from ..queries import is_reached_prefix

        return is_reached_prefix(self, node, fact)


class IDEResult(Generic[NodeT, FactT, ValueT]):
    """Value result for an IDE problem."""

    def __init__(
        self,
        values: Dict[tuple[NodeT, FactT], ValueT],
        values_by_context: Dict[tuple[NodeT, FactT], Dict[Hashable | None, ValueT]],
        path_edge_values: Dict[PathEdge[NodeT, FactT], ValueT],
        reached: Dict[NodeT, set[FactT]],
        jump_functions: Dict[PathEdge[NodeT, FactT], EdgeFunction[ValueT]],
        statistics: SolverStatistics,
        traces: Dict[
            PathEdge[NodeT, FactT], tuple[PropagationTrace[NodeT, FactT], ...]
        ],
        incoming: Dict[tuple, tuple[_IDEIncomingRecord[NodeT, FactT, ValueT], ...]],
        end_summary: Dict[tuple, EdgeFunction[ValueT]],
        *,
        status: AnalysisStatus = AnalysisStatus.COMPLETE,
        termination_reason: str | None = None,
    ) -> None:
        self._values = values
        self._values_by_context = values_by_context
        self._path_edge_values = path_edge_values
        self._reached = reached
        self._jump_functions = jump_functions
        self.statistics = statistics
        self._traces = traces
        self._incoming = incoming
        self._end_summary = end_summary
        self.status = status
        self.termination_reason = termination_reason
        unique_facts = {fact for facts in reached.values() for fact in facts}
        self._fact_ids = {
            fact: index
            for index, fact in enumerate(sorted(unique_facts, key=_stable_value_key))
        }

    @property
    def is_complete(self) -> bool:
        return self.status is AnalysisStatus.COMPLETE

    def facts_at(self, node: NodeT) -> FrozenSet[FactT]:
        return frozenset(self._reached.get(node, ()))

    def value_at(self, node: NodeT, fact: FactT) -> ValueT:
        return self._values[(node, fact)]

    def value_at_context(
        self, node: NodeT, fact: FactT, context: Hashable | None
    ) -> ValueT:
        return self._values_by_context[(node, fact)][context]

    def fact_id(self, fact: FactT) -> int:
        return self._fact_ids[fact]

    def values_at_contexts(
        self, node: NodeT, fact: FactT
    ) -> Dict[Hashable | None, ValueT]:
        return dict(self._values_by_context.get((node, fact), {}))

    def value_for_path_edge(self, path_edge: PathEdge[NodeT, FactT]) -> ValueT:
        return self._path_edge_values[path_edge]

    def path_edge_values(self) -> Dict[PathEdge[NodeT, FactT], ValueT]:
        return dict(self._path_edge_values)

    def jump_functions(self) -> Dict[PathEdge[NodeT, FactT], EdgeFunction[ValueT]]:
        return dict(self._jump_functions)

    def traces_for(self, path_edge: PathEdge[NodeT, FactT]):
        return self._traces.get(path_edge, ())

    def explain_fact(self, node: NodeT, fact: FactT):
        return {
            edge: traces
            for edge in self._jump_functions
            for traces in (self._traces.get(edge, ()),)
            if edge.node == node and edge.fact == fact
            if traces
        }

    def explain_path(
        self, node: NodeT, fact: FactT, *, max_steps: int = 256
    ) -> tuple[PropagationTrace[NodeT, FactT], ...]:
        candidates = sorted(
            (
                edge
                for edge in self._jump_functions
                if edge.node == node and edge.fact == fact and edge in self._traces
            ),
            key=repr,
        )
        if not candidates:
            return ()
        chain: list[PropagationTrace[NodeT, FactT]] = []
        current = candidates[0]
        visited: set[PathEdge[NodeT, FactT]] = set()
        while current not in visited and len(chain) < max_steps:
            visited.add(current)
            records = self._traces.get(current, ())
            if not records:
                break
            record = records[0]
            chain.append(record)
            if record.predecessor is None:
                break
            current = record.predecessor
        chain.reverse()
        return tuple(chain)

    def incoming_records(self, start_node: NodeT, start_fact: FactT):
        return self._incoming.get((start_node, start_fact), ())

    def end_summaries(self):
        return dict(self._end_summary)


class IFDSSolver(Generic[ProcT, NodeT, FactT]):
    """Classic tabulation-style IFDS solver.

    Set *max_call_string_depth* to an integer (e.g. 3) to enable bounded
    call-string context sensitivity.  The default ``None`` runs the solver
    context-insensitively, matching the original IFDS algorithm.
    """

    def __init__(
        self,
        *,
        options: SolverOptions | None = None,
        record_traces: bool = False,
        max_propagated_path_edges: int | None = None,
        max_call_string_depth: int | None = None,
    ) -> None:
        self.options = _solver_options(
            options=options,
            record_traces=record_traces,
            max_propagated_path_edges=max_propagated_path_edges,
            max_call_string_depth=max_call_string_depth,
        )
        self.record_traces = self.options.trace_mode == "all"
        self.max_propagated_path_edges = self.options.max_propagated_path_edges
        self.max_call_string_depth = self.options.max_call_string_depth

    def solve(
        self, problem: IFDSProblem[ProcT, NodeT, FactT]
    ) -> IFDSResult[NodeT, FactT]:
        supergraph = problem.supergraph
        use_context = self.max_call_string_depth is not None
        queue: deque[PathEdge[NodeT, FactT]] = deque()
        seen: set[PathEdge[NodeT, FactT]] = set()
        reached: DefaultDict[NodeT, set[FactT]] = defaultdict(set)
        incoming: DefaultDict[tuple, set[_IncomingRecord[NodeT, FactT]]] = defaultdict(
            set
        )
        end_summary: DefaultDict[tuple, set[FactT]] = defaultdict(set)
        contexts_by_procedure: DefaultDict[ProcT, set[Hashable | None]] = defaultdict(
            set
        )
        incoming_total = 0
        summary_entries = 0
        bookkeeping = _SolverBookkeeping[NodeT, FactT](
            options=self.options,
            limit_label="IFDS",
        )

        def propagate(
            path_edge: PathEdge[NodeT, FactT],
            *,
            kind: str,
            predecessor: PathEdge[NodeT, FactT] | None = None,
            note: str | None = None,
        ) -> None:
            if bookkeeping.status is not AnalysisStatus.COMPLETE:
                return
            if path_edge in seen:
                return
            seen.add(path_edge)
            reached[path_edge.node].add(path_edge.fact)
            facts_at_node = len(reached[path_edge.node])
            bookkeeping.observe("peak_facts_at_node", facts_at_node)
            max_facts = self.options.max_facts_per_node
            if max_facts is not None and facts_at_node > max_facts:
                bookkeeping.stop(
                    AnalysisStatus.PARTIAL,
                    f"IFDS exceeded max_facts_per_node={max_facts}",
                )
                return

            procedure = supergraph.procedure_of(path_edge.node)
            contexts = contexts_by_procedure[procedure]
            contexts.add(path_edge.context)
            bookkeeping.observe("peak_contexts_per_procedure", len(contexts))
            max_contexts = self.options.max_contexts_per_procedure
            if max_contexts is not None and len(contexts) > max_contexts:
                bookkeeping.stop(
                    AnalysisStatus.PARTIAL,
                    f"IFDS exceeded max_contexts_per_procedure={max_contexts}",
                )
                return
            bookkeeping.record_propagation(
                path_edge,
                kind=kind,
                predecessor=predecessor,
                note=note,
            )
            if bookkeeping.status is not AnalysisStatus.COMPLETE:
                return
            queue.append(path_edge)
            bookkeeping.check_budget(
                queue_size=len(queue),
                incoming_records=incoming_total,
                summary_entries=summary_entries,
            )

        def _seed_context() -> Hashable | None:
            if not use_context:
                return None
            depth: int = self.max_call_string_depth  # type: ignore[assignment]
            return CallContext(max_depth=depth)

        def _push_context(ctx: Hashable | None, call_site: Hashable) -> Hashable | None:
            if ctx is None or not use_context:
                return None
            if isinstance(ctx, CallContext):
                return ctx.push(call_site)
            return ctx

        def _contextual_key(*parts: Hashable, ctx: Hashable | None = None) -> tuple:
            if ctx is None or not use_context:
                return parts
            return (*parts, ctx)

        for node, facts in sorted(
            problem.initial_seeds().items(),
            key=lambda item: supergraph.node_id(item[0]),
        ):
            ctx = _seed_context()
            for fact in sorted(facts, key=_stable_value_key):
                propagate(
                    PathEdge(node, fact, node, fact, context=ctx),
                    kind="seed",
                )

        while queue and bookkeeping.status is AnalysisStatus.COMPLETE:
            bookkeeping.check_budget(
                queue_size=len(queue),
                incoming_records=incoming_total,
                summary_entries=summary_entries,
            )
            if bookkeeping.status is not AnalysisStatus.COMPLETE:
                break
            edge = queue.popleft()
            bookkeeping.increment("processed_path_edges")
            source_node = edge.source_node
            source_fact = edge.source_fact
            node = edge.node
            fact = edge.fact
            edge_ctx = edge.context

            if supergraph.is_call_node(node):
                for return_site in supergraph.ordered_call_to_return_successors(node):
                    bookkeeping.increment("call_to_return_steps")
                    for transition in _normalize_ifds_transitions(
                        problem.call_to_return_flow(node, return_site, fact)
                    ):
                        propagate(
                            PathEdge(
                                source_node,
                                source_fact,
                                return_site,
                                transition.fact,
                                context=edge_ctx,
                            ),
                            kind="call_to_return",
                            predecessor=edge,
                            note=f"{node!r} -> {return_site!r}",
                        )

                for callee in supergraph.ordered_callees_of_call_at(node):
                    start = supergraph.entry_of(callee)
                    bookkeeping.increment("call_flow_steps")
                    for transition in _normalize_ifds_transitions(
                        problem.call_flow(node, callee, fact)
                    ):
                        start_fact = transition.fact
                        callee_ctx = _push_context(edge_ctx, node)
                        incoming_key = _contextual_key(
                            start, start_fact, ctx=callee_ctx
                        )
                        for return_site in supergraph.ordered_return_sites_of_call_at(
                            node
                        ):
                            incoming_record = _IncomingRecord(
                                source_node,
                                source_fact,
                                edge_ctx,
                                node,
                                fact,
                                return_site,
                            )
                            if incoming_record not in incoming[incoming_key]:
                                incoming[incoming_key].add(incoming_record)
                                incoming_total += 1
                                bookkeeping.increment("incoming_records")
                                bookkeeping.check_budget(
                                    queue_size=len(queue),
                                    incoming_records=incoming_total,
                                    summary_entries=summary_entries,
                                )
                                for exit_node in supergraph.ordered_exits_of(callee):
                                    summary_key = _contextual_key(
                                        start,
                                        start_fact,
                                        exit_node,
                                        ctx=callee_ctx,
                                    )
                                    for exit_fact in sorted(
                                        end_summary.get(summary_key, ()),
                                        key=_stable_value_key,
                                    ):
                                        bookkeeping.increment("return_flow_steps")
                                        for transition in _normalize_ifds_transitions(
                                            problem.return_flow(
                                                node,
                                                callee,
                                                exit_node,
                                                return_site,
                                                fact,
                                                exit_fact,
                                            )
                                        ):
                                            propagate(
                                                PathEdge(
                                                    source_node,
                                                    source_fact,
                                                    return_site,
                                                    transition.fact,
                                                    context=edge_ctx,
                                                ),
                                                kind="return_flow(summary_replay)",
                                                note=f"{callee!r} via {return_site!r}",
                                            )

                        propagate(
                            PathEdge(
                                start,
                                start_fact,
                                start,
                                start_fact,
                                context=callee_ctx,
                            ),
                            kind="call_flow",
                            predecessor=edge,
                            note=f"{node!r} -> {callee!r}",
                        )

            if supergraph.is_exit_node(node):
                summary_key = _contextual_key(
                    source_node, source_fact, node, ctx=edge_ctx
                )
                if fact not in end_summary[summary_key]:
                    end_summary[summary_key].add(fact)
                    summary_entries += 1
                    bookkeeping.increment("summary_updates")
                    bookkeeping.check_budget(
                        queue_size=len(queue),
                        incoming_records=incoming_total,
                        summary_entries=summary_entries,
                    )
                    callee = supergraph.procedure_of(node)
                    caller_incoming_key = _contextual_key(
                        source_node, source_fact, ctx=edge_ctx
                    )
                    for incoming_record in sorted(
                        incoming.get(caller_incoming_key, ()),
                        key=_stable_value_key,
                    ):
                        bookkeeping.increment("return_flow_steps")
                        for transition in _normalize_ifds_transitions(
                            problem.return_flow(
                                incoming_record.call_node,
                                callee,
                                node,
                                incoming_record.return_site,
                                incoming_record.call_fact,
                                fact,
                            )
                        ):
                            propagate(
                                PathEdge(
                                    incoming_record.caller_source_node,
                                    incoming_record.caller_source_fact,
                                    incoming_record.return_site,
                                    transition.fact,
                                    context=incoming_record.caller_source_context,
                                ),
                                kind="return_flow",
                                predecessor=edge,
                                note=f"{callee!r} -> {incoming_record.return_site!r}",
                            )

            for successor in supergraph.ordered_normal_successors(node):
                bookkeeping.increment("normal_flow_steps")
                for transition in _normalize_ifds_transitions(
                    problem.normal_flow(node, successor, fact)
                ):
                    propagate(
                        PathEdge(
                            source_node,
                            source_fact,
                            successor,
                            transition.fact,
                            context=edge_ctx,
                        ),
                        kind="normal_flow",
                        predecessor=edge,
                        note=f"{node!r} -> {successor!r}",
                    )

        return IFDSResult(
            dict(reached),
            frozenset(seen),
            bookkeeping.statistics(
                check_budget=bookkeeping.status is AnalysisStatus.COMPLETE
            ),
            bookkeeping.frozen_traces(),
            {key: tuple(value) for key, value in incoming.items()},
            {key: frozenset(value) for key, value in end_summary.items()},
            status=bookkeeping.status,
            termination_reason=bookkeeping.termination_reason,
        )


class IDESolver(Generic[ProcT, NodeT, FactT, ValueT]):
    """Jump-function IDE solver keyed by source-relative path edges.

    Set *max_call_string_depth* to an integer (e.g. 3) to enable bounded
    call-string context sensitivity.
    """

    def __init__(
        self,
        *,
        options: SolverOptions | None = None,
        record_traces: bool = False,
        max_propagated_path_edges: int | None = None,
        max_call_string_depth: int | None = None,
    ) -> None:
        self.options = _solver_options(
            options=options,
            record_traces=record_traces,
            max_propagated_path_edges=max_propagated_path_edges,
            max_call_string_depth=max_call_string_depth,
        )
        self.record_traces = self.options.trace_mode == "all"
        self.max_propagated_path_edges = self.options.max_propagated_path_edges
        self.max_call_string_depth = self.options.max_call_string_depth

    def solve(
        self, problem: IDEProblem[ProcT, NodeT, FactT, ValueT]
    ) -> IDEResult[NodeT, FactT, ValueT]:
        supergraph = problem.supergraph
        use_context = self.max_call_string_depth is not None
        queue: deque[PathEdge[NodeT, FactT]] = deque()
        jump_functions: Dict[PathEdge[NodeT, FactT], EdgeFunction[ValueT]] = {}
        reached: DefaultDict[NodeT, set[FactT]] = defaultdict(set)
        incoming: DefaultDict[tuple, set[_IDEIncomingRecord[NodeT, FactT, ValueT]]] = (
            defaultdict(set)
        )
        end_summary: Dict[tuple, EdgeFunction[ValueT]] = {}
        contexts_by_procedure: DefaultDict[ProcT, set[Hashable | None]] = defaultdict(
            set
        )
        incoming_total = 0
        bookkeeping = _SolverBookkeeping[NodeT, FactT](
            options=self.options,
            limit_label="IDE",
        )
        identity = IdentityEdgeFunction[ValueT]()
        seed_values = dict(problem.initial_seed_values())

        def join_edge_functions(
            left: EdgeFunction[ValueT], right: EdgeFunction[ValueT]
        ) -> EdgeFunction[ValueT]:
            return left.join(right, problem.join_values)

        def _seed_context() -> Hashable | None:
            if not use_context:
                return None
            depth: int = self.max_call_string_depth  # type: ignore[assignment]
            return CallContext(max_depth=depth)

        def _push_context(ctx: Hashable | None, call_site: Hashable) -> Hashable | None:
            if ctx is None or not use_context:
                return None
            if isinstance(ctx, CallContext):
                return ctx.push(call_site)
            return ctx

        def _contextual_key(*parts: Hashable, ctx: Hashable | None = None) -> tuple:
            if ctx is None or not use_context:
                return parts
            return (*parts, ctx)

        def _source_key(node: NodeT, fact: FactT, ctx: Hashable | None) -> tuple:
            return _contextual_key(node, fact, ctx=ctx)

        def propagate(
            path_edge: PathEdge[NodeT, FactT],
            jump: EdgeFunction[ValueT],
            *,
            kind: str,
            predecessor: PathEdge[NodeT, FactT] | None = None,
            note: str | None = None,
        ) -> None:
            if bookkeeping.status is not AnalysisStatus.COMPLETE:
                return
            current = jump_functions.get(path_edge)
            if current is None:
                jump_functions[path_edge] = jump
                reached[path_edge.node].add(path_edge.fact)
                facts_at_node = len(reached[path_edge.node])
                bookkeeping.observe("peak_facts_at_node", facts_at_node)
                max_facts = self.options.max_facts_per_node
                if max_facts is not None and facts_at_node > max_facts:
                    bookkeeping.stop(
                        AnalysisStatus.PARTIAL,
                        f"IDE exceeded max_facts_per_node={max_facts}",
                    )
                    return
                procedure = supergraph.procedure_of(path_edge.node)
                contexts = contexts_by_procedure[procedure]
                contexts.add(path_edge.context)
                bookkeeping.observe("peak_contexts_per_procedure", len(contexts))
                max_contexts = self.options.max_contexts_per_procedure
                if max_contexts is not None and len(contexts) > max_contexts:
                    bookkeeping.stop(
                        AnalysisStatus.PARTIAL,
                        f"IDE exceeded max_contexts_per_procedure={max_contexts}",
                    )
                    return
                bookkeeping.record_propagation(
                    path_edge,
                    kind=kind,
                    predecessor=predecessor,
                    note=note,
                )
                if bookkeeping.status is not AnalysisStatus.COMPLETE:
                    return
                queue.append(path_edge)
                bookkeeping.check_budget(
                    queue_size=len(queue),
                    incoming_records=incoming_total,
                    summary_entries=len(end_summary),
                )
                return
            joined = join_edge_functions(current, jump)
            if joined != current:
                jump_functions[path_edge] = joined
                reached[path_edge.node].add(path_edge.fact)
                bookkeeping.record_propagation(
                    path_edge,
                    kind=kind,
                    predecessor=predecessor,
                    note=note,
                )
                if bookkeeping.status is not AnalysisStatus.COMPLETE:
                    return
                queue.append(path_edge)
                bookkeeping.check_budget(
                    queue_size=len(queue),
                    incoming_records=incoming_total,
                    summary_entries=len(end_summary),
                )

        seed_values_by_key: Dict[tuple, ValueT] = {}
        for seed, value in sorted(
            seed_values.items(),
            key=lambda item: (
                supergraph.node_id(item[0][0]),
                _stable_value_key(item[0][1]),
            ),
        ):
            node, fact = seed
            ctx = _seed_context()
            seed_key = _source_key(node, fact, ctx)
            existing_seed_value = seed_values_by_key.get(seed_key)
            seed_values_by_key[seed_key] = (
                value
                if existing_seed_value is None
                else problem.join_values(existing_seed_value, value)
            )
            propagate(
                PathEdge(node, fact, node, fact, context=ctx),
                identity,
                kind="seed",
            )

        while queue and bookkeeping.status is AnalysisStatus.COMPLETE:
            bookkeeping.check_budget(
                queue_size=len(queue),
                incoming_records=incoming_total,
                summary_entries=len(end_summary),
            )
            if bookkeeping.status is not AnalysisStatus.COMPLETE:
                break
            edge = queue.popleft()
            bookkeeping.increment("processed_path_edges")
            source_node = edge.source_node
            source_fact = edge.source_fact
            node = edge.node
            fact = edge.fact
            edge_ctx = edge.context
            current_jump = jump_functions[edge]

            if supergraph.is_call_node(node):
                for return_site in supergraph.ordered_call_to_return_successors(node):
                    bookkeeping.increment("call_to_return_steps")
                    for transition in _ordered_value_transitions(
                        problem.call_to_return_flow(node, return_site, fact)
                    ):
                        propagate(
                            PathEdge(
                                source_node,
                                source_fact,
                                return_site,
                                transition.fact,
                                context=edge_ctx,
                            ),
                            transition.edge_function.compose(current_jump),
                            kind="call_to_return",
                            predecessor=edge,
                            note=f"{node!r} -> {return_site!r}",
                        )

                for callee in supergraph.ordered_callees_of_call_at(node):
                    start = supergraph.entry_of(callee)
                    bookkeeping.increment("call_flow_steps")
                    for transition in _ordered_value_transitions(
                        problem.call_flow(node, callee, fact)
                    ):
                        call_jump = transition.edge_function.compose(current_jump)
                        callee_ctx = _push_context(edge_ctx, node)
                        incoming_key = _contextual_key(
                            start, transition.fact, ctx=callee_ctx
                        )
                        for return_site in supergraph.ordered_return_sites_of_call_at(
                            node
                        ):
                            incoming_record = _IDEIncomingRecord(
                                source_node,
                                source_fact,
                                edge_ctx,
                                node,
                                fact,
                                return_site,
                                call_jump,
                            )
                            if incoming_record not in incoming[incoming_key]:
                                incoming[incoming_key].add(incoming_record)
                                incoming_total += 1
                                bookkeeping.increment("incoming_records")
                                bookkeeping.check_budget(
                                    queue_size=len(queue),
                                    incoming_records=incoming_total,
                                    summary_entries=len(end_summary),
                                )
                                for exit_node in supergraph.ordered_exits_of(callee):
                                    for exit_fact in sorted(
                                        reached.get(exit_node, ()),
                                        key=_stable_value_key,
                                    ):
                                        summary_key = _contextual_key(
                                            start,
                                            transition.fact,
                                            exit_node,
                                            exit_fact,
                                            ctx=callee_ctx,
                                        )
                                        summary = end_summary.get(summary_key)
                                        if summary is None:
                                            continue
                                        for (
                                            return_transition
                                        ) in _ordered_value_transitions(
                                            problem.return_flow(
                                                node,
                                                callee,
                                                exit_node,
                                                return_site,
                                                fact,
                                                exit_fact,
                                            )
                                        ):
                                            combined = (
                                                return_transition.edge_function.compose(
                                                    summary
                                                ).compose(call_jump)
                                            )
                                            propagate(
                                                PathEdge(
                                                    source_node,
                                                    source_fact,
                                                    return_site,
                                                    return_transition.fact,
                                                    context=edge_ctx,
                                                ),
                                                combined,
                                                kind="return_flow(summary_replay)",
                                                note=f"{callee!r} via {return_site!r}",
                                            )

                        propagate(
                            PathEdge(
                                start,
                                transition.fact,
                                start,
                                transition.fact,
                                context=callee_ctx,
                            ),
                            identity,
                            kind="call_flow",
                            predecessor=edge,
                            note=f"{node!r} -> {callee!r}",
                        )

            if supergraph.is_exit_node(node):
                summary_key = _contextual_key(
                    source_node,
                    source_fact,
                    node,
                    fact,
                    ctx=edge_ctx,
                )
                current_summary = end_summary.get(summary_key)
                if current_summary is None:
                    end_summary[summary_key] = current_jump
                    summary_changed = True
                else:
                    joined_summary = join_edge_functions(current_summary, current_jump)
                    summary_changed = joined_summary != current_summary
                    if summary_changed:
                        end_summary[summary_key] = joined_summary
                if summary_changed:
                    bookkeeping.increment("summary_updates")
                    bookkeeping.check_budget(
                        queue_size=len(queue),
                        incoming_records=incoming_total,
                        summary_entries=len(end_summary),
                    )
                    callee = supergraph.procedure_of(node)
                    summary = end_summary[summary_key]
                    caller_incoming_key = _contextual_key(
                        source_node,
                        source_fact,
                        ctx=edge_ctx,
                    )
                    for incoming_record in sorted(
                        incoming.get(caller_incoming_key, ()),
                        key=_stable_value_key,
                    ):
                        bookkeeping.increment("return_flow_steps")
                        for return_transition in _ordered_value_transitions(
                            problem.return_flow(
                                incoming_record.call_node,
                                callee,
                                node,
                                incoming_record.return_site,
                                incoming_record.call_fact,
                                fact,
                            )
                        ):
                            combined = return_transition.edge_function.compose(
                                summary
                            ).compose(incoming_record.call_jump)
                            propagate(
                                PathEdge(
                                    incoming_record.caller_source_node,
                                    incoming_record.caller_source_fact,
                                    incoming_record.return_site,
                                    return_transition.fact,
                                    context=incoming_record.caller_source_context,
                                ),
                                combined,
                                kind="return_flow",
                                predecessor=edge,
                                note=f"{callee!r} -> {incoming_record.return_site!r}",
                            )

            for successor in supergraph.ordered_normal_successors(node):
                bookkeeping.increment("normal_flow_steps")
                for transition in _ordered_value_transitions(
                    problem.normal_flow(node, successor, fact)
                ):
                    propagate(
                        PathEdge(
                            source_node,
                            source_fact,
                            successor,
                            transition.fact,
                            context=edge_ctx,
                        ),
                        transition.edge_function.compose(current_jump),
                        kind="normal_flow",
                        predecessor=edge,
                        note=f"{node!r} -> {successor!r}",
                    )

        values: Dict[tuple[NodeT, FactT], ValueT] = {}
        values_by_context: DefaultDict[
            tuple[NodeT, FactT], Dict[Hashable | None, ValueT]
        ] = defaultdict(dict)
        path_edge_values: Dict[PathEdge[NodeT, FactT], ValueT] = {}
        source_values: Dict[tuple, ValueT] = {}

        source_keys: set[tuple] = set(seed_values_by_key)
        source_keys.update(
            _source_key(edge.source_node, edge.source_fact, edge.context)
            for edge in jump_functions
        )
        source_keys.update(incoming)
        for incoming_records in incoming.values():
            source_keys.update(
                _source_key(
                    record.caller_source_node,
                    record.caller_source_fact,
                    record.caller_source_context,
                )
                for record in incoming_records
            )

        changed = True
        while changed and bookkeeping.status is AnalysisStatus.COMPLETE:
            bookkeeping.check_budget(
                queue_size=0,
                incoming_records=incoming_total,
                summary_entries=len(end_summary),
            )
            changed = False
            for source_key in sorted(source_keys, key=repr):
                resolved = seed_values_by_key.get(source_key)
                for incoming_record in sorted(
                    incoming.get(source_key, ()), key=_stable_value_key
                ):
                    caller_key = _source_key(
                        incoming_record.caller_source_node,
                        incoming_record.caller_source_fact,
                        incoming_record.caller_source_context,
                    )
                    caller_value = source_values.get(caller_key)
                    if caller_value is None:
                        continue
                    incoming_value = incoming_record.call_jump(caller_value)
                    if resolved is None:
                        resolved = incoming_value
                    else:
                        resolved = problem.join_values(resolved, incoming_value)

                current = source_values.get(source_key)
                if resolved is None:
                    continue
                if current is None or resolved != current:
                    source_values[source_key] = resolved
                    changed = True

        for path_edge, jump in jump_functions.items():
            source_key = _source_key(
                path_edge.source_node,
                path_edge.source_fact,
                path_edge.context,
            )
            seed_value = source_values.get(source_key)
            if seed_value is None:
                continue
            value = jump(seed_value)
            path_edge_values[path_edge] = value
            key = (path_edge.node, path_edge.fact)
            if key in values:
                values[key] = problem.join_values(values[key], value)
            else:
                values[key] = value
            current_context_value = values_by_context[key].get(path_edge.context)
            if current_context_value is None:
                values_by_context[key][path_edge.context] = value
            else:
                values_by_context[key][path_edge.context] = problem.join_values(
                    current_context_value,
                    value,
                )

        for node, facts in reached.items():
            for fact in facts:
                values.setdefault((node, fact), problem.bottom_value)
                values_by_context.setdefault((node, fact), {})

        return IDEResult(
            values,
            {key: dict(value) for key, value in values_by_context.items()},
            path_edge_values,
            dict(reached),
            jump_functions,
            bookkeeping.statistics(
                check_budget=bookkeeping.status is AnalysisStatus.COMPLETE
            ),
            bookkeeping.frozen_traces(),
            {key: tuple(value) for key, value in incoming.items()},
            dict(end_summary),
            status=bookkeeping.status,
            termination_reason=bookkeeping.termination_reason,
        )
