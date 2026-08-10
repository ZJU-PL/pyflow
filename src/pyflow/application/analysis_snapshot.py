"""Published, revision-pinned results of a PyFlow analysis run."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Optional

from pyflow.api.queries import QueryComponents, create_query_components
from pyflow.analysis.typeinfo import TypeInfoService


@dataclass(frozen=True)
class AnalysisConfig:
    """Protocol-neutral selection of analyses to run."""

    ipa: bool = True
    cpa: bool = True
    lifetime: bool = True
    heap: bool = False
    type_info: bool = True

    def passes(self) -> list[str]:
        return [
            name
            for name, enabled in (
                ("ipa", self.ipa),
                ("cpa", self.cpa),
                ("lifetime", self.lifetime),
                ("heap", self.heap),
            )
            if enabled
        ]


@dataclass(frozen=True)
class AnalysisFeatures:
    """Facts actually present in a published snapshot, not tool exposure."""

    call_graph: bool = False
    control_flow: bool = False
    cpa: bool = False
    lifetime: bool = False
    heap: bool = False
    type_info: bool = False

    @classmethod
    def from_program(
        cls, program: object, *, type_info: bool = False
    ) -> "AnalysisFeatures":
        results = getattr(program, "analysis_results", {})
        return cls(
            call_graph="ipa" in results,
            control_flow=bool(getattr(program, "liveCode", ())),
            cpa="cpa" in results,
            lifetime="lifetime" in results,
            heap="heap" in results,
            type_info=type_info,
        )

    def supports(self, capability: str) -> bool:
        aliases = {
            "callgraph": "call_graph",
            "callers": "call_graph",
            "callees": "call_graph",
            "function_summaries": "call_graph",
            "cfg": "control_flow",
            "ssa": "control_flow",
            "cdg": "control_flow",
            "aliases": "heap",
            "points_to": "heap",
        }
        field = aliases.get(capability, capability)
        return bool(getattr(self, field, False))


@dataclass(frozen=True)
class AnalysisSnapshot:
    """A logically immutable collection of inputs and semantic results.

    A request obtains one instance and must use it throughout execution.  New
    analysis work creates and atomically publishes a replacement instance.
    """

    program: object
    compiler: object
    source_index: Any
    features: AnalysisFeatures
    revision: int
    semantic_revision: int
    source_revision: int
    semantic_stale: bool
    queries: QueryComponents
    source_files: Any = None
    type_info_service: Optional[TypeInfoService] = None

    @classmethod
    def create(
        cls,
        *,
        program: object,
        compiler: object,
        source_index: Any,
        revision: int,
        semantic_revision: Optional[int] = None,
        source_revision: int = 0,
        semantic_stale: bool = False,
        source_files: Any = None,
        type_info_service: Optional[TypeInfoService] = None,
    ) -> "AnalysisSnapshot":
        return cls(
            program=program,
            compiler=compiler,
            source_index=source_index,
            features=AnalysisFeatures.from_program(
                program, type_info=type_info_service is not None
            ),
            revision=revision,
            semantic_revision=(
                revision if semantic_revision is None else semantic_revision
            ),
            source_revision=source_revision,
            semantic_stale=semantic_stale,
            queries=create_query_components(
                compiler, program, type_info_service=type_info_service
            ),
            source_files=(
                MappingProxyType(dict(source_files))
                if source_files is not None
                else None
            ),
            type_info_service=type_info_service,
        )
