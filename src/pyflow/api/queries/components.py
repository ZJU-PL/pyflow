"""Composable, protocol-neutral semantic query components.

This module deliberately contains no transport or server lifecycle concepts.
Callers receive a component set for one published analysis snapshot and choose
the domain they need (``queries.call_graph``, ``queries.data_flow``, ...).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pyflow.analysis.typeinfo import TypeInfoService

from .call_graph import CallGraphQueries
from .context import QueryContext
from .control_flow import ControlFlowQueries
from .data_flow import DataFlowQueries
from .engine import GraphQueryEngine
from .localization import LocalizationQueries
from .test_generation import TestGenerationQueries
from .type_info import TypeInfoQueries


@dataclass(frozen=True)
class QueryComponents:
    """The semantic query domains available for one analysis result.

    The component set is intentionally a small composition root rather than a
    method-forwarding service.  It is safe to retain for the lifetime of the
    snapshot that created it.
    """

    context: QueryContext
    graph_engine: GraphQueryEngine
    call_graph: CallGraphQueries
    control_flow: ControlFlowQueries
    data_flow: DataFlowQueries
    localization: LocalizationQueries
    test_generation: TestGenerationQueries
    type_info: TypeInfoQueries


def create_query_components(
    compiler: object,
    program: object,
    *,
    type_info_service: Optional[TypeInfoService] = None,
) -> QueryComponents:
    """Create independent semantic query components for *program*.

    Ownership is intentionally held by the caller (normally an
    ``AnalysisSnapshot``), not by ``Program``.  This prevents analysis-result
    mutation from silently changing a long-lived query object's meaning.
    """

    context = QueryContext(compiler, program)
    graph_engine = GraphQueryEngine(context)
    control_flow = ControlFlowQueries(context, graph_engine)
    call_graph = CallGraphQueries(context, graph_engine)
    data_flow = DataFlowQueries(context, graph_engine)
    return QueryComponents(
        context=context,
        graph_engine=graph_engine,
        call_graph=call_graph,
        control_flow=control_flow,
        data_flow=data_flow,
        localization=LocalizationQueries(
            context, graph_engine, call_graph, control_flow, data_flow
        ),
        test_generation=TestGenerationQueries(
            context, graph_engine, call_graph, control_flow, data_flow
        ),
        type_info=TypeInfoQueries(type_info_service),
    )
