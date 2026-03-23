"""
Data-flow query helpers for PyFlow.

This module preserves the public `DataFlowQueries` facade while delegating
implementation details to focused internal helpers.
"""

import logging
from typing import Dict, List, Optional, Set, Union

from pyflow.application.errors import TemporaryLimitation

from ._dataflow_ipa import IpaAnalyzer
from ._dataflow_reaching_defs import ReachingDefsAnalyzer
from ._dataflow_store_graph import StoreGraphAnalyzer
from ._dataflow_taint import TaintAnalyzer
from ._models import (
    AliasInfo,
    IpaFunctionSummary,
    PointsToInfo,
    ReachingDef,
    TaintFlowReport,
)
from .context import QueryContext

LOG = logging.getLogger(__name__)


class DataFlowQueries:
    """Encapsulates IPA-driven facts in a task-aware facade."""

    def __init__(self, context: QueryContext, graph_engine=None):
        self.context = context
        self.graph_engine = graph_engine
        self._reaching_defs = ReachingDefsAnalyzer()
        self._store_graph = StoreGraphAnalyzer()
        self._taint = TaintAnalyzer()
        self._ipa = IpaAnalyzer()

    def get_reaching_defs(
        self, function: Union[str, object]
    ) -> Dict[str, List[ReachingDef]]:
        """Return reaching definitions for all variables in a function."""
        try:
            code = self.context.resolve_function(function)
        except ValueError as exc:
            raise ValueError(f"Cannot resolve function: {exc}")

        if self.graph_engine is None:
            return self._reaching_defs.from_defuse(code, self._get_var_name)

        try:
            ssa_cfg = self.graph_engine.get_ssa(code)
        except (ValueError, TypeError, AttributeError):
            LOG.debug("Falling back to def-use reaching defs for %r", function, exc_info=True)
            return self._reaching_defs.from_defuse(code, self._get_var_name)

        reaching_defs = self._reaching_defs.from_ssa(ssa_cfg)
        if reaching_defs:
            return reaching_defs
        return self._reaching_defs.from_defuse(code, self._get_var_name)

    def get_variable_uses(self, function: Union[str, object], variable: str) -> List[str]:
        """Return use locations for a single variable via def-use traversal."""
        try:
            code = self.context.resolve_function(function)
        except ValueError as exc:
            raise ValueError(f"Cannot resolve function: {exc}")
        return self._reaching_defs.get_variable_uses(code, variable, self._get_var_name)

    def get_aliases(self, function: Union[str, object]) -> Dict[str, AliasInfo]:
        """Return alias information for all variables in a function."""
        try:
            code = self.context.resolve_function(function)
        except ValueError as exc:
            raise ValueError(f"Cannot resolve function: {exc}")

        store_graph = self._store_graph.get_store_graph_safe(self.context.program)
        if store_graph is None:
            return self._store_graph.aliases_from_defuse(code, self._get_var_name)
        return self._store_graph.aliases_from_storegraph(
            code,
            self.context.code_name(code),
            store_graph,
        )

    def get_points_to(self, function: Union[str, object]) -> Dict[str, PointsToInfo]:
        """Return points-to information for all variables in a function."""
        try:
            code = self.context.resolve_function(function)
        except ValueError as exc:
            raise ValueError(f"Cannot resolve function: {exc}")

        store_graph = self._store_graph.get_store_graph_safe(self.context.program)
        if store_graph is None:
            return {}
        return self._store_graph.points_to_from_storegraph(
            self.context.code_name(code),
            store_graph,
        )

    def get_interprocedural_taint(
        self,
        function: Union[str, object],
        *,
        source_names: Set[str],
        sink_names: Set[str],
        sanitizer_names: Optional[Set[str]] = None,
    ) -> TaintFlowReport:
        """Run the shipped IFDS taint analysis for one function entry."""
        if self.graph_engine is None:
            raise TemporaryLimitation("Graph engine is required for IFDS taint analysis.")
        return self._taint.run(
            context=self.context,
            graph_engine=self.graph_engine,
            function=function,
            source_names=source_names,
            sink_names=sink_names,
            sanitizer_names=sanitizer_names,
        )

    def get_lifetime(self):
        """Return lifetime analysis results if available."""
        if getattr(self.context.program, "lifetime_analysis", None) is None:
            raise TemporaryLimitation(
                "Lifetime analysis not available; run the lifetime pass first."
            )
        return self.context.program.lifetime_analysis

    def get_store_graph(self):
        """Return the store graph if available."""
        if getattr(self.context.program, "storeGraph", None) is None:
            raise TemporaryLimitation("Store graph not available; run IPA/CPA first.")
        return self.context.program.storeGraph

    def get_ipa_analysis(self):
        """Return IPA analysis results when available."""
        return self.context.require_ipa()

    def get_ipa_function_summaries(
        self, function: Optional[Union[str, object]] = None
    ) -> List[IpaFunctionSummary]:
        """Return IPA summaries for all contexts (or a single function)."""
        return self._ipa.get_function_summaries(
            self.context,
            self.context.require_ipa(),
            function,
        )

    def _get_var_name(self, lcl):
        if hasattr(lcl, "constantValue"):
            return lcl.constantValue()
        if hasattr(lcl, "id"):
            return lcl.id
        if hasattr(lcl, "name"):
            return lcl.name
        return None
