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
            raise TemporaryLimitation("Graph engine is required for SSA queries.")
        ssa_cfg = self.graph_engine.get_ssa(code)
        return self._reaching_defs.from_ssa(ssa_cfg, code.ir_catalog, code)

    def get_variable_uses(self, function: Union[str, object], variable: str) -> List[str]:
        """Return use locations for a single variable via def-use traversal."""
        try:
            code = self.context.resolve_function(function)
        except ValueError as exc:
            raise ValueError(f"Cannot resolve function: {exc}")
        return self._reaching_defs.get_variable_uses(code, variable)

    def get_aliases(self, function: Union[str, object]) -> Dict[str, AliasInfo]:
        """Return alias information for all variables in a function."""
        try:
            code = self.context.resolve_function(function)
        except ValueError as exc:
            raise ValueError(f"Cannot resolve function: {exc}")

        from pyflow.ir.core import AnalysisFacts, Capabilities, Precision

        catalog = code.ir_catalog
        if not catalog.facts.has(Capabilities.ALIAS_REFERENCES):
            raise TemporaryLimitation("Alias facts are unavailable; run heap analysis.")
        facts = AnalysisFacts(catalog)
        procedure = catalog.procedure(code)
        result = {}
        for symbol in catalog.symbols:
            if symbol.id.scope != procedure.root_scope:
                continue
            references = catalog.facts.query(
                Capabilities.ALIAS_REFERENCES, symbol.id
            )
            if references.precision is Precision.UNKNOWN:
                continue
            locations = tuple(references.values)
            aliases = {
                self._location_label(alias)
                for location in locations
                for alias in facts.points_to(location)
            }
            entries = [
                (
                    facts.reference_count(location),
                    facts.is_escaped(location),
                )
                for location in locations
            ]
            result[symbol.display_name] = AliasInfo(
                variable=symbol.display_name,
                aliases=aliases,
                is_aliased=len(aliases) > 1,
                ref_count=max((count for count, _escaped in entries), default=0),
                is_escaped=any(escaped for _count, escaped in entries),
                is_singleton=all(count <= 1 for count, _escaped in entries),
                strong_update_possible=all(
                    count <= 1 and not escaped for count, escaped in entries
                ),
            )
        return result

    def get_points_to(self, function: Union[str, object]) -> Dict[str, PointsToInfo]:
        """Return points-to information for all variables in a function."""
        try:
            code = self.context.resolve_function(function)
        except ValueError as exc:
            raise ValueError(f"Cannot resolve function: {exc}")

        aliases = self.get_aliases(code)
        return {
            name: PointsToInfo(
                variable=name,
                points_to=set(info.aliases),
                may_be_null=False,
                ref_count=info.ref_count,
                is_escaped=info.is_escaped,
                is_singleton=info.is_singleton,
                strong_update_possible=info.strong_update_possible,
            )
            for name, info in aliases.items()
        }

    def get_aliases_for_variable(self, variable: str) -> AliasInfo:
        """Return published heap facts for one source-level variable label."""
        facts = self._require_alias_facts()
        locations = self._matching_locations(facts, variable)
        info = AliasInfo(variable=variable)
        for location in locations:
            info.aliases.update(
                self._location_label(alias) for alias in facts.points_to(location)
            )
        info.is_aliased = len(info.aliases) > 1
        info.ref_count = max(
            (facts.reference_count(location) for location in locations), default=0
        )
        info.is_escaped = any(facts.is_escaped(location) for location in locations)
        info.is_singleton = bool(locations) and all(
            facts.reference_count(location) <= 1 for location in locations
        )
        info.strong_update_possible = bool(locations) and all(
            facts.strong_update_possible(location) for location in locations
        )
        return info

    def get_points_to_for_variable(self, variable: str) -> PointsToInfo:
        """Return published points-to facts for one source-level variable label."""
        facts = self._require_alias_facts()
        locations = self._matching_locations(facts, variable)
        info = PointsToInfo(variable=variable)
        for location in locations:
            info.points_to.update(
                self._location_label(alias) for alias in facts.points_to(location)
            )
        info.ref_count = max(
            (facts.reference_count(location) for location in locations), default=0
        )
        info.is_escaped = any(facts.is_escaped(location) for location in locations)
        info.is_singleton = bool(locations) and all(
            facts.reference_count(location) <= 1 for location in locations
        )
        info.strong_update_possible = bool(locations) and all(
            facts.strong_update_possible(location) for location in locations
        )
        info.may_be_null = not locations or info.is_escaped
        return info

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
        """Return the revision-aware fact facade for lifetime queries."""
        from pyflow.ir.core import AnalysisFacts, Capabilities

        catalog = self.context.program.ir
        if not catalog.facts.has(Capabilities.LIFETIME_CODE_LIVE):
            raise TemporaryLimitation(
                "Lifetime analysis not available; run the lifetime pass first."
            )
        return AnalysisFacts(catalog)

    def get_ipa_function_summaries(
        self, function: Optional[Union[str, object]] = None
    ) -> List[IpaFunctionSummary]:
        """Return IPA summaries for all contexts (or a single function)."""
        return self._ipa.get_function_summaries(self.context, function)

    def _get_var_name(self, lcl):
        if hasattr(lcl, "constantValue"):
            return lcl.constantValue()
        if hasattr(lcl, "id"):
            return lcl.id
        if hasattr(lcl, "name"):
            return lcl.name
        return None

    @staticmethod
    def _location_label(location: object) -> str:
        root = getattr(location, "root", None)
        label = getattr(root, "label", None)
        return label or repr(location)

    def _require_alias_facts(self):
        from pyflow.ir.core import AnalysisFacts, Capabilities

        catalog = self.context.program.ir
        if not catalog.facts.has(Capabilities.ALIAS_POINTS_TO):
            raise TemporaryLimitation(
                "Alias facts are unavailable; ensure the 'heap' pass has run."
            )
        return AnalysisFacts(catalog)

    @staticmethod
    def _matching_locations(facts, variable: str) -> tuple[object, ...]:
        return tuple(facts.locations_by_label().get(variable, ()))
