"""Publish immutable flow-sensitive alias facts into the shared IR catalog."""

from __future__ import annotations

from collections import defaultdict
from typing import DefaultDict

from pyflow.ir.core import Capabilities, FactResult, SymbolId


def publish_alias_facts(catalog, graph, heap, codes) -> None:
    from pyflow.language.python import ast

    points_to = {}
    escaped = {}
    reference_counts = {}
    references: DefaultDict[SymbolId, set[object]] = defaultdict(set)
    for location, entry in graph.entries.items():
        points_to[location] = FactResult.exact(entry.aliases, "heap")
        escaped[location] = FactResult.exact((entry.is_escaped,), "heap")
        reference_counts[location] = FactResult.exact((entry.ref_count,), "heap")

    for code in codes:
        for _node_id, node in catalog.nodes():
            if not isinstance(node, ast.Local) or not catalog.has_node(node, code):
                continue
            if not catalog.has_symbol(node, code):
                continue
            symbol = catalog.symbol_id(node, code)
            references[symbol]
            references[symbol].update(
                heap.locations_for_local(code, node)
            )

    precision: dict[object, FactResult] = {}
    for _operation, identity in graph.operation_identities.items():
        reasons = graph.precision_degradations.get(identity, frozenset())
        precision[identity] = (
            FactResult.conservative((), "heap", sorted(reasons))
            if reasons
            else FactResult.exact((), "heap")
        )

    catalog.facts.publish_many(
        "heap",
        {
            Capabilities.ALIAS_POINTS_TO: points_to,
            Capabilities.ALIAS_REFERENCES: {
                symbol: FactResult.exact(locations, "heap")
                for symbol, locations in references.items()
            },
            Capabilities.ALIAS_ESCAPED: escaped,
            Capabilities.ALIAS_REFERENCE_COUNT: reference_counts,
            Capabilities.ALIAS_PRECISION: precision,
        },
    )


__all__ = ["publish_alias_facts"]
