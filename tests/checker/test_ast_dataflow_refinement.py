from dataclasses import dataclass

from pyflow.analysis.alias.flow_sensitive.model import (
    HeapLocation,
    HeapObject,
    HeapObjectCardinality,
    HeapObjectIdentity,
    HeapObjectKind,
)
from pyflow.checker.ast_dataflow.domain import TaintLocation
from pyflow.checker.ast_dataflow.semantics import (
    AdaptiveRefinementProvider,
    HeapGraphRefinementProvider,
    heap_location_adapter,
)


@dataclass(frozen=True)
class _Entry:
    location: HeapLocation


class _Graph:
    def __init__(self, location, strong):
        self.location = location
        self.strong = strong

    def locations_by_label(self):
        return {"payload": frozenset({self.location})}

    def strong_update_possible(self, location):
        assert location.root == self.location.root
        return self.strong and location.is_precise()


def _heap_location():
    root = HeapObject(
        HeapObjectKind.LOCAL,
        ("f", "payload"),
        "payload",
        cardinality=HeapObjectCardinality.ONE,
        identity=HeapObjectIdentity.SINGLETON,
    )
    return HeapLocation(root)


def test_heap_refinement_proves_strong_precise_field_update():
    graph = _Graph(_heap_location(), True)
    provider = HeapGraphRefinementProvider(graph, heap_location_adapter(graph))

    decision = provider.update_decision(
        TaintLocation(("f", "payload")).key("command"), None
    )

    assert decision.strong
    assert decision.reasons == ("heap-singleton",)


def test_heap_refinement_falls_back_to_weak_for_ambiguous_root():
    graph = _Graph(_heap_location(), False)
    graph.locations_by_label = lambda: {
        "payload": frozenset(
            {
                _heap_location(),
                HeapLocation(
                    HeapObject(
                        HeapObjectKind.LOCAL,
                        ("g", "payload"),
                        "payload",
                    )
                ),
            }
        )
    }
    provider = HeapGraphRefinementProvider(graph, heap_location_adapter(graph))

    decision = provider.update_decision(
        TaintLocation(("f", "payload")).key("command"), None
    )

    assert not decision.strong


def test_adaptive_refinement_only_queries_heap_for_object_paths():
    graph = _Graph(_heap_location(), True)
    adaptive = AdaptiveRefinementProvider(
        [HeapGraphRefinementProvider(graph, heap_location_adapter(graph))]
    )

    local = adaptive.update_decision(TaintLocation(("f", "payload")), None)
    field = adaptive.update_decision(
        TaintLocation(("f", "payload")).key("command"), None
    )
    repeated = adaptive.update_decision(
        TaintLocation(("f", "payload")).key("command"), None
    )

    assert local.strong
    assert field.strong
    assert repeated == field
    assert adaptive.refinement_requests == 1
    assert adaptive.successful_refinements == 1
