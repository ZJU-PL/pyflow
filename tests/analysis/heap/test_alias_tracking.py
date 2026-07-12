"""Tests for Level-1 heap-insensitive location alias tracking."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.ifds import IFDSResult, IFDSSolver, Supergraph, ZERO
from pyflow.analysis.ifds.cfg_adapter import CallEffect, CallResultRoute, CFGNode
from pyflow.analysis.ifds.clients._client_common import AnnotatedFactProblemBase
from pyflow.analysis.heap import HeapObjectKind, HeapPolicy, UpdatePolicy
from pyflow.analysis.ifds.problem import IFDSProblem
from pyflow.language.python import ast as py_ast


class AliasTestProblem(AnnotatedFactProblemBase[str], IFDSProblem[str, str, str]):
    analysis_name = "alias test"

    def __init__(self, sg: Supergraph[str, str]) -> None:
        self.adapter = None
        from pyflow.analysis.ifds.clients._call_model import CallModelRegistry

        self.call_models = CallModelRegistry()
        self._storage_overrides = {}
        self._site_counter = 0
        self._allocation_sites = {}
        self._site_storage = {}
        self._supergraph = sg
        self._raw_storage: dict[int, tuple[object, ...]] = {}

    def set_raw_storage(self, local: py_ast.Local, *locations: object) -> None:
        self._raw_storage[id(local)] = locations

    def _locations_for_local_raw(self, procedure, local) -> tuple[object, ...]:
        return self._raw_storage.get(id(local), ())

    @property
    def supergraph(self):
        return self._supergraph

    @property
    def zero_fact(self):
        return ZERO

    def initial_seeds(self):
        return {"main.entry": frozenset({ZERO})}

    def normal_flow(self, node: str, successor: str, fact: str):
        return (ZERO,) if fact is ZERO else (fact,)

    def _make_location_fact(self, location: object) -> str:
        return getattr(location, "label", repr(location))

    def _make_expression_fact(self, procedure, expression, result_index=0) -> str:
        return "expr"

    def _location_from_fact(self, fact: str) -> object | None:
        return None

    def _expression_fact_result(self, fact: str):
        return None


@dataclass(frozen=True, eq=False)
class Location:
    label: str

    def getForward(self):
        return self


def _labels(locations):
    return tuple(location.root.label for location in locations)


def _problem() -> AliasTestProblem:
    sg = Supergraph[str, str]()
    sg.add_procedure("main", "main.entry", ["main.exit"])
    sg.add_normal_edge("main.entry", "main.exit")
    return AliasTestProblem(sg)


class TestLocationAliasing:
    def test_independent_by_default(self):
        x, y = py_ast.Local("x"), py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs, ys = Location("xs"), Location("ys")
        p.set_raw_storage(x, xs)
        p.set_raw_storage(y, ys)
        assert _labels(p._locations_for_local(None, x)) == ("xs",)
        assert _labels(p._locations_for_local(None, y)) == ("ys",)

    def test_alias_makes_locations_identical(self):
        x, y = py_ast.Local("x"), py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Location("xs")
        p.set_raw_storage(x, xs)
        p.set_raw_storage(y, Location("ys"))
        p._alias_locals(None, y, x)
        assert _labels(p._locations_for_local(None, y)) == ("xs",)
        assert p._locations_for_local(None, y) == p._locations_for_local(None, x)

    def test_unalias_restores_identity(self):
        x, y = py_ast.Local("x"), py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs, ys = Location("xs"), Location("ys")
        p.set_raw_storage(x, xs)
        p.set_raw_storage(y, ys)
        p._alias_locals(None, y, x)
        assert _labels(p._locations_for_local(None, y)) == ("xs",)
        p._unalias_locals(None, y)
        assert _labels(p._locations_for_local(None, y)) == ("ys",)
        assert _labels(p._locations_for_local(None, x)) == ("xs",)

    def test_unalias_does_not_affect_source(self):
        x, y = py_ast.Local("x"), py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Location("xs")
        p.set_raw_storage(x, xs)
        p.set_raw_storage(y, Location("ys"))
        p._alias_locals(None, y, x)
        p._unalias_locals(None, y)
        assert _labels(p._locations_for_local(None, x)) == ("xs",)

    def test_update_aliases_local_to_local(self):
        x, y = py_ast.Local("x"), py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Location("xs")
        p.set_raw_storage(x, xs)
        p.set_raw_storage(y, Location("ys"))
        p._update_aliases_for_assignment(None, (y,), x)
        assert _labels(p._locations_for_local(None, y)) == ("xs",)

    def test_update_aliases_nonlocal_breaks_alias(self):
        x, y = py_ast.Local("x"), py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        ys = Location("ys")
        p.set_raw_storage(x, Location("xs"))
        p.set_raw_storage(y, ys)
        p._alias_locals(None, y, x)
        p._update_aliases_for_assignment(None, (y,), None)
        assert _labels(p._locations_for_local(None, y)) == ("ys",)

    def test_chain_alias(self):
        x = py_ast.Local("x")
        y = py_ast.Local("y")
        z = py_ast.Local("z")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Location("xs")
        p.set_raw_storage(x, xs)
        p.set_raw_storage(y, Location("ys"))
        p.set_raw_storage(z, Location("zs"))
        p._alias_locals(None, y, x)
        p._alias_locals(None, z, y)
        assert _labels(p._locations_for_local(None, z)) == ("xs",)

    def test_name_sync_does_not_retarget_distinct_alias_local(self):
        x_first = py_ast.Local("x")
        x_second = py_ast.Local("x")
        old_alias = py_ast.Local("old_alias")
        p = _problem()
        xs = Location("xs")
        fresh_xs = Location("fresh_xs")
        p.set_raw_storage(old_alias, Location("old_alias_storage"))

        p._heap().bind_local_to_locations(None, x_first, (xs,))
        p._alias_locals(None, old_alias, x_first)
        p._heap().bind_local_to_locations(None, x_second, (fresh_xs,))

        assert _labels(p._locations_for_local(None, old_alias)) == ("xs",)
        assert _labels(p._locations_for_local(None, x_first)) == ("fresh_xs",)
        assert _labels(p._locations_for_local(None, x_second)) == ("fresh_xs",)

    def test_null_source_does_not_alias(self):
        y = py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        ys = Location("ys")
        p.set_raw_storage(y, ys)
        p._alias_locals(None, y, py_ast.Local("missing"))
        assert _labels(p._locations_for_local(None, y)) == ("ys",)

    def test_solver_runs_with_alias_tracking(self):
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_node("main", "main.body")
        sg.add_node("main", "main.exit")
        sg.add_normal_edge("main.entry", "main.body")
        sg.add_normal_edge("main.body", "main.exit")
        p = AliasTestProblem(sg)
        result = IFDSSolver().solve(p)
        assert isinstance(result, IFDSResult)


class TestAllocationSites:
    def test_fresh_local_gets_unique_site(self):
        x = py_ast.Local("x")
        y = py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Location("xs")
        ys = Location("ys")
        p.set_raw_storage(x, xs)
        p.set_raw_storage(y, ys)
        x_locations = p._locations_for_local(None, x)
        y_locations = p._locations_for_local(None, y)
        assert _labels(x_locations) == ("xs",)
        assert _labels(y_locations) == ("ys",)
        assert x_locations is not y_locations

    def test_two_fresh_objects_have_different_sites(self):
        x = py_ast.Local("x")
        y = py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Location("xs")
        ys = Location("ys")
        p.set_raw_storage(x, xs)
        p.set_raw_storage(y, ys)

        p._unalias_locals(None, x)
        p._unalias_locals(None, y)
        x_site = p._allocation_sites[(id(None), id(x))]
        y_site = p._allocation_sites[(id(None), id(y))]
        assert x_site != y_site
        assert p._locations_for_local(None, x) is not p._locations_for_local(None, y)

    def test_alias_shares_site(self):
        x = py_ast.Local("x")
        y = py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Location("xs")
        p.set_raw_storage(x, xs)
        p.set_raw_storage(y, Location("ys"))
        p._alias_locals(None, y, x)
        x_site = p._allocation_sites[(id(None), id(x))]
        y_site = p._allocation_sites[(id(None), id(y))]
        assert x_site == y_site

    def test_reassign_gets_fresh_site(self):
        x = py_ast.Local("x")
        y = py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Location("xs")
        ys = Location("ys")
        p.set_raw_storage(x, xs)
        p.set_raw_storage(y, ys)

        p._alias_locals(None, y, x)
        assert p._allocation_sites[(id(None), id(y))] == p._allocation_sites[
            (id(None), id(x))
        ]
        p._unalias_locals(None, y)
        y_new_site = p._allocation_sites[(id(None), id(y))]
        x_site = p._allocation_sites[(id(None), id(x))]
        assert y_new_site != x_site


class TestHeapPolicyIntegration:
    def test_return_marks_returned_object_escaped(self):
        x = py_ast.Local("x")
        p = _problem()
        heap = p._heap()
        heap.policy = HeapPolicy(allow_strong_nested_fresh=True)
        heap.bind_allocation_targets(None, (x,), object(), label="fresh object")
        field = heap.dynamic_attribute_location(
            p._locations_for_local(None, x)[0],
            "payload",
        )

        assert heap.update_policy_for_location(field) is UpdatePolicy.STRONG
        p._mark_escaped_values_for_operation(None, py_ast.Return([x]))

        assert heap.update_policy_for_location(field) is UpdatePolicy.WEAK

    def test_unresolved_call_marks_argument_object_escaped(self):
        x = py_ast.Local("x")
        p = _problem()
        heap = p._heap()
        heap.policy = HeapPolicy(allow_strong_nested_fresh=True)
        heap.bind_allocation_targets(None, (x,), object(), label="fresh object")
        field = heap.dynamic_attribute_location(
            p._locations_for_local(None, x)[0],
            "payload",
        )
        call = py_ast.Call(py_ast.Local("external"), [x], [], None, None)
        node = CFGNode(None, None, "call")
        p.adapter = _EffectAdapter(
            CallEffect(
                node=node,
                operation=call,
                call_expression=call,
                evaluation_index=None,
                call_name="external",
                callees=(),
                actual_arguments=(x,),
                argument_bindings=(),
                return_sites=(),
                kill_slots=(),
                result_route=CallResultRoute("expression"),
            )
        )

        assert heap.update_policy_for_location(field) is UpdatePolicy.STRONG
        p._mark_unresolved_call_arguments_escaped(node, call)

        assert heap.update_policy_for_location(field) is UpdatePolicy.WEAK

    def test_strong_dynamic_writes_kill_only_precise_singleton_locations(self):
        obj = py_ast.Local("obj")
        value = py_ast.Local("value")
        key = py_ast.Existing(py_ast.program.Object("payload"))
        p = _problem()
        heap = p._heap()
        heap.policy = HeapPolicy(allow_strong_nested_fresh=True)
        heap.bind_allocation_targets(None, (obj,), object(), label="fresh object")
        base = p._locations_for_local(None, obj)[0]
        operation = py_ast.SetSubscript(value, obj, key)

        kills = p._strong_dynamic_write_locations_for_operation(None, operation)

        assert heap.dynamic_subscript_location(base, "['payload']") in kills
        assert heap.dynamic_subscript_location(base, "[*]") not in kills

    def test_call_assignment_materializes_constructor_as_fresh_allocation(self):
        target = py_ast.Local("target")
        call = py_ast.Call(py_ast.Local("User"), [], [], None, None)
        operation = py_ast.Assign(call, [target])
        p = _problem()

        p._materialize_call_result_location(None, operation, call, 0)

        location = p._locations_for_local(None, target)[0]
        assert location.root.kind is HeapObjectKind.ALLOCATION
        assert location.root.label == "User()"

    def test_call_assignment_materializes_configured_summary_return(self):
        target = py_ast.Local("target")
        call = py_ast.Call(py_ast.Local("library_value"), [], [], None, None)
        operation = py_ast.Assign(call, [target])
        p = _problem()
        p._heap().policy = HeapPolicy(
            summary_return_names=frozenset({"library_value"})
        )

        p._materialize_call_result_location(None, operation, call, 0)

        location = p._locations_for_local(None, target)[0]
        assert location.root.kind is HeapObjectKind.SUMMARY
        assert location.root.label == "library_value()"

    def test_unresolved_lowercase_call_assignment_stays_summary(self):
        target = py_ast.Local("target")
        call = py_ast.Call(py_ast.Local("unknown_factory"), [], [], None, None)
        operation = py_ast.Assign(call, [target])
        node = CFGNode(None, None, "call")
        p = _problem()
        p.adapter = _EffectAdapter(
            CallEffect(
                node=node,
                operation=operation,
                call_expression=call,
                evaluation_index=None,
                call_name="unknown_factory",
                callees=(),
                actual_arguments=(),
                argument_bindings=(),
                return_sites=(),
                kill_slots=(),
                result_route=CallResultRoute("assigned"),
            )
        )

        p._materialize_unresolved_call_summary(node, operation, call)

        location = p._locations_for_local(None, target)[0]
        assert location.root.kind is HeapObjectKind.SUMMARY
        assert location.root.label == "unknown_factory()"


class _EffectAdapter:
    def __init__(self, effect: CallEffect) -> None:
        self._effect = effect

    def effect_of(self, node: CFGNode):
        del node
        return self._effect
