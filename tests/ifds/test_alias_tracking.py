"""Tests for Level-1 heap-insensitive slot alias tracking."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.ifds import IFDSResult, IFDSSolver, Supergraph, ZERO
from pyflow.analysis.ifds.clients._client_common import AnnotatedFactProblemBase
from pyflow.analysis.ifds.problem import IFDSProblem
from pyflow.language.python import ast as py_ast


class AliasTestProblem(AnnotatedFactProblemBase[str], IFDSProblem[str, str, str]):
    analysis_name = "alias test"

    def __init__(self, sg: Supergraph[str, str]) -> None:
        self.adapter = None
        from pyflow.analysis.ifds.clients._call_model import CallModelRegistry

        self.call_models = CallModelRegistry()
        self._slot_overrides = {}
        self._site_counter = 0
        self._allocation_sites = {}
        self._site_slots = {}
        self._supergraph = sg
        self._raw_slots: dict[int, tuple[object, ...]] = {}

    def set_raw_slots(self, local: py_ast.Local, *slots: object) -> None:
        self._raw_slots[id(local)] = slots

    def _slots_for_local_raw(self, procedure, local) -> tuple[object, ...]:
        return self._raw_slots.get(id(local), ())

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

    def _make_slot_fact(self, slot: object) -> str:
        return getattr(slot, "label", repr(slot))

    def _make_expression_fact(self, procedure, expression, result_index=0) -> str:
        return "expr"

    def _slot_from_fact(self, fact: str) -> object | None:
        return None

    def _expression_fact_result(self, fact: str):
        return None


@dataclass(frozen=True, eq=False)
class Slot:
    label: str

    def getForward(self):
        return self


class TestSlotAliasing:
    def test_independent_by_default(self):
        x, y = py_ast.Local("x"), py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs, ys = Slot("xs"), Slot("ys")
        p.set_raw_slots(x, xs)
        p.set_raw_slots(y, ys)
        assert p._slots_for_local(None, x) == (xs,)
        assert p._slots_for_local(None, y) == (ys,)

    def test_alias_makes_slots_identical(self):
        x, y = py_ast.Local("x"), py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Slot("xs")
        p.set_raw_slots(x, xs)
        p.set_raw_slots(y, Slot("ys"))
        p._alias_locals(None, y, x)
        assert p._slots_for_local(None, y) == (xs,)
        assert p._slots_for_local(None, y) is p._slots_for_local(None, x)

    def test_unalias_restores_identity(self):
        x, y = py_ast.Local("x"), py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs, ys = Slot("xs"), Slot("ys")
        p.set_raw_slots(x, xs)
        p.set_raw_slots(y, ys)
        p._alias_locals(None, y, x)
        assert p._slots_for_local(None, y) == (xs,)
        p._unalias_locals(None, y)
        assert p._slots_for_local(None, y) == (ys,)
        assert p._slots_for_local(None, x) == (xs,)

    def test_unalias_does_not_affect_source(self):
        x, y = py_ast.Local("x"), py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Slot("xs")
        p.set_raw_slots(x, xs)
        p.set_raw_slots(y, Slot("ys"))
        p._alias_locals(None, y, x)
        p._unalias_locals(None, y)
        assert p._slots_for_local(None, x) == (xs,)

    def test_update_aliases_local_to_local(self):
        x, y = py_ast.Local("x"), py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Slot("xs")
        p.set_raw_slots(x, xs)
        p.set_raw_slots(y, Slot("ys"))
        p._update_aliases_for_assignment(None, (y,), x)
        assert p._slots_for_local(None, y) == (xs,)

    def test_update_aliases_nonlocal_breaks_alias(self):
        x, y = py_ast.Local("x"), py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        ys = Slot("ys")
        p.set_raw_slots(x, Slot("xs"))
        p.set_raw_slots(y, ys)
        p._alias_locals(None, y, x)
        p._update_aliases_for_assignment(None, (y,), None)
        assert p._slots_for_local(None, y) == (ys,)

    def test_chain_alias(self):
        x = py_ast.Local("x")
        y = py_ast.Local("y")
        z = py_ast.Local("z")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Slot("xs")
        p.set_raw_slots(x, xs)
        p.set_raw_slots(y, Slot("ys"))
        p.set_raw_slots(z, Slot("zs"))
        p._alias_locals(None, y, x)
        p._alias_locals(None, z, y)
        assert p._slots_for_local(None, z) == (xs,)

    def test_null_source_does_not_alias(self):
        y = py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        ys = Slot("ys")
        p.set_raw_slots(y, ys)
        p._alias_locals(None, y, py_ast.Local("missing"))
        assert p._slots_for_local(None, y) == (ys,)

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
        xs = Slot("xs")
        ys = Slot("ys")
        p.set_raw_slots(x, xs)
        p.set_raw_slots(y, ys)
        x_slots = p._slots_for_local(None, x)
        y_slots = p._slots_for_local(None, y)
        assert x_slots == (xs,)
        assert y_slots == (ys,)
        assert x_slots is not y_slots

    def test_two_fresh_objects_have_different_sites(self):
        x = py_ast.Local("x")
        y = py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Slot("xs")
        ys = Slot("ys")
        p.set_raw_slots(x, xs)
        p.set_raw_slots(y, ys)

        p._unalias_locals(None, x)
        p._unalias_locals(None, y)
        x_site = p._allocation_sites[(id(None), id(x))]
        y_site = p._allocation_sites[(id(None), id(y))]
        assert x_site != y_site
        assert p._slots_for_local(None, x) is not p._slots_for_local(None, y)

    def test_alias_shares_site(self):
        x = py_ast.Local("x")
        y = py_ast.Local("y")
        sg = Supergraph[str, str]()
        sg.add_procedure("main", "main.entry", ["main.exit"])
        sg.add_normal_edge("main.entry", "main.exit")
        p = AliasTestProblem(sg)
        xs = Slot("xs")
        p.set_raw_slots(x, xs)
        p.set_raw_slots(y, Slot("ys"))
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
        xs = Slot("xs")
        ys = Slot("ys")
        p.set_raw_slots(x, xs)
        p.set_raw_slots(y, ys)

        p._alias_locals(None, y, x)
        assert p._allocation_sites[(id(None), id(y))] == p._allocation_sites[(id(None), id(x))]
        p._unalias_locals(None, y)
        y_new_site = p._allocation_sites[(id(None), id(y))]
        x_site = p._allocation_sites[(id(None), id(x))]
        assert y_new_site != x_site
