from types import SimpleNamespace

import pytest

from pyflow.api.entrypoints import ExistingWrapper, InterfaceDeclaration, nullWrapper
from pyflow.application.errors import TemporaryLimitation
from pyflow.api.queries.call_graph import CallGraphQueries
from pyflow.api.queries.context import QueryContext
from pyflow.api.queries.engine import GraphQueryEngine
from pyflow.api.queries.localization import LocalizationCandidate, LocalizationQueries
from pyflow.api.queries.test_generation import TestGenerationQueries as _TestGenerationQueries


class DummyCode:
    def __init__(self, name, filename=None, lineno=None):
        self.name = name
        self.annotation = SimpleNamespace(
            origin=SimpleNamespace(filename=filename, lineno=lineno)
        )

    def codeName(self):
        return self.name


class DummyBlock:
    def __init__(self, bid):
        self.bid = bid
        self.next = None

    def forward(self):
        nxt = self.next
        if nxt is None:
            return []
        if isinstance(nxt, dict):
            return list(nxt.values())
        return [nxt]


class DummyIpaContext:
    def __init__(self, code):
        self.signature = SimpleNamespace(code=code)
        self.invokeOut = {}


def test_cfg_structure_handles_linear_successor(monkeypatch):
    entry = DummyBlock(1)
    tail = DummyBlock(2)
    entry.next = tail

    cfg = SimpleNamespace(entryTerminal=entry)
    code = DummyCode("f")
    compiler = object()
    program = SimpleNamespace(liveCode=[code], interface=None)
    context = QueryContext(compiler, program)
    engine = GraphQueryEngine(context)

    from pyflow.api.queries import engine as engine_module

    monkeypatch.setattr(engine_module.cfg_transform, "evaluate", lambda _c, _f: cfg)
    result = engine.get_cfg_structure("f")

    assert {"src": 1, "dst": 2, "type": "normal"} in result["edges"]


def test_test_scenarios_do_not_break_on_cfg_cycles():
    entry = DummyBlock(1)
    loop = DummyBlock(2)
    end = DummyBlock(3)
    entry.next = {"go": loop}
    loop.next = {"repeat": loop, "exit": end}
    end.next = {}

    cfg = SimpleNamespace(entryTerminal=entry)
    queries = _TestGenerationQueries(
        context=SimpleNamespace(resolve_function_name=lambda _: "f", resolve_function=lambda _: None),
        graph_engine=None,
        call_graph_queries=SimpleNamespace(get_callees=lambda _: [], get_callers=lambda _: []),
        control_flow_queries=SimpleNamespace(get_cfg=lambda _: cfg),
        data_flow_queries=SimpleNamespace(get_ipa_function_summaries=lambda *_: []),
    )

    scenarios = queries.get_test_scenarios("f")
    assert scenarios
    assert all(s.path_description for s in scenarios)


def test_callgraph_uses_disambiguated_node_ids():
    src = DummyCode("foo", "/tmp/a.py", 10)
    dst = DummyCode("foo", "/tmp/b.py", 22)
    src_ctx = DummyIpaContext(src)
    dst_ctx = DummyIpaContext(dst)
    src_ctx.invokeOut = {(None, dst_ctx): None}
    ipa = SimpleNamespace(contexts={"a": src_ctx, "b": dst_ctx})

    context = QueryContext(
        compiler=object(),
        program=SimpleNamespace(ipa_analysis=ipa, liveCode=[src, dst], interface=None),
    )
    engine = GraphQueryEngine(context)
    queries = CallGraphQueries(context, engine)

    graph = queries.get_callgraph().get()
    assert len(graph.keys()) == 2
    assert all("@/" in name for name in graph.keys())
    assert queries.get_callees("foo")
    assert queries.get_callgraph_data() == {
        caller: sorted(callees)
        for caller, callees in sorted(graph.items(), key=lambda item: item[0])
    }


def test_compute_slice_respects_variable_filter():
    call_graph = SimpleNamespace(
        get_upstream_functions=lambda *_args, **_kw: ["u1", "u2"],
        get_downstream_functions=lambda *_args, **_kw: ["d1", "d2"],
        get_callees=lambda *_args, **_kw: [],
        get_callers=lambda *_args, **_kw: [],
        get_shortest_path=lambda *_args, **_kw: None,
        get_callgraph=lambda: SimpleNamespace(get=lambda: {}),
    )
    queries = LocalizationQueries(
        context=SimpleNamespace(resolve_function_name=lambda _: "target"),
        graph_engine=None,
        call_graph_queries=call_graph,
        control_flow_queries=SimpleNamespace(get_ssa=lambda _: None),
        data_flow_queries=SimpleNamespace(
            get_reaching_defs=lambda *_: {},
            get_aliases=lambda *_: {},
            get_points_to=lambda *_: {},
            get_variable_uses=lambda *_: [],
        ),
    )
    queries.get_localization_candidates = lambda *_args, **_kwargs: [
        LocalizationCandidate("u1", 0.9, "touches 'x'", [], []),
        LocalizationCandidate("u2", 0.8, "no evidence for 'x'", [], []),
    ]
    queries._get_data_deps = lambda name: ["x"] if name == "d2" else []

    back = queries.compute_backward_slice("target", variable="x")
    fwd = queries.compute_forward_slice("target", variable="x")

    assert back.backward_slice == ["u1"]
    assert fwd.forward_slice == ["d2"]


def test_entrypoint_maps_keyword_arguments_to_positional():
    interface = InterfaceDeclaration()
    code = SimpleNamespace(
        codeParameters=lambda: SimpleNamespace(paramnames=["x", "y"])
    )

    ep = interface.createEntryPoint(
        code=code,
        selfarg=nullWrapper,
        args=(ExistingWrapper(1),),
        kwds=[("y", ExistingWrapper(2))],
        varg=nullWrapper,
        karg=nullWrapper,
    )
    assert len(ep.args) == 2
    assert not ep.kwds


def test_resolve_function_errors_on_ambiguous_short_name():
    code_a = DummyCode("foo", "/tmp/a.py", 1)
    code_b = DummyCode("foo", "/tmp/b.py", 2)
    context = QueryContext(
        compiler=object(),
        program=SimpleNamespace(liveCode=[code_a, code_b], interface=None),
    )

    with pytest.raises(ValueError, match="ambiguous"):
        context.resolve_function("foo")

    resolved = context.resolve_function(context.code_identifier(code_a))
    assert resolved is code_a


def test_get_all_cfgs_raises_when_any_cfg_construction_fails(monkeypatch):
    code_a = DummyCode("ok", "/tmp/a.py", 1)
    code_b = DummyCode("broken", "/tmp/b.py", 2)
    context = QueryContext(
        compiler=object(),
        program=SimpleNamespace(liveCode=[code_a, code_b], interface=None),
    )
    engine = GraphQueryEngine(context)

    from pyflow.api.queries import engine as engine_module

    def fake_evaluate(_compiler, code):
        if code is code_b:
            raise RuntimeError("CFG boom")
        return SimpleNamespace(entryTerminal=DummyBlock(1))

    monkeypatch.setattr(engine_module.cfg_transform, "evaluate", fake_evaluate)

    with pytest.raises(TemporaryLimitation, match="broken@/tmp/b.py:2"):
        engine.get_all_cfgs()


def test_get_ifds_supergraph_ignores_unrelated_cfg_failures(monkeypatch):
    code_a = DummyCode("ok", "/tmp/a.py", 1)
    code_b = DummyCode("broken", "/tmp/b.py", 2)
    context = QueryContext(
        compiler=object(),
        program=SimpleNamespace(liveCode=[code_a, code_b], interface=None),
    )
    engine = GraphQueryEngine(context)

    from pyflow.api.queries import engine as engine_module

    class DummyCfg:
        def __init__(self, code):
            self.code = code
            self.entryTerminal = DummyBlock(1)

    def fake_evaluate(_compiler, code):
        if code is code_b:
            raise RuntimeError("CFG boom")
        return DummyCfg(code)

    monkeypatch.setattr(engine_module.cfg_transform, "evaluate", fake_evaluate)

    with pytest.raises(TemporaryLimitation, match="annotation-complete programs"):
        engine.get_ifds_supergraph()
