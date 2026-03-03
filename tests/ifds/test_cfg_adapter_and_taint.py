"""Tests for CFG-backed IFDS adapter and shipped taint analysis."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from pyflow.application.errors import TemporaryLimitation
from pyflow.application import context
from pyflow.analysis.cfg import transform
from pyflow.analysis.ifds import (
    TaintConfiguration,
    analyze_taint,
    bind_call_arguments,
    build_supergraph_from_cfgs,
)
from pyflow.language.asttools.annotation import annotationSet, makeContextualAnnotation
from pyflow.language.python import ast


def make_code(name: str, params, body_blocks, *, return_name: str = "ret0"):
    return_param = ast.Local(return_name)
    code = ast.Code(
        name,
        ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=list(params),
            paramnames=[param.name for param in params],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[return_param],
            type_params=None,
        ),
        ast.Suite(list(body_blocks)),
    )
    return code, return_param


def build_cfg(compiler, code):
    annotate_code_for_ifds(code)
    return transform.evaluate(compiler, code)


@dataclass(frozen=True)
class FakeSlot:
    label: str

    def getForward(self):
        return self


def _ctx_annotation(*slots):
    return makeContextualAnnotation([annotationSet(slots)])


def annotate_code_for_ifds(code):
    local_slots: dict[str, FakeSlot] = {}
    global_slots: dict[str, FakeSlot] = {}
    cell_slots: dict[str, FakeSlot] = {}
    attr_slots: dict[tuple[str, str], FakeSlot] = {}
    subscript_slots: dict[tuple[str, str], FakeSlot] = {}

    def global_name(existing) -> str:
        pyobj = getattr(existing.object, "pyobj", None)
        if isinstance(pyobj, str):
            return pyobj
        return repr(pyobj)

    def attr_name(node) -> str:
        if isinstance(node, ast.Existing):
            return global_name(node)
        if isinstance(node, ast.Local) and node.name is not None:
            return node.name
        return "*"

    def subscript_name(node) -> str:
        if isinstance(node, ast.Existing):
            pyobj = getattr(node.object, "pyobj", None)
            return f"[{pyobj!r}]"
        return "[*]"

    def slot_for_local(local):
        return local_slots.setdefault(local.name, FakeSlot(local.name))

    def slot_for_global(existing):
        name = global_name(existing)
        return global_slots.setdefault(name, FakeSlot(name))

    def slot_for_cell(cell):
        return cell_slots.setdefault(cell.name, FakeSlot(cell.name))

    def slots_for_expr(expr):
        if expr is None or isinstance(expr, ast.leafTypes):
            return ()
        if isinstance(expr, ast.Local) and expr.name is not None:
            return (slot_for_local(expr),)
        if isinstance(expr, ast.GetGlobal):
            return (slot_for_global(expr.name),)
        if isinstance(expr, ast.GetCellDeref):
            return (slot_for_cell(expr.cell),)
        if isinstance(expr, ast.GetAttr):
            base_slots = slots_for_expr(expr.expr)
            name = attr_name(expr.name)
            return tuple(
                attr_slots.setdefault((base.label, name), FakeSlot(f"{base.label}.{name}"))
                for base in base_slots
            )
        if isinstance(expr, ast.Load):
            base_slots = slots_for_expr(expr.expr)
            name = attr_name(expr.name)
            return tuple(
                attr_slots.setdefault((base.label, name), FakeSlot(f"{base.label}.{name}"))
                for base in base_slots
            )
        if isinstance(expr, ast.GetSubscript):
            base_slots = slots_for_expr(expr.expr)
            key = subscript_name(expr.subscript)
            return tuple(
                subscript_slots.setdefault((base.label, key), FakeSlot(f"{base.label}{key}"))
                for base in base_slots
            )
        return ()

    def reads_for_node(node):
        if node is None or isinstance(node, ast.leafTypes):
            return ()
        if isinstance(node, (ast.Local, ast.GetGlobal, ast.GetCellDeref, ast.GetAttr, ast.Load, ast.GetSubscript)):
            return slots_for_expr(node)
        if isinstance(node, ast.Assign):
            return reads_for_node(node.expr)
        if isinstance(node, ast.Return):
            slots = []
            for expr in node.exprs:
                slots.extend(reads_for_node(expr))
            return tuple(slots)
        if isinstance(node, (ast.SetAttr, ast.SetSubscript, ast.SetGlobal, ast.SetCellDeref, ast.Store)):
            return reads_for_node(node.value)
        if isinstance(node, ast.Discard):
            return reads_for_node(node.expr)
        if isinstance(node, (ast.Call, ast.DirectCall, ast.MethodCall)):
            slots = []
            for arg in node.args:
                slots.extend(reads_for_node(arg))
            for _, value in node.kwds:
                slots.extend(reads_for_node(value))
            if isinstance(node, ast.MethodCall):
                slots.extend(reads_for_node(node.expr))
            return tuple(slots)
        if isinstance(node, ast.Suite):
            slots = []
            for block in node.blocks:
                slots.extend(reads_for_node(block))
            return tuple(slots)
        if isinstance(node, ast.TryExceptFinally):
            slots = list(reads_for_node(node.body))
            for handler in node.handlers:
                slots.extend(reads_for_node(handler))
            if node.defaultHandler is not None:
                slots.extend(reads_for_node(node.defaultHandler))
            if node.else_ is not None:
                slots.extend(reads_for_node(node.else_))
            if node.finally_ is not None:
                slots.extend(reads_for_node(node.finally_))
            return tuple(slots)
        if isinstance(node, ast.ExceptionHandler):
            slots = list(reads_for_node(node.preamble))
            slots.extend(reads_for_node(node.type))
            if node.value is not None:
                slots.extend(reads_for_node(node.value))
            slots.extend(reads_for_node(node.body))
            return tuple(slots)
        return ()

    def modifies_for_node(node):
        if isinstance(node, ast.Assign):
            return tuple(slot_for_local(local) for local in node.lcls if isinstance(local, ast.Local))
        if isinstance(node, ast.SetAttr):
            base_slots = slots_for_expr(node.expr)
            name = attr_name(node.name)
            return tuple(
                attr_slots.setdefault((base.label, name), FakeSlot(f"{base.label}.{name}"))
                for base in base_slots
            )
        if isinstance(node, ast.Store):
            base_slots = slots_for_expr(node.expr)
            name = attr_name(node.name)
            return tuple(
                attr_slots.setdefault((base.label, name), FakeSlot(f"{base.label}.{name}"))
                for base in base_slots
            )
        if isinstance(node, ast.SetSubscript):
            base_slots = slots_for_expr(node.expr)
            key = subscript_name(node.subscript)
            return tuple(
                subscript_slots.setdefault((base.label, key), FakeSlot(f"{base.label}{key}"))
                for base in base_slots
            )
        if isinstance(node, ast.SetGlobal):
            return (slot_for_global(node.name),)
        if isinstance(node, ast.SetCellDeref):
            return (slot_for_cell(node.cell),)
        return ()

    def visit(node):
        if node is None or isinstance(node, ast.leafTypes):
            return
        annotation = getattr(node, "annotation", None)
        if annotation is not None and hasattr(annotation, "rewrite"):
            rewrite = {}
            if hasattr(annotation, "opReads"):
                rewrite["opReads"] = _ctx_annotation(*reads_for_node(node))
                rewrite["opModifies"] = _ctx_annotation(*modifies_for_node(node))
            if hasattr(annotation, "references"):
                refs = ()
                if isinstance(node, ast.Local) and node.name is not None:
                    refs = (slot_for_local(node),)
                elif isinstance(node, ast.Cell):
                    refs = (slot_for_cell(node),)
                elif isinstance(node, ast.Existing):
                    refs = (FakeSlot(global_name(node)),)
                rewrite["references"] = _ctx_annotation(*refs)
            node.rewriteAnnotation(**rewrite)
        if isinstance(node, (list, tuple)):
            for child in node:
                visit(child)
            return
        if isinstance(node, ast.Code):
            node.rewriteAnnotation(contexts=(object(),))
            params = getattr(node, "codeparameters", None)
            if params is not None:
                visit(getattr(params, "selfparam", None))
                visit(getattr(params, "posonlyparams", ()))
                visit(getattr(params, "params", ()))
                visit(getattr(params, "defaults", ()))
                visit(getattr(params, "vparam", None))
                visit(getattr(params, "kparam", None))
                visit(getattr(params, "returnparams", ()))
            visit(node.ast)
            return
        node.visitChildren(visit)

    def iter_nodes(node):
        if node is None or isinstance(node, ast.leafTypes):
            return
        yield node
        if isinstance(node, (list, tuple)):
            for child in node:
                yield from iter_nodes(child)
            return
        if isinstance(node, ast.Code):
            params = getattr(node, "codeparameters", None)
            if params is not None:
                yield from iter_nodes(getattr(params, "selfparam", None))
                yield from iter_nodes(getattr(params, "posonlyparams", ()))
                yield from iter_nodes(getattr(params, "params", ()))
                yield from iter_nodes(getattr(params, "defaults", ()))
                yield from iter_nodes(getattr(params, "vparam", None))
                yield from iter_nodes(getattr(params, "kparam", None))
                yield from iter_nodes(getattr(params, "returnparams", ()))
            yield from iter_nodes(node.ast)
            return
        children = []
        node.visitChildren(children.append)
        for child in children:
            yield from iter_nodes(child)

    visit(code)
    assert code.annotation.contexts is not None
    for node in iter_nodes(code):
        annotation = getattr(node, "annotation", None)
        if annotation is None:
            continue
        if hasattr(annotation, "opReads"):
            assert getattr(annotation, "opReads", None) is not None
            assert getattr(annotation, "opModifies", None) is not None
        if hasattr(annotation, "references"):
            assert getattr(annotation, "references", None) is not None


def call_stmt(callee_code, args, targets=()):
    direct = ast.DirectCall(callee_code, None, list(args), [], None, None)
    if targets:
        return ast.Assign(direct, list(targets))
    return ast.Discard(direct)


def test_cfg_adapter_discovers_direct_call_edges_and_return_sites():
    compiler = context.CompilerContext(None)

    x = ast.Local("x")
    helper_code, _ = make_code("helper", [x], [ast.Return([x])], return_name="helper_ret")

    a = ast.Local("a")
    b = ast.Local("b")
    main_code, _ = make_code(
        "main",
        [a],
        [
            call_stmt(helper_code, [a], [b]),
            ast.Return([b]),
        ],
        return_name="main_ret",
    )

    helper_cfg = build_cfg(compiler, helper_code)
    main_cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([main_cfg, helper_cfg])

    call_nodes = [
        node
        for node in adapter.supergraph.nodes_of(main_cfg)
        if adapter.call_expression_of(node) is not None
    ]
    assert len(call_nodes) == 1

    call_node = call_nodes[0]
    assert adapter.callees_of(call_node) == (helper_cfg,)

    return_sites = adapter.supergraph.return_sites_of_call_at(call_node)
    assert len(return_sites) == 1
    return_site = next(iter(return_sites))
    assert isinstance(adapter.operation_of(return_site), ast.Assign)
    successors = adapter.supergraph.normal_successors(return_site)
    assert len(successors) == 1
    assert isinstance(adapter.operation_of(next(iter(successors))), ast.Return)


def test_interprocedural_taint_analysis_reports_only_unsanitized_sink_flow():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")

    param = ast.Local("param")
    helper_code, _ = make_code(
        "helper", [param], [ast.Return([param])], return_name="helper_ret"
    )

    sanitizer_param = ast.Local("value")
    sanitizer_code, _ = make_code(
        "sanitize",
        [sanitizer_param],
        [ast.Return([sanitizer_param])],
        return_name="sanitize_ret",
    )

    sink_param = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_param], [], return_name="sink_ret")

    a = ast.Local("a")
    b = ast.Local("b")
    c = ast.Local("c")
    main_code, _ = make_code(
        "main",
        [],
        [
            call_stmt(source_code, [], [a]),
            call_stmt(helper_code, [a], [b]),
            call_stmt(sanitizer_code, [b], [c]),
            call_stmt(sink_code, [b]),
            call_stmt(sink_code, [c]),
            ast.Return([c]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, helper_code),
        build_cfg(compiler, sanitizer_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
            sanitizer_names=frozenset({"sanitize"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.sink_name == "sink"
    assert [local.name for local in finding.tainted_arguments] == ["b"]


def test_interprocedural_taint_rejects_non_annotated_cfgs():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")
    local = ast.Local("local")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("source"), [], [], None, None), [local]),
            ast.Discard(ast.Call(ast.Local("sink"), [local], [], None, None)),
            ast.Return([local]),
        ],
        return_name="main_ret",
    )

    cfgs = [transform.evaluate(compiler, code) for code in (main_code, source_code, sink_code)]
    adapter = build_supergraph_from_cfgs(cfgs)

    with pytest.raises(TemporaryLimitation, match="annotation-complete programs"):
        analyze_taint(
            adapter,
            TaintConfiguration(
                source_names=frozenset({"source"}),
                sink_names=frozenset({"sink"}),
            ),
            entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
        )


def test_cfg_adapter_resolves_source_level_named_calls_without_directcall_nodes():
    compiler = context.CompilerContext(None)

    x = ast.Local("x")
    helper_code, _ = make_code("helper", [x], [ast.Return([x])], return_name="helper_ret")

    a = ast.Local("a")
    b = ast.Local("b")
    call = ast.Call(ast.Local("helper"), [a], [], None, None)
    main_code, _ = make_code(
        "main",
        [a],
        [
            ast.Assign(call, [b]),
            ast.Return([b]),
        ],
        return_name="main_ret",
    )

    helper_cfg = build_cfg(compiler, helper_code)
    main_cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([main_cfg, helper_cfg])

    call_nodes = [
        node
        for node in adapter.supergraph.nodes_of(main_cfg)
        if adapter.call_expression_of(node) is not None
    ]
    assert len(call_nodes) == 1
    assert adapter.callees_of(call_nodes[0]) == (helper_cfg,)


def test_cfg_adapter_does_not_resolve_ambiguous_named_calls_by_short_name():
    compiler = context.CompilerContext(None)

    x1 = ast.Local("x1")
    helper_code_a, _ = make_code(
        "helper", [x1], [ast.Return([x1])], return_name="helper_ret_a"
    )
    x2 = ast.Local("x2")
    helper_code_b, _ = make_code(
        "helper", [x2], [ast.Return([x2])], return_name="helper_ret_b"
    )

    a = ast.Local("a")
    b = ast.Local("b")
    main_code, _ = make_code(
        "main",
        [a],
        [
            ast.Assign(ast.Call(ast.Local("helper"), [a], [], None, None), [b]),
            ast.Return([b]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, helper_code_a),
        build_cfg(compiler, helper_code_b),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)

    call_nodes = [
        node
        for node in adapter.supergraph.nodes_of(cfgs[0])
        if adapter.call_expression_of(node) is not None
    ]
    assert len(call_nodes) == 1
    assert adapter.callees_of(call_nodes[0]) == ()


def test_interprocedural_taint_handles_return_calls():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")

    choose_x = ast.Local("x")
    choose_y = ast.Local("y")
    choose_code, _ = make_code(
        "choose",
        [choose_x, choose_y],
        [ast.Return([choose_x])],
        return_name="choose_ret",
    )

    choose_call = ast.Call(
        ast.Local("choose"),
        [ast.Call(ast.Local("source"), [], [], None, None), ast.Existing(ast.program.Object(0))],
        [],
        None,
        None,
    )
    wrapper_code, _ = make_code(
        "wrapper",
        [],
        [ast.Return([choose_call])],
        return_name="wrapper_ret",
    )

    sink_value = ast.Local("value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    tainted = ast.Local("tainted")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("wrapper"), [], [], None, None), [tainted]),
            ast.Discard(ast.Call(ast.Local("sink"), [tainted], [], None, None)),
            ast.Return([tainted]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, wrapper_code),
        build_cfg(compiler, choose_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["tainted"]


def test_interprocedural_taint_flows_through_if_branch_merge():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    cond = ast.Local("cond")
    branch_value = ast.Local("branch_value")
    main_code, _ = make_code(
        "main",
        [cond],
        [
            ast.Switch(
                ast.Condition(ast.Suite([]), cond),
                ast.Suite(
                    [
                        ast.Assign(
                            ast.DirectCall(source_code, None, [], [], None, None),
                            [branch_value],
                        )
                    ]
                ),
                ast.Suite(
                    [
                        ast.Assign(
                            ast.Existing(ast.program.Object(0)),
                            [branch_value],
                        )
                    ]
                ),
            ),
            ast.Discard(
                ast.DirectCall(sink_code, None, [branch_value], [], None, None)
            ),
            ast.Return([branch_value]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["branch_value"]


def test_interprocedural_taint_flows_through_while_loop_body():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    cond = ast.Local("cond")
    loop_value = ast.Local("loop_value")
    main_code, _ = make_code(
        "main",
        [cond],
        [
            ast.Assign(ast.Existing(ast.program.Object(0)), [loop_value]),
            ast.While(
                ast.Condition(ast.Suite([]), cond),
                ast.Suite(
                    [
                        ast.Assign(
                            ast.DirectCall(source_code, None, [], [], None, None),
                            [loop_value],
                        )
                    ]
                ),
                ast.Suite([]),
            ),
            ast.Discard(
                ast.DirectCall(sink_code, None, [loop_value], [], None, None)
            ),
            ast.Return([loop_value]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["loop_value"]


def test_cfg_adapter_normal_flow_raise_has_no_successor_to_following_statement():
    compiler = context.CompilerContext(None)

    value = ast.Local("value")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Raise(ast.Existing(ast.program.Object(ValueError)), None, None),
            ast.Return([value]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])

    raise_nodes = [
        node
        for node in adapter.supergraph.nodes_of(cfg)
        if isinstance(adapter.operation_of(node), ast.Raise)
    ]
    assert len(raise_nodes) == 1
    assert adapter.supergraph.normal_successors(raise_nodes[0]) == frozenset()


def test_interprocedural_taint_ignores_except_handlers_in_normal_flow_only_mode():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    handler_value = ast.Local("handler_value")
    handler = ast.ExceptionHandler(
        ast.Suite([]),
        ast.Existing(ast.program.Object(ValueError)),
        None,
        ast.Suite(
            [
                ast.Assign(
                    ast.DirectCall(source_code, None, [], [], None, None),
                    [handler_value],
                )
            ]
        ),
    )
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.TryExceptFinally(
                ast.Suite([ast.Raise(ast.Existing(ast.program.Object(ValueError)), None, None)]),
                [handler],
                None,
                None,
                None,
            ),
            ast.Discard(
                ast.DirectCall(sink_code, None, [handler_value], [], None, None)
            ),
            ast.Return([handler_value]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert result.findings == ()


def test_bind_call_arguments_maps_keywords_to_matching_formals():
    x = ast.Local("x")
    y = ast.Local("y")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[x, y],
        paramnames=["x", "y"],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    left = ast.Local("left")
    right = ast.Local("right")
    call = ast.Call(
        ast.Local("choose"),
        [],
        [("y", right), ("x", left)],
        None,
        None,
    )

    assert bind_call_arguments(call, params) == ((right, y), (left, x))


def test_bind_call_arguments_maps_extra_positionals_into_varargs():
    first = ast.Local("first")
    rest = ast.Local("rest")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[first],
        paramnames=["first"],
        defaults=[],
        vparam=rest,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    a = ast.Local("a")
    b = ast.Local("b")
    c = ast.Local("c")
    call = ast.Call(ast.Local("collect"), [a, b, c], [], None, None)

    assert bind_call_arguments(call, params) == ((a, first), (b, rest), (c, rest))


def test_bind_call_arguments_maps_unmatched_keywords_into_kwargs():
    named = ast.Local("named")
    extras = ast.Local("extras")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[named],
        paramnames=["named"],
        defaults=[],
        vparam=None,
        kparam=extras,
        returnparams=[],
        type_params=None,
    )
    value = ast.Local("value")
    other = ast.Local("other")
    call = ast.Call(
        ast.Local("collect"),
        [],
        [("named", value), ("other", other)],
        None,
        None,
    )

    assert bind_call_arguments(call, params) == ((value, named), (other, extras))


def test_interprocedural_taint_preserves_return_slot_mapping():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")

    left_out = ast.Local("pair_left")
    right_out = ast.Local("pair_right")
    pair_code = ast.Code(
        "pair",
        ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[],
            paramnames=[],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[left_out, right_out],
            type_params=None,
        ),
        ast.Suite(
            [
                ast.Return(
                    [
                        ast.Existing(ast.program.Object(0)),
                        ast.Call(ast.Local("source"), [], [], None, None),
                    ]
                )
            ]
        ),
    )

    left = ast.Local("left")
    right = ast.Local("right")
    sink_value = ast.Local("value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("pair"), [], [], None, None), [left, right]),
            ast.Discard(ast.Call(ast.Local("sink"), [left], [], None, None)),
            ast.Discard(ast.Call(ast.Local("sink"), [right], [], None, None)),
            ast.Return([right]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, pair_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["right"]


def test_cfg_adapter_creates_call_nodes_for_nested_calls_in_evaluation_order():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [ast.Return([])], return_name="source_ret")
    wrapper_param = ast.Local("value")
    wrapper_code, _ = make_code(
        "wrapper", [wrapper_param], [ast.Return([wrapper_param])], return_name="wrapper_ret"
    )
    sink_param = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_param], [], return_name="sink_ret")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Discard(
                ast.DirectCall(
                    sink_code,
                    None,
                    [ast.DirectCall(wrapper_code, None, [ast.DirectCall(source_code, None, [], [], None, None)], [], None, None)],
                    [],
                    None,
                    None,
                )
            ),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, wrapper_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)

    ordered_nodes = sorted(
        adapter.supergraph.nodes_of(cfgs[0]),
        key=lambda node: (
            node.index if node.index is not None else -1,
            node.call_index if node.call_index is not None else 99,
            node.kind,
        ),
    )
    call_names = [
        adapter.call_expression_of(node).code.codeName()
        for node in ordered_nodes
        if adapter.call_expression_of(node) is not None
    ]

    assert call_names == ["source", "wrapper", "sink"]


def test_interprocedural_taint_tracks_attribute_global_and_cell_flows():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    obj = ast.Local("obj")
    slot = ast.Cell("captured")
    payload_name = ast.Existing(ast.program.Object("payload"))
    global_name = ast.Existing(ast.program.Object("SHARED"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.SetAttr(
                ast.DirectCall(source_code, None, [], [], None, None),
                obj,
                payload_name,
            ),
            ast.SetGlobal(
                global_name,
                ast.DirectCall(source_code, None, [], [], None, None),
            ),
            ast.SetCellDeref(
                ast.DirectCall(source_code, None, [], [], None, None),
                slot,
            ),
            ast.Discard(
                ast.DirectCall(
                    sink_code,
                    None,
                    [ast.GetAttr(obj, payload_name)],
                    [],
                    None,
                    None,
                )
            ),
            ast.Discard(
                ast.DirectCall(
                    sink_code,
                    None,
                    [ast.GetGlobal(global_name)],
                    [],
                    None,
                    None,
                )
            ),
            ast.Discard(
                ast.DirectCall(
                    sink_code,
                    None,
                    [ast.GetCellDeref(slot)],
                    [],
                    None,
                    None,
                )
            ),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 3
    labels = sorted(
        label for finding in result.findings for label in finding.tainted_argument_labels
    )
    assert labels == ["SHARED", "captured", "obj.payload"]


def test_interprocedural_taint_strong_updates_locals_and_globals():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    tainted = ast.Local("tainted")
    global_name = ast.Existing(ast.program.Object("SHARED"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("source"), [], [], None, None), [tainted]),
            ast.Assign(ast.Existing(ast.program.Object(0)), [tainted]),
            ast.SetGlobal(global_name, ast.Call(ast.Local("source"), [], [], None, None)),
            ast.SetGlobal(global_name, ast.Existing(ast.program.Object(0))),
            ast.Discard(ast.Call(ast.Local("sink"), [tainted], [], None, None)),
            ast.Discard(ast.Call(ast.Local("sink"), [ast.GetGlobal(global_name)], [], None, None)),
            ast.Return([tainted]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert result.findings == ()


def test_interprocedural_taint_uses_weak_updates_for_heap_slots():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    obj = ast.Local("obj")
    payload_name = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.SetAttr(ast.Call(ast.Local("source"), [], [], None, None), obj, payload_name),
            ast.SetAttr(ast.Existing(ast.program.Object(0)), obj, payload_name),
            ast.Discard(
                ast.Call(
                    ast.Local("sink"),
                    [ast.GetAttr(obj, payload_name)],
                    [],
                    None,
                    None,
                )
            ),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert result.findings[0].tainted_argument_labels == ("obj.payload",)
