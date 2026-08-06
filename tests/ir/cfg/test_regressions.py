import unittest
from types import SimpleNamespace

from pyflow.application import context
from pyflow.ir.core import IRCatalog, SourceAnchor, SymbolKind
from pyflow.application.errors import TemporaryLimitation
from pyflow.ir.cdg import construct_cdg
from pyflow.frontend.extractor import Extractor
from pyflow.ir.cfg import (
    CFGVerificationError,
    dfs,
    dom,
    gc,
    graph as cfg_graph,
    inline,
    killflow,
    optimize,
    ssa,
    structuralanalysis,
    transform,
    verify_cfg,
)
from pyflow.language.python import ast as pyflow_ast
from pyflow.util.graphalgorithim import dominator


def try_semantics(x):
    try:
        value = 1 / x
    except ZeroDivisionError:
        value = 0
    else:
        value = 2
    finally:
        marker = 3
    return value


def _ssa_fixture(*symbol_groups):
    catalog = IRCatalog()
    code = object()
    procedure = catalog.register_code(
        code,
        module="test",
        qualname="ssa_fixture",
        anchor=SourceAnchor("test.py", 1, 0),
    )
    for group in symbol_groups:
        first = group[0]
        symbol = catalog.symbols.fresh(
            procedure.root_scope,
            first.name or "tmp",
            SymbolKind.LOCAL,
        )
        for local in group:
            catalog.bind_symbol(local, symbol.id)
    return catalog, SimpleNamespace(code=code), code


class TestCFGRegressions(unittest.TestCase):
    def setUp(self):
        self.compiler = context.CompilerContext(None)
        self.compiler.extractor = Extractor(self.compiler)

    def decompile(self, func):
        return self.compiler.extractor.convertFunction(func, ssa=False)

    def test_try_except_finally_is_preserved_as_structured_ast(self):
        code = self.decompile(try_semantics)

        g = transform.evaluate(self.compiler, code)
        structuralanalysis.evaluate(self.compiler, g)

        self.assertEqual(len(g.code.ast.blocks), 2)
        self.assertIsInstance(g.code.ast.blocks[0], pyflow_ast.TryExceptFinally)
        self.assertIsInstance(g.code.ast.blocks[1], pyflow_ast.Return)

    def test_ssa_rejects_try_except_finally_explicitly(self):
        code = self.decompile(try_semantics)
        g = transform.evaluate(self.compiler, code)

        with self.assertRaises(ssa.UnsupportedSSAError):
            ssa.evaluate(self.compiler, g)

    def test_typeswitch_flow_killer_recomputes_condition_flow(self):
        conditional = pyflow_ast.Local("value")
        original = pyflow_ast.TypeSwitch(
            conditional, [pyflow_ast.TypeSwitchCase([], None, pyflow_ast.Suite([]))]
        )
        node = cfg_graph.TypeSwitch(None, original)

        case_exit = cfg_graph.Exit(None)
        fail_exit = cfg_graph.Exit(None)
        error_exit = cfg_graph.Exit(None)

        node.setExit(0, case_exit)
        node.setExit("fail", fail_exit)
        node.setExit("error", error_exit)

        fk = killflow.FlowKiller(killflow.OpFlow())
        fk.opFlow.normal = False
        fk.opFlow.fails = True
        fk.opFlow.errors = True
        fk.opFlow.yields = False

        fk.visitTypeSwitch(node)

        self.assertIs(node.getExit(0), case_exit)
        self.assertIsNone(node.getExit("fail"))
        self.assertIsNone(node.getExit("error"))

    def test_opflow_handles_not_expression(self):
        op_flow = killflow.OpFlow()

        op_flow.process(pyflow_ast.Not(pyflow_ast.Local("flag")))

        self.assertTrue(op_flow.errors)

    def test_opflow_ignores_scope_declarations(self):
        op_flow = killflow.OpFlow()

        op_flow.process(
            pyflow_ast.Suite(
                [
                    pyflow_ast.GlobalDecl(pyflow_ast.Local("global_name")),
                    pyflow_ast.NonlocalDecl(pyflow_ast.Local("nonlocal_name")),
                ]
            )
        )

        self.assertTrue(op_flow.normal)
        self.assertFalse(op_flow.errors)

    def test_cfg_tolerates_orphaned_legacy_loop_control(self):
        code = pyflow_ast.Code(
            "legacy_control",
            pyflow_ast.CodeParameters(None, [], [], [], [], [], None, None, [], None),
            pyflow_ast.Suite(
                [
                    pyflow_ast.Break(),
                    pyflow_ast.Continue(),
                    pyflow_ast.Discard(
                        pyflow_ast.Existing(pyflow_ast.program.Object("reachable"))
                    ),
                ]
            ),
        )

        graph = transform.CFGTransformer().process(code)

        nodes = []
        dfs.CFGDFS(pre=nodes.append).process(graph.entryTerminal)
        operations = [op for node in nodes for op in getattr(node, "ops", ())]
        self.assertTrue(any(isinstance(op, pyflow_ast.Discard) for op in operations))

    def test_constant_switch_optimization_detaches_dead_switch_edges(self):
        predecessor = cfg_graph.Suite(None)
        switch = cfg_graph.Switch(
            None,
            pyflow_ast.Existing(pyflow_ast.program.Object(True)),
        )
        true_exit = cfg_graph.Exit(None)
        false_exit = cfg_graph.Exit(None)
        fail_exit = cfg_graph.Exit(None)
        error_exit = cfg_graph.Exit(None)

        predecessor.setExit("normal", switch)
        switch.setExit("true", true_exit)
        switch.setExit("false", false_exit)
        switch.setExit("fail", fail_exit)
        switch.setExit("error", error_exit)

        optimize.CFGOptPost(self.compiler).visitSwitch(switch)

        replacement = predecessor.getExit("normal")
        self.assertIs(replacement, true_exit)
        self.assertEqual(switch.next, {})
        for terminal in (true_exit, false_exit, fail_exit, error_exit):
            self.assertNotIn(switch, terminal.reverse())

    def test_structuralanalysis_leaves_unreducible_typeswitch_alone(self):
        code = cfg_graph.Code()
        code.code = pyflow_ast.Code(
            "f",
            pyflow_ast.CodeParameters(
                selfparam=None,
                posonlyparams=[],
                posonlynames=[],
                params=[],
                paramnames=[],
                defaults=[],
                vparam=None,
                kparam=None,
                returnparams=[],
                type_params=None,
            ),
            pyflow_ast.Suite([]),
        )

        entry_suite = cfg_graph.Suite(None)
        code.entryTerminal.setExit("entry", entry_suite)

        original = pyflow_ast.TypeSwitch(
            pyflow_ast.Local("cond"),
            [
                pyflow_ast.TypeSwitchCase([], None, pyflow_ast.Suite([])),
                pyflow_ast.TypeSwitchCase([], None, pyflow_ast.Suite([])),
            ],
        )
        node = cfg_graph.TypeSwitch(None, original)
        entry_suite.setExit("normal", node)

        case0 = cfg_graph.Suite(None)
        case1 = cfg_graph.Suite(None)
        ret0 = cfg_graph.Exit(None)
        ret1 = cfg_graph.Exit(None)

        case0.setExit("normal", ret0)
        case1.setExit("normal", ret1)
        node.setExit(0, case0)
        node.setExit(1, case1)

        compactor = structuralanalysis.Compactor(self.compiler, code, loops=set())
        compactor.visitTypeSwitch(node)

        self.assertIs(entry_suite.getExit("normal"), node)

    def test_phi_arguments_keep_predecessor_positions(self):
        prev_true = cfg_graph.Suite(None)
        prev_false = cfg_graph.Suite(None)
        merge = cfg_graph.Merge(None)

        prev_true.setExit("normal", merge)
        prev_false.setExit("normal", merge)

        original = pyflow_ast.Local("x")
        target = pyflow_ast.Local("x_2")
        arg = pyflow_ast.Local("x_1")

        catalog, graph, code = _ssa_fixture((original, target, arg))
        key = ssa.local_key(catalog, code, original)
        renamer = ssa.SSARename(
            graph, set(), {merge: {key}}, {key: original}, catalog
        )
        renamer.frames = {
            merge: {key: target},
            prev_true: {key: arg},
            prev_false: {},
        }
        renamer.read = {target}
        renamer.fixup = [merge]

        renamer.doFixup()

        self.assertEqual(len(merge.phi), 1)
        self.assertEqual(merge.phi[0].arguments, [arg, None])

    def test_merge_redirect_entries_preserves_labelled_edge_invariants(self):
        switch = cfg_graph.Switch(None, pyflow_ast.Local("condition"))
        merge = cfg_graph.Merge(None)
        replacement = cfg_graph.Merge(None)
        switch.setExit("true", merge)
        switch.setExit("false", merge)

        merge.redirectEntries(replacement)

        self.assertIs(switch.getExit("true"), replacement)
        self.assertIs(switch.getExit("false"), replacement)
        self.assertEqual(merge.iterprev(), [])
        self.assertEqual(
            set(replacement.iterprev()),
            {(switch, "true"), (switch, "false")},
        )

    def test_cfg_verifier_rejects_missing_predecessor_backlink(self):
        code = cfg_graph.Code()
        code.code = pyflow_ast.Code(
            "broken",
            pyflow_ast.CodeParameters(None, [], [], [], [], [], None, None, [], None),
            pyflow_ast.Suite([]),
        )
        suite = cfg_graph.Suite(None)
        code.entryTerminal.next["entry"] = suite

        with self.assertRaisesRegex(CFGVerificationError, "backlink"):
            verify_cfg(code)

    def test_cfg_verifier_rejects_phi_without_defined_input(self):
        code = cfg_graph.Code()
        code.code = pyflow_ast.Code(
            "broken_phi",
            pyflow_ast.CodeParameters(None, [], [], [], [], [], None, None, [], None),
            pyflow_ast.Suite([]),
        )
        left = cfg_graph.Suite(None)
        right = cfg_graph.Suite(None)
        merge = cfg_graph.Merge(None)
        code.entryTerminal.setExit("entry", left)
        left.setExit("normal", merge)
        right.setExit("normal", merge)
        merge.phi = [
            pyflow_ast.Phi(
                [None, None],
                pyflow_ast.Local("target"),
            )
        ]

        with self.assertRaisesRegex(CFGVerificationError, "no defined"):
            verify_cfg(code)

    def test_raise_terminates_normal_flow_and_keeps_failure_flow(self):
        dead = pyflow_ast.Local("dead")
        code = pyflow_ast.Code(
            "raises",
            pyflow_ast.CodeParameters(None, [], [], [], [], [], None, None, [], None),
            pyflow_ast.Suite(
                [
                    pyflow_ast.Raise(
                        pyflow_ast.Existing(pyflow_ast.program.Object(ValueError)),
                        None,
                        None,
                    ),
                    pyflow_ast.Assign(
                        pyflow_ast.Existing(pyflow_ast.program.Object(1)), [dead]
                    ),
                ]
            ),
        )

        graph = transform.evaluate(self.compiler, code)
        suite = graph.entryTerminal.getExit("entry")

        self.assertEqual([type(op) for op in suite.ops], [pyflow_ast.Raise])
        self.assertIsNone(suite.getExit("normal"))
        self.assertIsNotNone(suite.getExit("fail"))

    def test_typeswitch_bindings_use_branch_specific_ssa_frames(self):
        before = cfg_graph.Suite(None)
        left_suite = cfg_graph.Suite(None)
        right_suite = cfg_graph.Suite(None)
        left = pyflow_ast.Local("left")
        right = pyflow_ast.Local("right")
        condition = pyflow_ast.Local("condition")
        original = pyflow_ast.TypeSwitch(
            condition,
            [
                pyflow_ast.TypeSwitchCase([], left, pyflow_ast.Suite([])),
                pyflow_ast.TypeSwitchCase([], right, pyflow_ast.Suite([])),
            ],
        )
        switch = cfg_graph.TypeSwitch(None, original)
        before.setExit("normal", switch)
        switch.setExit(0, left_suite)
        switch.setExit(1, right_suite)
        catalog, graph, code = _ssa_fixture((condition,), (left,), (right,))
        left_key = ssa.local_key(catalog, code, left)
        right_key = ssa.local_key(catalog, code, right)
        renamer = ssa.SSARename(
            graph,
            set(),
            {},
            {left_key: left, right_key: right},
            catalog,
        )
        renamer.frames[before] = {}

        renamer.visitTypeSwitch(switch)

        self.assertIn(left_key, renamer.frames[left_suite])
        self.assertNotIn(right_key, renamer.frames[left_suite])
        self.assertIn(right_key, renamer.frames[right_suite])
        self.assertNotIn(left_key, renamer.frames[right_suite])

    def test_cfg_cloner_handles_returning_callee(self):
        source = """
def callee(x):
    return x
"""
        ns = {}
        exec(source, ns)
        self.compiler.extractor.source_code = source

        callee_code = self.compiler.extractor.convertFunction(ns["callee"], ssa=False)
        callee_cfg = transform.evaluate(self.compiler, callee_code)

        cloned = inline.CFGCloner().process(callee_cfg)

        self.assertEqual(len(cloned.code.codeparameters.params), 1)
        self.assertEqual(len(cloned.code.codeparameters.returnparams), 1)

    def test_cfg_inline_binds_arguments_and_materializes_return_values(self):
        callee_object = pyflow_ast.program.Object(object())
        parameter = pyflow_ast.Local("parameter")
        return_parameter = pyflow_ast.Local("return_parameter")
        callee = pyflow_ast.Code(
            "callee",
            pyflow_ast.CodeParameters(
                None,
                [],
                [],
                [parameter],
                ["parameter"],
                [],
                None,
                None,
                [return_parameter],
                None,
            ),
            pyflow_ast.Suite([pyflow_ast.Return([parameter])]),
        )
        callee_cfg = transform.CFGTransformer().process(callee)
        result = pyflow_ast.Local("result")
        call = pyflow_ast.Call(
            pyflow_ast.Existing(callee_object),
            [pyflow_ast.Existing(pyflow_ast.program.Object(7))],
            [],
            None,
            None,
        )
        caller = pyflow_ast.Code(
            "caller",
            pyflow_ast.CodeParameters(None, [], [], [], [], [], None, None, [], None),
            pyflow_ast.Suite([pyflow_ast.Assign(call, [result])]),
        )
        caller_cfg = transform.CFGTransformer().process(caller)

        remap = inline.evaluate(
            self.compiler, caller_cfg, {callee_object: callee_cfg}
        )

        self.assertEqual(len(remap.call_sites), 1)
        self.assertEqual(next(iter(remap.call_sites.values())), ())
        self.assertEqual(remap.allocation_sites, {})

        pending = [caller_cfg.entryTerminal]
        operations = []
        seen = set()
        while pending:
            block = pending.pop()
            if block in seen:
                continue
            seen.add(block)
            operations.extend(getattr(block, "ops", ()))
            pending.extend(block.forward())
        self.assertFalse(
            any(
                isinstance(op, (pyflow_ast.Return,))
                or isinstance(getattr(op, "expr", None), pyflow_ast.Call)
                for op in operations
            )
        )
        self.assertTrue(
            any(
                isinstance(op, pyflow_ast.Assign) and result in op.lcls
                for op in operations
            )
        )

    def test_transform_handles_global_and_nonlocal_declarations(self):
        source = """
def outer():
    x = 0
    def inner():
        nonlocal x
        return x
    global y
    return inner()
"""
        ns = {}
        exec(source, ns)
        self.compiler.extractor.source_code = source
        code = self.compiler.extractor.convertFunction(ns["outer"], ssa=False)

        g = transform.evaluate(self.compiler, code)
        self.assertIsNotNone(g)

    def test_transform_ignores_type_alias_markers(self):
        code = pyflow_ast.Code(
            "f",
            pyflow_ast.CodeParameters(
                selfparam=None,
                posonlyparams=[],
                posonlynames=[],
                params=[],
                paramnames=[],
                defaults=[],
                vparam=None,
                kparam=None,
                returnparams=[],
                type_params=None,
            ),
            pyflow_ast.Suite(
                [pyflow_ast.TypeAlias("Alias", [], pyflow_ast.Existing(pyflow_ast.program.Object(int)))]
            ),
        )
        graph = transform.evaluate(self.compiler, code)
        self.assertIsNotNone(graph)

    def test_transform_handles_plain_for_loop_without_assertion(self):
        source = """
def iterate(items):
    total = 0
    for item in items:
        total = item
    return total
"""
        ns = {}
        exec(source, ns)
        self.compiler.extractor.source_code = source
        code = self.compiler.extractor.convertFunction(ns["iterate"], ssa=False)

        graph = transform.evaluate(self.compiler, code)
        cdg = construct_cdg(graph)

        self.assertIsNotNone(graph)
        self.assertGreater(len(cdg.get_all_nodes()), 0)

    def test_transform_handles_for_else_without_duplicate_exit(self):
        source = """
def iterate(items):
    for item in items:
        seen = item
    else:
        seen = None
    return seen
"""
        ns = {}
        exec(source, ns)
        self.compiler.extractor.source_code = source
        code = self.compiler.extractor.convertFunction(ns["iterate"], ssa=False)

        graph = transform.evaluate(self.compiler, code)
        self.assertIsNotNone(graph)

    def test_for_loop_is_preserved_instead_of_rewritten_as_while(self):
        source = """
def iterate(items):
    for item in items:
        consume(item)
"""
        ns = {}
        exec(source, ns)
        self.compiler.extractor.source_code = source
        code = self.compiler.extractor.convertFunction(ns["iterate"], ssa=False)

        graph = transform.evaluate(self.compiler, code)
        structuralanalysis.evaluate(self.compiler, graph)

        self.assertEqual(len(graph.code.ast.blocks), 1)
        self.assertIsInstance(graph.code.ast.blocks[0], pyflow_ast.For)
        self.assertEqual(graph.code.ast.blocks[0].index.name, "item")

    def test_for_loop_has_iterator_header_and_loop_carried_ssa_phi(self):
        source = """
def iterate(items):
    value = None
    for item in items:
        value = item
    return value
"""
        ns = {}
        exec(source, ns)
        self.compiler.extractor.source_code = source
        code = self.compiler.extractor.convertFunction(ns["iterate"], ssa=False)
        graph = transform.evaluate(self.compiler, code)

        pending = [graph.entryTerminal]
        nodes = []
        seen = set()
        while pending:
            node = pending.pop()
            if node in seen:
                continue
            seen.add(node)
            nodes.append(node)
            pending.extend(node.forward())
        self.assertTrue(any(isinstance(node, cfg_graph.ForIter) for node in nodes))

        ssa.evaluate(self.compiler, graph)
        phis = [phi for node in nodes if isinstance(node, cfg_graph.Merge) for phi in node.phi]
        value_phis = [phi for phi in phis if phi.target.name == "value"]
        self.assertEqual(len(value_phis), 1)
        returns = [
            op
            for node in nodes
            for op in getattr(node, "ops", ())
            if isinstance(op, pyflow_ast.Return)
        ]
        self.assertIs(returns[0].exprs[0], value_phis[0].target)

    def test_gc_removes_matching_phi_argument_with_dead_predecessor(self):
        code = cfg_graph.Code()
        live = cfg_graph.Suite(None)
        dead = cfg_graph.Suite(None)
        merge = cfg_graph.Merge(None)

        code.entryTerminal.setExit("entry", live)
        live.setExit("normal", merge)
        dead.setExit("normal", merge)
        merge.setExit("normal", code.normalTerminal)
        merge.phi = [
            pyflow_ast.Phi(
                [pyflow_ast.Local("live"), pyflow_ast.Local("dead")],
                pyflow_ast.Local("target"),
            )
        ]

        gc.evaluate(self.compiler, code)

        self.assertEqual(merge.iterprev(), [(live, "normal")])
        self.assertEqual([arg.name for arg in merge.phi[0].arguments], ["live"])
        self.assertIsNone(dead.getExit("normal"))

    def test_cfg_dfs_handles_deep_linear_graph_iteratively(self):
        entry = cfg_graph.Entry(None)
        previous = entry
        exit_name = "entry"
        for _ in range(1500):
            current = cfg_graph.Suite(None)
            previous.setExit(exit_name, current)
            previous = current
            exit_name = "normal"

        traversal = dfs.CFGDFS()
        traversal.process(entry)
        self.assertEqual(len(traversal.processed), 1501)

    def test_dominator_construction_handles_deep_linear_graph_iteratively(self):
        entry = cfg_graph.Entry(None)
        previous = entry
        exit_name = "entry"
        for _ in range(1500):
            current = cfg_graph.Suite(None)
            previous.setExit(exit_name, current)
            previous = current
            exit_name = "normal"

        bound = {}
        roots = dom.evaluate(
            [entry],
            lambda node: node.forward(),
            lambda node, dj_node: bound.setdefault(node, dj_node),
        )

        self.assertEqual(len(bound), 1501)
        self.assertEqual(len(roots), 1)
        self.assertIs(roots[0].node, entry)

    def test_immediate_dominators_are_correct_for_irreducible_graph(self):
        edges = {
            0: (1, 2),
            1: (2, 3),
            2: (1, 2, 3),
            3: (2, 3),
        }

        idoms = dominator.findIDoms([0], edges.__getitem__)

        self.assertIsNone(idoms[0])
        self.assertEqual(idoms[1], 0)
        self.assertEqual(idoms[2], 0)
        self.assertEqual(idoms[3], 0)


if __name__ == "__main__":
    unittest.main()
