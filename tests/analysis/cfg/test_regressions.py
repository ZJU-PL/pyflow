import unittest

from pyflow.application import context
from pyflow.application.errors import TemporaryLimitation
from pyflow.analysis.cdg import construct_cdg
from pyflow.frontend.extractor import Extractor
from pyflow.analysis.cfg import (
    graph as cfg_graph,
    inline,
    killflow,
    ssa,
    structuralanalysis,
    transform,
)
from pyflow.language.python import ast as pyflow_ast


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

        renamer = ssa.SSARename(None, set(), {merge: {original}})
        renamer.frames = {
            merge: {original: target},
            prev_true: {original: arg},
            prev_false: {},
        }
        renamer.read = {target}
        renamer.fixup = [merge]

        renamer.doFixup()

        self.assertEqual(len(merge.phi), 1)
        self.assertEqual(merge.phi[0].arguments, [arg, None])

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

        cloned = inline.CFGCloner([]).process(callee_cfg)

        self.assertEqual(len(cloned.code.codeparameters.params), 1)
        self.assertEqual(len(cloned.code.codeparameters.returnparams), 1)

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


if __name__ == "__main__":
    unittest.main()
