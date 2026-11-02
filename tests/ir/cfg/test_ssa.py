import unittest

from pyflow.application import context
from pyflow.frontend.extractor import Extractor
from pyflow.ir.cfg import (
    transform,
    dump,
    ssa,
    expandphi,
    simplify,
    structuralanalysis,
)
from pyflow.ir.cfg import graph as cfg_graph
from pyflow.language.python.simplecodegen import SimpleCodeGen
from pyflow.language.python import ast
from pyflow.ir.core import IRRemap, ValueId, verify_catalog
from pyflow.ir.cfg.verifier import verify_ssa


def split(a, b):
    c = a
    if a:
        d = b
    else:
        d = -b
    return c, d


def doubleSplit(s, t):
    a = 1

    if s:
        if t:
            a = 2
        else:
            a = 3
    return a


def loop(a, b):
    count = 0

    while a:
        a -= 1
        count += 1
        reduceC = count / 2

        if b:
            break
    else:
        reduceC += 1

    return reduceC


def walrus_condition(xs):
    if (n := len(xs)) > 3:
        return n
    return 0


def chained_comparison(a, b, c):
    return a < b < c


def walrus_loop_break(items, g):
    x = 0
    for i in items:
        if (x := g(i)) is None:
            break
    return x


def dloop():
    count = 0

    while True:
        if count % 7:
            break
        count += 1

    return count


def parallax(tse, td):
    stepDepth = 1.0 / 16.0
    depth = 1.0

    while depth > 0.0:
        depth -= stepDepth

    return depth


def psimp(a):
    if a > 0:
        while a > 0:
            a -= 1
    return a


def read_after_delete():
    value = 1
    del value
    return value


def read_after_exception_target():
    try:
        raise ValueError()
    except ValueError as error:
        pass
    return error


class TestSSA(unittest.TestCase):
    def setUp(self):
        self.compiler = context.CompilerContext(None)
        self.compiler.extractor = Extractor(self.compiler)

    def decompile(self, func):
        return self.compiler.extractor.convertFunction(func, ssa=False)

    def runFunction(self, func, trace=False):
        code = self.decompile(func)

        if trace:
            # pprint(code)
            SimpleCodeGen(None).process(code)

        g = transform.evaluate(self.compiler, code)

        ssa.evaluate(self.compiler, g)
        expandphi.evaluate(self.compiler, g)
        simplify.evaluate(self.compiler, g)

        structuralanalysis.evaluate(self.compiler, g)

        if trace:
            dump.evaluate(self.compiler, g)

        if trace:
            # pprint(code)
            SimpleCodeGen(None).process(code)

            # dump.evaluate(self.compiler, g)

    def testSplit(self):
        self.runFunction(split)

    def testDoubleSplit(self):
        self.runFunction(doubleSplit)

    def testLoop(self):
        self.runFunction(loop)

    def testDLoop(self):
        self.runFunction(dloop)

    def testParallax(self):
        self.runFunction(parallax)

    def testPSimp(self):
        self.runFunction(psimp)

    def _cfg_blocks(self, graph):
        seen = set()
        pending = [graph.entryTerminal]
        while pending:
            block = pending.pop(0)
            if block in seen:
                continue
            seen.add(block)
            yield block
            pending.extend(block.next.values())

    def test_walrus_in_switch_condition_is_valid_ssa(self):
        code = self.decompile(walrus_condition)
        graph = transform.evaluate(self.compiler, code)
        ssa.evaluate(self.compiler, graph)
        verify_ssa(graph, code.ir_catalog)

    def test_chained_comparison_lowering_is_valid_ssa(self):
        code = self.decompile(chained_comparison)
        graph = transform.evaluate(self.compiler, code)
        ssa.evaluate(self.compiler, graph)
        verify_ssa(graph, code.ir_catalog)

    def test_walrus_in_loop_condition_gets_exit_phi(self):
        code = self.decompile(walrus_loop_break)
        graph = transform.evaluate(self.compiler, code)
        ssa.evaluate(self.compiler, graph)
        verify_ssa(graph, code.ir_catalog)

        # The loop-exit merge must join the pre-loop ``x = 0`` with the value
        # bound by the walrus.  Without the definition recorded in the switch
        # condition no phi is emitted and the return reads a non-dominating
        # value instead.
        x_measures = [
            phi
            for block in self._cfg_blocks(graph)
            if isinstance(block, cfg_graph.Merge)
            for phi in block.phi
            if getattr(phi.target, "name", None) == "x" and len(phi.arguments) == 2
        ]
        self.assertTrue(x_measures)

    def test_undefined_reads_are_explicit_and_ssa_is_verified(self):
        for function in (read_after_delete, read_after_exception_target, split, loop):
            code = self.decompile(function)
            graph = transform.evaluate(self.compiler, code)
            ssa.evaluate(self.compiler, graph)
            verify_ssa(graph, code.ir_catalog)

        catalog = code.ir_catalog
        # ``loop`` is the last function in the loop above; exercise the
        # undefined cases separately so the assertion is tied to their code.
        for function in (read_after_delete, read_after_exception_target):
            code = self.decompile(function)
            graph = transform.evaluate(self.compiler, code)
            ssa.evaluate(self.compiler, graph)
            values = tuple(code.ir_catalog.values)
            self.assertTrue(any(value.undefined for value in values))
            verify_ssa(graph, code.ir_catalog)

    def test_ssa_registers_typed_values_and_value_semantics(self):
        code = self.decompile(split)
        graph = transform.evaluate(self.compiler, code)

        before = code.ir_catalog.revision
        remap = ssa.evaluate(self.compiler, graph)

        self.assertIsInstance(remap, IRRemap)
        self.assertEqual(remap.before, before)
        self.assertTrue(remap.changed)
        self.assertEqual(remap.after, code.ir_catalog.revision)

        catalog = code.ir_catalog
        values = tuple(catalog.values)
        self.assertTrue(values)
        self.assertTrue(all(value.id.symbol in {s.id for s in catalog.symbols} for value in values))

        assignments = [
            op
            for block_id, block in catalog.blocks()
            if block_id.code == catalog.procedure(code).code_id and hasattr(block, "ops")
            for op in block.ops
            if isinstance(op, ast.Assign)
        ]
        self.assertTrue(assignments)
        self.assertTrue(
            any(
                any(
                    isinstance(identity, ValueId)
                    for identity in catalog.semantics_of(op, code=code).definitions
                )
                for op in assignments
            )
        )
        verify_catalog(catalog)


if __name__ == "__main__":
    unittest.main()
