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
from pyflow.language.python.simplecodegen import SimpleCodeGen
from pyflow.language.python import ast
from pyflow.ir.core import IRRemap, ValueId, verify_catalog


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
            if block_id.code == catalog.procedure(code).code_id
            and hasattr(block, "ops")
            for op in block.ops
            if isinstance(op, ast.Assign)
        ]
        self.assertTrue(assignments)
        self.assertTrue(
            any(
                any(isinstance(identity, ValueId) for identity in catalog.semantics_of(op, code=code).definitions)
                for op in assignments
            )
        )
        verify_catalog(catalog)


if __name__ == "__main__":
    unittest.main()
