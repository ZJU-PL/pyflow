from __future__ import absolute_import
import unittest

import pyflow.analysis.cpa
import pyflow.application.makefile
import pyflow.application.program
from pyflow.frontend.programextractor import extractProgram


from pyflow.util.application.console import Console
from pyflow.application.context import CompilerContext

from pyflow.frontend.programextractor import Extractor
from pyflow.util.python import replaceGlobals


class TestCPA(unittest.TestCase):
    def assertIn(self, first, second, msg=None):
        """Fail if the one object is not in the other, using the "in" operator."""
        if first not in second:
            raise self.failureException((msg or "%r not in %r" % (first, second)))

    def assertLocalRefTypes(self, lcl, types):
        refs = lcl.annotation.references[0]

        # There's one reference returned, and it's an integer.
        self.assertEqual(len(refs), len(types))
        for ref in refs:
            self.assertIn(ref.xtype.obj.type, types)

    def testAdd(self):
        def func(a, b):
            return 2 * a + b

        # Prevent leakage?
        func = replaceGlobals(func, {})

        # TODO mock console?
        compiler = CompilerContext(Console())
        program = pyflow.application.program.Program()

        program.interface.func.append(
            (
                func,
                (
                    pyflow.application.interface.ExistingWrapper(3),
                    pyflow.application.interface.ExistingWrapper(5),
                ),
            )
        )

        compiler.program = program
        compiler.extractor = pyflow.frontend.programextractor.Extractor(compiler)

        extractProgram(compiler, program)
        result = pyflow.analysis.cpa.evaluate(compiler, program)

        # Check argument and return types
        funcobj, funcast = compiler.extractor.getObjectCall(func)
        types = set([compiler.extractor.getObject(int)])

        for param in funcast.codeparameters.params:
            self.assertLocalRefTypes(param, types)

        for param in funcast.codeparameters.returnparams:
            self.assertLocalRefTypes(param, types)


if __name__ == "__main__":
    unittest.main()
