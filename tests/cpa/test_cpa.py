from __future__ import absolute_import
import unittest
import builtins

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
        # Get the Code object from the program's liveCode (the one processed by CPA)
        func_code = None
        for code in program.liveCode:
            if code.name == func.__name__:
                func_code = code
                break
        
        if func_code is None:
            self.fail(f"Could not find function {func.__name__} in program.liveCode")
        
        types = set([compiler.extractor.getObject(int)])

        for param in func_code.codeparameters.params:
            self.assertLocalRefTypes(param, types)

        for param in func_code.codeparameters.returnparams:
            self.assertLocalRefTypes(param, types)

    def test_conditional_execution(self):
        """Test CPA with conditional statements."""
        def func(x):
            if x > 0:
                return x * 2
            else:
                return x * -2

        func = replaceGlobals(func, {})

        compiler = CompilerContext(Console())
        program = pyflow.application.program.Program()

        program.interface.func.append(
            (func, (pyflow.application.interface.ExistingWrapper(5),))
        )

        compiler.program = program
        compiler.extractor = Extractor(compiler)

        extractProgram(compiler, program)
        result = pyflow.analysis.cpa.evaluate(compiler, program)

        # Find the function code
        func_code = None
        for code in program.liveCode:
            if code.name == func.__name__:
                func_code = code
                break

        self.assertIsNotNone(func_code, "Function code not found")

    def test_loop_analysis(self):
        """Test CPA with loop constructs."""
        def func():
            total = 0
            for i in range(3):
                total += i
            return total

        func = replaceGlobals(func, dict(vars(builtins)))

        compiler = CompilerContext(Console())
        program = pyflow.application.program.Program()

        program.interface.func.append((func, ()))

        compiler.program = program
        compiler.extractor = Extractor(compiler)

        extractProgram(compiler, program)
        result = pyflow.analysis.cpa.evaluate(compiler, program)

        # Find the function code
        func_code = None
        for code in program.liveCode:
            if code.name == func.__name__:
                func_code = code
                break

        self.assertIsNotNone(func_code, "Function code not found")

    def test_attribute_access(self):
        """Test CPA with attribute access."""
        def func():
            x = "hello"
            return len(x)

        func = replaceGlobals(func, dict(vars(builtins)))

        compiler = CompilerContext(Console())
        program = pyflow.application.program.Program()

        program.interface.func.append((func, ()))

        compiler.program = program
        compiler.extractor = Extractor(compiler)

        extractProgram(compiler, program)
        result = pyflow.analysis.cpa.evaluate(compiler, program)

        # Find the function code
        func_code = None
        for code in program.liveCode:
            if code.name == func.__name__:
                func_code = code
                break

        self.assertIsNotNone(func_code, "Function code not found")


if __name__ == "__main__":
    unittest.main()
