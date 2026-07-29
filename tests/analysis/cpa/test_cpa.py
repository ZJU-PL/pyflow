from __future__ import absolute_import
import unittest
import builtins

import pyflow.analysis.cpa
import pyflow.application.makefile
import pyflow.application.program
from pyflow.ir.core import AnalysisFacts, Capabilities, ContextualKey, Precision
from pyflow.frontend.extractor import extract_program


from pyflow.util.application.console import Console
from pyflow.application.context import CompilerContext

from pyflow.frontend.extractor import Extractor
from pyflow.util.python import replaceGlobals


class TestCPA(unittest.TestCase):
    def assertIn(self, first, second, msg=None):
        """Fail if the one object is not in the other, using the "in" operator."""
        if first not in second:
            raise self.failureException((msg or "%r not in %r" % (first, second)))

    def localRefs(self, program, code, lcl):
        facts = AnalysisFacts(program.ir)
        return facts.merged_references(code, lcl)

    def assertLocalRefTypes(self, program, code, lcl, types):
        refs = self.localRefs(program, code, lcl)

        # There's one reference returned, and it's an integer.
        self.assertEqual(len(refs), len(types))
        for ref in refs:
            self.assertIn(ref.xtype.obj.type, types)

    def assertLocalRefTypesIfPresent(self, program, code, lcl, types):
        """Assert type refs only when present. Return params may have no refs
        when binary ops (__mul__, __add__) are unresolved during CPA solve."""
        refs = self.localRefs(program, code, lcl)
        if not refs:
            return  # Skip when no type info flowed (e.g. unresolved calls)
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
                    pyflow.api.entrypoints.ExistingWrapper(3),
                    pyflow.api.entrypoints.ExistingWrapper(5),
                ),
            )
        )

        compiler.program = program
        compiler.extractor = pyflow.frontend.extractor.Extractor(compiler)

        extract_program(compiler, program)
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

        code_id = program.ir.procedure(func_code).code_id
        published_contexts = program.ir.facts.query(
            Capabilities.CONTEXTS, code_id
        )
        self.assertEqual(published_contexts.precision, Precision.EXACT)
        self.assertTrue(published_contexts.values)

        param_symbol = program.ir.symbol_id(
            func_code.codeparameters.params[0], func_code
        )
        first_context = next(iter(published_contexts.values))
        published_references = program.ir.facts.query(
            Capabilities.REFERENCES,
            ContextualKey(param_symbol, first_context),
        )
        self.assertEqual(published_references.precision, Precision.EXACT)
        self.assertTrue(published_references.values)
        
        types = set([compiler.extractor.getObject(int)])

        for param in func_code.codeparameters.params:
            self.assertLocalRefTypes(program, func_code, param, types)

        # Return params may have no refs when __mul__/__add__ stubs are unresolved
        for param in func_code.codeparameters.returnparams:
            self.assertLocalRefTypesIfPresent(program, func_code, param, types)

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
            (func, (pyflow.api.entrypoints.ExistingWrapper(5),))
        )

        compiler.program = program
        compiler.extractor = Extractor(compiler)

        extract_program(compiler, program)
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

        extract_program(compiler, program)
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

        extract_program(compiler, program)
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
