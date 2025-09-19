from __future__ import absolute_import
import unittest

from pyflow.util.typedispatch import *


class TestTypeDisbatch(unittest.TestCase):
    def testTD(self):
        def visitNumber(self, node):
            return "number"

        def visitDefault(self, node):
            return "default"

        class FooBar(TypeDispatcher):
            num = dispatch(int)(visitNumber)
            default = defaultdispatch(visitDefault)

        self.assertEqual(FooBar.__dict__["num"], visitNumber)
        self.assertEqual(FooBar.__dict__["default"], visitDefault)

        foo = FooBar()

        self.assertEqual(foo(1), "number")
        self.assertEqual(foo(2**70), "number")
        self.assertEqual(foo(1.0), "default")


import pyflow.util.python.calling
from pyflow.util.tvl import *


class TestCallingUtility(unittest.TestCase):
    def testExact(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [], None, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee, False, 2, False, 0, False
        )

        self.assertEqual(info.willSucceed, TVLTrue)

        self.assertTransfer(info.argParam, 0, 2, 0, 2, 2)
        self.assertEqual(info.argVParam.active, False)

        self.assertEqual(info.uncertainParam, False)
        self.assertEqual(info.uncertainVParam, False)

    def assertHardFail(self, info):
        self.assertEqual(info.willSucceed, TVLFalse)

        self.assertEqual(info.argParam.active, False)
        self.assertEqual(info.argVParam.active, False)

        self.assertEqual(info.uncertainParam, False)
        self.assertEqual(info.uncertainVParam, False)

    def assertHardSucceed(self, info):
        self.assertEqual(info.willSucceed, TVLTrue)

    def assertTransfer(
        self, transfer, sourceBegin, sourceEnd, destinationBegin, destinationEnd, count
    ):
        self.assertEqual(transfer.active, True)
        self.assertEqual(transfer.sourceBegin, sourceBegin)
        self.assertEqual(transfer.sourceEnd, sourceEnd)
        self.assertEqual(transfer.destinationBegin, destinationBegin)
        self.assertEqual(transfer.destinationEnd, destinationEnd)
        self.assertEqual(transfer.count, count)

    def testTooManyArgs(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [], None, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee, False, 3, False, 0, False
        )
        self.assertHardFail(info)

    def testTooFewArgs(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [], None, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee, False, 1, False, 0, False
        )
        self.assertHardFail(info)

    ### Vargs ###

    def testExactSpill(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [], 2, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee, False, 4, False, 0, False
        )

        self.assertHardSucceed(info)

        self.assertTransfer(info.argParam, 0, 2, 0, 2, 2)
        self.assertTransfer(info.argVParam, 2, 4, 0, 2, 2)

        self.assertEqual(info.uncertainParam, False)
        self.assertEqual(info.uncertainVParam, False)

    def testUncertainPullVargs(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [], 2, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee, False, 1, True, 0, False
        )

        self.assertEqual(info.willSucceed, TVLMaybe)

        self.assertTransfer(info.argParam, 0, 1, 0, 1, 1)
        self.assertEqual(info.argVParam.active, False)

        self.assertEqual(info.uncertainParam, True)
        self.assertEqual(info.uncertainParamStart, 1)

        self.assertEqual(info.uncertainVParam, True)

    def testUncertainPull(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [], None, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee, False, 1, True, 0, False
        )

        self.assertEqual(info.willSucceed, TVLMaybe)

        self.assertTransfer(info.argParam, 0, 1, 0, 1, 1)
        self.assertEqual(info.argVParam.active, False)

        self.assertEqual(info.uncertainParam, True)
        self.assertEqual(info.uncertainParamStart, 1)

        self.assertEqual(info.uncertainVParam, False)

    ### Known keywords ###

    def testSemiKeyword(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [], None, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee, False, 1, False, ("b",), False
        )

        self.assertHardSucceed(info)

        self.assertTransfer(info.argParam, 0, 1, 0, 1, 1)
        self.assertEqual(info.argVParam.active, False)

        self.assertEqual(info.uncertainParam, False)
        self.assertEqual(info.uncertainVParam, False)

        self.assertTrue(1 in info.certainKeywords)

    def testAllKeyword(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [], None, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee,
            False,
            0,
            False,
            (
                "a",
                "b",
            ),
            False,
        )

        self.assertHardSucceed(info)

        self.assertEqual(info.argParam.active, False)
        self.assertEqual(info.argVParam.active, False)
        self.assertEqual(info.uncertainParam, False)
        self.assertEqual(info.uncertainVParam, False)

        self.assertTrue(0 in info.certainKeywords)
        self.assertTrue(1 in info.certainKeywords)

    def testRedundantKeyword(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [], None, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee, False, 1, False, ("a",), False
        )
        self.assertHardFail(info)

    def testBogusKeyword(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [], None, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee, False, 2, False, ("c",), False
        )
        self.assertHardFail(info)

    ### Deaults ###

    def testIncompleteDefaults(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [2], None, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee, False, 0, False, (), False
        )
        self.assertHardFail(info)

    def testUsedDefaults(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [2], None, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee, False, 1, False, (), False
        )

        self.assertEqual(info.willSucceed, TVLTrue)
        self.assertTransfer(info.argParam, 0, 1, 0, 1, 1)
        self.assertEqual(info.argVParam.active, False)
        self.assertEqual(info.uncertainParam, False)
        self.assertEqual(info.uncertainVParam, False)

        self.assertTrue(1 in info.defaults)

    def testUnusedDefaults(self):
        callee = pyflow.util.python.calling.CalleeParams(
            None, [0, 1], ["a", "b"], [2], None, None, []
        )
        info = pyflow.util.python.calling.callStackToParamsInfo(
            callee, False, 2, False, (), False
        )

        self.assertEqual(info.willSucceed, TVLTrue)
        self.assertTransfer(info.argParam, 0, 2, 0, 2, 2)
        self.assertEqual(info.argVParam.active, False)
        self.assertEqual(info.uncertainParam, False)
        self.assertEqual(info.uncertainVParam, False)

        self.assertTrue(not info.defaults, info.defaults)


if __name__ == "__main__":
    unittest.main()
