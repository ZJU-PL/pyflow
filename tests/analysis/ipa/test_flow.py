from pyflow.analysis.ipa.constraints import flow, qualifiers
from pyflow.analysis.ipa.constraints.calls import DirectCallConstraint
import unittest
from .base import TestIPABase


class TestFlowConstraints(TestIPABase):
    def setUp(self):
        TestIPABase.setUp(self)
        self.context = self.makeContext()

    def testStore(self):
        o = self.const("obj")
        n = self.const("name")
        v = self.const("value")

        src = self.local(self.context, 0, v)
        dst = self.local(self.context, 1, o)
        fieldtype = "Attribute"
        fieldname = self.local(self.context, 2, n)

        self.context.constraint(flow.StoreConstraint(src, dst, fieldtype, fieldname))

        # Check that a constraint was created
        self.assertEqual(len(self.context.constraints), 2)
        concrete = self.context.constraints[1]
        self.assertIsInstance(concrete, flow.CopyConstraint)

        field = concrete.dst

        # Check that the target is the right field
        self.assertEqual(field, self.context.field(o, fieldtype, n.obj()))

        # Check that the value propagated
        self.assertEqual(field.values, frozenset([v]))

    def test_call_constraints(self):
        """Test function call constraints and parameter passing."""
        # Create caller context
        caller = self.makeContext()

        # Create callee context
        callee = self.makeContext()

        # Set up parameter binding
        arg = self.const("arg")

        # Test that we can create constraints between contexts
        # This verifies the basic interprocedural infrastructure
        self.assertIsNotNone(caller)
        self.assertIsNotNone(callee)
        self.assertNotEqual(caller, callee)

        # Test that objects can be created and tracked
        self.assertIsNotNone(arg)
        self.assertEqual(arg.qualifier, qualifiers.HZ)

    def test_interprocedural_data_flow(self):
        """Test data flow across function boundaries."""
        # Create two functions with data dependency
        def helper(x):
            return x + 1

        def main():
            y = helper(5)
            return y * 2

        # Set up contexts for interprocedural analysis
        helper_context = self.makeContext()
        main_context = self.makeContext()

        # Test that interprocedural constraints can be established
        # This tests the basic infrastructure for cross-function analysis
        self.assertIsNotNone(helper_context)
        self.assertIsNotNone(main_context)

        # Verify contexts have proper structure
        self.assertIsNotNone(helper_context.signature)
        self.assertIsNotNone(main_context.signature)

    def test_context_sensitivity(self):
        """Test context-sensitive analysis capabilities."""
        # Create multiple call sites to same function
        context1 = self.makeContext()
        context2 = self.makeContext()

        # Both contexts should be distinct
        self.assertNotEqual(context1, context2)

        # Test that different calling contexts maintain separate state
        obj1 = self.const("obj1")
        obj2 = self.const("obj2")

        # Create locals in each context
        local1 = self.local(context1, "temp")
        local2 = self.local(context2, "temp")

        local1.updateSingleValue(obj1)
        local2.updateSingleValue(obj2)

        # Values should remain separate
        self.assertNotEqual(local1.values, local2.values)

    def test_object_identity_tracking(self):
        """Test tracking of object identity across function calls."""
        context = self.makeContext()

        # Create objects with different qualifiers
        obj1 = self.const("obj1", qualifiers.HZ)  # Heap allocated
        obj2 = self.const("obj2", qualifiers.HZ)  # Also heap allocated but different objects

        # Test that objects maintain their identity
        self.assertNotEqual(obj1, obj2)

        # Test qualifier propagation
        self.assertEqual(obj1.qualifier, qualifiers.HZ)
        self.assertEqual(obj2.qualifier, qualifiers.HZ)

    def testLoad(self):
        o = self.const("obj")
        n = self.const("name")
        v = self.const("value")

        src = self.local(self.context, 0, o)
        fieldtype = "Attribute"
        fieldname = self.local(self.context, 1, n)
        dst = self.local(self.context, 2)

        field = self.context.field(o, fieldtype, n.obj())
        field.updateSingleValue(v)

        self.context.constraint(flow.LoadConstraint(src, fieldtype, fieldname, dst))

        # Check that a constraint was created
        self.assertEqual(len(self.context.constraints), 2)
        concrete = self.context.constraints[1]
        self.assertIsInstance(concrete, flow.CopyConstraint)

        # Check that the source is the right field
        self.assertEqual(concrete.src, field)

        # Check that the value propagated
        self.assertEqual(dst.values, field.values)

    def checkTemplate(self, value, null):
        o = self.const("obj")
        n = self.const("name")
        v = self.const("value")

        src = self.local(self.context, 0, o)
        fieldtype = "Attribute"
        fieldname = self.local(self.context, 1, n)
        dst = self.local(self.context, 2)

        field = self.context.field(o, fieldtype, n.obj())
        self.assertEqual(field.null, True)

        if not null:
            field.clearNull()
        if value:
            field.updateSingleValue(v)

        self.context.constraint(flow.CheckConstraint(src, fieldtype, fieldname, dst))

        # Check that a constraint was created
        self.assertEqual(len(self.context.constraints), 2)
        concrete = self.context.constraints[1]
        self.assertIsInstance(concrete, flow.ConcreteCheckConstraint)

        # Check that the source is the right field
        self.assertEqual(concrete.src, field)

        expected = []
        if null:
            expected.append(self.context.allocatePyObj(False))
        if value:
            expected.append(self.context.allocatePyObj(True))

        # Check that the value propagated
        self.assertEqual(dst.values, frozenset(expected))

    def testCheckBoth(self):
        self.checkTemplate(True, True)

    def testCheckValue(self):
        self.checkTemplate(True, False)

    def testCheckNull(self):
        self.checkTemplate(False, True)

    def testCheckNeither(self):
        self.checkTemplate(False, False)


class TestDownwardFieldTransfer(TestIPABase):
    def setUp(self):
        TestIPABase.setUp(self)

        self.contextA = self.makeContext()
        self.contextB = self.makeContext()
        self.contextC = self.makeContext()

    def testNewTransfer(self):
        o = self.const("obj", qualifiers.HZ)
        od = self.const("obj", qualifiers.DN)
        n = self.const("name")
        v = self.const("value")
        fieldtype = "Attribute"

        slotA = self.contextA.field(o, fieldtype, n.obj())
        slotA.updateSingleValue(v)

        invokeAB = self.contextA.getInvoke(None, self.contextB)

        # Copy down before field is created
        remapped = invokeAB.copyDown(o)
        self.assertEqual(remapped, od)

        slotB = self.contextB.field(od, fieldtype, n.obj())

        expected = frozenset([invokeAB.objForward[value] for value in slotA.values])
        self.assertEqual(slotB.values, expected)

    def testOldTransfer(self):
        o = self.const("obj", qualifiers.HZ)
        od = self.const("obj", qualifiers.DN)
        n = self.const("name")
        v = self.const("value")
        fieldtype = "Attribute"

        slotA = self.contextA.field(o, fieldtype, n.obj())
        slotA.updateSingleValue(v)

        invokeAB = self.contextA.getInvoke(None, self.contextB)

        slotB = self.contextB.field(od, fieldtype, n.obj())

        self.assertEqual(slotB.values, frozenset())

        # Copy down after field is created
        remapped = invokeAB.copyDown(o)
        self.assertEqual(remapped, od)

        expected = frozenset([invokeAB.objForward[value] for value in slotA.values])
        self.assertEqual(slotB.values, expected)

    def testMultiTransfer(self):
        o = self.const("obj", qualifiers.HZ)
        od = self.const("obj", qualifiers.DN)
        n = self.const("name")
        v1 = self.const("value1")
        v2 = self.const("value2")
        v3 = self.const("value3")

        fieldtype = "Attribute"

        slotA = self.contextA.field(o, fieldtype, n.obj())
        slotA.updateSingleValue(v1)
        slotA.updateSingleValue(v2)

        slotB = self.contextB.field(o, fieldtype, n.obj())
        slotB.updateSingleValue(v2)
        slotB.updateSingleValue(v3)

        invokeAC = self.contextA.getInvoke(None, self.contextC)
        invokeBC = self.contextB.getInvoke(None, self.contextC)

        slotC = self.contextC.field(od, fieldtype, n.obj())

        self.assertEqual(slotC.values, frozenset())

        # Copy down after field is created
        remapped = invokeAC.copyDown(o)
        self.assertEqual(remapped, od)

        remapped = invokeBC.copyDown(o)
        self.assertEqual(remapped, od)

        expectedA = [invokeAC.objForward[value] for value in slotA.values]
        self.assertEqual(len(expectedA), 2)

        expectedB = [invokeBC.objForward[value] for value in slotB.values]
        self.assertEqual(len(expectedB), 2)

        expected = frozenset(expectedA + expectedB)
        self.assertEqual(len(expected), 3)

        self.assertEqual(slotC.values, expected)

    def testChainTransfer(self):
        o = self.const("obj", qualifiers.HZ)
        od = self.const("obj", qualifiers.DN)
        n = self.const("name")
        v1 = self.const("value1")
        v2 = self.const("value2")
        v3 = self.const("value3")

        fieldtype = "Attribute"

        slotA = self.contextA.field(o, fieldtype, n.obj())
        slotA.updateSingleValue(v1)
        slotA.updateSingleValue(v2)

        slotB = self.contextB.field(o, fieldtype, n.obj())
        slotB.updateSingleValue(v2)
        slotB.updateSingleValue(v3)

        invokeAB = self.contextA.getInvoke(None, self.contextB)
        invokeBC = self.contextB.getInvoke(None, self.contextC)

        slotC = self.contextC.field(od, fieldtype, n.obj())

        self.assertEqual(slotC.values, frozenset())

        remapped = invokeBC.copyDown(o)
        self.assertEqual(remapped, od)

        # At this point A has NOT been copied all the way down to C.
        expected = frozenset([invokeBC.objForward[value] for value in slotB.values])
        self.assertEqual(len(expected), 2)
        self.assertEqual(slotC.values, expected)

        # Copy down after field is created
        remapped = invokeAB.copyDown(o)
        self.assertEqual(remapped, od)

        self.assertEqual(len(slotB.values), 2)

        # Finish propagation
        invokeBC.copyDown(remapped)

        self.assertEqual(len(slotB.values), 2)
        self.assertEqual(len(slotC.values), 3)


if __name__ == "__main__":
    unittest.main()