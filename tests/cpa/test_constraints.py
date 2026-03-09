from __future__ import absolute_import
import unittest
from unittest.mock import Mock, MagicMock, patch

from pyflow.analysis.cpa.constraints import (
    AssignmentConstraint, IsConstraint, LoadConstraint, StoreConstraint, 
    AllocateConstraint, SimpleCheckConstraint, CallConstraint, AbstractCallConstraint
)
from pyflow.analysis.cpa.base import AnalysisContext
from pyflow.analysis.storegraph import storegraph
from pyflow.analysis import cpasignature
from pyflow.util.python import calling


class TestConstraintIntegration(unittest.TestCase):
    """集成测试：测试约束系统的复杂交互场景"""
    
    def setUp(self):
        # 创建模拟的约束系统
        self.mock_sys = Mock()
        self.mock_sys.dirty = []
        self.mock_sys.constraint = Mock()
        self.mock_sys.extractor = Mock()
        self.mock_sys.canonical = Mock()
        self.mock_sys.createAssign = Mock()
        self.mock_sys.logRead = Mock()
        self.mock_sys.logModify = Mock()
        self.mock_sys.logAllocation = Mock()
        self.mock_sys.extendedInstanceType = Mock()
        
        # 创建模拟的槽位节点
        self.slot_a = Mock(spec=storegraph.SlotNode)
        self.slot_b = Mock(spec=storegraph.SlotNode)
        self.slot_c = Mock(spec=storegraph.SlotNode)
        self.slot_obj = Mock(spec=storegraph.SlotNode)
        self.slot_field = Mock(spec=storegraph.SlotNode)
        self.slot_target = Mock(spec=storegraph.SlotNode)
        
        # 创建模拟操作
        self.op = Mock()
        self.op.context = Mock()
        
    def test_complex_dataflow_scenario(self):
        """测试复杂数据流场景：赋值 -> 对象创建 -> 属性访问 -> 条件检查"""
        
        # 1. 创建赋值约束: a = b
        assign_constraint = AssignmentConstraint(self.mock_sys, self.slot_b, self.slot_a)
        self.assertEqual(assign_constraint.sourceslot, self.slot_b)
        self.assertEqual(assign_constraint.destslot, self.slot_a)
        
        # 2. 创建对象分配约束: obj = SomeClass()
        allocate_constraint = AllocateConstraint(self.mock_sys, self.op, Mock(), self.slot_obj)
        self.assertEqual(allocate_constraint.target, self.slot_obj)
        
        # 3. 创建属性加载约束: field = obj.attr
        load_constraint = LoadConstraint(
            self.mock_sys, self.op, self.slot_obj, "SomeClass", 
            Mock(spec=storegraph.SlotNode), self.slot_field
        )
        self.assertEqual(load_constraint.expr, self.slot_obj)
        self.assertEqual(load_constraint.target, self.slot_field)
        
        # 4. 创建属性存储约束: obj.attr = value
        store_constraint = StoreConstraint(
            self.mock_sys, self.op, self.slot_obj, "SomeClass",
            Mock(spec=storegraph.SlotNode), self.slot_c
        )
        self.assertEqual(store_constraint.expr, self.slot_obj)
        self.assertEqual(store_constraint.value, self.slot_c)
        
        # 5. 创建条件检查约束: if obj:
        check_constraint = SimpleCheckConstraint(self.mock_sys, self.op, self.slot_obj, self.slot_target)
        self.assertEqual(check_constraint.slot, self.slot_obj)
        self.assertEqual(check_constraint.target, self.slot_target)
        
        # 验证约束基本属性
        self.assertIn("->", assign_constraint.name())
        self.assertEqual(check_constraint.name(), self.op.op)
        
        # 验证约束读取和写入关系
        self.assertEqual(assign_constraint.reads(), (self.slot_b,))
        self.assertEqual(assign_constraint.writes(), (self.slot_a,))
        self.assertEqual(store_constraint.writes(), ())

    def test_constraint_solving_workflow(self):
        """测试约束求解工作流程：标记 -> 处理 -> 更新"""
        
        # 创建简单检查约束: if obj:
        check_constraint = SimpleCheckConstraint(self.mock_sys, self.op, self.slot_obj, self.slot_target)
        
        # 模拟约束求解流程
        # 1. 标记约束为脏
        check_constraint.mark()
        self.assertTrue(check_constraint.dirty)
        self.assertIn(check_constraint, self.mock_sys.dirty)
        
        # 2. 测试发射操作
        mock_obj = Mock()
        mock_xtype = Mock()
        mock_cobj = Mock()
        self.mock_sys.extractor.getObject.return_value = mock_obj
        self.mock_sys.canonical.existingType.return_value = mock_xtype
        self.slot_target.initializeType.return_value = mock_cobj
        
        check_constraint.emit(42)
        self.mock_sys.extractor.getObject.assert_called_with(42)
        self.mock_sys.canonical.existingType.assert_called_with(mock_obj)
        self.slot_target.initializeType.assert_called_with(mock_xtype)
        self.mock_sys.logAllocation.assert_called_with(self.op, mock_cobj)
        
        # 3. 测试更新操作
        self.slot_obj.refs = True
        self.slot_obj.null = False
        check_constraint.update()
        self.assertTrue(check_constraint.refs)
        self.mock_sys.logRead.assert_called_with(self.op, self.slot_obj)
        
        # 4. 测试错误检测
        bad_slots = check_constraint.getBad()
        # print(bad_slots)
        self.assertIsInstance(bad_slots, list)

    def test_analysis_context_binds_kwargs_parameter(self):
        """**kwargs arguments should flow into the callee kparam slot."""
        signature = Mock()
        signature.selfparam = None
        signature.params = ()
        signature.code = Mock()
        context = AnalysisContext(signature, None, Mock())

        sys = Mock()
        sys.createAssign = Mock()
        sys.canonical.opContext.return_value = Mock()

        kparam_slot = Mock(spec=storegraph.SlotNode)
        caller_kargs = Mock(spec=storegraph.SlotNode)
        caller = calling.CallerArgs(None, [], [], None, caller_kargs, None)
        callee = calling.CalleeParams(None, (), (), (), None, kparam_slot, ())

        with patch(
            "pyflow.analysis.cpa.base.calleeSlotsFromContext", return_value=callee
        ), patch.object(AnalysisContext, "initalizeParameter") as init_param:
            context.bindParameters(sys, caller)

        init_param.assert_called_once_with(sys, None, None, None)
        sys.createAssign.assert_called_once_with(caller_kargs, kparam_slot)

    def test_abstract_call_constraint_preserves_kargs_in_caller(self):
        """Call constraint lowering should retain **kwargs information."""
        fake = Mock()
        fake.args = []
        fake.selfarg = None
        fake.vargs = None
        fake.kargs = Mock(spec=storegraph.SlotNode)
        fake.targets = None
        fake.cache = set()
        fake.sys = Mock()
        fake.getCode = Mock()

        code = Mock()
        callee = calling.CalleeParams(None, (), (), (), None, Mock(), ())
        code.codeParameters.return_value = callee
        fake.getCode.return_value = code

        expr = Mock()
        expr.obj = Mock()

        info = Mock()
        info.willSucceed.maybeTrue.return_value = True

        with patch(
            "pyflow.analysis.cpa.constraints.calling.callStackToParamsInfo",
            return_value=info,
        ) as info_fn, patch(
            "pyflow.analysis.cpa.constraints.SimpleCallConstraint"
        ) as simple_call:
            AbstractCallConstraint.finalCombination(fake, expr, None, Mock(), 0)

        info_fn.assert_called_once_with(callee, False, 0, False, set(), True)
        caller = simple_call.call_args[0][-1]
        self.assertIs(caller.kargs, fake.kargs)


if __name__ == "__main__":
    unittest.main()
