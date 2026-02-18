from __future__ import absolute_import
import unittest
from unittest.mock import Mock, MagicMock

from pyflow.analysis.cpa.codecloner import (
    createCodeMap, FunctionCloner, NullCloner
)
from pyflow.language.python import ast


class TestCreateCodeMap(unittest.TestCase):
    def setUp(self):
        self.mock_code1 = Mock()
        self.mock_code2 = Mock()
        self.mock_code3 = Mock()
        self.live_code = [self.mock_code1, self.mock_code2, self.mock_code3]

    def test_createCodeMap(self):
        # Mock the clone method
        cloned1 = Mock()
        cloned2 = Mock()
        cloned3 = Mock()
        self.mock_code1.clone.return_value = cloned1
        self.mock_code2.clone.return_value = cloned2
        self.mock_code3.clone.return_value = cloned3

        result = createCodeMap(self.live_code)

        # Check that clone was called on each code object
        self.mock_code1.clone.assert_called_once()
        self.mock_code2.clone.assert_called_once()
        self.mock_code3.clone.assert_called_once()

        # Check the mapping
        self.assertEqual(len(result), 3)
        self.assertEqual(result[self.mock_code1], cloned1)
        self.assertEqual(result[self.mock_code2], cloned2)
        self.assertEqual(result[self.mock_code3], cloned3)


class TestFunctionCloner(unittest.TestCase):
    def setUp(self):
        self.mock_code1 = Mock()
        self.mock_code2 = Mock()
        self.live_code = [self.mock_code1, self.mock_code2]
        
        # Mock the cloned codes
        self.cloned_code1 = Mock()
        self.cloned_code2 = Mock()
        self.mock_code1.clone.return_value = self.cloned_code1
        self.mock_code2.clone.return_value = self.cloned_code2
        
        self.cloner = FunctionCloner(self.live_code)

    def test_initialization(self):
        self.assertEqual(len(self.cloner.codeMap), 2)
        self.assertEqual(self.cloner.codeMap[self.mock_code1], self.cloned_code1)
        self.assertEqual(self.cloner.codeMap[self.mock_code2], self.cloned_code2)

    def test_visitLocal_new_local(self):
        local = ast.Local("test_var")
        cloned_local = ast.Local("test_var")
        
        # Create a mock that replaces the local object
        mock_local = Mock()
        mock_local.clone.return_value = cloned_local
        
        # Initialize the cloner first to create localMap
        self.cloner.process(self.mock_code1)
        
        result = self.cloner.visitLocal(mock_local)
        
        self.assertEqual(result, cloned_local)
        mock_local.clone.assert_called_once()
        self.assertIn(mock_local, self.cloner.localMap)
        self.assertEqual(self.cloner.localMap[mock_local], cloned_local)

    def test_visitLocal_existing_local(self):
        local = ast.Local("test_var")
        cloned_local = ast.Local("test_var")
        
        # Initialize the cloner first to create localMap
        self.cloner.process(self.mock_code1)
        self.cloner.localMap[local] = cloned_local
        
        result = self.cloner.visitLocal(local)
        
        self.assertEqual(result, cloned_local)

    def test_visitCode(self):
        result = self.cloner.visitCode(self.mock_code1)
        self.assertEqual(result, self.cloned_code1)

    def test_visitCode_not_in_map(self):
        # Bug #10 fix: visitCode used to return None for dead direct calls
        # (code objects not in liveCode / codeMap).  The fix makes it return
        # the *original* node instead, so that downstream passes that
        # dereference the code field don't crash with AttributeError.
        unknown_code = Mock()
        result = self.cloner.visitCode(unknown_code)
        # The original node must be returned (not None).
        self.assertIs(result, unknown_code)

    def test_visitLeaf(self):
        leaf = "test_string"
        result = self.cloner.visitLeaf(leaf)
        self.assertEqual(result, leaf)

    def test_default(self):
        # Test with a mock node that has rewriteCloned
        mock_node = Mock()
        mock_node.__shared__ = False
        mock_result = Mock()
        mock_node.rewriteCloned.return_value = mock_result
        
        # Initialize the cloner first to create opMap
        self.cloner.process(self.mock_code1)
        
        result = self.cloner.default(mock_node)
        
        self.assertEqual(result, mock_result)
        mock_node.rewriteCloned.assert_called_once_with(self.cloner)
        self.assertIn(mock_node, self.cloner.opMap)
        self.assertEqual(self.cloner.opMap[mock_node], mock_result)

    def test_default_shared_node(self):
        # Test with a shared node (should raise assertion)
        mock_node = Mock()
        mock_node.__shared__ = True
        
        with self.assertRaises(AssertionError):
            self.cloner.default(mock_node)

    def test_process(self):
        # Mock the replaceChildren method
        self.cloned_code1.replaceChildren = Mock()
        self.cloned_code2.replaceChildren = Mock()
        
        self.cloner.process(self.mock_code1)
        
        # Check that localMap and opMap are initialized
        self.assertIsNotNone(self.cloner.localMap)
        self.assertIsNotNone(self.cloner.opMap)
        
        # Check that replaceChildren was called
        self.cloned_code1.replaceChildren.assert_called_once_with(self.cloner)

    def test_op(self):
        mock_op = Mock()
        mock_cloned_op = Mock()
        
        # Initialize the cloner first to create opMap
        self.cloner.process(self.mock_code1)
        self.cloner.opMap[mock_op] = mock_cloned_op
        
        result = self.cloner.op(mock_op)
        self.assertEqual(result, mock_cloned_op)

    def test_lcl(self):
        mock_local = Mock()
        mock_cloned_local = Mock()
        
        # Initialize the cloner first to create localMap
        self.cloner.process(self.mock_code1)
        self.cloner.localMap[mock_local] = mock_cloned_local
        
        result = self.cloner.lcl(mock_local)
        self.assertEqual(result, mock_cloned_local)

    def test_code(self):
        result = self.cloner.code(self.mock_code1)
        self.assertEqual(result, self.cloned_code1)


class TestNullCloner(unittest.TestCase):
    def setUp(self):
        self.live_code = [Mock(), Mock()]
        self.cloner = NullCloner(self.live_code)

    def test_initialization(self):
        # NullCloner should not do anything in __init__
        self.assertIsNotNone(self.cloner)

    def test_process(self):
        # process should do nothing
        mock_code = Mock()
        self.cloner.process(mock_code)
        # No assertions needed - just ensure no exceptions

    def test_op(self):
        mock_op = Mock()
        result = self.cloner.op(mock_op)
        self.assertEqual(result, mock_op)

    def test_lcl(self):
        mock_local = Mock()
        result = self.cloner.lcl(mock_local)
        self.assertEqual(result, mock_local)

    def test_code(self):
        mock_code = Mock()
        result = self.cloner.code(mock_code)
        self.assertEqual(result, mock_code)


if __name__ == "__main__":
    unittest.main()
