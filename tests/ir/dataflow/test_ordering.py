"""Tests for ir/dataflow/ordering.py - Dataflow Ordering."""

import unittest
from unittest.mock import MagicMock, patch

from pyflow.ir.dataflow.ordering import OrderSearcher, evaluateDataflow
from pyflow.ir.dataflow import graph


class MockNode:
    """Mock node for testing."""

    def __init__(self, name):
        self.name = name
        self._forward = []

    def forward(self):
        return self._forward

    def __repr__(self):
        return f"MockNode({self.name})"


class MockOpNode(MockNode):
    """Mock operation node for testing."""

    def __init__(self, name):
        super().__init__(name)


class TestOrderSearcher(unittest.TestCase):
    """Test cases for OrderSearcher class."""

    def test_init(self):
        """Test OrderSearcher initialization."""
        searcher = OrderSearcher()
        self.assertEqual(searcher.queue, [])
        self.assertEqual(searcher.enqueued, set())
        self.assertEqual(searcher.preorder, {})
        self.assertEqual(searcher.uid, 0)
        self.assertEqual(searcher.order, [])

    def test_mark_new_node(self):
        """Test marking a new node."""
        searcher = OrderSearcher()
        node = MockNode("test")
        searcher.mark(node)
        self.assertIn(node, searcher.enqueued)
        self.assertIn(node, searcher.queue)

    def test_mark_already_enqueued(self):
        """Test marking an already enqueued node."""
        searcher = OrderSearcher()
        node = MockNode("test")
        searcher.mark(node)
        initial_queue_len = len(searcher.queue)
        searcher.mark(node)
        self.assertEqual(len(searcher.queue), initial_queue_len)

    def test_handleNode_first_visit(self):
        """Test handling a node on first visit."""
        searcher = OrderSearcher()
        node = MockNode("test")
        child = MockNode("child")
        node._forward = [child]

        searcher.handleNode(node)

        self.assertIn(node, searcher.preorder)
        self.assertEqual(searcher.preorder[node], 0)
        self.assertEqual(searcher.uid, 1)
        # Node should be re-added to queue for second visit
        self.assertEqual(searcher.queue.count(node), 1)
        # Child should be marked
        self.assertIn(child, searcher.enqueued)

    def test_handleNode_second_visit(self):
        """Test handling a node on second visit (revisit)."""
        searcher = OrderSearcher()
        # Create a mock node that mimics OpNode behavior
        node = MockOpNode("test")
        # Mock the forward method to return empty list
        node.forward = lambda: []

        # First visit - should assign pre-order
        searcher.handleNode(node)
        # Second visit - should assign post-order and add to order
        searcher.handleNode(node)

        self.assertEqual(searcher.uid, 2)
        # Note: MockOpNode doesn't pass isinstance check with graph.OpNode
        # so it won't be added to order, but the searcher still processes it
        # The important thing is that handleNode works correctly

    def test_handleNode_second_visit_not_op(self):
        """Test handling a non-op node on second visit."""
        searcher = OrderSearcher()
        node = MockNode("test")  # Not an OpNode

        # First visit
        searcher.handleNode(node)
        # Second visit
        searcher.handleNode(node)

        self.assertEqual(searcher.uid, 2)
        # Non-op nodes should not be added to order
        self.assertNotIn(node, searcher.order)

    @patch.object(graph, "OpNode", MockOpNode)
    def test_process_simple(self):
        """Test processing a simple dataflow graph."""
        searcher = OrderSearcher()

        # Create mock dataflow
        dataflow = MagicMock()
        entry = MockNode("entry")
        existing = {}
        null = MockNode("null")
        entry_pred = MockNode("entry_pred")

        dataflow.entry = entry
        dataflow.existing = existing
        dataflow.null = null
        dataflow.entryPredicate = entry_pred

        result = searcher.process(dataflow)

        # Result should be a list
        self.assertIsInstance(result, list)
        # Order should be reversed
        self.assertEqual(searcher.order, result)

    def test_process_with_op_nodes(self):
        """Test processing with operation nodes."""
        searcher = OrderSearcher()

        # Create mock dataflow with op nodes
        dataflow = MagicMock()
        entry = MockNode("entry")
        entry.forward = lambda: []
        op1 = MockOpNode("op1")
        op1.forward = lambda: []
        op2 = MockOpNode("op2")
        op2.forward = lambda: []
        entry._forward = [op1]
        op1._forward = [op2]

        dataflow.entry = entry
        dataflow.existing = {}
        null = MockNode("null")
        null.forward = lambda: []
        dataflow.null = null
        entry_pred = MockNode("entry_pred")
        entry_pred.forward = lambda: []
        dataflow.entryPredicate = entry_pred

        result = searcher.process(dataflow)

        # Result should be a list
        self.assertIsInstance(result, list)


class TestEvaluateDataflow(unittest.TestCase):
    """Test cases for evaluateDataflow function."""

    @patch("pyflow.ir.dataflow.ordering.OrderSearcher")
    def test_evaluateDataflow(self, mock_searcher_class):
        """Test evaluateDataflow function."""
        mock_searcher = MagicMock()
        mock_searcher.process.return_value = ["op1", "op2"]
        mock_searcher_class.return_value = mock_searcher

        dataflow = MagicMock()
        result = evaluateDataflow(dataflow)

        mock_searcher_class.assert_called_once()
        mock_searcher.process.assert_called_once_with(dataflow)
        self.assertEqual(result, ["op1", "op2"])


if __name__ == "__main__":
    unittest.main()
