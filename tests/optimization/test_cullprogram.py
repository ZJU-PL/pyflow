"""Tests for optimization/cullprogram.py - Program culling optimization."""

import unittest
from pyflow.optimization.cullprogram import CodeContextCuller, evaluateCode
from pyflow.language.python import ast


class MockAnnotation:
    """Mock annotation for testing."""

    def __init__(self, contexts=None):
        self.contexts = contexts or []

    def contextSubset(self, remap):
        """Return a new annotation with subset of contexts."""
        new_annotation = MockAnnotation()
        new_annotation.contexts = [self.contexts[i] for i in remap]
        return new_annotation


class MockCode:
    """Mock code object for testing."""

    def __init__(self, contexts=None):
        self.annotation = MockAnnotation(contexts)

    def visitChildren(self, visitor):
        return self

    def visitChildrenForced(self, visitor):
        return self


class TestCodeContextCuller(unittest.TestCase):
    """Test cases for CodeContextCuller class."""

    def test_init(self):
        """Test CodeContextCuller initialization."""
        culler = CodeContextCuller()
        # Initialize locals and remap as process would do
        culler.locals = set()
        culler.remap = []
        self.assertEqual(culler.locals, set())
        self.assertEqual(culler.remap, [])

    def test_visitLeaf_does_nothing(self):
        """Test that visitLeaf does nothing for leaf types."""
        culler = CodeContextCuller()
        culler.locals = set()
        culler.remap = []
        # Should not raise
        culler.visitLeaf(ast.Local("x"))

    def test_visitLocal_adds_to_locals(self):
        """Test that visitLocal adds local to locals set."""
        culler = CodeContextCuller()
        culler.locals = set()
        culler.remap = []
        local = ast.Local("x")
        culler.visitLocal(local)
        self.assertIn(local, culler.locals)

    def test_process_empty_contexts(self):
        """Test process with empty contexts."""
        code = MockCode(contexts=["context1", "context2"])
        culler = CodeContextCuller()
        culler.process(code, set())
        # All contexts should be removed
        self.assertEqual(len(code.annotation.contexts), 0)

    def test_process_all_contexts(self):
        """Test process with all contexts."""
        contexts = ["context1", "context2", "context3"]
        code = MockCode(contexts=contexts)
        culler = CodeContextCuller()
        culler.process(code, set(contexts))
        # All contexts should be preserved
        self.assertEqual(len(code.annotation.contexts), 3)

    def test_process_subset_contexts(self):
        """Test process with subset of contexts."""
        contexts = ["context1", "context2", "context3"]
        code = MockCode(contexts=contexts)
        culler = CodeContextCuller()
        culler.process(code, {"context1", "context3"})
        # Only 2 contexts should remain
        self.assertEqual(len(code.annotation.contexts), 2)


class TestEvaluateCode(unittest.TestCase):
    """Test cases for evaluateCode function."""

    def test_no_change_needed(self):
        """Test when no contexts need to be removed."""
        contexts = ["context1", "context2"]
        code = MockCode(contexts=contexts)
        ccc = CodeContextCuller()
        evaluateCode(code, set(contexts), ccc)
        # All contexts should remain
        self.assertEqual(len(code.annotation.contexts), 2)

    def test_contexts_removed(self):
        """Test when some contexts are removed."""
        contexts = ["context1", "context2", "context3"]
        code = MockCode(contexts=contexts)
        ccc = CodeContextCuller()
        evaluateCode(code, {"context1", "context3"}, ccc)
        # Only 2 contexts should remain
        self.assertEqual(len(code.annotation.contexts), 2)


if __name__ == "__main__":
    unittest.main()
