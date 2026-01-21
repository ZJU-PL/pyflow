"""Tests for pyflow.util.graphalgorithim.merge module."""

import unittest
from pyflow.util.graphalgorithim.merge import MergeError, MergeOptimizer, serializeMerges


class TestMergeOptimizer(unittest.TestCase):
    """Test cases for MergeOptimizer class."""

    def test_simple_emit_transfer(self):
        """Test emitTransfer method."""
        mo = MergeOptimizer()
        mo.remap = {}
        mo.result = []
        mo.emitTransfer('a', 'x')
        self.assertEqual(mo.result, [('a', 'x')])

    def test_emit_transfer_with_remap(self):
        """Test emitTransfer with a remapped source."""
        mo = MergeOptimizer()
        mo.remap = {'a': 'temp_a'}
        mo.result = []
        mo.emitTransfer('a', 'x')
        self.assertEqual(mo.result, [('temp_a', 'x')])

    def test_save_creates_temporary(self):
        """Test save method creates temporary."""
        mo = MergeOptimizer()
        mo.remap = {}
        mo.temporaries = []
        mo.genTemp = lambda n: 'temp_' + str(n)
        mo.save('x')
        self.assertEqual(mo.remap['x'], 'temp_x')
        self.assertEqual(mo.temporaries, ['temp_x'])

    def test_save_no_duplicate_temporary(self):
        """Test save doesn't create duplicate temporaries."""
        mo = MergeOptimizer()
        mo.remap = {}
        mo.temporaries = []
        mo.genTemp = lambda n: 'temp_' + str(n)
        mo.save('x')
        mo.save('x')
        self.assertEqual(mo.remap['x'], 'temp_x')
        self.assertEqual(mo.temporaries, ['temp_x'])

    def test_build_reverse_graph_simple(self):
        """Test buildReverseGraph with simple input."""
        mo = MergeOptimizer()
        mo.g = {}
        merges = [('a', 'x'), ('b', 'y')]
        entries = mo.buildReverseGraph(merges)
        self.assertEqual(mo.g, {'x': 'a', 'y': 'b'})
        self.assertEqual(set(entries), {'x', 'y'})

    def test_build_reverse_graph_duplicate_definition(self):
        """Test buildReverseGraph raises error on duplicate definition."""
        mo = MergeOptimizer()
        mo.g = {}
        merges = [('a', 'x'), ('b', 'x')]
        with self.assertRaises(MergeError):
            mo.buildReverseGraph(merges)

    def test_process_simple(self):
        """Test process method with simple merges."""
        mo = MergeOptimizer()
        merges = [('a', 'x'), ('b', 'y')]
        genTemp = lambda n: 'temp_' + str(n)
        mo.process(merges, genTemp)
        self.assertEqual(mo.result, [('a', 'x'), ('b', 'y')])
        self.assertEqual(mo.temporaries, [])


class TestSerializeMerges(unittest.TestCase):
    """Test cases for serializeMerges function."""

    def test_empty_merges(self):
        """Test serializeMerges with empty list."""
        result, temps = serializeMerges([], lambda n: 'temp_' + str(n))
        self.assertEqual(result, [])
        self.assertEqual(temps, [])

    def test_simple_no_dependencies(self):
        """Test serializeMerges with no dependencies."""
        merges = [('a', 'x'), ('b', 'y')]
        result, temps = serializeMerges(merges, lambda n: 'temp_' + str(n))
        self.assertEqual(len(result), 2)
        self.assertEqual(temps, [])

    def test_sequential_dependency(self):
        """Test serializeMerges with sequential dependency."""
        merges = [('a', 'x'), ('x', 'y')]
        result, temps = serializeMerges(merges, lambda n: 'temp_' + str(n))
        self.assertEqual(len(result), 2)
        self.assertEqual(temps, [])

    def test_cycle_requires_temporary(self):
        """Test serializeMerges with cycle (swap)."""
        merges = [('y', 'x'), ('x', 'y')]
        result, temps = serializeMerges(merges, lambda n: 'temp_' + str(n))
        # Should have created a temporary
        self.assertTrue(len(temps) > 0)
        # At least one temporary should have been created
        self.assertTrue(any('temp' in t for t in temps))

    def test_complex_chain(self):
        """Test serializeMerges with complex dependency chain."""
        merges = [('1', 'a'), ('2', 'b'), ('3', 'c')]
        result, temps = serializeMerges(merges, lambda n: 'temp_' + str(n))
        self.assertEqual(len(result), 3)
        self.assertEqual(temps, [])

    def test_multiple_cycles(self):
        """Test serializeMerges with multiple cycles."""
        # Swap a<->b and c<->d
        merges = [('b', 'a'), ('a', 'b'), ('d', 'c'), ('c', 'd')]
        result, temps = serializeMerges(merges, lambda n: 'temp_' + str(n))
        self.assertTrue(len(temps) >= 2)


class TestMergeError(unittest.TestCase):
    """Test cases for MergeError exception."""

    def test_merge_error_raised(self):
        """Test MergeError is raised correctly."""
        with self.assertRaises(MergeError):
            raise MergeError("Test error message")

    def test_merge_error_message(self):
        """Test MergeError message content."""
        try:
            raise MergeError("Duplicate definition of x")
        except MergeError as e:
            self.assertEqual(str(e), "Duplicate definition of x")


if __name__ == "__main__":
    unittest.main()
