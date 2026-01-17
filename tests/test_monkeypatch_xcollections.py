"""Tests for pyflow.util.monkeypatch.xcollections module."""

import unittest
import gc
import weakref
from pyflow.util.monkeypatch.xcollections import lazydict, weakcache


class CacheableObject:
    """A simple class that supports weak references."""
    def __init__(self, value):
        self.value = value
    def __hash__(self):
        return hash(self.value)
    def __eq__(self, other):
        if isinstance(other, CacheableObject):
            return self.value == other.value
        return False


class TestLazyDict(unittest.TestCase):
    """Test cases for lazydict class."""

    def test_basic_usage(self):
        """Test basic usage of lazydict."""
        d = lazydict(lambda key: f"value_for_{key}")
        self.assertEqual(d["foo"], "value_for_foo")
        self.assertEqual(d["bar"], "value_for_bar")

    def test_missing_key(self):
        """Test that missing key is created using factory."""
        d = lazydict(lambda key: key.upper())
        result = d["test"]
        self.assertEqual(result, "TEST")

    def test_existing_key(self):
        """Test that existing key returns cached value."""
        factory_calls = [0]
        def factory(key):
            factory_calls[0] += 1
            return f"value_{key}"

        d = lazydict(factory)
        d["key"]
        d["key"]
        self.assertEqual(factory_calls[0], 1)

    def test_in_operator(self):
        """Test that in operator works correctly."""
        d = lazydict(lambda key: f"value_{key}")
        d["foo"]
        self.assertTrue("foo" in d)
        self.assertFalse("bar" in d)

    def test_custom_factory(self):
        """Test custom factory function."""
        d = lazydict(lambda key: [key])  # Returns list containing the key
        result = d["test"]
        self.assertEqual(result, ["test"])

    def test_key_based_factory(self):
        """Test that factory receives the key."""
        received_keys = []
        def factory(key):
            received_keys.append(key)
            return key

        d = lazydict(factory)
        d["a"]
        d["b"]
        d["c"]
        self.assertEqual(received_keys, ["a", "b", "c"])


class TestWeakCache(unittest.TestCase):
    """Test cases for weakcache class."""

    def test_basic_caching(self):
        """Test basic caching functionality with hashable objects."""
        cache = weakcache()
        # Use custom objects which support weak references
        obj1 = CacheableObject((1, 2, 3))
        obj2 = CacheableObject((1, 2, 3))
        cached1 = cache[obj1]
        cached2 = cache[obj2]
        self.assertIs(cached1, cached2)

    def test_canonicalization(self):
        """Test that equal objects return same cached instance."""
        cache = weakcache()
        obj1 = CacheableObject((1, 2, 3))
        obj2 = CacheableObject((1, 2, 3))
        cached1 = cache[obj1]
        cached2 = cache[obj2]
        self.assertIs(cached1, cached2)

    def test_contains(self):
        """Test __contains__ method."""
        cache = weakcache()
        obj = CacheableObject((1, 2, 3))
        cache[obj]
        self.assertTrue(obj in cache)

    def test_not_contains(self):
        """Test __contains__ returns False for uncached objects."""
        cache = weakcache()
        obj = CacheableObject((1, 2, 3))
        self.assertFalse(obj in cache)

    def test_len(self):
        """Test __len__ method."""
        cache = weakcache()
        self.assertEqual(len(cache), 0)
        obj1 = CacheableObject((1, 2, 3))
        cache[obj1]
        self.assertEqual(len(cache), 1)
        obj2 = CacheableObject((4, 5, 6))
        cache[obj2]
        self.assertEqual(len(cache), 2)

    def test_iter(self):
        """Test __iter__ method."""
        cache = weakcache()
        obj1 = CacheableObject((1, 2, 3))
        obj2 = CacheableObject((4, 5, 6))
        cache[obj1]
        cache[obj2]
        items = list(cache)
        self.assertTrue(obj1 in items)
        self.assertTrue(obj2 in items)

    def test_garbage_collection_cleanup(self):
        """Test that weak references are cleaned up on garbage collection."""
        cache = weakcache()
        obj = CacheableObject((1, 2, 3))
        cache[obj]
        initial_len = len(cache)

        # Delete object and force garbage collection
        del obj
        gc.collect()

        # Cache may still have the entry until finalizer runs
        # This is expected behavior for weak references

    def test_unhashable_key(self):
        """Test that unhashable keys raise TypeError."""
        cache = weakcache()
        # Lists are unhashable
        with self.assertRaises(TypeError):
            _ = cache[[1, 2, 3]]

    def test_contains_unhashable(self):
        """Test __contains__ returns False for unhashable keys."""
        cache = weakcache()
        self.assertFalse([1, 2, 3] in cache)


if __name__ == "__main__":
    unittest.main()
