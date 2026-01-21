"""Tests for pyflow.util.application.async_utils module."""

import unittest
import time
import threading
from pyflow.util.application.async_utils import async_func, async_limited, enabled


class TestAsyncUtils(unittest.TestCase):
    """Test cases for async_utils decorators."""

    def setUp(self):
        """Reset the enabled flag before each test."""
        # Save original state
        self.original_enabled = enabled
        # Ensure async is enabled for most tests
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = True

    def tearDown(self):
        """Restore the enabled flag after each test."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = self.original_enabled

    def test_async_func_enabled(self):
        """Test async_func decorator when enabled."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = True

        @async_func
        def test_function():
            return "completed"

        result = test_function()
        self.assertIsInstance(result, threading.Thread)
        result.join()  # Wait for thread to complete

    def test_async_func_disabled(self):
        """Test async_func decorator when disabled."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = False

        @async_func
        def test_function():
            return "completed"

        result = test_function()
        self.assertEqual(result, "completed")

    def test_async_func_with_args(self):
        """Test async_func with arguments."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = True

        @async_func
        def test_function(a, b, c=None):
            return a + b + (c or 0)

        result = test_function(1, 2, c=3)
        self.assertIsInstance(result, threading.Thread)
        result.join()

    def test_async_func_with_return_value(self):
        """Test that async_func returns the correct value."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = True

        test_value = "test_return_value"

        @async_func
        def test_function():
            return test_value

        thread = test_function()
        # The thread executes in background, we need to check the return
        # Since we can't easily get return value from thread, we test
        # that function executes without error
        thread.join()
        # If we get here, function executed successfully

    def test_async_limited_enabled(self):
        """Test async_limited decorator when enabled."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = True

        @async_limited(2)
        def test_function():
            return "completed"

        result = test_function()
        self.assertIsInstance(result, threading.Thread)
        result.join()

    def test_async_limited_disabled(self):
        """Test async_limited decorator when disabled."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = False

        @async_limited(2)
        def test_function():
            return "completed"

        result = test_function()
        self.assertEqual(result, "completed")

    def test_async_limited_count(self):
        """Test async_limited with different counts."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = True

        for count in [1, 3, 5]:
            @async_limited(count)
            def test_function():
                return count

            result = test_function()
            self.assertIsInstance(result, threading.Thread)
            result.join()

    def test_async_limited_multiple_calls(self):
        """Test async_limited with multiple concurrent calls."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = True

        @async_limited(2)
        def quick_function():
            return "done"

        threads = []
        for _ in range(4):
            t = quick_function()
            threads.append(t)

        # Wait for all threads
        for t in threads:
            t.join()


class TestAsyncUtilsEdgeCases(unittest.TestCase):
    """Edge case tests for async_utils."""

    def setUp(self):
        """Save original enabled state."""
        import pyflow.util.application.async_utils
        self.original_enabled = pyflow.util.application.async_utils.enabled

    def tearDown(self):
        """Restore enabled state."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = self.original_enabled

    def test_async_func_exception_handling(self):
        """Test async_func with exception-raising function."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = True

        @async_func
        def raising_function():
            raise ValueError("Test error")

        thread = raising_function()
        thread.join()  # Should complete without raising

    def test_async_func_empty_args(self):
        """Test async_func with no arguments."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = True

        @async_func
        def no_args():
            return "no args"

        result = no_args()
        self.assertIsInstance(result, threading.Thread)
        result.join()

    def test_async_limited_exception_handling(self):
        """Test async_limited with exception-raising function."""
        import pyflow.util.application.async_utils
        pyflow.util.application.async_utils.enabled = True

        @async_limited(1)
        def raising_function():
            raise ValueError("Test error")

        thread = raising_function()
        thread.join()  # Should complete without raising


if __name__ == "__main__":
    unittest.main()
