"""Tests for pyflow.util.io.formatting module."""

import unittest
from pyflow.util.io.formatting import elapsedTime, memorySize


class TestElapsedTime(unittest.TestCase):
    """Test cases for elapsedTime function."""

    def test_milliseconds(self):
        """Test formatting of milliseconds."""
        self.assertIn("ms", elapsedTime(0.001))
        self.assertIn("ms", elapsedTime(0.05))
        self.assertIn("ms", elapsedTime(0.5))

    def test_seconds(self):
        """Test formatting of seconds."""
        result = elapsedTime(1.0)
        self.assertIn("s", result)

    def test_minutes(self):
        """Test formatting of minutes."""
        result = elapsedTime(60.0)
        self.assertIn("m", result)

    def test_hours(self):
        """Test formatting of hours."""
        result = elapsedTime(3600.0)
        self.assertIn("h", result)

    def test_zero(self):
        """Test formatting of zero time."""
        result = elapsedTime(0)
        self.assertIn("ms", result)

    def test_edge_cases(self):
        """Test edge cases."""
        # Just under 1 second
        self.assertIn("ms", elapsedTime(0.999))
        # Just under 1 minute
        self.assertIn("s", elapsedTime(59.999))
        # Just under 1 hour
        self.assertIn("m", elapsedTime(3599.999))


class TestMemorySize(unittest.TestCase):
    """Test cases for memorySize function."""

    def test_bytes(self):
        """Test formatting of bytes."""
        result = memorySize(100)
        self.assertIn("B", result)

    def test_kilobytes(self):
        """Test formatting of kilobytes."""
        result = memorySize(1024)
        self.assertIn("KB", result)

    def test_megabytes(self):
        """Test formatting of megabytes."""
        result = memorySize(1024**2)
        self.assertIn("MB", result)

    def test_gigabytes(self):
        """Test formatting of gigabytes."""
        result = memorySize(1024**3)
        self.assertIn("GB", result)

    def test_terabytes(self):
        """Test formatting of terabytes."""
        result = memorySize(1024**4)
        self.assertIn("TB", result)

    def test_float_input(self):
        """Test that float input is handled correctly."""
        result = memorySize(1024.0)
        self.assertIn("KB", result)

    def test_edge_cases(self):
        """Test edge cases."""
        # Just under 1 KB
        result = memorySize(1023)
        self.assertIn("B", result)
        # Just under 1 MB
        result = memorySize(1024**2 - 1)
        self.assertIn("KB", result)
        # Just under 1 GB
        result = memorySize(1024**3 - 1)
        self.assertIn("MB", result)


if __name__ == "__main__":
    unittest.main()
