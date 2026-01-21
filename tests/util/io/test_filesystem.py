"""Tests for pyflow.util.io.filesystem module."""

import os
import tempfile
import shutil
import unittest
from pyflow.util.io.filesystem import (
    ensureDirectoryExists,
    join,
    relative,
    fileInput,
    readData,
    fileOutput,
    writeData,
    writeBinaryData,
    dataHash,
    fileHash,
    writeFileIfChanged,
)


class TestEnsureDirectoryExists(unittest.TestCase):
    """Test cases for ensureDirectoryExists function."""

    def setUp(self):
        """Create a temporary directory for tests."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_creates_directory(self):
        """Test that directory is created if it doesn't exist."""
        new_dir = os.path.join(self.temp_dir, "new_dir", "nested")
        ensureDirectoryExists(new_dir)
        self.assertTrue(os.path.exists(new_dir))

    def test_no_op_if_exists(self):
        """Test that function works if directory already exists."""
        ensureDirectoryExists(self.temp_dir)
        self.assertTrue(os.path.exists(self.temp_dir))


class TestJoin(unittest.TestCase):
    """Test cases for join function."""

    def test_without_format(self):
        """Test joining without format."""
        result = join("/path/to", "file")
        self.assertEqual(result, "/path/to/file")

    def test_with_format(self):
        """Test joining with format."""
        result = join("/path/to", "file", "txt")
        self.assertEqual(result, "/path/to/file.txt")


class TestRelative(unittest.TestCase):
    """Test cases for relative function."""

    def test_relative_path(self):
        """Test computing relative path."""
        result = relative("/path/to/file.txt", "/path/to")
        self.assertEqual(result, "file.txt")

    def test_nested_relative_path(self):
        """Test computing relative path for nested directory."""
        result = relative("/a/b/c/d.txt", "/a/b")
        self.assertEqual(result, "c/d.txt")


class TestFileInput(unittest.TestCase):
    """Test cases for fileInput function."""

    def setUp(self):
        """Create a temporary directory and file for tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "w") as f:
            f.write("test content")

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_read_text_file(self):
        """Test reading a text file."""
        with fileInput(self.temp_dir, "test", "txt") as f:
            content = f.read()
        self.assertEqual(content, "test content")

    def test_read_binary_file(self):
        """Test reading a binary file."""
        bin_file = os.path.join(self.temp_dir, "test.bin")
        with open(bin_file, "wb") as f:
            f.write(b"\x00\x01\x02\x03")
        with fileInput(self.temp_dir, "test", "bin", binary=True) as f:
            content = f.read()
        self.assertEqual(content, b"\x00\x01\x02\x03")


class TestReadData(unittest.TestCase):
    """Test cases for readData function."""

    def setUp(self):
        """Create a temporary directory and file for tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "w") as f:
            f.write("test content")

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_read_text_data(self):
        """Test reading text data."""
        result = readData(self.temp_dir, "test", "txt")
        self.assertEqual(result, "test content")

    def test_read_binary_data(self):
        """Test reading binary data."""
        bin_file = os.path.join(self.temp_dir, "test.bin")
        with open(bin_file, "wb") as f:
            f.write(b"\x00\x01\x02\x03")
        result = readData(self.temp_dir, "test", "bin", binary=True)
        self.assertEqual(result, b"\x00\x01\x02\x03")


class TestFileOutput(unittest.TestCase):
    """Test cases for fileOutput function."""

    def setUp(self):
        """Create a temporary directory for tests."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_write_text_file(self):
        """Test writing to a text file."""
        with fileOutput(self.temp_dir, "test", "txt") as f:
            f.write("test content")
        test_file = os.path.join(self.temp_dir, "test.txt")
        with open(test_file, "r") as f:
            self.assertEqual(f.read(), "test content")

    def test_creates_directory(self):
        """Test that directory is created if it doesn't exist."""
        nested_dir = os.path.join(self.temp_dir, "nested")
        with fileOutput(nested_dir, "test", "txt") as f:
            f.write("content")
        self.assertTrue(os.path.exists(nested_dir))


class TestWriteData(unittest.TestCase):
    """Test cases for writeData function."""

    def setUp(self):
        """Create a temporary directory for tests."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_write_text_data(self):
        """Test writing text data."""
        writeData(self.temp_dir, "test", "txt", "test content")
        test_file = os.path.join(self.temp_dir, "test.txt")
        with open(test_file, "r") as f:
            self.assertEqual(f.read(), "test content")

    def test_write_binary_data(self):
        """Test writing binary data."""
        writeData(self.temp_dir, "test", "bin", b"\x00\x01\x02\x03", binary=True)
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, "rb") as f:
            self.assertEqual(f.read(), b"\x00\x01\x02\x03")


class TestWriteBinaryData(unittest.TestCase):
    """Test cases for writeBinaryData function."""

    def setUp(self):
        """Create a temporary directory for tests."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_write_binary_data(self):
        """Test writing binary data."""
        writeBinaryData(self.temp_dir, "test", "bin", b"\x00\x01\x02\x03")
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, "rb") as f:
            self.assertEqual(f.read(), b"\x00\x01\x02\x03")


class TestDataHash(unittest.TestCase):
    """Test cases for dataHash function."""

    def test_hash_unicode(self):
        """Test hashing unicode string."""
        result = dataHash("hello".encode('utf-8'))
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 20)  # SHA-1 produces 20 bytes

    def test_hash_binary(self):
        """Test hashing binary data."""
        result = dataHash(b"\x00\x01\x02\x03")
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 20)

    def test_hash_consistency(self):
        """Test that same data produces same hash."""
        data = b"test data"
        hash1 = dataHash(data)
        hash2 = dataHash(data)
        self.assertEqual(hash1, hash2)


class TestFileHash(unittest.TestCase):
    """Test cases for fileHash function."""

    def setUp(self):
        """Create a temporary directory and file for tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.bin")
        with open(self.test_file, "wb") as f:
            f.write(b"test content")

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_file_hash(self):
        """Test computing hash of a binary file."""
        result = fileHash(self.temp_dir, "test", "bin", binary=True)
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 20)

    def test_file_hash_consistency(self):
        """Test that same file produces same hash."""
        hash1 = fileHash(self.temp_dir, "test", "bin", binary=True)
        hash2 = fileHash(self.temp_dir, "test", "bin", binary=True)
        self.assertEqual(hash1, hash2)


class TestWriteFileIfChanged(unittest.TestCase):
    """Test cases for writeFileIfChanged function."""

    def setUp(self):
        """Create a temporary directory for tests."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_writes_new_file(self):
        """Test that new file is written (using binary mode)."""
        result = writeFileIfChanged(self.temp_dir, "test", "bin", b"content", binary=True)
        self.assertTrue(result)

    def test_no_write_if_same(self):
        """Test that file is not written if content is same (using binary mode)."""
        writeFileIfChanged(self.temp_dir, "test", "bin", b"content", binary=True)
        result = writeFileIfChanged(self.temp_dir, "test", "bin", b"content", binary=True)
        self.assertFalse(result)

    def test_write_if_different(self):
        """Test that file is written if content differs (using binary mode)."""
        writeFileIfChanged(self.temp_dir, "test", "bin", b"content1", binary=True)
        result = writeFileIfChanged(self.temp_dir, "test", "bin", b"content2", binary=True)
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
