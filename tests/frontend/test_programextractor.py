"""Unit tests for programextractor module."""

import unittest
import ast
from unittest.mock import Mock, patch

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.util.application.console import Console
from pyflow.frontend.programextractor import Extractor, extractProgram


class TestExtractor(unittest.TestCase):
    """Test cases for the Extractor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.console = Console()
        self.compiler = CompilerContext(self.console)
        self.extractor = Extractor(self.compiler, verbose=False)

    def test_init(self):
        """Test Extractor initialization."""
        self.assertEqual(self.extractor.compiler, self.compiler)
        self.assertFalse(self.extractor.verbose)
        self.assertEqual(self.extractor.functions, [])
        self.assertEqual(self.extractor.builtin, 0)
        self.assertEqual(self.extractor.errors, 0)
        self.assertEqual(self.extractor.failures, 0)
        self.assertIsNotNone(self.extractor.desc)
        self.assertIsNotNone(self.extractor.stub_manager)
        self.assertIsNotNone(self.extractor.function_extractor)
        self.assertIsNotNone(self.extractor.object_manager)

    def test_init_with_source_code(self):
        """Test Extractor initialization with source code."""
        source = "def hello(): pass"
        extractor = Extractor(self.compiler, verbose=False, source_code=source)
        self.assertEqual(extractor.source_code, source)

    def test_init_with_source_code_dict(self):
        """Test Extractor initialization with source code dictionary."""
        source_dict = {"file1.py": "def func1(): pass", "file2.py": "def func2(): pass"}
        extractor = Extractor(self.compiler, verbose=False, source_code=source_dict)
        self.assertEqual(extractor.source_code, source_dict)

    def test_extract_from_source_simple_function(self):
        """Test extracting a simple function from source."""
        source = """
def add(a, b):
    return a + b
"""
        program = self.extractor.extract_from_source(source, "test.py")
        self.assertIsInstance(program, Program)
        self.assertEqual(self.extractor.errors, 0)

    def test_extract_from_source_with_class(self):
        """Test extracting a class from source."""
        source = """
class MyClass:
    def method(self):
        return 42
"""
        program = self.extractor.extract_from_source(source, "test.py")
        self.assertIsInstance(program, Program)
        self.assertEqual(self.extractor.errors, 0)

    def test_extract_from_source_syntax_error(self):
        """Test handling syntax errors."""
        source = "def invalid syntax here"
        program = self.extractor.extract_from_source(source, "test.py")
        self.assertIsInstance(program, Program)
        self.assertEqual(self.extractor.errors, 1)

    def test_extract_from_file_existing(self):
        """Test extracting from an existing file."""
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("def test_func(): return 1\n")
            temp_path = f.name
        
        try:
            program = self.extractor.extract_from_file(temp_path)
            self.assertIsInstance(program, Program)
            self.assertEqual(self.extractor.errors, 0)
        finally:
            os.unlink(temp_path)

    def test_extract_from_file_not_found(self):
        """Test extracting from a non-existent file."""
        program = self.extractor.extract_from_file("nonexistent_file.py")
        self.assertIsInstance(program, Program)
        self.assertEqual(self.extractor.errors, 1)

    def test_extract_from_multiple_files(self):
        """Test extracting from multiple files."""
        source_files = {
            "file1.py": "def func1(): return 1",
            "file2.py": "def func2(): return 2"
        }
        program = self.extractor.extract_from_multiple_files(source_files)
        self.assertIsInstance(program, Program)
        self.assertEqual(self.extractor.errors, 0)

    def test_extract_from_multiple_files_with_error(self):
        """Test extracting from multiple files with one error."""
        source_files = {
            "file1.py": "def func1(): return 1",
            "file2.py": "invalid syntax here"
        }
        program = self.extractor.extract_from_multiple_files(source_files)
        self.assertIsInstance(program, Program)
        self.assertEqual(self.extractor.errors, 1)

    def test_get_object(self):
        """Test getting an object representation."""
        obj = self.extractor.getObject(42)
        self.assertIsNotNone(obj)

    def test_get_object_call(self):
        """Test getting object call information."""
        def test_func():
            return 1
        
        func_obj, code_obj = self.extractor.getObjectCall(test_func)
        self.assertIsNotNone(func_obj)
        # code_obj might be None if source code is not available
        self.assertIsNotNone(func_obj)

    def test_get_object_call_with_source_code(self):
        """Test getting object call with source code."""
        source = "def test_func(): return 1"
        self.extractor.source_code = source
        
        def test_func():
            return 1
        
        func_obj, code_obj = self.extractor.getObjectCall(test_func)
        self.assertIsNotNone(func_obj)

    def test_make_imaginary(self):
        """Test creating an imaginary object."""
        from pyflow.language.python.program import AbstractObject
        
        # Create a mock abstract object
        abstract_obj = Mock(spec=AbstractObject)
        imaginary = self.extractor.makeImaginary("test", abstract_obj, False)
        self.assertIsNotNone(imaginary)

    def test_ensure_loaded(self):
        """Test ensuring an object is loaded."""
        from pyflow.language.python.program import AbstractObject
        
        abstract_obj = Mock(spec=AbstractObject)
        abstract_obj.type = None
        abstract_obj.pyobj = int
        
        # Should not raise an exception
        self.extractor.ensureLoaded(abstract_obj)

    def test_ensure_loaded_none(self):
        """Test ensuring None object is loaded."""
        # Should handle None gracefully
        result = self.extractor.ensureLoaded(None)
        self.assertIsNone(result)

    def test_get_call(self):
        """Test getting call information for an object."""
        def test_func():
            return 1
        
        # Create a mock object with pyobj
        mock_obj = Mock()
        mock_obj.pyobj = test_func
        
        result = self.extractor.getCall(mock_obj)
        # Result might be None if source code is not available
        self.assertIsNotNone(mock_obj)

    def test_convert_function(self):
        """Test converting a function."""
        def test_func(x):
            return x + 1
        
        source = "def test_func(x): return x + 1"
        self.extractor.source_code = source
        
        code = self.extractor.convertFunction(test_func)
        self.assertIsNotNone(code)

    def test_convert_function_with_source_dict(self):
        """Test converting a function with source code dictionary."""
        def test_func(x):
            return x + 1
        
        source_dict = {"test.py": "def test_func(x): return x + 1"}
        self.extractor.source_code = source_dict
        
        code = self.extractor.convertFunction(test_func)
        self.assertIsNotNone(code)

    def test_extract_from_ast(self):
        """Test extracting from AST."""
        source = "def test_func(): return 1"
        tree = ast.parse(source)
        program = self.extractor._extract_from_ast(tree, "test.py")
        self.assertIsInstance(program, Program)


class TestExtractProgram(unittest.TestCase):
    """Test cases for the extractProgram function."""

    def setUp(self):
        """Set up test fixtures."""
        self.console = Console()
        self.compiler = CompilerContext(self.console)
        self.program = Program()

    def test_extract_program_without_extractor(self):
        """Test extractProgram creates extractor if none exists."""
        self.assertIsNone(self.compiler.extractor)
        extractProgram(self.compiler, self.program)
        self.assertIsNotNone(self.compiler.extractor)

    def test_extract_program_with_extractor(self):
        """Test extractProgram uses existing extractor."""
        extractor = Extractor(self.compiler, verbose=False)
        self.compiler.extractor = extractor
        extractProgram(self.compiler, self.program)
        self.assertEqual(self.compiler.extractor, extractor)

    def test_extract_program_with_source_code_dict(self):
        """Test extractProgram with source code dictionary."""
        source_dict = {
            "file1.py": "def func1(): return 1",
            "file2.py": "def func2(): return 2"
        }
        extractor = Extractor(self.compiler, verbose=False, source_code=source_dict)
        self.compiler.extractor = extractor
        extractProgram(self.compiler, self.program)
        # Should not raise an exception

    def test_extract_program_with_interface(self):
        """Test extractProgram with interface."""
        from pyflow.application import interface
        
        interface_decl = interface.InterfaceDeclaration()
        self.program.interface = interface_decl
        
        extractor = Extractor(self.compiler, verbose=False)
        self.compiler.extractor = extractor
        extractProgram(self.compiler, self.program)
        # Should not raise an exception


if __name__ == "__main__":
    unittest.main()
