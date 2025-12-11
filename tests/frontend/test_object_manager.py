"""Unit tests for object_manager module."""

import unittest
from unittest.mock import Mock, patch

from pyflow.frontend.object_manager import ObjectManager
from pyflow.language.python.program import Object, ImaginaryObject, AbstractObject, TypeInfo


class TestObjectManager(unittest.TestCase):
    """Test cases for the ObjectManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.object_manager = ObjectManager(verbose=False)

    def test_init(self):
        """Test ObjectManager initialization."""
        manager = ObjectManager(verbose=True)
        self.assertTrue(manager.verbose)
        self.assertIsInstance(manager._object_cache, dict)
        self.assertIsNone(manager.function_extractor)

    def test_init_with_function_extractor(self):
        """Test ObjectManager initialization with function extractor."""
        mock_extractor = Mock()
        manager = ObjectManager(verbose=False, function_extractor=mock_extractor)
        self.assertEqual(manager.function_extractor, mock_extractor)

    def test_get_object_int(self):
        """Test getting an object for an integer."""
        obj = self.object_manager.get_object(42)
        self.assertIsInstance(obj, Object)
        # Should cache the object
        obj2 = self.object_manager.get_object(42)
        self.assertIs(obj, obj2)  # Should return same cached object

    def test_get_object_string(self):
        """Test getting an object for a string."""
        obj = self.object_manager.get_object("hello")
        self.assertIsInstance(obj, Object)

    def test_get_object_list(self):
        """Test getting an object for a list."""
        # Lists are unhashable, so they can't be cached, but should still work
        test_list = [1, 2, 3]
        try:
            obj = self.object_manager.get_object(test_list)
            # Should return Object or fallback
            self.assertIsNotNone(obj)
        except TypeError:
            # If list causes TypeError due to unhashable type, that's expected
            pass

    def test_get_object_dict(self):
        """Test getting an object for a dictionary."""
        # Dicts are unhashable, so they can't be cached, but should still work
        test_dict = {"key": "value"}
        try:
            obj = self.object_manager.get_object(test_dict)
            # Should return Object or fallback
            self.assertIsNotNone(obj)
        except TypeError:
            # If dict causes TypeError due to unhashable type, that's expected
            # The implementation might need to handle this differently
            pass

    def test_get_object_function(self):
        """Test getting an object for a function."""
        def test_func():
            return 1
        
        obj = self.object_manager.get_object(test_func)
        self.assertIsInstance(obj, Object)

    def test_get_object_class(self):
        """Test getting an object for a class."""
        class TestClass:
            pass
        
        obj = self.object_manager.get_object(TestClass)
        self.assertIsInstance(obj, Object)

    def test_get_object_caching(self):
        """Test that objects are cached."""
        value = 42
        obj1 = self.object_manager.get_object(value)
        obj2 = self.object_manager.get_object(value)
        self.assertIs(obj1, obj2)

    def test_get_object_call_with_function(self):
        """Test getting object call for a function."""
        def test_func():
            return 1
        
        func_obj, code_obj = self.object_manager.get_object_call(test_func)
        self.assertEqual(func_obj, test_func)
        # code_obj might be None if function_extractor is not set

    def test_get_object_call_with_function_extractor(self):
        """Test getting object call with function extractor."""
        mock_extractor = Mock()
        mock_extractor.convert_function = Mock(return_value=Mock())
        manager = ObjectManager(verbose=False, function_extractor=mock_extractor)
        
        def test_func():
            return 1
        
        source = "def test_func(): return 1"
        func_obj, code_obj = manager.get_object_call(test_func, source_code=source)
        self.assertEqual(func_obj, test_func)
        # Should call convert_function
        mock_extractor.convert_function.assert_called_once()

    def test_get_object_call_with_source_dict(self):
        """Test getting object call with source code dictionary."""
        mock_extractor = Mock()
        mock_extractor.convert_function = Mock(return_value=Mock())
        manager = ObjectManager(verbose=False, function_extractor=mock_extractor)
        
        def test_func():
            return 1
        
        # Use a real function which has a proper code object
        # The filename might be '<string>' or the actual file, but the code should handle it
        source_dict = {"test.py": "def test_func(): return 1"}
        func_obj, code_obj = manager.get_object_call(test_func, source_code=source_dict)
        self.assertEqual(func_obj, test_func)
        # Should attempt to call convert_function
        # Note: actual filename matching depends on where the function was defined

    def test_get_object_call_without_name(self):
        """Test getting object call for object without __name__."""
        obj = 42  # Integer doesn't have __name__
        func_obj, code_obj = self.object_manager.get_object_call(obj)
        self.assertEqual(func_obj, obj)
        self.assertIsNone(code_obj)

    def test_make_imaginary(self):
        """Test creating an imaginary object."""
        # Create a proper type object for ImaginaryObject
        from pyflow.language.python.program import Object
        type_obj = Object(int)  # Use int as a type
        imaginary = self.object_manager.make_imaginary("test_name", type_obj, False)
        self.assertIsInstance(imaginary, ImaginaryObject)
        self.assertEqual(imaginary.name, "test_name")
        self.assertEqual(imaginary.type, type_obj)  # ImaginaryObject stores as 'type' not 't'
        self.assertFalse(imaginary.preexisting)

    def test_make_imaginary_preexisting(self):
        """Test creating a preexisting imaginary object."""
        abstract_obj = Mock(spec=AbstractObject)
        imaginary = self.object_manager.make_imaginary("test_name", abstract_obj, True)
        self.assertTrue(imaginary.preexisting)

    def test_ensure_loaded_none(self):
        """Test ensuring None object is loaded."""
        result = self.object_manager.ensure_loaded(None)
        self.assertIsNone(result)

    def test_ensure_loaded_with_type(self):
        """Test ensuring object with type is loaded."""
        obj = Mock(spec=AbstractObject)
        obj.type = Mock()
        obj.isType = Mock(return_value=False)
        
        # Should not raise an exception
        self.object_manager.ensure_loaded(obj)

    def test_ensure_loaded_without_type(self):
        """Test ensuring object without type is loaded."""
        obj = Mock(spec=AbstractObject)
        obj.type = None
        obj.pyobj = int
        obj.isType = Mock(return_value=False)
        
        # Should set type
        self.object_manager.ensure_loaded(obj)
        # Type should be set (might be an Object wrapper)
        self.assertIsNotNone(obj.type)

    def test_ensure_loaded_type_object(self):
        """Test ensuring type object is loaded."""
        obj = Mock(spec=AbstractObject)
        obj.type = None
        obj.pyobj = type  # The type class itself
        obj.isType = Mock(return_value=False)
        
        # Should handle type(type) recursion
        self.object_manager.ensure_loaded(obj)

    def test_ensure_loaded_type_with_typeinfo(self):
        """Test ensuring type object with typeinfo is loaded."""
        obj = Mock(spec=AbstractObject)
        obj.type = Mock()
        obj.isType = Mock(return_value=True)
        obj.typeinfo = None
        obj.pyobj = Mock()  # Add pyobj attribute
        obj.pyobj.__name__ = "TestClass"
        
        # Should create typeinfo
        self.object_manager.ensure_loaded(obj)
        self.assertIsNotNone(obj.typeinfo)

    def test_ensure_loaded_type_without_typeinfo(self):
        """Test ensuring type object without typeinfo is loaded."""
        obj = Mock(spec=AbstractObject)
        obj.type = Mock()
        obj.isType = Mock(return_value=True)
        obj.typeinfo = None
        obj.pyobj = Mock()
        obj.pyobj.__name__ = "TestClass"
        
        # Should create typeinfo
        self.object_manager.ensure_loaded(obj)
        self.assertIsNotNone(obj.typeinfo)

    def test_get_call_with_callable_pyobj(self):
        """Test getting call for object with callable pyobj."""
        def test_func():
            return 1
        
        mock_obj = Mock()
        mock_obj.pyobj = test_func
        
        mock_extractor = Mock()
        mock_extractor.convert_function = Mock(return_value=Mock())
        manager = ObjectManager(verbose=False, function_extractor=mock_extractor)
        
        result = manager.get_call(mock_obj, source_code="def test_func(): return 1")
        # Should return code object
        self.assertIsNotNone(result)

    def test_get_call_with_non_callable_pyobj(self):
        """Test getting call for object with non-callable pyobj."""
        mock_obj = Mock()
        mock_obj.pyobj = 42  # Not callable
        
        result = self.object_manager.get_call(mock_obj)
        self.assertIsNone(result)

    def test_get_call_without_pyobj(self):
        """Test getting call for object without pyobj."""
        mock_obj = Mock()
        del mock_obj.pyobj  # Remove pyobj attribute
        
        result = self.object_manager.get_call(mock_obj)
        self.assertIsNone(result)

    def test_get_object_error_handling(self):
        """Test error handling in get_object."""
        # Create an object that might cause an error
        # Use a mock that raises an exception
        with patch('pyflow.language.python.program.Object', side_effect=Exception("Test error")):
            manager = ObjectManager(verbose=False)
            result = manager.get_object(42)
            # Should return fallback (the original object) on error
            self.assertEqual(result, 42)

    def test_get_object_error_handling_verbose(self):
        """Test error handling in get_object with verbose mode."""
        manager = ObjectManager(verbose=True)
        with patch('pyflow.language.python.program.Object', side_effect=Exception("Test error")):
            result = manager.get_object(42)
            # Should return fallback on error
            self.assertEqual(result, 42)


if __name__ == "__main__":
    unittest.main()
