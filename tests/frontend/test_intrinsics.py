"""Unit tests for frontend intrinsic models."""

import builtins
import unittest

from pyflow.frontend.runtime.intrinsics import IntrinsicManager
from pyflow.application.context import CompilerContext
from pyflow.util.application.console import Console


class TestIntrinsicManager(unittest.TestCase):
    """Test cases for the IntrinsicManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.console = Console()
        self.compiler = CompilerContext(self.console)
        self.intrinsic_manager = IntrinsicManager(self.compiler)

    def test_init(self):
        """Test IntrinsicManager initialization."""
        self.assertEqual(self.intrinsic_manager.compiler, self.compiler)
        self.assertIsNotNone(self.intrinsic_manager.stubs)

    def test_stubs_has_exports(self):
        """Test that stubs have exports attribute."""
        self.assertTrue(hasattr(self.intrinsic_manager.stubs, 'exports'))
        self.assertIsInstance(self.intrinsic_manager.stubs.exports, dict)

    def test_stubs_interpreter_functions(self):
        """Test that stubs include interpreter functions."""
        exports = self.intrinsic_manager.stubs.exports
        self.assertIn('interpreter_getattribute', exports)
        self.assertIn('interpreter__mul__', exports)
        self.assertIn('interpreter__matmul__', exports)
        self.assertIn('interpreter__add__', exports)
        self.assertIn('interpreter__sub__', exports)
        self.assertIn('interpreter__div__', exports)
        self.assertIn('interpreter__truediv__', exports)
        self.assertIn('interpreter__mod__', exports)
        self.assertIn('interpreter__pow__', exports)

    def test_stubs_comparison_operators(self):
        """Test that stubs include comparison operators."""
        exports = self.intrinsic_manager.stubs.exports
        self.assertIn('interpreter__eq__', exports)
        self.assertIn('interpreter__ne__', exports)
        self.assertIn('interpreter__lt__', exports)
        self.assertIn('interpreter__le__', exports)
        self.assertIn('interpreter__gt__', exports)
        self.assertIn('interpreter__ge__', exports)

    def test_stubs_bitwise_operators(self):
        """Test that stubs include bitwise operators."""
        exports = self.intrinsic_manager.stubs.exports
        self.assertIn('interpreter__and__', exports)
        self.assertIn('interpreter__or__', exports)
        self.assertIn('interpreter__xor__', exports)
        self.assertIn('interpreter__lshift__', exports)
        self.assertIn('interpreter__rshift__', exports)

    def test_stubs_object_methods(self):
        """Test that stubs include object methods."""
        exports = self.intrinsic_manager.stubs.exports
        self.assertIn('object__getattribute__', exports)
        self.assertIn('object__setattribute__', exports)
        self.assertIn('object__call__', exports)

    def test_stubs_function_methods(self):
        """Test that stubs include function methods."""
        exports = self.intrinsic_manager.stubs.exports
        self.assertIn('function__get__', exports)
        self.assertIn('function__call__', exports)

    def test_stubs_method_descriptors(self):
        """Test that stubs include method descriptors."""
        exports = self.intrinsic_manager.stubs.exports
        self.assertIn('method__get__', exports)
        self.assertIn('method__call__', exports)
        self.assertIn('methoddescriptor__get__', exports)
        self.assertIn('methoddescriptor__call__', exports)

    def test_stubs_call_methods(self):
        """Test that stubs include call methods."""
        exports = self.intrinsic_manager.stubs.exports
        self.assertIn('interpreter_call', exports)
        self.assertIn('interpreter_getitem', exports)
        self.assertIn('interpreter_merge_kwargs', exports)
        self.assertIn('interpreter_merge_varargs', exports)

    def test_build_map_dynamic_fold_preserves_unpack_order(self):
        fold = self.intrinsic_manager.stubs.exports[
            "interpreter_build_map"
        ].annotation.dynamicFold

        self.assertEqual(
            fold(
                [
                    ("mapping", {"key": "mapping"}),
                    ("item", "key", "explicit"),
                ],
                [],
            ),
            {"key": "explicit"},
        )
        self.assertEqual(
            fold(
                [
                    ("item", "key", "explicit"),
                    ("mapping", {"key": "mapping"}),
                ],
                [],
            ),
            {"key": "mapping"},
        )

    def test_matrix_multiplication_dynamic_fold(self):
        class Matrix:
            def __matmul__(self, other):
                return (self, other)

        left = Matrix()
        right = Matrix()
        fold = self.intrinsic_manager.stubs.exports[
            "interpreter__matmul__"
        ].annotation.dynamicFold

        self.assertEqual(fold(left, right), (left, right))

    def test_true_division_dynamic_fold(self):
        fold = self.intrinsic_manager.stubs.exports[
            "interpreter__truediv__"
        ].annotation.dynamicFold

        self.assertEqual(fold(7, 2), 3.5)

    def test_vararg_merge_accepts_general_iterables(self):
        fold = self.intrinsic_manager.stubs.exports[
            "interpreter_merge_varargs"
        ].annotation.dynamicFold

        self.assertEqual(fold((item for item in (1, 2)), range(3, 5)), [1, 2, 3, 4])

    def test_set_add_matches_set_add_return_value(self):
        fold = self.intrinsic_manager.stubs.exports[
            "interpreter_set_add"
        ].annotation.dynamicFold
        values = set()

        result = fold(values, "item")

        self.assertIsNone(result)
        self.assertEqual(values, {"item"})

    def test_pattern_predicates_reject_strings_and_non_mappings(self):
        exports = self.intrinsic_manager.stubs.exports
        sequence = exports[
            "interpreter_match_sequence_len"
        ].annotation.dynamicFold
        mapping = exports[
            "interpreter_match_mapping_len"
        ].annotation.dynamicFold

        self.assertFalse(sequence("ab", 2))
        self.assertTrue(sequence([1, 2], 2))
        self.assertFalse(mapping([("key", "value")], 1))
        self.assertTrue(mapping({"key": "value"}, 1))

    @unittest.skipUnless(hasattr(builtins, "ExceptionGroup"), "Requires Python 3.11+")
    def test_exception_group_extract_returns_matching_subgroup(self):
        fold = self.intrinsic_manager.stubs.exports[
            "interpreter_exception_group_extract"
        ].annotation.dynamicFold
        group = ExceptionGroup("mixed", [ValueError("value"), TypeError("type")])

        extracted = fold(group, ValueError)

        self.assertEqual(len(extracted.exceptions), 1)
        self.assertIsInstance(extracted.exceptions[0], ValueError)

    def test_stubs_code_structure(self):
        """Test that stub codes have correct structure."""
        exports = self.intrinsic_manager.stubs.exports
        code = exports['interpreter__add__']
        
        # Check that code has required attributes
        self.assertIsNotNone(code)
        # Code should have annotation
        self.assertTrue(hasattr(code, 'annotation'))

    def test_stubs_annotation_properties(self):
        """Test that stub annotations have correct properties."""
        exports = self.intrinsic_manager.stubs.exports
        code = exports['interpreter__add__']
        
        if hasattr(code, 'annotation'):
            annotation = code.annotation
            # Check annotation properties
            self.assertTrue(hasattr(annotation, 'origin'))
            self.assertTrue(hasattr(annotation, 'interpreter'))
            self.assertTrue(hasattr(annotation, 'runtime'))
            # Interpreter functions should have interpreter=True
            self.assertTrue(annotation.interpreter)

    def test_create_minimal_stubs(self):
        """Intrinsic models are created without a legacy collection pipeline."""
        manager = IntrinsicManager(self.compiler)
        self.assertIsNotNone(manager.stubs)
        self.assertTrue(hasattr(manager.stubs, 'exports'))

    def test_minimal_stubs_structure(self):
        """Test that minimal stubs have correct structure."""
        # Test that stubs have the required structure
        manager = IntrinsicManager(self.compiler)
        exports = manager.stubs.exports
        
        # Should have all required interpreter functions
        required_functions = [
            'interpreter_getattribute',
            'interpreter__mul__',
            'interpreter__add__',
            'interpreter__sub__',
            'interpreter__div__',
            'interpreter__mod__',
            'interpreter__pow__',
        ]
        
        for func_name in required_functions:
            self.assertIn(func_name, exports)
            code = exports[func_name]
            self.assertIsNotNone(code)
            self.assertTrue(hasattr(code, 'annotation'))

    def test_stub_code_parameters(self):
        """Test that stub codes have parameters."""
        exports = self.intrinsic_manager.stubs.exports
        code = exports['interpreter__add__']
        
        # Code should have codeparameters
        if hasattr(code, 'codeparameters'):
            params = code.codeparameters
            self.assertIsNotNone(params)

    def test_structured_intrinsics_have_matching_parameter_counts(self):
        exports = self.intrinsic_manager.stubs.exports
        expected = {
            "interpreter_enter": 1,
            "interpreter_exit": 4,
            "interpreter_aenter": 1,
            "interpreter_aexit": 4,
            "interpreter_aiter": 1,
            "interpreter_format": 3,
            "interpreter_join_str": 1,
        }

        for name, count in expected.items():
            self.assertEqual(len(exports[name].codeparameters.params), count)

    def test_interpreter_format_dynamic_fold_models_f_strings(self):
        formatter = self.intrinsic_manager.stubs.exports[
            "interpreter_format"
        ].annotation.dynamicFold

        self.assertEqual(formatter(12.345, -1, ".2f"), "12.35")
        self.assertEqual(formatter("x", ord("r"), None), "'x'")

    def test_stub_code_body(self):
        """Test that stub codes have body."""
        exports = self.intrinsic_manager.stubs.exports
        code = exports['interpreter__add__']
        
        # Code should have body
        if hasattr(code, 'body'):
            body = code.body
            self.assertIsNotNone(body)

    def test_async_and_pattern_helpers_have_dynamic_fold(self):
        """Async/pattern helper stubs should expose conservative dynamic folds."""
        exports = self.intrinsic_manager.stubs.exports
        for name in (
            "interpreter_aiter",
            "interpreter_aenter",
            "interpreter_aexit",
            "interpreter_match_sequence_len",
            "interpreter_match_sequence_len_min",
            "interpreter_match_mapping_len",
            "interpreter_match_rest",
            "interpreter_exception_group_extract",
            "interpreter_exception_type",
            "interpreter_make_generator",
        ):
            code = exports[name]
            self.assertIsNotNone(code.annotation.dynamicFold)


if __name__ == "__main__":
    unittest.main()
