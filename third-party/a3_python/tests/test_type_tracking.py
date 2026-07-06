"""
Tests for context-sensitive type tracking (Iteration 544).

These tests validate that type tracking:
1. Correctly identifies types after conversions
2. Improves taint analysis precision
3. Reduces false positives where type makes value safe
4. Integrates properly with the taint lattice
"""

import pytest
from a3_python.z3model.type_tracking import (
    ConcreteType, TypeLabel, TypeAwareTaintLabel,
    get_conversion_result_type, is_type_conversion
)
from a3_python.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType
)


class TestConcreteType:
    """Test the ConcreteType enum."""
    
    def test_all_types_defined(self):
        """Ensure all expected types are defined."""
        assert ConcreteType.UNKNOWN == 0
        assert ConcreteType.INT == 3
        assert ConcreteType.STR == 5
        assert ConcreteType.UUID == 13


class TestTypeLabel:
    """Test TypeLabel operations."""
    
    def test_unknown_type(self):
        """Test creation of unknown type label."""
        label = TypeLabel.unknown()
        assert label.concrete_type == ConcreteType.UNKNOWN
        assert len(label.conversion_history) == 0
    
    def test_from_type(self):
        """Test creating type label from concrete type."""
        label = TypeLabel.from_type(ConcreteType.INT, "int()")
        assert label.concrete_type == ConcreteType.INT
        assert "int()" in label.conversion_history
    
    def test_convert_to(self):
        """Test type conversion tracking."""
        label1 = TypeLabel.from_type(ConcreteType.STR, "initial")
        label2 = label1.convert_to(ConcreteType.INT, "int()")
        
        assert label2.concrete_type == ConcreteType.INT
        assert "initial" in label2.conversion_history
        assert "int()" in label2.conversion_history
    
    def test_is_numeric(self):
        """Test numeric type checking."""
        assert TypeLabel.from_type(ConcreteType.INT).is_numeric()
        assert TypeLabel.from_type(ConcreteType.FLOAT).is_numeric()
        assert TypeLabel.from_type(ConcreteType.BOOL).is_numeric()
        assert not TypeLabel.from_type(ConcreteType.STR).is_numeric()
    
    def test_is_string_like(self):
        """Test string-like type checking."""
        assert TypeLabel.from_type(ConcreteType.STR).is_string_like()
        assert TypeLabel.from_type(ConcreteType.BYTES).is_string_like()
        assert not TypeLabel.from_type(ConcreteType.INT).is_string_like()
    
    def test_is_safe_for_sql(self):
        """Test SQL safety checking based on type."""
        # Numeric types are safe
        assert TypeLabel.from_type(ConcreteType.INT).is_safe_for_sql()
        assert TypeLabel.from_type(ConcreteType.FLOAT).is_safe_for_sql()
        assert TypeLabel.from_type(ConcreteType.BOOL).is_safe_for_sql()
        
        # Structured types are safe
        assert TypeLabel.from_type(ConcreteType.DATETIME).is_safe_for_sql()
        assert TypeLabel.from_type(ConcreteType.UUID).is_safe_for_sql()
        
        # String types are NOT inherently safe
        assert not TypeLabel.from_type(ConcreteType.STR).is_safe_for_sql()
    
    def test_is_safe_for_command(self):
        """Test command injection safety based on type."""
        # Numeric types and UUIDs are safe
        assert TypeLabel.from_type(ConcreteType.INT).is_safe_for_command()
        assert TypeLabel.from_type(ConcreteType.UUID).is_safe_for_command()
        
        # Strings are NOT safe (can contain shell metacharacters)
        assert not TypeLabel.from_type(ConcreteType.STR).is_safe_for_command()
    
    def test_is_safe_for_path(self):
        """Test path injection safety based on type."""
        # Path objects are canonicalized, so safe
        assert TypeLabel.from_type(ConcreteType.PATH).is_safe_for_path()
        assert TypeLabel.from_type(ConcreteType.UUID).is_safe_for_path()
        assert TypeLabel.from_type(ConcreteType.INT).is_safe_for_path()
        
        # Strings are NOT inherently safe
        assert not TypeLabel.from_type(ConcreteType.STR).is_safe_for_path()


class TestTypeAwareTaintLabel:
    """Test combined type-aware taint labels."""
    
    def test_untainted_value_is_safe(self):
        """Test that untainted values are safe regardless of type."""
        taint = TaintLabel.clean()
        typ = TypeLabel.from_type(ConcreteType.STR)
        
        type_aware = TypeAwareTaintLabel(taint_label=taint, type_label=typ)
        
        # Clean value is always safe
        assert type_aware.is_safe_for_sink_considering_type(SinkType.SQL_EXECUTE)
    
    def test_tainted_int_safe_for_sql(self):
        """Test that tainted integer is safe for SQL (no injection possible)."""
        # Tainted from user input
        taint = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        # But converted to int
        typ = TypeLabel.from_type(ConcreteType.INT, "int()")
        
        type_aware = TypeAwareTaintLabel(taint_label=taint, type_label=typ)
        
        # Even though tainted, int cannot contain SQL injection
        assert type_aware.is_safe_for_sink_considering_type(SinkType.SQL_EXECUTE)
    
    def test_tainted_string_unsafe_for_sql(self):
        """Test that tainted string is UNSAFE for SQL."""
        taint = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        typ = TypeLabel.from_type(ConcreteType.STR)
        
        type_aware = TypeAwareTaintLabel(taint_label=taint, type_label=typ)
        
        # Tainted string can contain SQL injection
        assert not type_aware.is_safe_for_sink_considering_type(SinkType.SQL_EXECUTE)
    
    def test_tainted_uuid_safe_for_path(self):
        """Test that tainted UUID is safe for path operations."""
        taint = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        typ = TypeLabel.from_type(ConcreteType.UUID, "uuid.UUID()")
        
        type_aware = TypeAwareTaintLabel(taint_label=taint, type_label=typ)
        
        # UUID format is validated, safe for paths
        assert type_aware.is_safe_for_sink_considering_type(SinkType.FILE_PATH)
    
    def test_tainted_float_safe_for_command(self):
        """Test that tainted float is safe for command injection."""
        taint = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        typ = TypeLabel.from_type(ConcreteType.FLOAT, "float()")
        
        type_aware = TypeAwareTaintLabel(taint_label=taint, type_label=typ)
        
        # Float cannot contain shell metacharacters
        assert type_aware.is_safe_for_sink_considering_type(SinkType.COMMAND_SHELL)
    
    def test_unknown_type_falls_back_to_taint(self):
        """Test that unknown type uses pure taint checking."""
        taint = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        typ = TypeLabel.unknown()
        
        type_aware = TypeAwareTaintLabel(taint_label=taint, type_label=typ)
        
        # Unknown type, tainted → UNSAFE
        assert not type_aware.is_safe_for_sink_considering_type(SinkType.SQL_EXECUTE)
    
    def test_sanitized_value_safe_regardless_of_type(self):
        """Test that sanitized values are safe regardless of type."""
        taint = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        # Apply SQL_ESCAPE sanitizer
        from a3_python.z3model.taint_lattice import SanitizerType
        taint = taint.sanitize(SanitizerType.SQL_ESCAPE)
        
        typ = TypeLabel.from_type(ConcreteType.STR)  # Still a string
        type_aware = TypeAwareTaintLabel(taint_label=taint, type_label=typ)
        
        # Sanitized string is safe
        assert type_aware.is_safe_for_sink_considering_type(SinkType.SQL_EXECUTE)
    
    def test_join_same_types(self):
        """Test joining type-aware labels with same type."""
        taint1 = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        taint2 = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        typ1 = TypeLabel.from_type(ConcreteType.INT, "int()")
        typ2 = TypeLabel.from_type(ConcreteType.INT, "int()")
        
        label1 = TypeAwareTaintLabel(taint_label=taint1, type_label=typ1)
        label2 = TypeAwareTaintLabel(taint_label=taint2, type_label=typ2)
        
        joined = label1.join(label2)
        
        # Taint merged
        assert joined.taint_label.has_untrusted_taint()
        # Type preserved
        assert joined.type_label.concrete_type == ConcreteType.INT
    
    def test_join_different_types(self):
        """Test joining type-aware labels with different types."""
        taint1 = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        taint2 = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        typ1 = TypeLabel.from_type(ConcreteType.INT, "int()")
        typ2 = TypeLabel.from_type(ConcreteType.STR, "str()")
        
        label1 = TypeAwareTaintLabel(taint_label=taint1, type_label=typ1)
        label2 = TypeAwareTaintLabel(taint_label=taint2, type_label=typ2)
        
        joined = label1.join(label2)
        
        # Taint merged
        assert joined.taint_label.has_untrusted_taint()
        # Type becomes UNKNOWN (loss of precision)
        assert joined.type_label.concrete_type == ConcreteType.UNKNOWN


class TestTypeConversionMappings:
    """Test function name to type mappings."""
    
    def test_builtin_conversions(self):
        """Test builtin type conversions."""
        assert get_conversion_result_type('int') == ConcreteType.INT
        assert get_conversion_result_type('builtins.int') == ConcreteType.INT
        assert get_conversion_result_type('float') == ConcreteType.FLOAT
        assert get_conversion_result_type('bool') == ConcreteType.BOOL
        assert get_conversion_result_type('str') == ConcreteType.STR
        assert get_conversion_result_type('bytes') == ConcreteType.BYTES
    
    def test_string_validation_methods(self):
        """Test string validation methods return bool."""
        assert get_conversion_result_type('str.isdigit') == ConcreteType.BOOL
        assert get_conversion_result_type('str.isalpha') == ConcreteType.BOOL
        assert get_conversion_result_type('str.isalnum') == ConcreteType.BOOL
    
    def test_datetime_conversions(self):
        """Test datetime parsing functions."""
        assert get_conversion_result_type('datetime.datetime.fromisoformat') == ConcreteType.DATETIME
        assert get_conversion_result_type('datetime.datetime.strptime') == ConcreteType.DATETIME
        assert get_conversion_result_type('datetime.date.fromisoformat') == ConcreteType.DATE
    
    def test_structured_types(self):
        """Test structured type conversions."""
        assert get_conversion_result_type('uuid.UUID') == ConcreteType.UUID
        assert get_conversion_result_type('ipaddress.ip_address') == ConcreteType.IPADDRESS
        assert get_conversion_result_type('pathlib.Path') == ConcreteType.PATH
    
    def test_is_type_conversion(self):
        """Test checking if function is type conversion."""
        assert is_type_conversion('int')
        assert is_type_conversion('uuid.UUID')
        assert is_type_conversion('datetime.datetime.fromisoformat')
        assert not is_type_conversion('print')
        assert not is_type_conversion('random.function')
    
    def test_unknown_function(self):
        """Test unknown functions return None."""
        assert get_conversion_result_type('unknown.function') is None
        assert not is_type_conversion('not.a.conversion')


class TestEndToEndScenarios:
    """Test complete type tracking scenarios."""
    
    def test_int_conversion_prevents_sql_injection_fp(self):
        """
        Test that int(user_input) prevents SQL injection false positive.
        
        Even though the value is tainted, converting to int makes it safe
        for SQL because integers cannot contain SQL injection payloads.
        """
        # User input is tainted
        user_input = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        user_input_type = TypeLabel.from_type(ConcreteType.STR)
        
        # Before conversion: tainted string → UNSAFE
        before = TypeAwareTaintLabel(taint_label=user_input, type_label=user_input_type)
        assert not before.is_safe_for_sink_considering_type(SinkType.SQL_EXECUTE)
        
        # After int() conversion: tainted int → SAFE
        converted_type = TypeLabel.from_type(ConcreteType.INT, "int()")
        after = TypeAwareTaintLabel(taint_label=user_input, type_label=converted_type)
        assert after.is_safe_for_sink_considering_type(SinkType.SQL_EXECUTE)
    
    def test_uuid_validation_prevents_path_injection_fp(self):
        """
        Test that uuid.UUID() validation prevents path injection false positive.
        
        Even though the input is tainted, validating as UUID makes it safe
        for path operations because UUIDs have constrained format.
        """
        # User input is tainted
        user_input = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        # Before validation: tainted string → UNSAFE for paths
        before_type = TypeLabel.from_type(ConcreteType.STR)
        before = TypeAwareTaintLabel(taint_label=user_input, type_label=before_type)
        assert not before.is_safe_for_sink_considering_type(SinkType.FILE_PATH)
        
        # After UUID validation: tainted UUID → SAFE for paths
        after_type = TypeLabel.from_type(ConcreteType.UUID, "uuid.UUID()")
        after = TypeAwareTaintLabel(taint_label=user_input, type_label=after_type)
        assert after.is_safe_for_sink_considering_type(SinkType.FILE_PATH)
    
    def test_type_narrowing_through_conversion_chain(self):
        """Test tracking type through multiple conversions."""
        # Start with unknown
        label = TypeLabel.unknown()
        
        # Convert to string
        label = label.convert_to(ConcreteType.STR, "str()")
        assert label.concrete_type == ConcreteType.STR
        
        # Convert to int
        label = label.convert_to(ConcreteType.INT, "int()")
        assert label.concrete_type == ConcreteType.INT
        assert "str()" in label.conversion_history
        assert "int()" in label.conversion_history
    
    def test_datetime_parsing_safe_for_sql(self):
        """Test that datetime parsing makes values safe for SQL."""
        # Tainted input
        taint = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        # After datetime parsing
        typ = TypeLabel.from_type(ConcreteType.DATETIME, "datetime.fromisoformat()")
        type_aware = TypeAwareTaintLabel(taint_label=taint, type_label=typ)
        
        # Datetime objects are safe for SQL (cannot contain injection)
        assert type_aware.is_safe_for_sink_considering_type(SinkType.SQL_EXECUTE)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
