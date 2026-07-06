"""
Test type-based sanitizers for improved precision.

These sanitizers work by constraining the value domain through type conversion:
- int(), float(), bool() constrain to specific numeric/boolean domains
- str.isdigit(), isalpha(), isalnum() validate string format
- datetime parsing validates temporal format
- pathlib.Path canonicalizes paths
- ipaddress validates IP address format
- enum constrains to predefined values
- json.loads is safe for deserialization (no code exec)

Barrier-theoretic justification:
    For a type conversion T: V -> T(V), if T strictly validates/constrains:
        - For SQL injection: int(x) prevents most injection (can't inject SQL operators)
        - For path traversal: Path(x).resolve() canonicalizes and prevents ../ tricks
        - For command injection: bool(x) constrains to True/False (no shell metacharacters)
    
    Safety predicate:
        safe_after_conversion(v, sink) := (v = T(v_tainted) ∧ domain(T) ∩ exploit_strings(sink) = ∅)
"""

import pytest
from a3_python.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType, SanitizerType
)
from a3_python.contracts.security_lattice import (
    _sanitizer_contracts, apply_sanitizer
)


class TestTypeSanitizers:
    """Test that type conversions act as sanitizers for appropriate sinks."""
    
    def test_int_sanitizes_sql(self):
        """int() conversion sanitizes for SQL injection."""
        # Tainted from HTTP parameter
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
        # Apply int() sanitizer (pass function_id string, not contract)
        sanitized = apply_sanitizer("builtins.int", label)
        
        # Should now be safe for SQL
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
    def test_float_sanitizes_sql(self):
        """float() conversion sanitizes for SQL injection."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        assert not label.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
        sanitized = apply_sanitizer("builtins.float", label)
        
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
    
    def test_bool_sanitizes_multiple_sinks(self):
        """bool() conversion sanitizes for SQL, command, and path sinks."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        sanitized = apply_sanitizer("builtins.bool", label)
        
        # Boolean can only be True/False - safe for multiple sinks
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        assert sanitized.is_safe_for_sink(SinkType.COMMAND_SHELL)
        assert sanitized.is_safe_for_sink(SinkType.FILE_PATH)
    
    def test_datetime_sanitizes_sql(self):
        """datetime.fromisoformat() validates format and sanitizes SQL."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        
        sanitized = apply_sanitizer("datetime.datetime.fromisoformat", label)
        
        # Datetime parsing validates format - safe for SQL
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
    
    def test_pathlib_canonicalize(self):
        """pathlib.Path.resolve() canonicalizes paths and prevents traversal."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        assert not label.is_safe_for_sink(SinkType.FILE_PATH)
        
        sanitized = apply_sanitizer("pathlib.Path.resolve", label)
        
        # Canonicalized path - safe for file operations
        assert sanitized.is_safe_for_sink(SinkType.FILE_PATH)
    
    def test_ip_address_validation(self):
        """ipaddress.ip_address() validates format."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        
        sanitized = apply_sanitizer("ipaddress.ip_address", label)
        
        # Valid IP address - safe for SQL and HTTP requests
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        assert sanitized.is_safe_for_sink(SinkType.HTTP_REQUEST)
    
    def test_enum_constrains_to_allowlist(self):
        """enum.Enum constrains value to predefined set."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        sanitized = apply_sanitizer("enum.Enum", label)
        
        # Enum lookup constrains to predefined values
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        assert sanitized.is_safe_for_sink(SinkType.COMMAND_SHELL)
    
    def test_json_loads_safe_deserialization(self):
        """json.loads() is safe for deserialization (no code execution)."""
        label = TaintLabel.from_untrusted_source(SourceType.NETWORK_RECV)
        assert not label.is_safe_for_sink(SinkType.DESERIALIZE)
        
        sanitized = apply_sanitizer("json.loads", label)
        
        # JSON has no code execution - safe to deserialize
        assert sanitized.is_safe_for_sink(SinkType.DESERIALIZE)
    
    def test_str_isdigit_validation(self):
        """str.isdigit() validates numeric format."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        
        sanitized = apply_sanitizer("str.isdigit", label)
        
        # All digits - safe for SQL
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
    
    def test_str_isalnum_validation(self):
        """str.isalnum() validates alphanumeric format (no special chars)."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        
        sanitized = apply_sanitizer("str.isalnum", label)
        
        # Alphanumeric only - no SQL operators, shell metacharacters, or path traversal
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        assert sanitized.is_safe_for_sink(SinkType.COMMAND_SHELL)
        assert sanitized.is_safe_for_sink(SinkType.FILE_PATH)


class TestTypeSanitizerComposition:
    """Test that type sanitizers compose correctly with other operations."""
    
    def test_int_then_string_interpolation(self):
        """int() sanitizes even if later converted to string."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        # Apply int() sanitizer
        sanitized = apply_sanitizer("int", label)
        
        # Even if converted to string later, still safe (int domain is constrained)
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
    
    def test_uuid_validation_for_sql_and_path(self):
        """UUID validation sanitizes both SQL and file path sinks."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        
        sanitized = apply_sanitizer("uuid.UUID", label)
        
        # UUID format is constrained - safe for both sinks
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        assert sanitized.is_safe_for_sink(SinkType.FILE_PATH)
    
    def test_bytes_encoding_sanitizes_sql(self):
        """bytes conversion sanitizes for SQL."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        
        sanitized = apply_sanitizer("builtins.bytes", label)
        
        # Bytes have constrained representation
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)


class TestTypeSanitizerNegatives:
    """Test that type sanitizers don't over-sanitize."""
    
    def test_int_does_not_sanitize_code_eval(self):
        """int() does NOT sanitize for code evaluation."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        
        sanitized = apply_sanitizer("int", label)
        
        # int() doesn't sanitize CODE_EVAL (could be 0, 1, etc. that are code)
        # Actually, int() only sanitizes SQL, FILE_PATH, COMMAND_SHELL
        assert not sanitized.is_safe_for_sink(SinkType.CODE_EVAL)
    
    def test_float_does_not_sanitize_command(self):
        """float() does NOT sanitize for command injection."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        
        sanitized = apply_sanitizer("builtins.float", label)
        
        # float() only sanitizes SQL_EXECUTE
        assert not sanitized.is_safe_for_sink(SinkType.COMMAND_SHELL)
    
    def test_datetime_does_not_sanitize_html(self):
        """datetime parsing does NOT sanitize HTML output."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        
        sanitized = apply_sanitizer("datetime.datetime.fromisoformat", label)
        
        # Datetime only sanitizes SQL
        assert not sanitized.is_safe_for_sink(SinkType.HTML_OUTPUT)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
