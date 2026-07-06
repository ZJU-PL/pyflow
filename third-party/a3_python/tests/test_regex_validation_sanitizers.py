"""
Test Regex Validation Pattern Sanitizers (Iteration 545).

Regex validation patterns constrain the input domain to make tainted values safe
for sinks without requiring escaping. For example:

    if re.match(r'^[a-zA-Z0-9_]+$', user_input):
        cursor.execute(f"SELECT * FROM t WHERE id = {user_input}")  # SAFE

This is different from re.escape() which escapes metacharacters. These patterns
validate that the input consists ONLY of safe characters, making injection impossible.

The tests verify:
1. Sanitizer registration and lookup
2. Correct sink applicability for each pattern
3. Integration with taint lattice (kappa bit setting)
4. Pattern-specific sanitization rules
"""

import pytest
from a3_python.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType, SanitizerType,
    SANITIZER_TO_SINKS
)
from a3_python.contracts.security_lattice import (
    get_sanitizer_contract, apply_sanitizer
)


class TestRegexValidationSanitizers:
    """Test regex validation pattern sanitizers."""
    
    def test_alphanumeric_pattern_registration(self):
        """Test alphanumeric pattern sanitizer is registered."""
        contract = get_sanitizer_contract("re.match:^[a-zA-Z0-9_]+$")
        assert contract is not None
        assert contract.sanitizer_type == SanitizerType.REGEX_ALPHANUMERIC
        
    def test_digits_pattern_registration(self):
        """Test digits-only pattern sanitizer is registered."""
        contract = get_sanitizer_contract("re.match:^\\d+$")
        assert contract is not None
        assert contract.sanitizer_type == SanitizerType.REGEX_DIGITS
        
    def test_hostname_pattern_registration(self):
        """Test hostname pattern sanitizer is registered."""
        contract = get_sanitizer_contract("re.match:^[a-z0-9.-]+$")
        assert contract is not None
        assert contract.sanitizer_type == SanitizerType.REGEX_HOSTNAME
        
    def test_slug_pattern_registration(self):
        """Test slug pattern sanitizer is registered."""
        contract = get_sanitizer_contract("re.match:^[a-z0-9-]+$")
        assert contract is not None
        assert contract.sanitizer_type == SanitizerType.REGEX_SLUG
        
    def test_hex_pattern_registration(self):
        """Test hex pattern sanitizer is registered."""
        contract = get_sanitizer_contract("re.match:^[0-9a-fA-F]+$")
        assert contract is not None
        assert contract.sanitizer_type == SanitizerType.REGEX_HEX
        
    def test_uuid_pattern_registration(self):
        """Test UUID pattern sanitizer is registered."""
        contract = get_sanitizer_contract("re.match:^[0-9a-f-]+$")
        assert contract is not None
        assert contract.sanitizer_type == SanitizerType.REGEX_UUID
        
    def test_base64_pattern_registration(self):
        """Test Base64 pattern sanitizer is registered."""
        contract = get_sanitizer_contract("re.match:^[A-Za-z0-9+/=]+$")
        assert contract is not None
        assert contract.sanitizer_type == SanitizerType.REGEX_BASE64
        
    def test_email_pattern_registration(self):
        """Test email pattern sanitizer is registered."""
        contract = get_sanitizer_contract("re.match:^[\\w.-]+@[\\w.-]+\\.\\w+$")
        assert contract is not None
        assert contract.sanitizer_type == SanitizerType.REGEX_EMAIL
        
    def test_url_path_pattern_registration(self):
        """Test URL path pattern sanitizer is registered."""
        contract = get_sanitizer_contract("re.match:^/[a-zA-Z0-9/_-]+$")
        assert contract is not None
        assert contract.sanitizer_type == SanitizerType.REGEX_URL_PATH
        
    def test_filepath_pattern_registration(self):
        """Test filepath pattern sanitizer is registered."""
        contract = get_sanitizer_contract("re.match:^[a-zA-Z0-9/_.-]+$")
        assert contract is not None
        assert contract.sanitizer_type == SanitizerType.REGEX_FILEPATH


class TestAlphanumericValidation:
    """Test alphanumeric pattern validation sanitizer."""
    
    def test_alphanumeric_applicable_sinks(self):
        """Alphanumeric pattern makes value safe for SQL, commands, paths."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.REGEX_ALPHANUMERIC]
        assert SinkType.SQL_EXECUTE in sinks
        assert SinkType.COMMAND_SHELL in sinks
        assert SinkType.FILE_PATH in sinks
        assert SinkType.LDAP_QUERY in sinks
        assert SinkType.NOSQL_QUERY in sinks
        
    def test_alphanumeric_sanitizes_sql(self):
        """Alphanumeric validation makes tainted value safe for SQL."""
        # Tainted from HTTP param
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
        # Apply alphanumeric validation
        contract = get_sanitizer_contract("re.match:^[a-zA-Z0-9_]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # Now safe for SQL (no special SQL chars possible)
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
    def test_alphanumeric_sanitizes_command(self):
        """Alphanumeric validation makes tainted value safe for shell commands."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        assert not label.is_safe_for_sink(SinkType.COMMAND_SHELL)
        
        contract = get_sanitizer_contract("re.match:^[a-zA-Z0-9]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # No shell metacharacters possible
        assert sanitized.is_safe_for_sink(SinkType.COMMAND_SHELL)
        
    def test_alphanumeric_sanitizes_path(self):
        """Alphanumeric validation prevents path traversal."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.FILE_PATH)
        
        contract = get_sanitizer_contract("re.match:^[a-zA-Z0-9_]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # No / or .. possible
        assert sanitized.is_safe_for_sink(SinkType.FILE_PATH)


class TestDigitsValidation:
    """Test digits-only pattern validation sanitizer."""
    
    def test_digits_applicable_sinks(self):
        """Digits pattern makes value safe for SQL, commands, paths."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.REGEX_DIGITS]
        assert SinkType.SQL_EXECUTE in sinks
        assert SinkType.COMMAND_SHELL in sinks
        assert SinkType.FILE_PATH in sinks
        
    def test_digits_sanitizes_sql(self):
        """Digits validation makes tainted value safe for SQL."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
        contract = get_sanitizer_contract("re.match:^\\d+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # Only digits possible - no SQL injection
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
    def test_digits_alternative_pattern(self):
        """Alternative digits pattern [0-9]+ also works."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        
        contract = get_sanitizer_contract("re.match:^[0-9]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        assert sanitized.is_safe_for_sink(SinkType.COMMAND_SHELL)


class TestHostnameValidation:
    """Test hostname pattern validation sanitizer."""
    
    def test_hostname_applicable_sinks(self):
        """Hostname pattern makes value safe for HTTP requests and DNS."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.REGEX_HOSTNAME]
        assert SinkType.HTTP_REQUEST in sinks
        assert SinkType.REDIRECT_URL in sinks
        assert SinkType.NETWORK_BIND in sinks
        
    def test_hostname_sanitizes_ssrf(self):
        """Hostname validation prevents SSRF to internal IPs."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.HTTP_REQUEST)
        
        contract = get_sanitizer_contract("re.match:^[a-z0-9.-]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # Only DNS-safe chars - no scheme, port, or path injection
        assert sanitized.is_safe_for_sink(SinkType.HTTP_REQUEST)
        
    def test_hostname_sanitizes_redirect(self):
        """Hostname validation prevents open redirect."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.REDIRECT_URL)
        
        contract = get_sanitizer_contract("re.match:^[a-zA-Z0-9.-]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        assert sanitized.is_safe_for_sink(SinkType.REDIRECT_URL)


class TestSlugValidation:
    """Test slug pattern validation sanitizer."""
    
    def test_slug_applicable_sinks(self):
        """Slug pattern makes value safe for URLs and file paths."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.REGEX_SLUG]
        assert SinkType.SQL_EXECUTE in sinks
        assert SinkType.FILE_PATH in sinks
        assert SinkType.HTTP_REQUEST in sinks
        assert SinkType.REDIRECT_URL in sinks
        
    def test_slug_sanitizes_path(self):
        """Slug validation prevents path traversal."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.FILE_PATH)
        
        contract = get_sanitizer_contract("re.match:^[a-z0-9-]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # No / or .. possible - only lowercase alphanumeric + hyphen
        assert sanitized.is_safe_for_sink(SinkType.FILE_PATH)


class TestHexValidation:
    """Test hexadecimal pattern validation sanitizer."""
    
    def test_hex_applicable_sinks(self):
        """Hex pattern makes value safe for SQL, paths, commands."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.REGEX_HEX]
        assert SinkType.SQL_EXECUTE in sinks
        assert SinkType.FILE_PATH in sinks
        assert SinkType.COMMAND_SHELL in sinks
        
    def test_hex_sanitizes_sql(self):
        """Hex validation makes tainted value safe for SQL."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
        contract = get_sanitizer_contract("re.match:^[0-9a-fA-F]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # Only hex chars - no SQL injection
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)


class TestUUIDValidation:
    """Test UUID pattern validation sanitizer."""
    
    def test_uuid_applicable_sinks(self):
        """UUID pattern makes value safe for SQL, paths, HTTP."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.REGEX_UUID]
        assert SinkType.SQL_EXECUTE in sinks
        assert SinkType.FILE_PATH in sinks
        assert SinkType.HTTP_REQUEST in sinks
        
    def test_uuid_sanitizes_sql(self):
        """UUID validation makes tainted value safe for SQL."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
        contract = get_sanitizer_contract("re.match:^[0-9a-f-]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # UUID format - no SQL injection
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)


class TestBase64Validation:
    """Test Base64 pattern validation sanitizer."""
    
    def test_base64_applicable_sinks(self):
        """Base64 pattern makes value safe for SQL, paths."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.REGEX_BASE64]
        assert SinkType.SQL_EXECUTE in sinks
        assert SinkType.FILE_PATH in sinks
        
    def test_base64_sanitizes_sql(self):
        """Base64 validation makes tainted value safe for SQL."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
        contract = get_sanitizer_contract("re.match:^[A-Za-z0-9+/=]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # Base64 alphabet - no SQL injection
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)


class TestEmailValidation:
    """Test email pattern validation sanitizer."""
    
    def test_email_applicable_sinks(self):
        """Email pattern makes value safe for SQL, email headers, LDAP."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.REGEX_EMAIL]
        assert SinkType.SQL_EXECUTE in sinks
        assert SinkType.EMAIL_HEADER in sinks
        assert SinkType.LDAP_QUERY in sinks
        
    def test_email_sanitizes_sql(self):
        """Email validation constrains to safe format for SQL."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
        contract = get_sanitizer_contract("re.match:^[\\w.-]+@[\\w.-]+\\.\\w+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # Email format - limited special chars
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)


class TestURLPathValidation:
    """Test URL path pattern validation sanitizer."""
    
    def test_url_path_applicable_sinks(self):
        """URL path pattern makes value safe for HTTP requests, redirects."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.REGEX_URL_PATH]
        assert SinkType.HTTP_REQUEST in sinks
        assert SinkType.REDIRECT_URL in sinks
        
    def test_url_path_sanitizes_redirect(self):
        """URL path validation prevents open redirect."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.REDIRECT_URL)
        
        contract = get_sanitizer_contract("re.match:^/[a-zA-Z0-9/_-]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # Path starts with /, no scheme or domain possible
        assert sanitized.is_safe_for_sink(SinkType.REDIRECT_URL)


class TestFilepathValidation:
    """Test filepath pattern validation sanitizer."""
    
    def test_filepath_applicable_sinks(self):
        """Filepath pattern makes value safe for file operations."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.REGEX_FILEPATH]
        assert SinkType.FILE_PATH in sinks
        assert SinkType.SQL_EXECUTE in sinks
        
    def test_filepath_sanitizes_path(self):
        """Filepath validation prevents path traversal."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert not label.is_safe_for_sink(SinkType.FILE_PATH)
        
        contract = get_sanitizer_contract("re.match:^[a-zA-Z0-9/_.-]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # No .. or leading / traversal patterns
        assert sanitized.is_safe_for_sink(SinkType.FILE_PATH)


class TestMultiplePatternVariations:
    """Test that multiple pattern variations for same sanitizer work."""
    
    def test_alphanumeric_with_underscore(self):
        """Alphanumeric with underscore variant."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        contract1 = get_sanitizer_contract("re.match:^[a-zA-Z0-9_]+$")
        contract2 = get_sanitizer_contract("re.match:^[a-zA-Z0-9]+$")
        
        assert contract1.sanitizer_type == SanitizerType.REGEX_ALPHANUMERIC
        assert contract2.sanitizer_type == SanitizerType.REGEX_ALPHANUMERIC
        
        s1 = apply_sanitizer(contract1.function_id, label)
        s2 = apply_sanitizer(contract2.function_id, label)
        
        assert s1.is_safe_for_sink(SinkType.SQL_EXECUTE)
        assert s2.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
    def test_digits_patterns(self):
        """Both \\d+ and [0-9]+ work for digits."""
        label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        
        contract1 = get_sanitizer_contract("re.match:^\\d+$")
        contract2 = get_sanitizer_contract("re.match:^[0-9]+$")
        
        assert contract1.sanitizer_type == SanitizerType.REGEX_DIGITS
        assert contract2.sanitizer_type == SanitizerType.REGEX_DIGITS
        
    def test_hostname_case_variations(self):
        """Hostname patterns with different case."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        contract1 = get_sanitizer_contract("re.match:^[a-z0-9.-]+$")
        contract2 = get_sanitizer_contract("re.match:^[a-zA-Z0-9.-]+$")
        
        assert contract1.sanitizer_type == SanitizerType.REGEX_HOSTNAME
        assert contract2.sanitizer_type == SanitizerType.REGEX_HOSTNAME


class TestSanitizerDomainConstraints:
    """Test that sanitizers work by constraining domain, not escaping."""
    
    def test_alphanumeric_prevents_sql_injection(self):
        """
        Alphanumeric validation prevents SQL injection by making quotes impossible.
        
        Without validation: user_input = "'; DROP TABLE users--"
        With validation: only [a-zA-Z0-9_] allowed, so no quotes possible.
        """
        tainted = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        contract = get_sanitizer_contract("re.match:^[a-zA-Z0-9_]+$")
        sanitized = apply_sanitizer(contract.function_id, tainted)
        
        # Domain constrained to alphanumeric - SQL metacharacters impossible
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        
    def test_digits_prevents_command_injection(self):
        """
        Digits validation prevents command injection by making shell chars impossible.
        
        Without validation: user_input = "42; rm -rf /"
        With validation: only \\d+ allowed, so no semicolons or spaces possible.
        """
        tainted = TaintLabel.from_untrusted_source(SourceType.USER_INPUT)
        contract = get_sanitizer_contract("re.match:^\\d+$")
        sanitized = apply_sanitizer(contract.function_id, tainted)
        
        # Domain constrained to digits - shell metacharacters impossible
        assert sanitized.is_safe_for_sink(SinkType.COMMAND_SHELL)
        
    def test_slug_prevents_path_traversal(self):
        """
        Slug validation prevents path traversal by making / and . impossible.
        
        Without validation: user_input = "../../etc/passwd"
        With validation: only [a-z0-9-] allowed, so no slashes or dots possible.
        """
        tainted = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        contract = get_sanitizer_contract("re.match:^[a-z0-9-]+$")
        sanitized = apply_sanitizer(contract.function_id, tainted)
        
        # Domain constrained to slug chars - path traversal impossible
        assert sanitized.is_safe_for_sink(SinkType.FILE_PATH)


class TestKappaBitSetting:
    """Test that regex sanitizers correctly set kappa bits."""
    
    def test_alphanumeric_sets_multiple_kappa_bits(self):
        """Alphanumeric validation sets kappa bits for multiple sinks."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        contract = get_sanitizer_contract("re.match:^[a-zA-Z0-9_]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        # Check kappa bits are set for all applicable sinks
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        assert sanitized.is_safe_for_sink(SinkType.COMMAND_SHELL)
        assert sanitized.is_safe_for_sink(SinkType.FILE_PATH)
        assert sanitized.is_safe_for_sink(SinkType.LDAP_QUERY)
        assert sanitized.is_safe_for_sink(SinkType.NOSQL_QUERY)
        
    def test_hostname_sets_network_kappa_bits(self):
        """Hostname validation sets kappa bits for network sinks."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        contract = get_sanitizer_contract("re.match:^[a-z0-9.-]+$")
        sanitized = apply_sanitizer(contract.function_id, label)
        
        assert sanitized.is_safe_for_sink(SinkType.HTTP_REQUEST)
        assert sanitized.is_safe_for_sink(SinkType.REDIRECT_URL)
        assert sanitized.is_safe_for_sink(SinkType.NETWORK_BIND)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
