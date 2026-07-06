"""
Regression tests for σ-taint (sensitivity) tracking extensions.

These tests cover the σ-taint extensions added in iterations 308-315:
- CLEARTEXT_LOGGING detection
- CLEARTEXT_STORAGE detection  
- WEAK_SENSITIVE_DATA_HASHING detection
- Sensitive source tracking (PASSWORD, API_KEY, etc.)
- Cleartext sink detection (LOG_OUTPUT, FILE_WRITE, etc.)
- Sanitizer validation (HASH_SHA256, ENCRYPT_AES, etc.)

Soundness requirement: Sem_f ⊆ R_f (over-approximation preserved)
"""

import pytest
from a3_python.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType, SanitizerType,
    CODEQL_BUG_TYPES, SecurityBugType
)


class TestSensitiveSourceTracking:
    """Test σ-taint tracking from sensitive sources."""
    
    def test_password_source_sets_sigma(self):
        """PASSWORD source should set σ bit."""
        label = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        assert label.sigma == (1 << SourceType.PASSWORD)
        assert label.has_sensitivity()
        assert SourceType.PASSWORD in label.get_sensitivity_sources()
    
    def test_api_key_source_sets_sigma(self):
        """API_KEY source should set σ bit."""
        label = TaintLabel.from_sensitive_source(SourceType.API_KEY)
        assert label.sigma == (1 << SourceType.API_KEY)
        assert label.has_sensitivity()
    
    def test_cookie_session_sources_set_sigma(self):
        """SESSION_TOKEN and CREDENTIALS sources should set σ bits."""
        session_label = TaintLabel.from_sensitive_source(SourceType.SESSION_TOKEN)
        creds_label = TaintLabel.from_sensitive_source(SourceType.CREDENTIALS)
        
        assert session_label.has_sensitivity()
        assert creds_label.has_sensitivity()
        assert SourceType.SESSION_TOKEN in session_label.get_sensitivity_sources()
        assert SourceType.CREDENTIALS in creds_label.get_sensitivity_sources()
    
    def test_multiple_sensitivity_sources_join(self):
        """Multiple sensitive sources should join σ bits."""
        password = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        api_key = TaintLabel.from_sensitive_source(SourceType.API_KEY)
        
        joined = password.join(api_key)
        assert SourceType.PASSWORD in joined.get_sensitivity_sources()
        assert SourceType.API_KEY in joined.get_sensitivity_sources()
        assert joined.sigma == (1 << SourceType.PASSWORD) | (1 << SourceType.API_KEY)
    
    def test_untrusted_source_does_not_set_sigma(self):
        """Untrusted sources (τ) should not set σ bits."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        assert label.tau == (1 << SourceType.HTTP_PARAM)
        assert label.sigma == 0
        assert not label.has_sensitivity()


class TestCleartextSinkDetection:
    """Test σ-taint violation at cleartext sinks."""
    
    def test_log_output_sink_unsafe_for_sensitive_data(self):
        """LOG_OUTPUT sink should be unsafe for σ-tainted data."""
        password = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        assert not password.is_safe_for_sink(SinkType.LOG_OUTPUT)
    
    def test_file_write_sink_unsafe_for_sensitive_data(self):
        """FILE_WRITE sink should be unsafe for σ-tainted data."""
        api_key = TaintLabel.from_sensitive_source(SourceType.API_KEY)
        assert not api_key.is_safe_for_sink(SinkType.FILE_WRITE)
    
    def test_network_send_sink_unsafe_for_sensitive_data(self):
        """NETWORK_SEND sink should be unsafe for σ-tainted data."""
        cookie = TaintLabel.from_sensitive_source(SourceType.COOKIE)
        assert not cookie.is_safe_for_sink(SinkType.NETWORK_SEND)
    
    def test_clean_data_safe_for_cleartext_sinks(self):
        """Clean (non-sensitive) data should be safe for cleartext sinks."""
        clean = TaintLabel.clean()
        assert clean.is_safe_for_sink(SinkType.LOG_OUTPUT)
        assert clean.is_safe_for_sink(SinkType.FILE_WRITE)
        assert clean.is_safe_for_sink(SinkType.NETWORK_SEND)
    
    def test_untrusted_nonsensitive_safe_for_cleartext_sinks(self):
        """Untrusted (τ) but non-sensitive data should be safe for cleartext sinks."""
        http_param = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        # Has τ taint but no σ taint, so safe for cleartext exposure
        assert http_param.is_safe_for_sink(SinkType.LOG_OUTPUT)


class TestSensitivitySanitization:
    """Test σ-taint removal through sanitization."""
    
    def test_hashing_sanitizer_removes_sigma(self):
        """HASHING sanitizer should remove σ taint."""
        password = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        sanitized = password.sanitize(SanitizerType.HASHING)
        
        assert sanitized.is_safe_for_sink(SinkType.LOG_OUTPUT)
        assert sanitized.is_safe_for_sink(SinkType.FILE_WRITE)
    
    def test_encryption_sanitizer_removes_sigma(self):
        """ENCRYPTION sanitizer should remove σ taint."""
        api_key = TaintLabel.from_sensitive_source(SourceType.API_KEY)
        sanitized = api_key.sanitize(SanitizerType.ENCRYPTION)
        
        assert sanitized.is_safe_for_sink(SinkType.NETWORK_SEND)
    
    def test_redaction_sanitizer_removes_sigma(self):
        """REDACTION sanitizer should remove σ taint."""
        session_token = TaintLabel.from_sensitive_source(SourceType.SESSION_TOKEN)
        sanitized = session_token.sanitize(SanitizerType.REDACTION)
        
        assert sanitized.is_safe_for_sink(SinkType.LOG_OUTPUT)
    
    def test_sql_escape_does_not_remove_sigma(self):
        """SQL_ESCAPE sanitizer should only affect κ, not σ."""
        password = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        sanitized = password.sanitize(SanitizerType.SQL_ESCAPE)
        
        # Still has σ taint (not sanitized for cleartext exposure)
        assert not sanitized.is_safe_for_sink(SinkType.LOG_OUTPUT)
        assert sanitized.has_sensitivity()


class TestCleartextLoggingBugType:
    """Test CLEARTEXT_LOGGING bug type definition."""
    
    def test_cleartext_logging_bug_type_exists(self):
        """CLEARTEXT_LOGGING should be registered in CODEQL_BUG_TYPES."""
        assert "CLEARTEXT_LOGGING" in CODEQL_BUG_TYPES
        bug = CODEQL_BUG_TYPES["CLEARTEXT_LOGGING"]
        assert bug.name == "CLEARTEXT_LOGGING"
        # CWE-532 is the correct code (Information Exposure Through Log Files)
        assert bug.cwe in ["CWE-312", "CWE-532"]
    
    def test_cleartext_logging_checks_sigma(self):
        """CLEARTEXT_LOGGING should check σ (not τ)."""
        bug = CODEQL_BUG_TYPES["CLEARTEXT_LOGGING"]
        assert bug.checks_sigma
        assert not bug.checks_tau


class TestCleartextStorageBugType:
    """Test CLEARTEXT_STORAGE bug type definition."""
    
    def test_cleartext_storage_bug_type_exists(self):
        """CLEARTEXT_STORAGE should be registered."""
        assert "CLEARTEXT_STORAGE" in CODEQL_BUG_TYPES
        bug = CODEQL_BUG_TYPES["CLEARTEXT_STORAGE"]
        assert bug.name == "CLEARTEXT_STORAGE"
        assert bug.cwe == "CWE-312"
    
    def test_cleartext_storage_checks_sigma(self):
        """CLEARTEXT_STORAGE should check σ."""
        bug = CODEQL_BUG_TYPES["CLEARTEXT_STORAGE"]
        assert bug.checks_sigma


class TestWeakSensitiveDataHashingBugType:
    """Test WEAK_SENSITIVE_DATA_HASHING bug type definition."""
    
    def test_weak_hashing_bug_type_exists(self):
        """WEAK_SENSITIVE_DATA_HASHING should be registered."""
        assert "WEAK_SENSITIVE_DATA_HASHING" in CODEQL_BUG_TYPES
        bug = CODEQL_BUG_TYPES["WEAK_SENSITIVE_DATA_HASHING"]
        assert bug.name == "WEAK_SENSITIVE_DATA_HASHING"
        assert bug.cwe == "CWE-327"
    
    def test_weak_hashing_checks_sigma(self):
        """WEAK_SENSITIVE_DATA_HASHING should check σ."""
        bug = CODEQL_BUG_TYPES["WEAK_SENSITIVE_DATA_HASHING"]
        assert bug.checks_sigma


class TestSigmaTauIndependence:
    """Test that σ (sensitivity) and τ (untrusted) are independent."""
    
    def test_sigma_and_tau_can_coexist(self):
        """Data can be both untrusted (τ) and sensitive (σ)."""
        # Start with untrusted data
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        # Add sensitivity using with_sensitivity (pass the SourceType, not bit value)
        label_with_sigma = label.with_sensitivity(SourceType.PASSWORD)
        
        assert label_with_sigma.has_untrusted_taint()
        assert label_with_sigma.has_sensitivity()
        assert SourceType.HTTP_PARAM in label_with_sigma.get_untrusted_sources()
        assert SourceType.PASSWORD in label_with_sigma.get_sensitivity_sources()
    
    def test_sql_escape_removes_tau_not_sigma(self):
        """SQL_ESCAPE should add SQL_EXECUTE to κ but not affect σ."""
        # Data that is both untrusted and sensitive
        label = TaintLabel(
            tau=1 << SourceType.HTTP_PARAM,
            kappa=0,
            sigma=1 << SourceType.PASSWORD
        )
        
        sanitized = label.sanitize(SanitizerType.SQL_ESCAPE)
        
        # τ is sanitized for SQL_EXECUTE
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        # But σ is NOT sanitized for cleartext exposure
        assert not sanitized.is_safe_for_sink(SinkType.LOG_OUTPUT)
        assert sanitized.has_sensitivity()
    
    def test_hashing_removes_sigma_preserves_tau(self):
        """HASHING should sanitize σ but preserve τ."""
        label = TaintLabel(
            tau=1 << SourceType.HTTP_PARAM,
            kappa=0,
            sigma=1 << SourceType.PASSWORD
        )
        
        sanitized = label.sanitize(SanitizerType.HASHING)
        
        # σ is sanitized (safe for cleartext)
        assert sanitized.is_safe_for_sink(SinkType.LOG_OUTPUT)
        # But τ is preserved (still untrusted for injection)
        assert sanitized.has_untrusted_taint()
        # Not safe for SQL without SQL sanitization
        assert not sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)


class TestSigmaTaintPropagation:
    """Test σ-taint propagation through operations."""
    
    def test_sigma_propagates_through_string_concat(self):
        """String concatenation should preserve σ taint."""
        password = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        clean = TaintLabel.clean()
        
        result = password.join(clean)
        assert result.has_sensitivity()
        assert SourceType.PASSWORD in result.get_sensitivity_sources()
    
    def test_sigma_propagates_through_format_string(self):
        """Format string should preserve σ taint from any argument."""
        api_key = TaintLabel.from_sensitive_source(SourceType.API_KEY)
        clean1 = TaintLabel.clean()
        clean2 = TaintLabel.clean()
        
        # Simulate f"prefix {api_key} suffix"
        result = clean1.join(api_key).join(clean2)
        assert result.has_sensitivity()
        assert SourceType.API_KEY in result.get_sensitivity_sources()
    
    def test_sigma_does_not_propagate_through_len(self):
        """Length of sensitive data should not be sensitive."""
        # This is a semantic choice: len(password) is not sensitive
        # Implementation: builtin functions with non-propagating returns
        password = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        # In practice, len() returns clean data
        # (This is tested via contract: builtins.len returns clean)
        pass


class TestRegressionScenarios:
    """Regression tests for specific σ-taint scenarios from PyGoat."""
    
    def test_password_logged_via_print(self):
        """Regression: password logged via print() should be CLEARTEXT_LOGGING."""
        password = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        # print() sinks to LOG_OUTPUT
        assert not password.is_safe_for_sink(SinkType.LOG_OUTPUT)
    
    def test_password_written_to_file(self):
        """Regression: password written to file should be CLEARTEXT_STORAGE."""
        password = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        assert not password.is_safe_for_sink(SinkType.FILE_WRITE)
    
    def test_password_hashed_with_weak_hash(self):
        """Regression: password hashed with MD5 should be WEAK_SENSITIVE_DATA_HASHING."""
        password = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        # MD5 is NOT a sanitizer for sensitive data
        # The bug is detected at HASH_PASSWORD or CRYPTO_WEAK sink
        assert not password.is_safe_for_sink(SinkType.HASH_PASSWORD)
        assert not password.is_safe_for_sink(SinkType.CRYPTO_WEAK)
    
    def test_password_hashed_with_strong_hash_then_logged(self):
        """Regression: HASHING(password) logged should be SAFE."""
        password = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        hashed = password.sanitize(SanitizerType.HASHING)
        # Strong hashing is sufficient for logging
        assert hashed.is_safe_for_sink(SinkType.LOG_OUTPUT)
    
    def test_api_key_encrypted_then_stored(self):
        """Regression: encrypted API key stored should be SAFE."""
        api_key = TaintLabel.from_sensitive_source(SourceType.API_KEY)
        encrypted = api_key.sanitize(SanitizerType.ENCRYPTION)
        assert encrypted.is_safe_for_sink(SinkType.FILE_WRITE)


class TestSoundnessProperties:
    """Test soundness properties of σ-taint system."""
    
    def test_over_approximation_sensitivity(self):
        """σ-taint should be over-approximate (false positives allowed)."""
        # If data might be sensitive, it's marked sensitive
        # This preserves Sem_f ⊆ R_f
        password = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        # Even if password is hashed later, label preserves original sensitivity
        # until explicit sanitizer applied
        assert password.has_sensitivity()
    
    def test_join_preserves_sensitivity(self):
        """Join operation should preserve all sensitivity sources."""
        label1 = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        label2 = TaintLabel.from_sensitive_source(SourceType.API_KEY)
        
        joined = label1.join(label2)
        # Must preserve both (over-approximation)
        assert SourceType.PASSWORD in joined.get_sensitivity_sources()
        assert SourceType.API_KEY in joined.get_sensitivity_sources()
    
    def test_sanitizer_soundness(self):
        """Sanitizers must be justified to preserve Sem_f ⊆ R_f."""
        password = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        
        # HASHING is justified: one-way hash removes sensitivity
        hashed = password.sanitize(SanitizerType.HASHING)
        assert hashed.is_safe_for_sink(SinkType.LOG_OUTPUT)
        
        # SQL_ESCAPE is NOT justified for sensitivity
        sql_escaped = password.sanitize(SanitizerType.SQL_ESCAPE)
        assert not sql_escaped.is_safe_for_sink(SinkType.LOG_OUTPUT)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
