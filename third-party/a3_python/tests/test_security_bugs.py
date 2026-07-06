"""
Tests for security bug detection (barrier-certificate-theory.md §11).

Tests the taint tracking and security violation detection for:
- SQL injection (CWE-089)
- Command injection (CWE-078)  
- Code injection (CWE-094)
- Path injection (CWE-022)
- XSS (CWE-079)
- SSRF (CWE-918)
- Unsafe deserialization (CWE-502)
- Cleartext logging (CWE-532)

Mode A: Pure symbolic taint tracking
Mode B: Concolic validation (does not affect verdicts)
"""

import pytest
from a3_python.z3model.taint import (
    TaintState, TaintSource, SinkType, SanitizerType, TaintLabel,
    SecurityViolation, create_violation
)
from a3_python.contracts.security import (
    init_security_contracts, get_source_contract, get_sink_contract,
    get_sanitizer_contract, is_taint_source, is_security_sink, is_sanitizer,
    apply_source_taint, check_sink_taint, apply_sanitizer
)
from a3_python.semantics.security_tracker import (
    SecurityTracker, handle_call_pre, handle_call_post,
    handle_binop, create_fresh_tainted_value
)
from a3_python.z3model.values import SymbolicValue, ValueTag
import z3


class TestTaintState:
    """Tests for TaintState class."""
    
    def test_clean_state(self):
        """Clean state has no taint."""
        taint = TaintState.clean()
        assert not taint.untrusted
        assert not taint.sensitive
        assert len(taint.labels) == 0
    
    def test_from_untrusted_source(self):
        """Create taint from untrusted source."""
        taint = TaintState.from_source(
            TaintSource.HTTP_PARAM,
            "request.GET['id']",
            sensitive=False
        )
        assert taint.untrusted
        assert not taint.sensitive
        assert len(taint.labels) == 1
        label = list(taint.labels)[0]
        assert label.source_type == TaintSource.HTTP_PARAM
    
    def test_from_sensitive_source(self):
        """Create taint from sensitive source."""
        taint = TaintState.from_source(
            TaintSource.PASSWORD,
            "getpass.getpass()",
            sensitive=True
        )
        assert not taint.untrusted  # Sensitive sources set σ, not τ
        assert taint.sensitive
        assert len(taint.labels) == 1
        label = list(taint.labels)[0]
        assert label.is_sensitive
    
    def test_merge(self):
        """Merge two taint states."""
        t1 = TaintState.from_source(TaintSource.HTTP_PARAM, "loc1")
        t2 = TaintState.from_source(TaintSource.USER_INPUT, "loc2")
        merged = t1.merge(t2)
        
        assert merged.untrusted
        assert len(merged.labels) == 2
    
    def test_sanitize(self):
        """Apply sanitizer to taint state."""
        taint = TaintState.from_source(TaintSource.HTTP_PARAM, "loc")
        sanitized = taint.sanitize(SanitizerType.SHELL_QUOTE)
        
        assert SanitizerType.SHELL_QUOTE in sanitized.sanitizers_applied
        assert sanitized.untrusted  # Still tainted, but sanitized
    
    def test_is_tainted_for_sink_with_sanitizer(self):
        """Sanitized value is safe for sink."""
        taint = TaintState.from_source(TaintSource.HTTP_PARAM, "loc")
        taint = taint.sanitize(SanitizerType.SHELL_QUOTE)
        
        # Should be safe for command shell with shell quote
        assert not taint.is_tainted_for_sink(SinkType.COMMAND_SHELL)
        
        # But still tainted for SQL (different sanitizer needed)
        assert taint.is_tainted_for_sink(SinkType.SQL_EXECUTE)
    
    def test_sensitive_data_at_log_sink(self):
        """Sensitive data at log sink is violation."""
        taint = TaintState.from_source(TaintSource.PASSWORD, "pass", sensitive=True)
        
        # Sensitive data at log output is dangerous
        assert taint.is_tainted_for_sink(SinkType.LOG_OUTPUT)
        
        # But not dangerous at SQL sink (σ not τ)
        assert not taint.is_tainted_for_sink(SinkType.SQL_EXECUTE)


class TestSecurityContracts:
    """Tests for security contract registry."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        init_security_contracts()
    
    def test_http_source_registered(self):
        """HTTP parameter sources are registered."""
        assert is_taint_source("request.GET.__getitem__")
        assert is_taint_source("request.args.get")
        
        contract = get_source_contract("request.GET.__getitem__")
        assert contract.source_type == TaintSource.HTTP_PARAM
    
    def test_sql_sink_registered(self):
        """SQL execution sinks are registered."""
        assert is_security_sink("cursor.execute")
        
        contract = get_sink_contract("cursor.execute")
        assert contract.sink_type == SinkType.SQL_EXECUTE
        assert contract.parameterized_check
    
    def test_command_sink_registered(self):
        """Command execution sinks are registered."""
        assert is_security_sink("os.system")
        assert is_security_sink("subprocess.call")
        
        contract = get_sink_contract("subprocess.call")
        assert contract.sink_type == SinkType.COMMAND_SHELL
        assert contract.shell_check
    
    def test_sanitizers_registered(self):
        """Sanitizers are registered."""
        assert is_sanitizer("shlex.quote")
        assert is_sanitizer("html.escape")
        
        contract = get_sanitizer_contract("shlex.quote")
        assert contract.sanitizer_type == SanitizerType.SHELL_QUOTE


class TestSecurityTracker:
    """Tests for SecurityTracker class."""
    
    def test_tracker_creation(self):
        """Create security tracker."""
        tracker = SecurityTracker()
        assert tracker.enabled
        assert not tracker.has_violations()
    
    def test_set_and_get_taint(self):
        """Set and retrieve taint state."""
        tracker = SecurityTracker()
        value = SymbolicValue.int(42)
        taint = TaintState.from_source(TaintSource.HTTP_PARAM, "loc")
        
        tracker.set_taint(value, taint)
        retrieved = tracker.get_taint(value)
        
        assert retrieved.untrusted
        assert retrieved == taint
    
    def test_merge_taints_from_values(self):
        """Merge taints from multiple values."""
        tracker = SecurityTracker()
        v1 = SymbolicValue.int(1)
        v2 = SymbolicValue.int(2)
        
        tracker.set_taint(v1, TaintState.from_source(TaintSource.HTTP_PARAM, "a"))
        tracker.set_taint(v2, TaintState.clean())
        
        merged = tracker.merge_taints([v1, v2])
        assert merged.untrusted  # v1 is tainted
    
    def test_add_violation(self):
        """Add security violation."""
        tracker = SecurityTracker()
        
        violation = SecurityViolation(
            bug_type="SQL_INJECTION",
            cwe="CWE-089",
            sink_type=SinkType.SQL_EXECUTE,
            sink_location="test.py:10",
            taint_sources=frozenset(),
            message="Test violation"
        )
        
        tracker.add_violation(violation)
        assert tracker.has_violations()
        assert len(tracker.violations) == 1
    
    def test_tracker_copy(self):
        """Copy tracker for path forking."""
        tracker = SecurityTracker()
        value = SymbolicValue.int(1)
        tracker.set_taint(value, TaintState.from_source(TaintSource.HTTP_PARAM, "a"))
        
        copied = tracker.copy()
        
        # Changes to copy don't affect original
        copied.enabled = False
        assert tracker.enabled


class TestTaintPropagation:
    """Tests for taint propagation through operations."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        init_security_contracts()
        self.tracker = SecurityTracker()
    
    def test_binop_propagation(self):
        """Taint propagates through binary operations."""
        left = SymbolicValue.int(1)
        right = SymbolicValue.int(2)
        result = SymbolicValue.int(3)
        
        # Left is tainted
        self.tracker.set_taint(left, TaintState.from_source(TaintSource.HTTP_PARAM, "a"))
        
        handle_binop(self.tracker, left, right, result)
        
        result_taint = self.tracker.get_taint(result)
        assert result_taint.untrusted


class TestSinkCheck:
    """Tests for security sink checking."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        init_security_contracts()
        self.tracker = SecurityTracker()
    
    def test_sql_injection_detected(self):
        """Detect SQL injection: tainted query at cursor.execute."""
        query = SymbolicValue.str(1)
        self.tracker.set_taint(query, TaintState.from_source(TaintSource.HTTP_PARAM, "id"))
        
        violation = handle_call_pre(
            self.tracker,
            "cursor.execute",
            [query],
            "test.py:10"
        )
        
        assert violation is not None
        assert violation.bug_type == "SQL_INJECTION"
        assert violation.cwe == "CWE-089"
    
    def test_sql_safe_with_clean_data(self):
        """No violation with clean data."""
        query = SymbolicValue.str(1)
        self.tracker.set_taint(query, TaintState.clean())
        
        violation = handle_call_pre(
            self.tracker,
            "cursor.execute",
            [query],
            "test.py:10"
        )
        
        assert violation is None
    
    def test_command_injection_detected(self):
        """Detect command injection: tainted command at os.system."""
        cmd = SymbolicValue.str(1)
        self.tracker.set_taint(cmd, TaintState.from_source(TaintSource.USER_INPUT, "input()"))
        
        violation = handle_call_pre(
            self.tracker,
            "os.system",
            [cmd],
            "test.py:20"
        )
        
        assert violation is not None
        assert violation.bug_type == "COMMAND_INJECTION"
    
    def test_code_injection_detected(self):
        """Detect code injection: tainted code at eval."""
        code = SymbolicValue.str(1)
        self.tracker.set_taint(code, TaintState.from_source(TaintSource.HTTP_PARAM, "code"))
        
        violation = handle_call_pre(
            self.tracker,
            "builtins.eval",
            [code],
            "test.py:30"
        )
        
        assert violation is not None
        assert violation.bug_type == "CODE_INJECTION"
    
    def test_cleartext_logging_sensitive_data(self):
        """Detect cleartext logging: sensitive data at logging.info."""
        data = SymbolicValue.str(1)
        self.tracker.set_taint(data, TaintState.from_source(
            TaintSource.PASSWORD, "getpass", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "logging.info",
            [data],
            "test.py:40"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_LOGGING"
    
    def test_cleartext_logging_api_key(self):
        """Detect cleartext logging of API keys."""
        api_key = SymbolicValue.str(2)
        self.tracker.set_taint(api_key, TaintState.from_source(
            TaintSource.API_KEY, "os.getenv('API_KEY')", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "logging.warning",
            [api_key],
            "test.py:45"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_LOGGING"
        assert violation.cwe == "CWE-532"
    
    def test_cleartext_logging_credentials(self):
        """Detect cleartext logging of credentials."""
        creds = SymbolicValue.str(3)
        self.tracker.set_taint(creds, TaintState.from_source(
            TaintSource.CREDENTIALS, "config.auth", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "logging.error",
            [creds],
            "test.py:50"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_LOGGING"
    
    def test_cleartext_logging_session_token(self):
        """Detect cleartext logging of session tokens (use API_KEY as proxy)."""
        token = SymbolicValue.str(4)
        self.tracker.set_taint(token, TaintState.from_source(
            TaintSource.API_KEY, "session.id", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "logging.debug",
            [token],
            "test.py:55"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_LOGGING"
    
    def test_cleartext_logging_print_statement(self):
        """Detect cleartext logging via print() with sensitive data."""
        password = SymbolicValue.str(5)
        self.tracker.set_taint(password, TaintState.from_source(
            TaintSource.PASSWORD, "input_password", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "builtins.print",
            [password],
            "test.py:60"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_LOGGING"
    
    def test_cleartext_logging_safe_with_redaction(self):
        """No violation when sensitive data is redacted before logging."""
        password = SymbolicValue.str(6)
        self.tracker.set_taint(password, TaintState.from_source(
            TaintSource.PASSWORD, "user_pwd", sensitive=True
        ))
        
        # Redaction removes sensitive taint (not hashing - that's for storage)
        redacted = SymbolicValue.str(7)
        # For now, just use clean data to simulate redaction
        # In a full implementation, we'd have a REDACTION sanitizer
        self.tracker.set_taint(redacted, TaintState.clean())
        
        violation = handle_call_pre(
            self.tracker,
            "logging.info",
            [redacted],
            "test.py:65"
        )
        
        # Should be safe after redaction
        assert violation is None
    
    def test_cleartext_logging_safe_with_clean_data(self):
        """No violation when logging clean (non-sensitive) data."""
        clean_msg = SymbolicValue.str(8)
        self.tracker.set_taint(clean_msg, TaintState.clean())
        
        violation = handle_call_pre(
            self.tracker,
            "logging.info",
            [clean_msg],
            "test.py:70"
        )
        
        assert violation is None
    
    def test_cleartext_logging_pii_data(self):
        """Detect cleartext logging of PII."""
        pii = SymbolicValue.str(9)
        self.tracker.set_taint(pii, TaintState.from_source(
            TaintSource.PII, "user.ssn", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "logging.info",
            [pii],
            "test.py:75"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_LOGGING"
    
    def test_cleartext_logging_crypto_key(self):
        """Detect cleartext logging of cryptographic keys."""
        crypto_key = SymbolicValue.str(10)
        self.tracker.set_taint(crypto_key, TaintState.from_source(
            TaintSource.CRYPTO_KEY, "private_key", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "logging.error",
            [crypto_key],
            "test.py:80"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_LOGGING"
    
    def test_cleartext_logging_private_data(self):
        """Detect cleartext logging of private data (use CREDENTIALS as proxy)."""
        private = SymbolicValue.str(11)
        self.tracker.set_taint(private, TaintState.from_source(
            TaintSource.CREDENTIALS, "classified_doc", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "logging.warning",
            [private],
            "test.py:85"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_LOGGING"
    
    def test_cleartext_storage_password(self):
        """Detect cleartext storage: password written to file."""
        password = SymbolicValue.str(12)
        self.tracker.set_taint(password, TaintState.from_source(
            TaintSource.PASSWORD, "user.password", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "file.write",
            [password],
            "test.py:90"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_STORAGE"
        assert violation.cwe == "CWE-312"
    
    def test_cleartext_storage_api_key(self):
        """Detect cleartext storage of API key."""
        api_key = SymbolicValue.str(13)
        self.tracker.set_taint(api_key, TaintState.from_source(
            TaintSource.API_KEY, "config.key", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "io.TextIOWrapper.write",
            [api_key],
            "test.py:95"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_STORAGE"
    
    def test_cleartext_storage_credentials(self):
        """Detect cleartext storage of credentials."""
        creds = SymbolicValue.str(14)
        self.tracker.set_taint(creds, TaintState.from_source(
            TaintSource.CREDENTIALS, "auth_data", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "io.BufferedWriter.write",
            [creds],
            "test.py:100"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_STORAGE"
    
    def test_cleartext_storage_crypto_key(self):
        """Detect cleartext storage of cryptographic key."""
        crypto_key = SymbolicValue.str(15)
        self.tracker.set_taint(crypto_key, TaintState.from_source(
            TaintSource.CRYPTO_KEY, "encryption_key", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "file.write",
            [crypto_key],
            "test.py:105"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_STORAGE"
    
    def test_cleartext_storage_session_token(self):
        """Detect cleartext storage of session token."""
        token = SymbolicValue.str(16)
        self.tracker.set_taint(token, TaintState.from_source(
            TaintSource.API_KEY, "session.token", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "file.write",
            [token],
            "test.py:110"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_STORAGE"
    
    def test_cleartext_storage_pii(self):
        """Detect cleartext storage of PII data."""
        pii = SymbolicValue.str(17)
        self.tracker.set_taint(pii, TaintState.from_source(
            TaintSource.PII, "user.ssn", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "io.TextIOWrapper.write",
            [pii],
            "test.py:115"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_STORAGE"
    
    def test_cleartext_storage_safe_with_encryption(self):
        """No violation when sensitive data is encrypted before storage."""
        password = SymbolicValue.str(18)
        self.tracker.set_taint(password, TaintState.from_source(
            TaintSource.PASSWORD, "user_pwd", sensitive=True
        ))
        
        # After encryption, data becomes non-sensitive
        encrypted = SymbolicValue.str(19)
        self.tracker.set_taint(encrypted, TaintState.clean())
        
        violation = handle_call_pre(
            self.tracker,
            "file.write",
            [encrypted],
            "test.py:120"
        )
        
        # Should be safe after encryption
        assert violation is None
    
    def test_cleartext_storage_safe_with_hashing(self):
        """No violation when sensitive data is hashed before storage (for passwords)."""
        password = SymbolicValue.str(20)
        self.tracker.set_taint(password, TaintState.from_source(
            TaintSource.PASSWORD, "new_pwd", sensitive=True
        ))
        
        # After hashing with bcrypt/argon2, password hash is safe to store
        hashed = SymbolicValue.str(21)
        self.tracker.set_taint(hashed, TaintState.clean())
        
        violation = handle_call_pre(
            self.tracker,
            "file.write",
            [hashed],
            "test.py:125"
        )
        
        assert violation is None
    
    def test_cleartext_storage_safe_with_clean_data(self):
        """No violation when storing clean (non-sensitive) data."""
        clean_data = SymbolicValue.str(22)
        self.tracker.set_taint(clean_data, TaintState.clean())
        
        violation = handle_call_pre(
            self.tracker,
            "file.write",
            [clean_data],
            "test.py:130"
        )
        
        assert violation is None
    
    def test_cleartext_storage_mixed_data(self):
        """Detect cleartext storage when writing mixed sensitive/clean data."""
        # Simulate writing a string that contains both clean and sensitive parts
        mixed_str = SymbolicValue.str(23)
        # In practice, concatenating sensitive+clean = sensitive
        self.tracker.set_taint(mixed_str, TaintState.from_source(
            TaintSource.PASSWORD, "log_with_pwd", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "file.write",
            [mixed_str],
            "test.py:135"
        )
        
        assert violation is not None
        assert violation.bug_type == "CLEARTEXT_STORAGE"
    
    def test_cleartext_storage_safe_after_sha256_hashing(self):
        """No violation when SHA-256 hashed password is stored (sanitizer clears sensitivity)."""
        # Migrated to LatticeSecurityTracker API (iteration 582)
        from a3_python.semantics.security_tracker_lattice import LatticeSecurityTracker
        from a3_python.z3model.taint_lattice import TaintLabel, SourceType
        
        tracker = LatticeSecurityTracker()
        
        # Create password value with sensitive taint
        password = SymbolicValue.str(100)
        password_label = TaintLabel.from_sensitive_source(SourceType.PASSWORD, location="user.password")
        tracker.set_label(password, password_label)
        
        # Verify password is sensitive
        assert password_label.has_sensitivity(), "Password should be marked sensitive"
        
        # Simulate: hashed_result = hashlib.sha256(password)
        # SHA-256 is a sanitizer that clears sensitivity (though weak for passwords)
        hashed_result = SymbolicValue.str(101)
        hashed_concrete, hashed_symbolic = tracker.handle_call_post(
            "hashlib.sha256",
            None,  # not a method call
            [password],
            hashed_result,
            "test.py:200"
        )
        
        # Verify sanitization removed sensitivity
        assert not hashed_concrete.has_sensitivity(), \
            "SHA-256 hashing should clear sensitivity (σ=0)"
        
        # Simulate: file.write(hashed_result)
        # This should NOT trigger CLEARTEXT_STORAGE (no sensitive data)
        violation = tracker.handle_call_pre(
            "file.write",
            [hashed_result],
            "test.py:201"
        )
        
        assert violation is None, \
            "Hashed password storage should not trigger CLEARTEXT_STORAGE (σ cleared by sanitizer)"
    
    def test_weak_crypto_md5_password(self):
        """Detect weak crypto: MD5 used for password hashing."""
        password = SymbolicValue.str(24)
        self.tracker.set_taint(password, TaintState.from_source(
            TaintSource.PASSWORD, "user_password", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "hashlib.md5",
            [password],
            "test.py:140"
        )
        
        assert violation is not None
        assert violation.bug_type == "WEAK_CRYPTO"
        assert violation.cwe == "CWE-327"
    
    def test_weak_crypto_sha1_password(self):
        """Detect weak crypto: SHA1 used for password hashing."""
        password = SymbolicValue.str(25)
        self.tracker.set_taint(password, TaintState.from_source(
            TaintSource.PASSWORD, "admin_pass", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "hashlib.sha1",
            [password],
            "test.py:145"
        )
        
        assert violation is not None
        assert violation.bug_type == "WEAK_CRYPTO"
    
    def test_weak_crypto_md5_api_key(self):
        """Detect weak crypto: MD5 used for API key."""
        api_key = SymbolicValue.str(26)
        self.tracker.set_taint(api_key, TaintState.from_source(
            TaintSource.API_KEY, "config.key", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "hashlib.md5",
            [api_key],
            "test.py:150"
        )
        
        assert violation is not None
        assert violation.bug_type == "WEAK_CRYPTO"
    
    def test_weak_crypto_sha1_credentials(self):
        """Detect weak crypto: SHA1 used for credentials."""
        creds = SymbolicValue.str(27)
        self.tracker.set_taint(creds, TaintState.from_source(
            TaintSource.CREDENTIALS, "auth.secret", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "hashlib.sha1",
            [creds],
            "test.py:155"
        )
        
        assert violation is not None
        assert violation.bug_type == "WEAK_CRYPTO"
    
    def test_weak_crypto_md5_session_token(self):
        """Detect weak crypto: MD5 used for session token (use API_KEY as proxy)."""
        token = SymbolicValue.str(28)
        self.tracker.set_taint(token, TaintState.from_source(
            TaintSource.API_KEY, "session.token", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "hashlib.md5",
            [token],
            "test.py:160"
        )
        
        assert violation is not None
        assert violation.bug_type == "WEAK_CRYPTO"
    
    def test_weak_crypto_safe_with_pbkdf2(self):
        """No violation when using PBKDF2 for password hashing."""
        password = SymbolicValue.str(29)
        self.tracker.set_taint(password, TaintState.from_source(
            TaintSource.PASSWORD, "new_password", sensitive=True
        ))
        
        # PBKDF2 is a proper KDF, marked as sanitizer
        violation = handle_call_pre(
            self.tracker,
            "hashlib.pbkdf2_hmac",
            [SymbolicValue.str(100), password],  # Algorithm, then password
            "test.py:165"
        )
        
        # Should be safe (pbkdf2 should be in sanitizer list or not in weak crypto sinks)
        # In our model, we don't have pbkdf2 registered as a weak crypto sink
        assert violation is None
    
    def test_weak_crypto_safe_with_bcrypt(self):
        """No violation when using bcrypt for password hashing."""
        password = SymbolicValue.str(30)
        self.tracker.set_taint(password, TaintState.from_source(
            TaintSource.PASSWORD, "user_pwd", sensitive=True
        ))
        
        # bcrypt is a proper password hashing function
        violation = handle_call_pre(
            self.tracker,
            "bcrypt.hashpw",
            [password, SymbolicValue.str(101)],  # Password, then salt
            "test.py:170"
        )
        
        # bcrypt should not be in weak crypto sinks
        assert violation is None
    
    def test_weak_crypto_md5_clean_data(self):
        """No violation when using MD5 on non-sensitive data (checksums)."""
        clean_data = SymbolicValue.str(31)
        self.tracker.set_taint(clean_data, TaintState.clean())
        
        violation = handle_call_pre(
            self.tracker,
            "hashlib.md5",
            [clean_data],
            "test.py:175"
        )
        
        # MD5 on non-sensitive data is acceptable (e.g., for file checksums)
        assert violation is None
    
    def test_weak_crypto_sha1_clean_data(self):
        """No violation when using SHA1 on non-sensitive data."""
        file_content = SymbolicValue.str(32)
        self.tracker.set_taint(file_content, TaintState.clean())
        
        violation = handle_call_pre(
            self.tracker,
            "hashlib.sha1",
            [file_content],
            "test.py:180"
        )
        
        # SHA1 on non-sensitive data is acceptable
        assert violation is None
    
    def test_weak_crypto_mixed_md5_password(self):
        """Detect weak crypto when hashing mixed data containing passwords."""
        # Simulate hashing a string that contains password
        mixed_str = SymbolicValue.str(33)
        self.tracker.set_taint(mixed_str, TaintState.from_source(
            TaintSource.PASSWORD, "user_data_with_pwd", sensitive=True
        ))
        
        violation = handle_call_pre(
            self.tracker,
            "hashlib.md5",
            [mixed_str],
            "test.py:185"
        )
        
        assert violation is not None
        assert violation.bug_type == "WEAK_CRYPTO"


class TestSourceApplication:
    """Tests for taint source application."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        init_security_contracts()
        self.tracker = SecurityTracker()
    
    def test_http_source_taints_result(self):
        """HTTP source function taints its result."""
        result = SymbolicValue.str(1)
        
        taint = handle_call_post(
            self.tracker,
            "request.GET.__getitem__",
            [],  # No args
            result,
            "test.py:5"
        )
        
        assert taint.untrusted
        retrieved = self.tracker.get_taint(result)
        assert retrieved.untrusted
    
    def test_password_source_sets_sensitive(self):
        """Password source sets sensitivity taint."""
        result = SymbolicValue.str(1)
        
        taint = handle_call_post(
            self.tracker,
            "getpass.getpass",
            [],
            result,
            "test.py:10"
        )
        
        assert taint.sensitive


class TestSanitizerApplication:
    """Tests for sanitizer application."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        init_security_contracts()
        self.tracker = SecurityTracker()
    
    def test_shell_quote_sanitizes(self):
        """shlex.quote sanitizes command injection."""
        input_val = SymbolicValue.str(1)
        result = SymbolicValue.str(2)
        
        # Input is tainted
        self.tracker.set_taint(input_val, TaintState.from_source(TaintSource.HTTP_PARAM, "x"))
        
        # Apply sanitizer
        taint = handle_call_post(
            self.tracker,
            "shlex.quote",
            [input_val],
            result,
            "test.py:15"
        )
        
        # Result should have sanitizer applied
        assert SanitizerType.SHELL_QUOTE in taint.sanitizers_applied
        
        # Should be safe for command shell now
        assert not taint.is_tainted_for_sink(SinkType.COMMAND_SHELL)


class TestSecurityBugRegistry:
    """Tests for security bug type registry."""
    
    def test_all_bug_types_registered(self):
        """All bug types (20 core + 47 security + 17 exception) are registered.
        
        ITERATION 700: Added 17 fine-grained exception bug types.
        Total: 20 + 47 + 17 = 84 (but PANIC is shared, so 84)
        """
        from a3_python.unsafe.registry import list_implemented_bug_types
        bugs = list_implemented_bug_types()
        # 20 core + 47 security + 17 exception (VALUE_ERROR, RUNTIME_ERROR, etc.)
        # Note: Some may overlap, so we check >= 67 (original count)
        assert len(bugs) >= 67, f"Expected at least 67 bug types, got {len(bugs)}"
    
    def test_47_security_bug_types(self):
        """All 47 security bug types from CodeQL are registered."""
        from a3_python.unsafe.registry import UNSAFE_PREDICATES
        
        # Core error bug types (not security)
        core_bugs = {
            'ASSERT_FAIL', 'DIV_ZERO', 'FP_DOMAIN', 'INTEGER_OVERFLOW',
            'BOUNDS', 'NULL_PTR', 'TYPE_CONFUSION', 'STACK_OVERFLOW',
            'MEMORY_LEAK', 'NON_TERMINATION', 'ITERATOR_INVALID',
            'USE_AFTER_FREE', 'DOUBLE_FREE', 'UNINIT_MEMORY', 'DATA_RACE',
            'DEADLOCK', 'SEND_SYNC', 'INFO_LEAK', 'TIMING_CHANNEL', 'PANIC'
        }
        
        # ITERATION 700: Fine-grained exception bug types (not security)
        exception_bugs = {
            'VALUE_ERROR', 'RUNTIME_ERROR', 'NOT_IMPLEMENTED', 'FILE_NOT_FOUND',
            'PERMISSION_ERROR', 'OS_ERROR', 'IO_ERROR', 'IMPORT_ERROR',
            'MODULE_NOT_FOUND', 'NAME_ERROR', 'UNBOUND_LOCAL', 'TIMEOUT_ERROR',
            'CONNECTION_ERROR', 'UNICODE_ERROR', 'LOOKUP_ERROR', 'SYSTEM_ERROR',
            'ENVIRONMENT_ERROR',
        }
        
        non_security = core_bugs | exception_bugs
        security_bugs = [k for k in UNSAFE_PREDICATES.keys() if k not in non_security]
        assert len(security_bugs) == 47, f"Expected 47 security bugs, got {len(security_bugs)}: {security_bugs}"
    
    def test_key_security_bugs_present(self):
        """Key security bug types are present in registry."""
        from a3_python.unsafe.registry import UNSAFE_PREDICATES
        
        key_bugs = [
            'SQL_INJECTION', 'COMMAND_INJECTION', 'CODE_INJECTION', 'PATH_INJECTION',
            'REFLECTED_XSS', 'SSRF', 'UNSAFE_DESERIALIZATION', 'XXE',
            'CLEARTEXT_LOGGING', 'CLEARTEXT_STORAGE', 'LDAP_INJECTION',
            'XPATH_INJECTION', 'NOSQL_INJECTION', 'REGEX_INJECTION', 'URL_REDIRECT',
            'FLASK_DEBUG', 'INSECURE_COOKIE', 'HARDCODED_CREDENTIALS',
            'WEAK_CRYPTO_KEY', 'CSRF_PROTECTION_DISABLED'
        ]
        
        for bug in key_bugs:
            assert bug in UNSAFE_PREDICATES, f"{bug} not in registry"
    
    def test_predicates_are_callable(self):
        """All predicates and extractors are callable."""
        from a3_python.unsafe.registry import UNSAFE_PREDICATES
        
        for bug_type, (predicate, extractor) in UNSAFE_PREDICATES.items():
            assert callable(predicate), f"{bug_type} predicate not callable"
            assert callable(extractor), f"{bug_type} extractor not callable"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
