# INFO_LEAK Synthetic Test Suite

**Bug Type**: Information Leak (Taint Analysis)

**Definition**: A secret or sensitive value flows from a taint source to a public sink (logs, error messages, URLs, output streams) without proper sanitization.

## Semantic Characterization

**Taint sources**: Secrets, passwords, API keys, tokens, private keys, PII
**Sinks**: 
- `print()`, `logging.*()` output
- Exception messages (captured in tracebacks)
- URLs (logged by servers/proxies/browsers)
- Any externally-observable output channel

**Unsafe region**: `U_INFO_LEAK(σ) := ∃tainted_value v, sink s. Reaches(v, s) ∧ IsSensitive(v) ∧ IsPublic(s) ∧ ¬Sanitized(v, s)`

**Key challenges**:
1. Tracking taint propagation through program (dataflow)
2. Identifying sensitivity labels (annotations, naming heuristics, static analysis)
3. Identifying public sinks
4. Recognizing sanitization operations (masking, redaction, filtering)

## True Positives (BUG - 5 cases)

1. **tp_01_secret_logged_to_console.py**
   - Secret: API key passed to function
   - Sink: `logging.debug()` logs full API key to console
   - Path: `api_key` → f-string interpolation → logging output

2. **tp_02_password_in_error_message.py**
   - Secret: Password parameter
   - Sink: `ValueError` exception message text
   - Path: `password` → f-string in `raise ValueError()` → exception message → `print()`

3. **tp_03_api_key_in_url_parameter.py**
   - Secret: API key
   - Sink: URL query parameter (highly visible, logged everywhere)
   - Path: `api_key` → f-string URL construction → `print(url)`

4. **tp_04_token_in_http_header_logged.py**
   - Secret: JWT bearer token
   - Sink: Logged HTTP headers dict
   - Path: `token` → `headers` dict → `logging.debug(headers)`

5. **tp_05_private_key_in_traceback.py**
   - Secret: RSA private key
   - Sink: Exception traceback with local variable values
   - Path: `private_key` local var → exception raised in scope → `traceback.print_exc()`

## True Negatives (SAFE - 5 cases)

1. **tn_01_secrets_masked_in_logs.py**
   - Secret is masked (first 4 + "****" + last 4 chars) before logging
   - Sanitization: Explicit masking function applied before sink

2. **tn_02_sensitive_data_redacted_from_errors.py**
   - Error messages contain only username/metadata, not password
   - Pattern: Error construction excludes sensitive parameters

3. **tn_03_secure_credential_handling.py**
   - API key passed in Authorization header (not URL)
   - Headers not logged; only URL and header count logged
   - Pattern: Secrets in headers + selective logging

4. **tn_04_filtered_logging_secret_exclusion.py**
   - Custom `logging.Filter` redacts sensitive keys before output
   - Pattern: Infrastructure-level sanitization via logging filter

5. **tn_05_exception_handling_no_secret_exposure.py**
   - Exceptions caught and re-raised with generic message
   - `from None` suppresses traceback chain
   - Pattern: Defensive exception handling without secrets in scope

## Detection Strategy (Semantics-First)

### Taint tracking requirements:
1. **Taint sources**: 
   - Function parameters named `password`, `api_key`, `token`, `secret`, `private_key`, etc.
   - Variables with sensitivity annotations
   - Return values from credential-loading functions

2. **Taint propagation**:
   - Direct assignment: `x = tainted` → `x` is tainted
   - String formatting: `f"...{tainted}..."` → result is tainted
   - Container inclusion: `{..., tainted, ...}` → container is tainted
   - Function calls: model argument-to-return taint transfer

3. **Sinks**:
   - `print()`, `sys.stdout.write()`
   - `logging.debug/info/warning/error()`
   - Exception message construction (`raise E(f"... {x} ...")`)
   - URL construction with query params
   - Traceback generation with tainted values in scope

4. **Sanitization**:
   - Masking functions (`mask()`, `redact()`, string slicing with replacement)
   - Logging filters that scrub sensitive keys
   - Exception message construction that explicitly excludes tainted values

### Unsafe predicate:
```
U_INFO_LEAK(σ) := 
  ∃obj in σ.heap: 
    Taint(obj) ∧ 
    ∃instruction i in σ.trace:
      IsSink(i) ∧ 
      Reachable(obj, i.operands) ∧
      ¬Sanitized(obj, i)
```

## Expected Analyzer Behavior

- **BUG**: Report when a tainted value flows to a public sink without sanitization, with:
  - Taint source location (parameter/variable name)
  - Data flow path (assignments, function calls, string ops)
  - Sink location (print/log/exception/URL)
  - Concrete example value trace

- **SAFE**: Require proof that:
  - All tainted values are sanitized before sinks, OR
  - Tainted values never reach sinks (dead code / unreachable path)

- **UNKNOWN**: When:
  - Cannot determine if value is sensitive (no annotation/naming heuristic)
  - Cannot track dataflow through complex operations
  - External library calls with unknown taint behavior

## Notes

- INFO_LEAK detection requires **inter-procedural taint analysis**
- String operations are critical: f-strings, `.format()`, concatenation all propagate taint
- Library calls may introduce or remove taint (need contracts/summaries)
- This is a **must-not-reach** property: tainted data must not reach sinks
- Unlike other bug types, this requires **labels** (what is sensitive?) - often heuristic-based in practice
- Conservative approach: over-taint (more false positives) safer than under-taint (missed leaks)
