"""
INFO_LEAK: Taint / noninterference violation (secret data → sink).

Unsafe region: machine state where sensitive/tainted data flows to an
observable sink without proper sanitization/declassification.

This is a **noninterference** property: the program's observable behavior at
sinks should be independent of secret inputs. An info leak occurs when:
- A value derived from a tainted/secret source (e.g., password, API key, PII)
- Flows to a public sink (e.g., log file, network, print, exception message)
- Without explicit declassification/sanitization

The semantic model tracks:
1. **Taint sources**: inputs marked as sensitive (env vars, files, network)
2. **Taint propagation**: dataflow through operations (taint spreads)
3. **Sinks**: observable outputs (print, log, network, exceptions, timing)
4. **Declassification**: explicit sanitization points (hash, encryption, redaction)

Detection approach:
- Label-based taint tracking: each value has a taint label set
- Taint propagation rules: taints flow through operations
- Sink check: if tainted value reaches sink → INFO_LEAK
- Implicit flows: control flow dependent on tainted data also taints

Common Python info leak patterns:
- Logging sensitive data: `logging.info(f"Password: {pwd}")`
- Exception messages with secrets: `raise ValueError(f"Invalid: {api_key}")`
- Debug prints: `print(f"Config: {config}")`
- Network leaks: `requests.post(url, json={"secret": secret})`
- Timing channels: `if secret == guess: time.sleep(1)` (detected by TIMING_CHANNEL)
- File writes: `open("log.txt", "w").write(credit_card)`

Taint sources (configurable, conservative default):
- os.environ (all environment variables)
- sys.argv (command-line arguments)
- open() on certain paths (/etc/passwd, ~/.ssh/, *.key, *.pem)
- network recv/read operations
- getpass.getpass()
- explicit taint annotations (e.g., @sensitive decorator)

Taint sinks (conservative):
- print, logging.* (all levels)
- sys.stdout.write, sys.stderr.write
- open().write on world-readable paths
- network send/write operations
- exception messages (unhandled exceptions visible in traceback)
- sys.exit(message)

Declassification (explicit, must be justified):
- hashlib.* (hashing is declassification)
- cryptography.* (encryption with public key is declassification)
- Explicit sanitization functions (e.g., redact_pii)
- Domain-specific sanitizers (e.g., mask_credit_card)

The unsafe predicate checks:
- tainted_value_at_sink flag set by symbolic VM
- OR taint label on value flowing to sink operation
- OR implicit flow: control flow tainted and then observable side effect
"""

from typing import Optional
import z3


def is_unsafe_info_leak(state) -> bool:
    """
    Unsafe predicate U_INFO_LEAK(σ).
    
    Returns True if the machine state σ shows an information leak:
    - tainted_value_at_sink flag set (indicating taint analysis found leak)
    - OR explicit taint label on value at sink operation
    - OR control-flow taint leading to observable side effect
    - OR exception message containing tainted data
    
    The symbolic VM tracks:
    1. Taint labels per value: TaintLabel = {Secret, PII, Credential, ...}
    2. Taint propagation: operations spread taints
    3. Sink operations: print, log, network, exception, file write
    4. Declassification points: hash, encrypt, sanitize (explicit only)
    
    Taint tracking (forward dataflow analysis):
    - Each symbolic value has a taint set: T(v) ⊆ TaintLabel
    - Sources: T(getenv(k)) = {Secret}, T(getpass()) = {Credential}
    - Propagation: T(f(v1, v2, ...)) = T(v1) ∪ T(v2) ∪ ...
    - Sinks: if T(v) ≠ ∅ and v reaches sink → INFO_LEAK
    - Declassification: T(hash(v)) = ∅ (justified by cryptographic property)
    
    Implicit flows (control-flow taint):
    - If branch condition depends on tainted value, all subsequent values
      in that branch are implicitly tainted (until dominator join point)
    - Example: if secret == x: print("match") → "match" is tainted by secret
    - Detection: track PC (program counter) taint; when PC is tainted,
      all side effects are tainted
    
    Noninterference formulation (alternative view):
    - Two runs with different secret inputs should produce same public outputs
    - Violation: ∃s1, s2. Secret(s1) ≠ Secret(s2) ∧ Public(run(s1)) ≠ Public(run(s2))
    - We check: if secret affects public output → leak
    
    Note: This is a **semantic** definition - we detect leaks based on
    information flow in the execution model, not pattern matching on source text.
    """
    # Explicit info leak flag set by symbolic VM
    if hasattr(state, 'tainted_value_at_sink') and state.tainted_value_at_sink:
        return True
    
    # Check taint tracking results
    if hasattr(state, 'taint_violations'):
        # taint_violations: list of (value, sink_location, taint_labels)
        if state.taint_violations:
            return True
    
    # Check if exception message contains tainted data
    if state.exception and hasattr(state, 'exception_tainted'):
        if state.exception_tainted:
            return True
    
    # Check control-flow taint at sink
    if hasattr(state, 'pc_taint') and hasattr(state, 'at_sink_operation'):
        # If program counter is tainted (branched on secret) and we're at a sink
        if state.pc_taint and state.at_sink_operation:
            return True
    
    # Check for tainted network/file output
    if hasattr(state, 'output_tainted') and state.output_tainted:
        return True
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for INFO_LEAK bug.
    
    Returns a dictionary with:
    - bug_type: "INFO_LEAK"
    - trace: list of executed instructions
    - leak_details: what tainted data flowed where
    - taint_source: where the sensitive data originated
    - sink_location: where the leak occurred
    - taint_labels: what kinds of sensitive data leaked
    - path_condition: the Z3 path constraint
    """
    leak_details = {
        "bug_type": "INFO_LEAK",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception,
            "halted": state.halted
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
    
    # Extract taint violation details
    if hasattr(state, 'taint_violations') and state.taint_violations:
        leak_details["taint_violations"] = [
            {
                "value": str(v[0]) if v else "unknown",
                "sink": v[1] if len(v) > 1 else "unknown",
                "taints": list(v[2]) if len(v) > 2 else []
            }
            for v in state.taint_violations
        ]
    
    # Extract source information
    if hasattr(state, 'taint_sources'):
        leak_details["taint_sources"] = state.taint_sources
    
    # Extract sink information
    if hasattr(state, 'sink_location'):
        leak_details["sink_location"] = state.sink_location
    
    # Extract taint labels
    if hasattr(state, 'leaked_taint_labels'):
        leak_details["taint_labels"] = list(state.leaked_taint_labels)
    
    # Implicit flow details
    if hasattr(state, 'implicit_flow_leak'):
        leak_details["implicit_flow"] = state.implicit_flow_leak
    
    # Exception taint details
    if hasattr(state, 'exception_tainted') and state.exception_tainted:
        leak_details["exception_leak"] = {
            "exception_type": state.exception,
            "tainted": True
        }
    
    return leak_details
