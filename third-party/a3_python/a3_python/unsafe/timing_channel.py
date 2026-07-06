"""
TIMING_CHANNEL: Secret-dependent timing side-channel.

Unsafe region: machine state where execution time/observable timing behavior
depends on sensitive/secret data.

This is a **timing noninterference** property: the program's execution time
at observable points should be independent of secret inputs. A timing channel
occurs when:
- A secret/tainted value influences control flow (branching/looping)
- Different secret values lead to measurably different execution times
- The timing difference is observable to an attacker

The semantic model tracks:
1. **Secret sources**: same as INFO_LEAK taint sources (passwords, keys, etc.)
2. **Timing-sensitive operations**: branches, loops, early returns
3. **Observable timing points**: function returns, network responses, API calls
4. **Secret-dependent branching**: if/while conditions on secret data
5. **Variable-time operations**: string comparison, array scan, etc.

Detection approach:
- Track timing taint (subset of general taint): secrets that affect timing
- Control-flow dependency analysis: does branch/loop depend on secret?
- Timing observation points: returns, yields, external calls
- Variable-time primitive operations: string equality, list search

Common Python timing channel patterns:
- Password comparison: `if password == user_input:` (byte-by-byte comparison)
- Secret-dependent loop: `for i in range(secret_value): ...`
- Early exit on match: `if key in secret_list: return True`
- Variable-time crypto: implementing crypto without constant-time primitives
- Secret-dependent sleep/delay: `time.sleep(secret)` (though less subtle)

Critical distinction from INFO_LEAK:
- INFO_LEAK: secret value directly observable in output data
- TIMING_CHANNEL: secret value indirectly observable via execution time
- Example: `if secret == x: time.sleep(0.1)` is both INFO_LEAK and TIMING_CHANNEL
- Example: `if secret == x: compute_expensive()` is TIMING_CHANNEL only

Timing-sensitive operations (Python-specific):
- String comparison: `s1 == s2` (CPython short-circuits on length, then byte-by-byte)
- List/set membership: `x in lst` (linear scan for list, varies by position)
- Dict lookup: `d[k]` (timing varies by hash collisions, though usually negligible)
- Early return in loops: `for x in lst: if predicate(x): return True`
- Variable-length operations: `sum(lst)`, `max(lst)` (time depends on list size)

Constant-time declassification:
- hmac.compare_digest(a, b): constant-time comparison (safe)
- secrets.compare_digest(a, b): same, explicitly for timing safety
- Explicitly marked constant-time functions

The unsafe predicate checks:
- secret_dependent_branch flag set by symbolic VM (branch condition tainted)
- secret_dependent_loop flag (loop bound/condition depends on secret)
- timing_observation_point flag (at return/yield/external call)
- variable_time_operation flag (non-constant-time primitive on secret data)
- AND observable_timing flag (timing is externally observable)

Semantic definition:
- Let T(σ) = execution steps to reach state σ from S0
- Let Secret(σ) = secret inputs in state σ
- Timing channel exists if:
  ∃σ1, σ2. Secret(σ1) ≠ Secret(σ2) ∧ Observable(σ1) ∧ Observable(σ2) ∧ T(σ1) ≠ T(σ2)
- We approximate by tracking: tainted control flow + observable timing point

Note: This is a **conservative** check. Not all timing differences are exploitable
(e.g., nanosecond differences may not be observable over network). However, we
follow the barrier-certificate discipline: report potential timing channels,
do not try to estimate exploitability.
"""

from typing import Optional
import z3


def is_unsafe_timing_channel(state) -> bool:
    """
    Unsafe predicate U_TIMING_CHANNEL(σ).
    
    Returns True if the machine state σ shows a timing channel:
    - Secret-dependent control flow (branch/loop on tainted condition)
    - At an observable timing point (return, external call, yield)
    - OR variable-time operation on secret data (string comparison, etc.)
    
    The symbolic VM tracks:
    1. Timing taint: which values affect execution time (subset of general taint)
    2. Control-flow dependency: does branch/loop condition depend on secret?
    3. Observable timing points: returns, external calls, network operations
    4. Variable-time primitives: operations without constant-time guarantees
    
    Timing taint propagation:
    - Sources: same as INFO_LEAK (getpass, env vars, network input)
    - Propagation: standard dataflow taint
    - Timing-sensitive points:
      - Branch conditions: if tainted_value: ...
      - Loop bounds/conditions: while tainted_value: ..., for i in range(tainted): ...
      - String/sequence comparison: tainted_str == other (non-constant-time)
      - Collection membership: x in tainted_list (variable-time scan)
    
    Observable timing points:
    - Function return (timing observable to caller)
    - Yield (observable to iterator consumer)
    - External calls (network, IPC, syscalls - timing externally observable)
    - Exceptions (timing of exception vs normal return may differ)
    
    Variable-time operations (primitive-level timing dependencies):
    - String equality: == on strings (short-circuit comparison)
    - List/tuple scan: x in lst, lst.index(x)
    - Set/dict operations: usually constant-time-ish, but not guaranteed
    - Early exit patterns: any()/all() with secret-dependent predicates
    
    Constant-time operations (safe for secrets):
    - hmac.compare_digest(a, b)
    - secrets.compare_digest(a, b)
    - Explicitly annotated constant-time functions
    
    Detection logic (conservative):
    1. Track PC taint: is current control flow tainted by secrets?
    2. Track loop taint: are loop bounds/iterations secret-dependent?
    3. At observable point: check if PC taint or recent operations were tainted
    4. Variable-time operations: flag if operation is not constant-time and operands are tainted
    
    Example patterns detected:
    - `if password == user_input: return True` → TIMING_CHANNEL
      (comparison time reveals how many characters match)
    - `for i in range(secret): compute()` → TIMING_CHANNEL
      (iteration count reveals secret)
    - `if secret_key in key_list: authenticate()` → TIMING_CHANNEL
      (search time reveals position of key in list)
    - `time.sleep(secret)` → TIMING_CHANNEL (trivial, but still detected)
    
    False negatives (limitations):
    - Compiler/interpreter optimizations may introduce timing variations we don't model
    - Cache timing (we don't model CPU cache)
    - GC timing (we don't model garbage collector pauses)
    - Network timing (we model network calls as timing-observable, but not jitter)
    
    These limitations are inherent to static analysis of timing channels.
    We follow the conservative principle: better to flag potential channels
    than to miss real ones.
    """
    # Explicit timing channel flag set by symbolic VM
    if hasattr(state, 'timing_channel_detected') and state.timing_channel_detected:
        return True
    
    # Secret-dependent control flow at observable timing point
    if hasattr(state, 'pc_taint') and hasattr(state, 'observable_timing_point'):
        # PC taint: current control flow depends on secret
        # Observable timing point: timing is externally visible (return, call, yield)
        if state.pc_taint and state.observable_timing_point:
            return True
    
    # Secret-dependent loop at observable point
    if hasattr(state, 'loop_taint') and hasattr(state, 'observable_timing_point'):
        # Loop taint: loop iteration count depends on secret
        if state.loop_taint and state.observable_timing_point:
            return True
    
    # Variable-time operation on secret data
    if hasattr(state, 'variable_time_operation') and hasattr(state, 'operand_tainted'):
        # Variable-time operation: non-constant-time primitive
        # Operand tainted: operation input is secret-dependent
        if state.variable_time_operation and state.operand_tainted:
            return True
    
    # Timing violations list (detailed tracking)
    if hasattr(state, 'timing_violations'):
        # timing_violations: list of (operation, location, taint_source, timing_observable)
        if state.timing_violations:
            return True
    
    # String comparison on tainted value (common pattern)
    if hasattr(state, 'string_compare_tainted') and state.string_compare_tainted:
        # String comparison is variable-time in Python (short-circuit on mismatch)
        return True
    
    # Collection scan with tainted search target or collection
    if hasattr(state, 'collection_scan_tainted') and state.collection_scan_tainted:
        # `x in lst` where x or lst is tainted → timing depends on position
        return True
    
    # Secret-dependent early exit (return/break in tainted control flow)
    if hasattr(state, 'early_exit_tainted') and state.early_exit_tainted:
        # Early exit (return, break, continue) in secret-dependent branch
        return True
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for TIMING_CHANNEL bug.
    
    Returns a dictionary with:
    - bug_type: "TIMING_CHANNEL"
    - trace: list of executed instructions
    - timing_details: what secret data influenced timing
    - taint_source: where the secret originated
    - timing_point: where the timing is observable
    - timing_dependency: what control-flow/operation depends on secret
    - path_condition: the Z3 path constraint
    """
    timing_details = {
        "bug_type": "TIMING_CHANNEL",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception,
            "halted": state.halted
        },
        "timing_violation": {}
    }
    
    # Extract timing channel details
    if hasattr(state, 'timing_violations') and state.timing_violations:
        timing_details["timing_violation"] = {
            "violations": state.timing_violations,
            "count": len(state.timing_violations)
        }
    
    # PC taint (control flow dependency)
    if hasattr(state, 'pc_taint') and state.pc_taint:
        timing_details["control_flow_tainted"] = True
        if hasattr(state, 'pc_taint_source'):
            timing_details["taint_source"] = state.pc_taint_source
    
    # Loop taint
    if hasattr(state, 'loop_taint') and state.loop_taint:
        timing_details["loop_tainted"] = True
        if hasattr(state, 'loop_taint_details'):
            timing_details["loop_details"] = state.loop_taint_details
    
    # Observable timing point
    if hasattr(state, 'observable_timing_point'):
        timing_details["observable_at"] = state.observable_timing_point
    
    # Variable-time operation
    if hasattr(state, 'variable_time_operation'):
        timing_details["variable_time_op"] = state.variable_time_operation
    
    # Specific patterns
    if hasattr(state, 'string_compare_tainted'):
        timing_details["string_compare_leak"] = state.string_compare_tainted
    
    if hasattr(state, 'collection_scan_tainted'):
        timing_details["collection_scan_leak"] = state.collection_scan_tainted
    
    if hasattr(state, 'early_exit_tainted'):
        timing_details["early_exit_leak"] = state.early_exit_tainted
    
    # Path condition (if available)
    if hasattr(state, 'path_condition'):
        timing_details["path_condition"] = str(state.path_condition)
    
    # Concrete values (if DSE provided them)
    if hasattr(state, 'concrete_witness'):
        timing_details["concrete_witness"] = state.concrete_witness
    
    # Function context (where in the code)
    if hasattr(state, 'current_function'):
        timing_details["function"] = state.current_function
    
    if hasattr(state, 'current_line'):
        timing_details["line"] = state.current_line
    
    # Explanation
    timing_details["explanation"] = (
        "Timing channel detected: execution time depends on secret data. "
        "An attacker observing timing may be able to infer secret values. "
        "Consider using constant-time operations (e.g., hmac.compare_digest) "
        "or restructuring control flow to eliminate timing dependencies."
    )
    
    return timing_details
