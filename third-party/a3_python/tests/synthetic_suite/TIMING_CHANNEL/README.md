# TIMING_CHANNEL Synthetic Test Suite

## Bug Type: TIMING_CHANNEL (Timing Side-Channel Attack)

**Definition**: A timing channel vulnerability occurs when the execution time of security-sensitive operations depends on secret data, allowing an attacker to infer information about secrets by measuring timing differences.

**Barrier Certificate Formulation**:
- **Unsafe Region**: Program states where execution time varies based on secret data values
- **Safety Property**: For all secret values s1, s2 and public input p: Time(Compute(s1, p)) ≈ Time(Compute(s2, p)) (within negligible bounds)

## Test Structure

This suite contains ground-truth test cases for TIMING_CHANNEL detection:

### True Positives (5 cases - MUST be detected as BUG)

1. **tp_01_early_return_on_password_mismatch.py**
   - Bug: Password comparison with early return on mismatch
   - Timing leaks: Password length and character positions
   - Attack: Attacker measures time to determine correct characters

2. **tp_02_length_dependent_string_comparison.py**
   - Bug: Built-in string equality (==) short-circuits on length mismatch
   - Timing leaks: Secret token length
   - Attack: Try different lengths and measure timing

3. **tp_03_short_circuit_on_secret_bit.py**
   - Bug: Conditional branching based on secret boolean value
   - Timing leaks: Admin status (fast path vs expensive path)
   - Attack: Measure response time to determine admin flag

4. **tp_04_secret_dependent_loop_iterations.py**
   - Bug: Number of loop iterations depends on secret value
   - Timing leaks: Secret key value and hamming weight
   - Attack: Measure time to infer secret magnitude

5. **tp_05_conditional_expensive_operation.py**
   - Bug: Expensive operation conditionally executed based on secret
   - Timing leaks: Signature bytes and cache key prefixes
   - Attack: Measure large timing differences to leak secrets

### True Negatives (5 cases - MUST NOT be flagged)

1. **tn_01_constant_time_comparison_hmac.py**
   - Safe: Uses hmac.compare_digest for constant-time comparison
   - Mitigation: Cryptographic comparison function designed to prevent timing leaks

2. **tn_02_fixed_iteration_count.py**
   - Safe: Fixed number of iterations regardless of secret value
   - Mitigation: Always perform maximum iterations with dummy operations

3. **tn_03_dummy_operations_equalize_timing.py**
   - Safe: All code paths perform equivalent operations
   - Mitigation: Both branches execute same amount of work

4. **tn_04_blinded_operations_on_secrets.py**
   - Safe: Apply blinding/masking to secret values
   - Mitigation: Random blinding makes timing independent of actual secret

5. **tn_05_data_independent_control_flow.py**
   - Safe: Control flow independent of secret data
   - Mitigation: Rate limiting and always computing all paths

## Detection Strategy

A semantically-grounded analyzer must:

1. **Identify secret data sources**:
   - Function parameters marked as sensitive
   - Data from secure sources (passwords, keys, tokens)
   - Results of cryptographic operations

2. **Track secret propagation**:
   - Taint analysis to track secret-derived values
   - Control-flow dependencies on secret data

3. **Detect timing variations**:
   - Branching based on secret values (if secret: fast_path else slow_path)
   - Early returns in comparisons (for i: if s[i] != t[i]: return False)
   - Secret-dependent loop bounds (for i in range(secret): ...)
   - Conditional expensive operations (if secret_condition: expensive_work())

4. **Verify constant-time mitigations**:
   - hmac.compare_digest usage
   - Fixed iteration counts
   - Dummy operations to equalize paths
   - Blinding/masking techniques

## Semantic Modeling

**Unsafe predicate**: U_timing(σ) holds when:
- There exist states σ1, σ2 that differ only in secret data values
- Execution paths from σ1 and σ2 have different lengths or costs
- The timing difference is observable to an attacker

**Symbolic timing model**:
- Associate path cost with each transition
- Track secret-dependent vs public-dependent costs
- Detect paths where cost depends on secret values

## Ground Truth

| File | Expected | Reason |
|------|----------|--------|
| tp_01 | BUG | Early return leaks password characters |
| tp_02 | BUG | Length-dependent comparison |
| tp_03 | BUG | Secret-dependent branching |
| tp_04 | BUG | Secret-dependent loop count |
| tp_05 | BUG | Conditional expensive operation |
| tn_01 | SAFE | hmac.compare_digest (constant-time) |
| tn_02 | SAFE | Fixed iteration count |
| tn_03 | SAFE | Equalized timing via dummy ops |
| tn_04 | SAFE | Blinded operations |
| tn_05 | SAFE | Data-independent control flow |

## Notes on Detection Difficulty

- **Requires taint analysis**: Must track which data is secret
- **Requires path cost modeling**: Must model execution time/cost
- **Requires symbolic execution**: Must explore multiple paths
- **Challenge**: Distinguishing negligible vs exploitable timing differences
- **Precision**: Need to recognize constant-time primitives (hmac.compare_digest)

## Attack Scenarios

1. **Remote timing attacks**: Network attacker measures response times
2. **Local timing attacks**: Malicious process measures syscall/cache timing
3. **Cross-VM attacks**: Attacker in different VM measures shared resource contention

## Mitigation Patterns

1. **Cryptographic libraries**: Use hmac.compare_digest, secrets module
2. **Algorithmic**: Fixed iteration count, constant-time selection
3. **Architectural**: Random delays, rate limiting, dummy operations
4. **Blinding**: Randomize intermediate values to decorrelate from secrets
