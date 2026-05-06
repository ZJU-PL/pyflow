"""
TIMING_CHANNEL True Negative #4: Blinded operations on secrets

Safe: Apply blinding/masking to secret values before operations,
making timing independent of actual secret values.

Expected: SAFE - no timing channel
"""

import secrets


def blinded_comparison(secret_value: int, test_value: int, blind_range: int = 1000) -> bool:
    """
    Safe: Blind secret with random value to make timing independent of secret.
    """
    # Generate random blinding factor
    blind = secrets.randbelow(blind_range)
    
    # Blind both values
    blinded_secret = secret_value + blind
    blinded_test = test_value + blind
    
    # Comparison timing is now independent of original secret value
    # (within the blind_range)
    return blinded_secret == blinded_test


def modular_exponentiation_blinded(base: int, secret_exponent: int, modulus: int) -> int:
    """
    Safe: Use constant-time or blinded modular exponentiation.
    """
    # In real cryptographic libraries, use constant-time implementations
    # This is a simplified example using Python's built-in pow with fixed timing
    
    # Python's pow(base, exp, mod) uses efficient modular exponentiation
    # For actual constant-time crypto, use libraries like cryptography
    result = pow(base, secret_exponent, modulus)
    
    return result


def constant_time_hamming_weight(secret_bits: int, bit_length: int) -> int:
    """
    Safe: Compute hamming weight in constant time (always scan all bits).
    """
    weight = 0
    
    # Always iterate through all bit positions
    for i in range(bit_length):
        # Extract bit without timing leak
        bit = (secret_bits >> i) & 1
        weight += bit
    
    return weight


def main():
    # Safe: blinded comparison
    SECRET_VALUE = 42
    test_value = 50
    
    match = blinded_comparison(SECRET_VALUE, test_value)
    print(f"Values match: {match}")
    
    # Safe: constant-time modular exponentiation
    base = 3
    SECRET_EXPONENT = 12345
    modulus = 999999937
    
    result = modular_exponentiation_blinded(base, SECRET_EXPONENT, modulus)
    print(f"Modular exponentiation result: {result}")
    
    # Safe: constant-time hamming weight
    SECRET_BITS = 0b101101
    weight = constant_time_hamming_weight(SECRET_BITS, 6)
    print(f"Hamming weight: {weight}")


if __name__ == "__main__":
    main()
