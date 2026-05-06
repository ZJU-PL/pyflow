"""
TIMING_CHANNEL True Positive #4: Secret-dependent loop iterations

Bug: Number of loop iterations depends on secret value, creating timing
side-channel that leaks information about the secret.

Expected: BUG - TIMING_CHANNEL detected
"""

def compute_with_secret(secret_key: int, public_input: int) -> int:
    """
    Vulnerable: Loop iterations depend on secret_key value.
    """
    result = public_input
    
    # Number of iterations leaks information about secret_key
    for i in range(secret_key):
        result = (result * 31 + 17) % 1000000007
    
    return result


def cryptographic_operation(plaintext: int, secret_bits: str) -> int:
    """
    Vulnerable: Processing time depends on number of 1-bits in secret.
    """
    result = plaintext
    
    # Timing leaks hamming weight of secret_bits
    for bit in secret_bits:
        if bit == '1':
            # Expensive operation only for '1' bits
            for _ in range(100):
                result = (result * result) % 999999937
    
    return result


def main():
    # Secret encryption key (timing leaks information about its value)
    SECRET_KEY = 42
    
    public_data = 123456
    encrypted = compute_with_secret(SECRET_KEY, public_data)
    print(f"Encrypted: {encrypted}")
    
    # Secret bit pattern (timing leaks hamming weight)
    SECRET_BITS = "101101"  # 4 ones
    
    result = cryptographic_operation(public_data, SECRET_BITS)
    print(f"Result: {result}")


if __name__ == "__main__":
    main()
