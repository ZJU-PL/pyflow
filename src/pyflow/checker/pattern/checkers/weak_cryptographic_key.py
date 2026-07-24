"""
B505: Test for weak cryptographic key generation.

Using weak key sizes in cryptographic operations can be
trivially broken. Use recommended key sizes for each algorithm.
"""
from ..core import issue
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B505")
def weak_cryptographic_key(context):
    qualname = context.call_function_name_qual
    if qualname in {
        "RSA.generate",  # PyCrypto
        "rsa.newkeys",  # rsa library
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
        "cryptography.hazmat.primitives.asymmetric.dh.generate_parameters",
        "cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key",
        "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key",
    }:
        for kw in context.node.keywords:
            if kw.arg in ("key_size", "key_size_bits", "key_bits", "nbits"):
                if hasattr(kw.value, "value") and isinstance(kw.value.value, int):
                    if kw.value.value < 2048:
                        return issue.Issue(
                            severity="MEDIUM",
                            confidence="HIGH",
                            cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH,
                            text=f"Weak cryptographic key size ({kw.value.value}). "
                            f"Using key sizes below 2048 bits is considered "
                            f"insecure. Use at least 2048 bit keys.",
                        )
    return None
