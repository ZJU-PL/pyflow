"""
INTEGER_OVERFLOW True Positive #3: struct.pack overflow
EXPECTED: BUG
REASON: Packing large integer into small format causes overflow/wrapping
"""
import struct

def overflow_struct_pack():
    # 'h' is signed short (16-bit): -32768 to 32767
    large_value = 40000
    try:
        # This will silently wrap/truncate
        packed = struct.pack('h', large_value)
        unpacked = struct.unpack('h', packed)[0]
        # Value has wrapped: 40000 → -25536
        assert unpacked == large_value  # Will fail
        return unpacked
    except struct.error:
        # If struct raises an error, that's actually safer
        return None

if __name__ == "__main__":
    result = overflow_struct_pack()
    if result is not None:
        print(f"Overflow occurred: {40000} → {result}")
