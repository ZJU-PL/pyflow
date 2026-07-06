"""
INTEGER_OVERFLOW True Negative #5: Try-except overflow handling
EXPECTED: SAFE
REASON: Potential overflows are caught and handled safely
"""
import struct

def safe_struct_pack_with_handler(value: int, fmt: str) -> bytes:
    """Pack integer with overflow handling."""
    try:
        return struct.pack(fmt, value)
    except struct.error as e:
        # Overflow detected, handle gracefully
        print(f"Overflow detected for {value} with format {fmt}: {e}")
        # Return packed zero as safe fallback
        return struct.pack(fmt, 0)

def safe_range_limited_pack(value: int) -> int:
    """Pack into int16 with range enforcement."""
    try:
        # Try to pack as signed short (-32768 to 32767)
        if not (-32768 <= value <= 32767):
            raise ValueError(f"Value {value} out of range")
        packed = struct.pack('h', value)
        unpacked = struct.unpack('h', packed)[0]
        assert unpacked == value
        return unpacked
    except (struct.error, ValueError) as e:
        print(f"Caught error: {e}")
        raise

if __name__ == "__main__":
    # Safe operations
    result1 = safe_struct_pack_with_handler(30000, 'h')
    print(f"Packed successfully: {result1}")
    
    # Overflow handled gracefully
    result2 = safe_struct_pack_with_handler(40000, 'h')
    print(f"Overflow handled: {result2}")
    
    # Safe within range
    result3 = safe_range_limited_pack(30000)
    print(f"Safe range: {result3}")
