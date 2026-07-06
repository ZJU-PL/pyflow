"""
UNINIT_MEMORY True Negative #4: Try-except with guaranteed assignment

Bug type: UNINIT_MEMORY
Expected result: SAFE
Reason: Variable is assigned in both try and except branches, ensuring
        it's always initialized regardless of whether an exception occurs.

Semantic: Both normal and exceptional control flow paths assign the
variable before use.
"""

def safe_parse(raw_input: str) -> int:
    try:
        parsed_value = int(raw_input)
    except ValueError:
        # Assign default value in exception handler
        parsed_value = -1
    
    # SAFE: parsed_value is assigned in both try and except branches
    return parsed_value

def safe_parse_with_finally(raw_input: str) -> tuple[int, bool]:
    success = False
    try:
        result = int(raw_input)
        success = True
    except ValueError:
        result = 0
        success = False
    
    # SAFE: both result and success are assigned in all paths
    return (result, success)

if __name__ == "__main__":
    value1 = safe_parse("42")
    value2 = safe_parse("not_a_number")
    value3, ok = safe_parse_with_finally("invalid")
    print(f"Results: {value1}, {value2}, ({value3}, {ok})")
