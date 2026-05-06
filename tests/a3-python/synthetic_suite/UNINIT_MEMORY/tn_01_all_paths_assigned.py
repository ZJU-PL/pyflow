"""
UNINIT_MEMORY True Negative #1: All paths assign before use

Bug type: UNINIT_MEMORY
Expected result: SAFE
Reason: Variable 'result' is assigned in both branches of the conditional,
        ensuring it's always initialized before use.

Semantic proof: Every path through the CFG assigns 'result' before
the return statement reads it.
"""

def compute_value(x: int) -> int:
    if x > 10:
        result = x * 2
    else:
        result = x + 5
    
    # SAFE: result is assigned in all paths before this use
    return result

if __name__ == "__main__":
    value1 = compute_value(15)
    value2 = compute_value(5)
    print(f"Results: {value1}, {value2}")
