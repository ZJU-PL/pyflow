"""
UNINIT_MEMORY True Negative #3: Default parameter provides initialization

Bug type: UNINIT_MEMORY
Expected result: SAFE
Reason: Using default parameter or explicit initialization ensures the
        variable is always defined before use.

Semantic: Variable is assigned at declaration/parameter-binding time,
so no path can reach a use before definition.
"""

def process_data(input_str: str, default_output: str = "N/A") -> str:
    # output is initialized from parameter
    output = default_output
    
    if input_str:
        output = input_str.upper()
    
    # SAFE: output is always assigned (either from default or in if-block)
    return output

def with_explicit_init(condition: bool) -> int:
    # Explicit initialization before conditional logic
    value = 0
    
    if condition:
        value = 42
    
    # SAFE: value has explicit default initialization
    return value

if __name__ == "__main__":
    result1 = process_data("", "default")
    result2 = with_explicit_init(False)
    print(f"Results: {result1}, {result2}")
