"""
NULL_PTR True Negative #1: None check before use

Ground truth: SAFE
Bug type: NULL_PTR
Reason: Explicit None check guards all uses

Semantic model: Control flow ensures value is not None at dereference point.
"""

def get_value():
    return None

def main():
    result = get_value()
    # SAFE: None check guards the method call
    if result is not None:
        output = result.upper()
        print(output)
    else:
        print("No value")

if __name__ == "__main__":
    main()
