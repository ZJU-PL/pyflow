"""
STACK_OVERFLOW True Positive #5: Recursive Parser with Deeply Nested Input
Ground Truth: BUG (RecursionError)

Recursive descent parser handling deeply nested structure.
Malicious/pathological input with extreme nesting exhausts stack.
"""

def parse_nested(data, depth=0):
    """Parse nested dictionary/list structure recursively."""
    if isinstance(data, dict):
        return {k: parse_nested(v, depth + 1) for k, v in data.items()}
    elif isinstance(data, list):
        return [parse_nested(item, depth + 1) for item in data]
    else:
        return data

def build_deeply_nested_dict(depth):
    """Build pathologically nested dictionary."""
    result = {"value": 0}
    for i in range(depth):
        result = {"nested": result}
    return result

def main():
    # Create input with nesting deeper than recursion limit
    depth = 5000
    print(f"Building nested structure (depth={depth})...")
    data = build_deeply_nested_dict(depth)
    
    print("Parsing nested structure...")
    parsed = parse_nested(data)  # STACK_OVERFLOW during parsing
    print(f"Parsed successfully")

if __name__ == "__main__":
    main()
