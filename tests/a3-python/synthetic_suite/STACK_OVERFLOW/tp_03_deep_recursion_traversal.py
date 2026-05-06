"""
STACK_OVERFLOW True Positive #3: Deep Recursive Data Structure Traversal
Ground Truth: BUG (RecursionError)

Recursive traversal of deeply nested data structure.
No tail-call optimization in Python means each level adds a frame.
"""

def build_deep_structure(depth):
    """Build a deeply nested list structure."""
    if depth == 0:
        return 0
    return [build_deep_structure(depth - 1)]

def traverse_deep(structure):
    """Traverse nested structure recursively - no depth limit."""
    if isinstance(structure, list):
        return sum(traverse_deep(item) for item in structure)
    return structure

def main():
    # Build structure deeper than recursion limit (default ~1000)
    # This will exhaust stack during traversal
    depth = 10000
    print(f"Building structure of depth {depth}...")
    structure = build_deep_structure(depth)
    
    print("Traversing structure...")
    result = traverse_deep(structure)  # STACK_OVERFLOW here
    print(f"Result: {result}")

if __name__ == "__main__":
    main()
