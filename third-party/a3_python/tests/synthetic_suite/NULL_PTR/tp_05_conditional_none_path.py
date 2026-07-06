"""
NULL_PTR True Positive #5: Conditional path leads to None dereference

Ground truth: BUG
Bug type: NULL_PTR
Reason: Variable conditionally assigned None, then dereferenced on some path

Semantic model: Control flow allows None value to reach dereference point.
"""

def process(value, mode):
    if mode == "default":
        result = {"status": "ok"}
    else:
        result = None  # BUG: Some paths set result to None
    
    # BUG: If mode != "default", result is None
    # Accessing .get() on None raises AttributeError
    status = result.get("status")
    return status

def main():
    output = process(42, "custom")
    print(output)

if __name__ == "__main__":
    main()
