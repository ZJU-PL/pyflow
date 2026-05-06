"""
TYPE_CONFUSION True Negative #5: Try-except for type errors

Expected: SAFE
Reason: Potential type errors caught by exception handler
"""

def safe_operation(value, operation):
    """Uses try-except to handle potential type mismatches"""
    try:
        if operation == "append":
            value.append("item")
        elif operation == "get":
            return value.get('key')
        elif operation == "multiply":
            return value * 2
        return value
    except (AttributeError, TypeError) as e:
        # Handle type confusion gracefully
        print(f"Type error handled: {e}")
        return None

def main():
    # All calls safe due to exception handling
    safe_operation([1, 2], "append")
    safe_operation({'key': 'value'}, "get")
    safe_operation("hello", "multiply")
    safe_operation(42, "append")  # Would fail but caught
    print("All operations completed safely")

if __name__ == "__main__":
    main()
