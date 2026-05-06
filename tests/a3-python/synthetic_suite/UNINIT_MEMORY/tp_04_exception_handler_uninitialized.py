"""
UNINIT_MEMORY True Positive #4: Exception handler with uninitialized variable

Bug type: UNINIT_MEMORY
Expected result: BUG
Reason: Variable 'parsed_value' is only assigned in the try block. If an
        exception occurs before the assignment, the except block tries to
        access the uninitialized variable.

Control flow through exception edges: there exists a reachable path
(exception before assignment) where use-before-def occurs.
"""

def parse_input(raw_input: str) -> int:
    try:
        # This line might raise ValueError before parsed_value is assigned
        if len(raw_input) == 0:
            raise ValueError("Empty input")
        parsed_value = int(raw_input)
    except ValueError:
        # BUG: if exception raised before assignment, parsed_value is uninitialized
        print(f"Failed to parse: {parsed_value}")  # UnboundLocalError
        return -1
    
    return parsed_value

if __name__ == "__main__":
    # Trigger exception before assignment
    result = parse_input("")
    print(result)
