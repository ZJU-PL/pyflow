"""
UNINIT_MEMORY True Positive #2: Conditional assignment with missing branch

Bug type: UNINIT_MEMORY
Expected result: BUG
Reason: Variable 'output' is only assigned in the if-branch, but used after
        conditional regardless of which path was taken.

This is a control-flow-sensitive uninitialized variable bug: there exists
a path (condition=False) where 'output' is never assigned before use.
"""

def process_data(condition: bool, data: str) -> str:
    if condition:
        output = data.upper()
    # else: output is not assigned
    
    # BUG: if condition is False, 'output' is uninitialized here
    return output  # UnboundLocalError when condition=False

if __name__ == "__main__":
    # Trigger the buggy path
    result = process_data(False, "test")
    print(result)
