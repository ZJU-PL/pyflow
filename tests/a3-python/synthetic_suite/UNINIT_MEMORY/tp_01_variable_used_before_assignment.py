"""
UNINIT_MEMORY True Positive #1: Variable used before assignment

Bug type: UNINIT_MEMORY
Expected result: BUG
Reason: Variable 'result' is used before being assigned in any path

The semantic unsafe region: referencing a name that is not bound in the
current namespace (UnboundLocalError at runtime, or statically provable
that no assignment precedes the use).
"""

def compute_value(x: int) -> int:
    # result is declared here but never assigned
    # Attempting to use it will raise UnboundLocalError
    if x > 10:
        pass  # No assignment in this branch
    
    # This line will try to read 'result' but it was never assigned
    return result  # BUG: UnboundLocalError

if __name__ == "__main__":
    value = compute_value(15)
    print(value)
