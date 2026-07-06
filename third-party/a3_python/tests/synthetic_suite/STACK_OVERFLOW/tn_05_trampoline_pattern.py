"""
STACK_OVERFLOW True Negative #5: Trampoline Pattern for Mutual Recursion
Ground Truth: SAFE

Trampoline pattern converts recursion to iteration.
Returns thunks instead of direct recursive calls.
"""

class Thunk:
    """Deferred computation."""
    def __init__(self, func, *args):
        self.func = func
        self.args = args

def trampoline(func, *args):
    """Execute function using trampoline pattern."""
    result = func(*args)
    while isinstance(result, Thunk):
        result = result.func(*result.args)
    return result

def is_even_trampoline(n):
    """Check if n is even using trampoline."""
    if n == 0:
        return True
    return Thunk(is_odd_trampoline, n - 1)

def is_odd_trampoline(n):
    """Check if n is odd using trampoline."""
    if n == 0:
        return False
    return Thunk(is_even_trampoline, n - 1)

def main():
    # Large input safe with trampoline - no stack growth
    n = 10000
    result = trampoline(is_even_trampoline, n)
    print(f"is_even({n}) = {result}")
    
    result = trampoline(is_odd_trampoline, n)
    print(f"is_odd({n}) = {result}")

if __name__ == "__main__":
    main()
