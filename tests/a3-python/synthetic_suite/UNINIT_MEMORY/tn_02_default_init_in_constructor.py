"""
UNINIT_MEMORY True Negative #2: Default initialization in __init__

Bug type: UNINIT_MEMORY
Expected result: SAFE
Reason: Instance attributes are always initialized in __init__ before
        any method can access them.

Semantic: object attributes are guaranteed present in __dict__ after
construction, so all accesses are to initialized memory.
"""

class Counter:
    def __init__(self, initial: int = 0):
        # Always initialize all attributes
        self.count = initial
        self.name = "Counter"
    
    def increment(self) -> None:
        # SAFE: self.count is always initialized in __init__
        self.count += 1
    
    def get_count(self) -> int:
        # SAFE: self.count is guaranteed to exist
        return self.count

if __name__ == "__main__":
    counter = Counter(10)
    counter.increment()
    print(f"Count: {counter.get_count()}")
