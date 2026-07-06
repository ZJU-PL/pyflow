"""
GROUND TRUTH: BUG (MEMORY_LEAK)
REASON: Global cache accumulates without bound, no eviction policy
SEMANTIC: Cache dictionary grows indefinitely without cleanup mechanism
"""

_global_cache = {}

def compute_and_cache(key):
    if key not in _global_cache:
        _global_cache[key] = [0] * 1000
    return _global_cache[key]

def leak_through_cache():
    for i in range(100000):
        compute_and_cache(f"key_{i}")

if __name__ == "__main__":
    leak_through_cache()
