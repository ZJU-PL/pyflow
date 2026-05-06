"""
GROUND TRUTH: SAFE (NO MEMORY_LEAK)
REASON: Proper weakref usage allows garbage collection
SEMANTIC: Weak references don't prevent collection of referenced objects
"""

import weakref

class CacheEntry:
    def __init__(self, data):
        self.data = data

def safe_weak_cache():
    cache = {}
    for i in range(10000):
        entry = CacheEntry([0] * 1000)
        cache[i] = weakref.ref(entry)

if __name__ == "__main__":
    safe_weak_cache()
