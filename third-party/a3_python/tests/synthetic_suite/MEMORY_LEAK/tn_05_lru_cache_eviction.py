"""
GROUND TRUTH: SAFE (NO MEMORY_LEAK)
REASON: LRU cache with eviction policy prevents unbounded growth
SEMANTIC: Least-recently-used items are evicted when capacity is reached
"""

from collections import OrderedDict

class LRUCache:
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = OrderedDict()
    
    def get(self, key):
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        return None
    
    def put(self, key, value):
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)

def safe_lru_cache():
    cache = LRUCache(1000)
    for i in range(100000):
        cache.put(i, [0] * 100)

if __name__ == "__main__":
    safe_lru_cache()
