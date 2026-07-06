"""
GROUND TRUTH: SAFE (NO MEMORY_LEAK)
REASON: Bounded buffer with max size limit enforced
SEMANTIC: Collection growth is capped at fixed maximum size
"""

class BoundedBuffer:
    def __init__(self, max_size):
        self.max_size = max_size
        self.buffer = []
    
    def add(self, item):
        if len(self.buffer) >= self.max_size:
            self.buffer.pop(0)
        self.buffer.append(item)

def safe_bounded_collection():
    buffer = BoundedBuffer(1000)
    for i in range(100000):
        buffer.add([0] * 100)

if __name__ == "__main__":
    safe_bounded_collection()
