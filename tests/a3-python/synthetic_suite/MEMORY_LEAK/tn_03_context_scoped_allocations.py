"""
GROUND TRUTH: SAFE (NO MEMORY_LEAK)
REASON: Context-scoped allocations are freed when context exits
SEMANTIC: Allocations bound to function scope are reclaimed on return
"""

def process_batch(batch_size):
    data = []
    for i in range(batch_size):
        data.append([0] * 1000)
    return len(data)

def safe_scoped_allocations():
    for i in range(1000):
        process_batch(100)

if __name__ == "__main__":
    safe_scoped_allocations()
