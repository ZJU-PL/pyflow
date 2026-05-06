"""
GROUND TRUTH: BUG (MEMORY_LEAK)
REASON: Unbounded list growth in infinite loop without cleanup
SEMANTIC: Global list accumulates indefinitely without bound
"""

global_accumulator = []

def leak_memory():
    i = 0
    while True:
        global_accumulator.append([0] * 1000)
        i += 1
        if i > 1000000:
            break

if __name__ == "__main__":
    leak_memory()
