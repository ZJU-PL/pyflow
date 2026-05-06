"""
GROUND TRUTH: BUG (MEMORY_LEAK)
REASON: Closures capture large context and are retained indefinitely
SEMANTIC: Each closure retains reference to large data, accumulating in global list
"""

closures = []

def create_leaky_closures():
    for i in range(10000):
        large_data = [0] * 10000
        def closure():
            return large_data[0]
        closures.append(closure)

if __name__ == "__main__":
    create_leaky_closures()
