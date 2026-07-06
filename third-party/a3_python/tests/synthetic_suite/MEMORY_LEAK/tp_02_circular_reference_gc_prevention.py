"""
GROUND TRUTH: BUG (MEMORY_LEAK)
REASON: Circular references prevent garbage collection
SEMANTIC: Objects reference each other forming cycle, preventing deallocation
"""

class Node:
    def __init__(self, value):
        self.value = value
        self.ref = None
        self.data = [0] * 10000

def create_circular_leak():
    nodes = []
    for i in range(10000):
        n1 = Node(i)
        n2 = Node(i + 1)
        n1.ref = n2
        n2.ref = n1
        nodes.append((n1, n2))

if __name__ == "__main__":
    create_circular_leak()
