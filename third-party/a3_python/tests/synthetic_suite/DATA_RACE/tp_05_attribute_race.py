"""
DATA_RACE True Positive #5: Object attribute race

Bug type: DATA_RACE
Expected: BUG (race on object attributes)
Reason: Multiple threads modify object attributes without synchronization
Unsafe state: Concurrent attribute reads and writes (non-atomic)
"""

import threading

class Counter:
    def __init__(self):
        self.value = 0
        self.count = 0

    def increment(self):
        # Race: multiple attributes updated without atomicity
        self.value += 1
        self.count += 1

def worker(obj):
    for _ in range(5000):
        obj.increment()

def main():
    obj = Counter()
    threads = [threading.Thread(target=worker, args=(obj,)) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Expected: value == count == 10000, but race makes them inconsistent
    print(f"Value: {obj.value}, Count: {obj.count}")

if __name__ == "__main__":
    main()
