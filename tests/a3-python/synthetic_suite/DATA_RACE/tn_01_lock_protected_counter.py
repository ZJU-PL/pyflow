"""
DATA_RACE True Negative #1: Lock-protected counter

Bug type: DATA_RACE
Expected: SAFE (no race)
Reason: Shared counter protected by Lock
Safe pattern: All accesses to shared state guarded by lock
"""

import threading

counter = 0
lock = threading.Lock()

def increment():
    global counter
    for _ in range(10000):
        with lock:
            counter += 1

def main():
    threads = [threading.Thread(target=increment) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f"Counter: {counter}")  # Always 20000

if __name__ == "__main__":
    main()
