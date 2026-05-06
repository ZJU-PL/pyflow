"""
DATA_RACE True Positive #1: Shared counter without lock

Bug type: DATA_RACE
Expected: BUG (race on shared counter)
Reason: Multiple threads increment shared counter without synchronization
Unsafe state: Read-modify-write race on counter (non-atomic increment)
"""

import threading

counter = 0

def increment():
    global counter
    for _ in range(10000):
        # Race: read-modify-write without lock
        counter += 1

def main():
    threads = [threading.Thread(target=increment) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Expected: 20000, but race makes result non-deterministic
    print(f"Counter: {counter}")

if __name__ == "__main__":
    main()
