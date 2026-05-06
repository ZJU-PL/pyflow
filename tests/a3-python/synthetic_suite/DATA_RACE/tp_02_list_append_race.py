"""
DATA_RACE True Positive #2: List append race

Bug type: DATA_RACE
Expected: BUG (race on shared list)
Reason: Multiple threads append to shared list without synchronization
Unsafe state: Concurrent list.append() calls (non-atomic structure modification)
"""

import threading

shared_list = []

def append_items(start):
    for i in range(start, start + 1000):
        # Race: list.append is not atomic in presence of concurrent modifications
        shared_list.append(i)

def main():
    t1 = threading.Thread(target=append_items, args=(0,))
    t2 = threading.Thread(target=append_items, args=(1000,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    # Expected: 2000 items, but race may corrupt list structure
    print(f"List length: {len(shared_list)}")

if __name__ == "__main__":
    main()
