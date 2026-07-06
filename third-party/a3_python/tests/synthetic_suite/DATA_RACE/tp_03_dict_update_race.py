"""
DATA_RACE True Positive #3: Dictionary update race

Bug type: DATA_RACE
Expected: BUG (race on shared dict)
Reason: Multiple threads update shared dict without synchronization
Unsafe state: Concurrent dict updates (structure corruption possible)
"""

import threading

shared_dict = {}

def update_dict(thread_id):
    for i in range(1000):
        key = f"{thread_id}_{i}"
        # Race: dict updates without lock can corrupt internal structure
        shared_dict[key] = i

def main():
    threads = [threading.Thread(target=update_dict, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Expected: 3000 entries, but race may corrupt dict
    print(f"Dict size: {len(shared_dict)}")

if __name__ == "__main__":
    main()
