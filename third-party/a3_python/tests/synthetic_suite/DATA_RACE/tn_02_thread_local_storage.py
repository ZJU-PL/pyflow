"""
DATA_RACE True Negative #2: Thread-local storage

Bug type: DATA_RACE
Expected: SAFE (no race)
Reason: Each thread has its own storage (no sharing)
Safe pattern: threading.local() provides per-thread state
"""

import threading

thread_data = threading.local()

def worker(thread_id):
    thread_data.value = 0
    for i in range(10000):
        # No race: each thread modifies only its own thread_data
        thread_data.value += 1
    print(f"Thread {thread_id}: {thread_data.value}")

def main():
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
