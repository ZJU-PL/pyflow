"""
DATA_RACE True Negative #3: Immutable shared data

Bug type: DATA_RACE
Expected: SAFE (no race)
Reason: Shared data is immutable (reads only, no writes)
Safe pattern: Immutable objects can be safely shared
"""

import threading

# Immutable shared data
shared_config = {
    "timeout": 30,
    "retries": 3,
    "url": "https://example.com"
}

def worker(thread_id):
    for _ in range(1000):
        # Safe: only reads from immutable dict
        timeout = shared_config["timeout"]
        retries = shared_config["retries"]
    print(f"Thread {thread_id} done")

def main():
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
