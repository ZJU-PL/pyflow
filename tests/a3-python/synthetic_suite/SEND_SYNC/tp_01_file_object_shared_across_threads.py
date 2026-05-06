"""
SEND_SYNC True Positive #1: File object shared across threads
Expected: BUG (SEND_SYNC violation)

Rationale: File objects are not thread-safe. Concurrent write operations
from multiple threads without synchronization can lead to interleaved
writes, corrupted data, or internal state corruption.

Bug type: Non-thread-safe object passed between threads
"""

import threading


def worker(file_obj, data):
    """Write to shared file object without synchronization"""
    for i in range(100):
        file_obj.write(f"{data}-{i}\n")


def main():
    # Open a file and share the file object across threads
    f = open("output.txt", "w")
    
    # Create threads that all write to the same file object
    t1 = threading.Thread(target=worker, args=(f, "thread1"))
    t2 = threading.Thread(target=worker, args=(f, "thread2"))
    t3 = threading.Thread(target=worker, args=(f, "thread3"))
    
    t1.start()
    t2.start()
    t3.start()
    
    t1.join()
    t2.join()
    t3.join()
    
    f.close()


if __name__ == "__main__":
    main()
