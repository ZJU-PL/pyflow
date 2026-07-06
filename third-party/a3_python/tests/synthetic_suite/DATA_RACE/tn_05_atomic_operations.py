"""
DATA_RACE True Negative #5: Atomic operations with threading primitives

Bug type: DATA_RACE
Expected: SAFE (no race)
Reason: RLock guards check-then-act pattern atomically
Safe pattern: Lock held during entire critical section
"""

import threading

balance = 100
lock = threading.RLock()

def withdraw(amount):
    global balance
    with lock:
        # Atomic: check and withdraw are both protected by lock
        if balance >= amount:
            balance -= amount
            return True
        return False

def main():
    threads = [threading.Thread(target=withdraw, args=(60,)) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Safe: balance never goes negative
    print(f"Final balance: {balance}")

if __name__ == "__main__":
    main()
