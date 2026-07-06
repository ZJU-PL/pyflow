"""
DATA_RACE True Positive #4: Check-then-act race (TOCTOU)

Bug type: DATA_RACE
Expected: BUG (TOCTOU race)
Reason: Check-then-act pattern without atomicity (time-of-check-time-of-use)
Unsafe state: Condition checked and action taken are not atomic
"""

import threading

balance = 100

def withdraw(amount):
    global balance
    # Race: check and withdraw are not atomic
    if balance >= amount:
        # Another thread may withdraw here
        balance -= amount
        return True
    return False

def main():
    threads = [threading.Thread(target=withdraw, args=(60,)) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Expected: balance >= 0 always, but race allows negative balance
    print(f"Final balance: {balance}")

if __name__ == "__main__":
    main()
