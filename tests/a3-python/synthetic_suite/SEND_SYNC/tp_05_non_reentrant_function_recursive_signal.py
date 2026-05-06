"""
SEND_SYNC True Positive #5: Non-reentrant function called from signal handler
Expected: BUG (SEND_SYNC violation)

Rationale: Signal handlers can interrupt execution at any point. If a
signal handler calls a non-reentrant function (e.g., one that uses
global state), and that function is interrupted mid-execution, the
global state can be corrupted.

Bug type: Reentrancy violation via signal handler
"""

import signal
import sys

# Global state that is not protected against reentrancy
counter = 0
in_progress = False


def non_reentrant_function():
    """Function that uses global state, not reentrant"""
    global counter, in_progress
    
    # Check if we're already inside this function (reentrancy check)
    if in_progress:
        # This would indicate reentrancy occurred
        print("ERROR: Reentrancy detected!", file=sys.stderr)
        sys.exit(1)
    
    in_progress = True
    
    # Simulate some work with global state
    temp = counter
    counter = temp + 1
    
    in_progress = False


def signal_handler(signum, frame):
    """Signal handler that calls non-reentrant function"""
    # BUG: Calling non-reentrant function from signal handler
    non_reentrant_function()


def main():
    # Install signal handler
    signal.signal(signal.SIGALRM, signal_handler)
    
    # Set an alarm to trigger the signal
    signal.alarm(1)
    
    # Keep calling the non-reentrant function
    # The signal can interrupt this call, causing reentrancy
    for _ in range(100000):
        non_reentrant_function()
    
    signal.alarm(0)  # Cancel alarm


if __name__ == "__main__":
    main()
