"""
TIMING_CHANNEL True Positive #1: Early return on password mismatch

Bug: Password comparison returns early on first mismatch, creating
timing side-channel that leaks password length and character positions.

An attacker can measure timing differences to determine:
1. Password length (by timing first-byte mismatches)
2. Character positions (by timing progressive matches)

Expected: BUG - TIMING_CHANNEL detected
"""

def check_password(user_input: str, correct_password: str) -> bool:
    """
    Vulnerable: Early return on mismatch creates timing side-channel.
    """
    if len(user_input) != len(correct_password):
        # Timing leaks password length immediately
        return False
    
    for i in range(len(correct_password)):
        if user_input[i] != correct_password[i]:
            # Early return: timing reveals how many characters matched
            return False
    
    return True


def main():
    # Secret password
    SECRET_PASSWORD = "super_secret_password_12345"
    
    # Attacker can measure timing differences:
    # - Short input: fast rejection (length check)
    # - Correct length, wrong first char: slightly slower
    # - Correct length, first N chars correct: progressively slower
    
    user_attempt = input("Enter password: ")
    
    if check_password(user_attempt, SECRET_PASSWORD):
        print("Access granted")
    else:
        print("Access denied")


if __name__ == "__main__":
    main()
