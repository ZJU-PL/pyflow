"""
TIMING_CHANNEL True Positive #3: Short-circuit on secret bit

Bug: Conditional logic branches based on secret data, creating timing
differences that leak information about the secret.

Expected: BUG - TIMING_CHANNEL detected
"""

def check_permission(user_id: int, admin_flag: bool) -> bool:
    """
    Vulnerable: Early return based on secret admin flag creates timing leak.
    """
    # If admin_flag is secret (e.g., from database), timing reveals its value
    if admin_flag:
        # Admin path: fast return
        return True
    
    # Non-admin path: expensive permission check
    # Simulated expensive operation
    permissions = []
    for i in range(1000):
        permissions.append(i * user_id % 997)
    
    return user_id in permissions


def process_request(user_id: int, secret_admin_status: bool):
    """
    Process request with timing side-channel.
    Admin users get fast path, non-admins get slow path.
    Attacker can time requests to determine if target user is admin.
    """
    if check_permission(user_id, secret_admin_status):
        print(f"User {user_id} granted access")
    else:
        print(f"User {user_id} denied access")


def main():
    # Secret: user 42 is an admin
    SECRET_ADMIN_USERS = {42, 123, 999}
    
    user_id = 42
    is_admin = user_id in SECRET_ADMIN_USERS
    
    # Timing reveals admin status via different code paths
    process_request(user_id, is_admin)


if __name__ == "__main__":
    main()
