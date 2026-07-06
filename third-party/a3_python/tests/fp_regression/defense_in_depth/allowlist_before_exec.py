"""
Defense-in-depth pattern: Allowlist before exec.

This pattern uses a strict allowlist to validate input before executing it.
The execute() call is protected by the allowlist check.

Expected: NO bugs (or LOW confidence) due to defense-in-depth mitigation
"""

import subprocess

# Strict allowlist of allowed commands
ALLOWED_COMMANDS = frozenset(['ls', 'cat', 'pwd', 'whoami', 'date'])


def sanitize_command(cmd: str) -> str:
    """Validate and sanitize command against allowlist."""
    cmd = cmd.strip().lower()
    if cmd not in ALLOWED_COMMANDS:
        raise ValueError(f"Command '{cmd}' not in allowlist")
    return cmd


def safe_execute(user_input: str) -> str:
    """Execute command after allowlist validation.
    
    This is SAFE because:
    1. sanitize_command validates against a strict allowlist
    2. Only pre-defined safe commands can be executed
    3. User cannot inject arbitrary commands
    """
    # Defense-in-depth: validate against allowlist first
    validated_cmd = sanitize_command(user_input)
    
    # Now safe to execute - only allowed commands reach here
    result = subprocess.run([validated_cmd], capture_output=True, text=True)
    return result.stdout


if __name__ == "__main__":
    # User input from CLI (simulated)
    cmd = input("Enter command (ls, cat, pwd, whoami, date): ")
    
    try:
        output = safe_execute(cmd)
        print(f"Output:\n{output}")
    except ValueError as e:
        print(f"Error: {e}")
