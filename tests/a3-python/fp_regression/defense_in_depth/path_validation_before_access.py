"""
Defense-in-depth pattern: Path validation before access.

This pattern validates path inputs against a safe base directory
before performing file operations.

Expected: NO bugs (or LOW confidence) due to defense-in-depth mitigation
"""

from pathlib import Path
import os


class SecureFileHandler:
    """File handler with path validation defense-in-depth."""
    
    def __init__(self, base_dir: str):
        # Normalize and resolve the base directory
        self.base_dir = Path(base_dir).resolve()
        if not self.base_dir.is_dir():
            raise ValueError(f"Base directory does not exist: {base_dir}")
    
    def validate_path(self, user_path: str) -> Path:
        """Validate and normalize user-provided path.
        
        This is the key defense-in-depth mechanism.
        Prevents path traversal attacks by ensuring the resolved
        path is under the base directory.
        """
        # Normalize the path
        requested = Path(user_path)
        
        # Make it relative to base if absolute
        if requested.is_absolute():
            # Try to make it relative
            try:
                requested = requested.relative_to('/')
            except ValueError:
                pass
        
        # Resolve against base directory
        full_path = (self.base_dir / requested).resolve()
        
        # CRITICAL: Ensure resolved path is under base_dir
        # This prevents path traversal attacks like "../../../etc/passwd"
        if not str(full_path).startswith(str(self.base_dir)):
            raise ValueError(f"Path traversal detected: {user_path}")
        
        return full_path
    
    def safe_read(self, user_path: str) -> str:
        """Safely read file after path validation.
        
        This is SAFE because:
        1. validate_path ensures path is under base_dir
        2. Path traversal attacks are blocked
        3. Only files in allowed directory can be accessed
        """
        # Defense-in-depth: validate path first
        validated_path = self.validate_path(user_path)
        
        # Now safe to read - path is guaranteed to be under base_dir
        with open(validated_path, 'r') as f:
            return f.read()
    
    def safe_write(self, user_path: str, content: str) -> None:
        """Safely write file after path validation."""
        validated_path = self.validate_path(user_path)
        
        with open(validated_path, 'w') as f:
            f.write(content)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure file handler')
    parser.add_argument('--base-dir', default='./data', help='Base directory')
    parser.add_argument('--file', required=True, help='File to read')
    args = parser.parse_args()
    
    # Create handler with restricted base directory
    handler = SecureFileHandler(args.base_dir)
    
    try:
        # User-provided path is validated before access
        content = handler.safe_read(args.file)
        print(f"Content:\n{content}")
    except ValueError as e:
        print(f"Security error: {e}")
    except FileNotFoundError as e:
        print(f"File not found: {e}")


if __name__ == "__main__":
    main()
