"""
FP Regression Test: Environment variable config paths.

Environment variables for config paths are common in CLI tools and 12-factor apps.
These should NOT be flagged as PATH_INJECTION.

Expected: NO FINDINGS (or LOW confidence if any)
"""
import os
from pathlib import Path


def load_config():
    """Load config from environment variable path - should NOT flag."""
    
    # Common patterns in CLI tools / 12-factor apps
    config_path = os.environ.get("CONFIG_PATH", "/etc/myapp/config.yaml")
    data_dir = os.getenv("DATA_DIR", "/var/lib/myapp")
    home = os.environ.get("HOME", "/root")
    
    # These are controlled by the operator, not an attacker
    config_file = Path(config_path)
    if config_file.exists():
        with open(config_path, 'r') as f:  # Should NOT flag
            return f.read()
    
    # XDG directories - common pattern
    xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    app_config = Path(xdg_config) / "myapp" / "config.yaml"
    
    if app_config.exists():
        with open(app_config, 'r') as f:  # Should NOT flag
            return f.read()
    
    return None


def main():
    config = load_config()
    print(f"Loaded config: {config is not None}")


if __name__ == "__main__":
    main()
