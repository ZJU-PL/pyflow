"""
PANIC true negative #3: Exception chaining with context preservation

Ground truth: SAFE
Reason: Exceptions are caught, re-wrapped with context, and handled at top level.
        Exception chaining preserves debugging info while preventing crash.

Expected analyzer behavior:
- Should verify inner exceptions are caught and re-raised with context
- Should verify outer exception handler exists for the chained exception
- Should report SAFE: exception handling chain is complete
"""

class ConfigError(Exception):
    """Custom exception for configuration errors."""
    pass

def load_config(filename: str) -> dict:
    """Load config file - may raise FileNotFoundError."""
    with open(filename, 'r') as f:
        return {}

def parse_config(filename: str) -> dict:
    """Parse config with exception chaining."""
    try:
        return load_config(filename)
    except FileNotFoundError as e:
        # Chain the exception with context
        raise ConfigError(f"Failed to load config: {filename}") from e

def initialize_app(config_file: str) -> bool:
    """Initialize application with full exception handling."""
    try:
        config = parse_config(config_file)
        print(f"Config loaded: {config}")
        return True
    except ConfigError as e:
        print(f"Configuration error: {e}")
        print(f"Cause: {e.__cause__}")
        return False  # Handled gracefully

def main():
    success = initialize_app("nonexistent.conf")
    if success:
        print("App initialized")
    else:
        print("App initialization failed, continuing with defaults")

if __name__ == "__main__":
    main()
