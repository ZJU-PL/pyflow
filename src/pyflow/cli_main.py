"""Main CLI entry point for PyFlow."""

import sys
from pathlib import Path

# Add the src directory to the path so we can import pyflow modules
sys.path.insert(0, str(Path(__file__).parent))

from pyflow.cli.main import main

if __name__ == "__main__":
    main()
