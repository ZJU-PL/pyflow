"""
Allow running a3_python as a module:

    python3 -m a3_python <target> [options]

Delegates to a3_python.cli:main().
"""
import sys
from .cli import _main_wrapper

sys.exit(_main_wrapper())
