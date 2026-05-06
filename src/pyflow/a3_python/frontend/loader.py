"""
Frontend: load Python source files and compile to code objects.

Provides utilities for loading Python programs for analysis.
"""

import types
from pathlib import Path
from typing import Optional


def load_python_file(filepath: Path) -> Optional[types.CodeType]:
    """
    Load and compile a Python source file.
    
    Args:
        filepath: Path to .py file
    
    Returns:
        Compiled code object, or None on error
    """
    try:
        with open(filepath, 'r') as f:
            source = f.read()
        
        # Compile to code object
        code = compile(source, str(filepath), 'exec')
        return code
    
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return None


def load_python_string(source: str, filename: str = "<string>") -> Optional[types.CodeType]:
    """
    Compile Python source code from a string.
    
    Args:
        source: Python source code
        filename: Filename to use in error messages
    
    Returns:
        Compiled code object, or None on error
    """
    try:
        code = compile(source, filename, 'exec')
        return code
    except Exception as e:
        print(f"Error compiling {filename}: {e}")
        return None
