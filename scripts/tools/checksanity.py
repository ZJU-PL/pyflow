"""
Check compilation sanity of Python files in a directory.

This script verifies the consistency between Python source files (.py) and
compiled bytecode files (.pyc, .pyo). It identifies:
- Uncompiled Python files (no corresponding .pyc or .pyo)
- Orphaned bytecode files (no corresponding .py source)
- Dead directories (contain only uncompiled .py files, no bytecode, no subdirs)

Usage:
    python checksanity.py

The script walks through the 'bin' directory by default and reports any
inconsistencies found.
"""

import os.path

if __name__ == "__main__":
    dn = "bin"

    # Walk through directory tree checking compilation status
    for path, dirs, files in os.walk(dn):
        fileset = set(files)  # Use set for O(1) lookup
        compiled = 0  # Count of compiled files found
        uncompiled = 0  # Count of uncompiled Python files

        # Check each file in the directory
        for fn in files:
            root, ext = os.path.splitext(fn)

            if ext == ".py":
                # Check if corresponding bytecode file exists
                pyc = root + ".pyc"
                pyo = root + ".pyo"
                if pyc not in fileset and pyo not in fileset:
                    print("Uncompiled:\t%s" % os.path.join(path, fn))
                    uncompiled += 1

            elif ext == ".pyc" or ext == ".pyo":
                # Check if source file exists for this bytecode
                py = root + ".py"
                if py not in fileset:
                    print("No source:\t%s" % os.path.join(path, fn))
                compiled += 1

        # Detect dead directories: only uncompiled .py files, no bytecode, no subdirs
        if uncompiled and not compiled and not dirs:
            print("Dead directory:\t%s" % path)
