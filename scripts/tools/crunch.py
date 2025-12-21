"""
Generate an HTML file containing all Python source files from a directory.

This script walks through a directory tree (default: 'bin'), finds all Python
files, and generates a single HTML file ('crunch.html') that contains all the
source code with proper formatting.

Usage:
    python crunch.py

The output file 'crunch.html' will contain:
- Each Python file's path as a heading
- The full source code of each file in a <pre> block
- A copyright notice for each file
"""

import os.path

from xmloutput import XMLOutput


def handleFile(o, fullname):
	"""
	Write a single Python file's contents to the XML output.
	
	Args:
		o: XMLOutput instance to write to
		fullname: Full path to the Python file to include
	"""
    with o.scope("p"):
        with o.scope("b"):
            o << fullname
    o.endl()

    with o.scope("pre"):
        o << "# Copyright (c) 2025 rainoftime"
        o.endl()
        o.endl()

        for line in open(fullname):
            o << line.rstrip()
            o.endl()


# Main execution: generate HTML file from all Python files in 'bin' directory
o = open("crunch.html", "w")
o = XMLOutput(o)

# Generate HTML structure with all Python files
with o.scope("html"):
    with o.scope("body"):
        # Walk through the 'bin' directory tree
        for path, dirs, files in os.walk("bin"):
            for f in files:
                # Only process Python files
                if f[-3:] == ".py":
                    fullname = os.path.join(path, f)
                    print(fullname)

                    handleFile(o, fullname)
