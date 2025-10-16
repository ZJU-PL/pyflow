"""
Core call graph data structure and operations.

This module provides the fundamental CallGraph class for representing
function call relationships in Python code.
"""


class CallGraph(object):
    """Core call graph data structure."""
    
    def __init__(self):
        self.cg = {}  # call graph: {caller -> {callees}}
        self.modnames = {}  # module names: {function -> module}

    def add_node(self, name, modname=""):
        """Add a function node to the call graph."""
        if not isinstance(name, str):
            raise CallGraphError("Only string node names allowed")
        if not name:
            raise CallGraphError("Empty node name")

        if name not in self.cg:
            self.cg[name] = set()
            self.modnames[name] = modname

        if name in self.cg and not self.modnames[name]:
            self.modnames[name] = modname

    def add_edge(self, src, dest):
        """Add a call relationship from src to dest."""
        self.add_node(src)
        self.add_node(dest)
        self.cg[src].add(dest)

    def get(self):
        """Get the call graph as a dictionary."""
        return self.cg

    def get_edges(self):
        """Get all edges as a list of [src, dest] pairs."""
        output = []
        for src in self.cg:
            for dst in self.cg[src]:
                output.append([src, dst])
        return output

    def get_modules(self):
        """Get module names for all functions."""
        return self.modnames


class CallGraphError(Exception):
    """Exception raised for call graph related errors."""
    pass