"""Program representation for PyFlow static analysis.

This module defines the core Program class that represents a Python program
being analyzed by PyFlow's static analysis tools.
"""

from . import interface


class Program(object):
    """Represents a Python program for static analysis.
    
    The Program class serves as the central data structure that holds all
    information about a Python program being analyzed, including its interface
    declarations, entry points, and live code.
    
    Attributes:
        interface: InterfaceDeclaration object containing function/class declarations.
        storeGraph: Store graph for object relationships (optional).
        entryPoints: List of program entry points.
        liveCode: Set of live code elements (functions, classes).
        stats: Statistics about the program (optional).
    """
    __slots__ = "interface", "storeGraph", "entryPoints", "liveCode", "stats", "ipa_analysis"

    def __init__(self):
        """Initialize a new Program instance.

        Creates a new program with empty interface, no store graph, empty entry
        points list, empty live code set, no statistics, and no IPA analysis results.
        """
        self.interface = interface.InterfaceDeclaration()
        self.storeGraph = None
        self.entryPoints = []
        self.liveCode = set()
        self.stats = None
        self.ipa_analysis = None
