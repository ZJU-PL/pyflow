"""
Program representation for PyFlow static analysis.

This module defines the core Program class that represents a Python program
being analyzed by PyFlow's static analysis tools. The Program class serves
as the central data structure that holds all information about a program
throughout the analysis pipeline.

**Program Structure:**
- Interface: Declarations of functions, classes, and entry points
- Store Graph: Object relationship graph (populated during analysis)
- Entry Points: Functions/methods where analysis starts
- Live Code: Set of code elements that are reachable
- Analysis Results: Results from various analyses (e.g., IPA)
"""

from . import interface


class Program(object):
    """
    Represents a Python program for static analysis.
    
    The Program class serves as the central data structure that holds all
    information about a Python program being analyzed. It maintains:
    - Interface declarations (functions, classes, entry points)
    - Analysis results (store graph, IPA results, etc.)
    - Live code tracking
    - Statistics
    
    **Lifecycle:**
    1. Creation: Program is created with empty interface
    2. Configuration: Interface is populated with function/class declarations
    3. Extraction: Program extractor processes interface and creates entry points
    4. Analysis: Various analysis passes populate storeGraph, liveCode, etc.
    5. Results: Analysis results are stored (e.g., ipa_analysis)
    
    Attributes:
        interface: InterfaceDeclaration containing function/class declarations
        storeGraph: Store graph for object relationships (populated during analysis)
        entryPoints: List of program entry points (populated during extraction)
        liveCode: Set of live code elements (functions, classes) reachable from entry points
        stats: Statistics about the program (optional, populated during analysis)
        ipa_analysis: Results from Inter-Procedural Analysis (populated by IPA pass)
    """
    __slots__ = "interface", "storeGraph", "entryPoints", "liveCode", "stats", "ipa_analysis"

    def __init__(self):
        """
        Initialize a new Program instance.

        Creates a new program with:
        - Empty interface (no functions/classes declared yet)
        - No store graph (populated during analysis)
        - Empty entry points list (populated during extraction)
        - Empty live code set (populated during analysis)
        - No statistics
        - No IPA analysis results
        """
        self.interface = interface.InterfaceDeclaration()
        self.storeGraph = None
        self.entryPoints = []
        self.liveCode = set()
        self.stats = None
        self.ipa_analysis = None
