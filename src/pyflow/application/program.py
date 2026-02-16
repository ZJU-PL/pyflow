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
- Class Hierarchy: Cross-module class hierarchy with MRO resolution
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
    - Class hierarchy for cross-module MRO resolution

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
        cpa_analysis: Results from Constraint Propagation Analysis (optional)
        lifetime_analysis: Results from lifetime analysis (optional)
        semantic_queries: Cached semantic query service (optional)
        class_hierarchy: ClassHierarchy for MRO and cross-module resolution
        cross_module_resolver: CrossModuleResolver for resolving across modules
    """

    __slots__ = (
        "interface",
        "storeGraph",
        "entryPoints",
        "liveCode",
        "stats",
        "ipa_analysis",
        "cpa_analysis",
        "lifetime_analysis",
        "semantic_queries",
        "semantic_queries_mode",
        "class_hierarchy",
        "cross_module_resolver",
    )

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
        - No class hierarchy (populated during extraction)
        """
        self.interface = interface.InterfaceDeclaration()
        self.storeGraph = None
        self.entryPoints = []
        self.liveCode = set()
        self.stats = None
        self.ipa_analysis = None
        self.cpa_analysis = None
        self.lifetime_analysis = None
        self.semantic_queries = None
        self.semantic_queries_mode = None
        self.class_hierarchy = None
        self.cross_module_resolver = None

    def get_semantic_queries(self, compiler, server_mode=None):
        """Get or create a semantic query service for this program."""
        from .queries import SemanticQueryService
        from .queries import DEFAULT_MODE

        mode = server_mode or DEFAULT_MODE
        if (
            self.semantic_queries is None
            or self.semantic_queries.compiler is not compiler
            or self.semantic_queries_mode is not mode
        ):
            self.semantic_queries = SemanticQueryService(
                compiler, self, server_mode=mode
            )
            self.semantic_queries_mode = mode
        return self.semantic_queries

    def get_queries(self, compiler, server_mode=None):
        """Alias for get_semantic_queries."""
        return self.get_semantic_queries(compiler, server_mode=server_mode)
