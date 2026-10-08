"""Program representation for PyFlow static analysis."""

from pyflow.model.entrypoints import InterfaceDeclaration


class Program(object):
    """
    Represents a Python program for static analysis.

    The Program class serves as the central data structure that holds all
    information about a Python program being analyzed. It maintains:
    - Interface declarations (functions, classes, entry points)
    - Extracted heap/store graph and the associated analysis session
    - Live code tracking
    - Statistics
    - Class hierarchy for cross-module MRO resolution

    **Lifecycle:**
    1. Creation: Program is created with empty interface
    2. Configuration: Interface is populated with function/class declarations
    3. Extraction: Program extractor processes interface and creates entry points
    4. Analysis: Various analysis passes populate storeGraph, liveCode, etc.
    5. Results: transient solver objects are owned by ``program.session``;
       client-facing semantic results are published through ``program.ir``.
    """

    __slots__ = (
        "__weakref__",
        "interface",
        "storeGraph",
        "entryPoints",
        "liveCode",
        "stats",
        "class_hierarchy",
        "cross_module_resolver",
        "frontend_telemetry",
        "frontend_diagnostics",
        "session",
        "ir",
    )

    def __init__(self, *, options=None):
        """
        Initialize a new Program instance.

        Creates a new program with:
        - Empty interface (no functions/classes declared yet)
        - No store graph (populated during analysis)
        - Empty entry points list (populated during extraction)
        - Empty live code set (populated during analysis)
        - No statistics
        - A fresh session with explicit options and an empty result registry
        - No class hierarchy (populated during extraction)
        """
        self.interface = InterfaceDeclaration()
        self.storeGraph = None
        self.entryPoints = []
        self.liveCode = set()
        self.stats = None
        self.class_hierarchy = None
        self.cross_module_resolver = None
        self.frontend_telemetry = None
        self.frontend_diagnostics = ()
        from pyflow.ir.core import IRCatalog

        self.ir = IRCatalog()
        from .session import AnalysisSession

        self.session = AnalysisSession(self, options=options)
