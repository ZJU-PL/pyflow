"""Program representation for PyFlow static analysis."""

from pyflow.api.entrypoints import InterfaceDeclaration


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
    5. Results: transient solver objects are stored in one analysis registry;
       client-facing semantic results are published through ``program.ir``.
    """

    ANALYSIS_KEYS = {
        "ipa": "ipa",
        "ipa_refresh": "ipa",
        "ipa_after_simplify": "ipa",
        "cpa": "cpa",
        "cpa_path_sensitive": "cpa",
        "cpa_after_simplify": "cpa",
        "lifetime": "lifetime",
        "lifetime_refresh": "lifetime",
        "lifetime_after_simplify": "lifetime",
        "heap": "heap",
    }

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
        "analysis_results",
        "ir",
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
        self.interface = InterfaceDeclaration()
        self.storeGraph = None
        self.entryPoints = []
        self.liveCode = set()
        self.stats = None
        self.class_hierarchy = None
        self.cross_module_resolver = None
        self.frontend_telemetry = None
        from pyflow.ir.core import IRCatalog

        self.ir = IRCatalog()
        self.analysis_results = {}

    def set_analysis_result(self, pass_name: str, result) -> None:
        """Record an internal solver result in the canonical registry."""
        key = self.ANALYSIS_KEYS.get(pass_name)
        if key is None:
            raise KeyError(f"Unknown analysis pass '{pass_name}'")
        self.analysis_results[key] = result

    def get_analysis_result(self, analysis_name: str):
        """Return an analysis result from the central registry."""
        key = self.ANALYSIS_KEYS.get(analysis_name, analysis_name)
        return self.analysis_results.get(key)

    def clear_analysis_result(self, pass_name: str) -> None:
        """Clear one analysis result and dependent semantic-query caches."""
        key = self.ANALYSIS_KEYS.get(pass_name)
        if key is None:
            return
        self.analysis_results.pop(key, None)

    def clear_analysis_results(self, pass_names) -> None:
        """Clear multiple analysis results addressed by pass names."""
        for pass_name in pass_names:
            self.clear_analysis_result(pass_name)
