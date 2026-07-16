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
    5. Results: Analysis results are stored (e.g., ipa_analysis)

    Analysis outputs are kept in a small central registry so pass-manager based
    invalidation has a single place to clear and refresh them. The legacy
    attributes (`ipa_analysis`, `cpa_analysis`, `lifetime_analysis`) remain as
    compatibility mirrors for existing analysis code.
    """

    ANALYSIS_ATTRS = {
        "ipa": "ipa_analysis",
        "ipa_refresh": "ipa_analysis",
        "cpa": "cpa_analysis",
        "cpa_path_sensitive": "cpa_analysis",
        "lifetime": "lifetime_analysis",
        "lifetime_refresh": "lifetime_analysis",
        "heap": "heap_analysis",
    }

    __slots__ = (
        "__weakref__",
        "interface",
        "storeGraph",
        "entryPoints",
        "liveCode",
        "stats",
        "ipa_analysis",
        "cpa_analysis",
        "lifetime_analysis",
        "heap_analysis",
        "semantic_queries",
        "semantic_queries_mode",
        "class_hierarchy",
        "cross_module_resolver",
        "frontend_telemetry",
        "analysis_results",
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
        self.ipa_analysis = None
        self.cpa_analysis = None
        self.lifetime_analysis = None
        self.heap_analysis = None
        self.semantic_queries = None
        self.semantic_queries_mode = None
        self.class_hierarchy = None
        self.cross_module_resolver = None
        self.frontend_telemetry = None
        self.analysis_results = {
            "ipa_analysis": None,
            "cpa_analysis": None,
            "lifetime_analysis": None,
            "heap_analysis": None,
        }

    def set_analysis_result(self, pass_name: str, result) -> None:
        """Record an analysis result in the canonical registry and legacy slot."""
        attr = self.ANALYSIS_ATTRS.get(pass_name)
        if attr is None:
            raise KeyError(f"Unknown analysis pass '{pass_name}'")
        setattr(self, attr, result)
        self.analysis_results[attr] = result
        self.invalidate_semantic_queries()

    def get_analysis_result(self, analysis_name: str):
        """Return an analysis result from the central registry."""
        if analysis_name not in self.analysis_results:
            raise KeyError(f"Unknown analysis result '{analysis_name}'")
        return self.analysis_results[analysis_name]

    def clear_analysis_result(self, pass_name: str) -> None:
        """Clear one analysis result and dependent semantic-query caches."""
        attr = self.ANALYSIS_ATTRS.get(pass_name)
        if attr is None:
            return
        if getattr(self, attr, None) is not None:
            setattr(self, attr, None)
            self.analysis_results[attr] = None
            self.invalidate_semantic_queries()

    def clear_analysis_results(self, pass_names) -> None:
        """Clear multiple analysis results addressed by pass names."""
        for pass_name in pass_names:
            self.clear_analysis_result(pass_name)

    def invalidate_semantic_queries(self) -> None:
        """Drop cached semantic-query facades after analysis changes."""
        self.semantic_queries = None
        self.semantic_queries_mode = None

    def get_semantic_queries(self, compiler, server_mode=None):
        """Get or create a semantic query service for this program."""
        from pyflow.api.queries import SemanticQueryService, DEFAULT_MODE

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
