"""Explicit registration and prerequisites for builtin passes."""

from .builtin import (
    StatisticsPass,
    IPAAnalysisPass,
    CPAAnalysisPass,
    LifetimeAnalysisPass,
    HeapAnalysisPass,
    MethodCallOptimizationPass,
    SimplifyOptimizationPass,
    CloneOptimizationPass,
    ArgumentNormalizationPass,
    ProgramCullingPass,
    InliningPass,
    StoreEliminationPass,
    LoadEliminationPass,
    DeadCodeEliminationPass,
    DependencyAnchorPass,
)

# Registry of standard passes
STANDARD_PASSES = {
    "stats": StatisticsPass,
    "ipa": IPAAnalysisPass,
    "cpa": CPAAnalysisPass,
    "lifetime": LifetimeAnalysisPass,
    "heap": HeapAnalysisPass,
    "methodcall": MethodCallOptimizationPass,
    "simplify": SimplifyOptimizationPass,
    "clone": CloneOptimizationPass,
    "argument_normalization": ArgumentNormalizationPass,
    "cull_program": ProgramCullingPass,
    "inlining": InliningPass,
    "load_elimination": LoadEliminationPass,
    "store_elimination": StoreEliminationPass,
    "dce": DeadCodeEliminationPass,
    "ipa_refresh": lambda: IPAAnalysisPass(
        "ipa_refresh", "Recompute IPA after whole-program transformations"
    ),
    "ipa_after_simplify": lambda: IPAAnalysisPass(
        "ipa_after_simplify", "Recompute IPA after simplification"
    ),
    "cpa_after_simplify": lambda: CPAAnalysisPass(
        "cpa_after_simplify",
        description="Recompute CPA after simplification",
    ),
    "lifetime_after_simplify": lambda: LifetimeAnalysisPass(
        "lifetime_after_simplify", "Recompute lifetime facts after simplification"
    ),
    "cpa_path_sensitive": lambda: CPAAnalysisPass(
        "cpa_path_sensitive",
        op_path_length=3,
        first_pass=False,
        description="Path-sensitive CPA rerun after first-pass optimizations",
    ),
    "lifetime_refresh": lambda: LifetimeAnalysisPass(
        "lifetime_refresh", "Recompute lifetime analysis after path-sensitive CPA"
    ),
    "simplify_final": lambda: SimplifyOptimizationPass(
        "simplify_final",
        "Final simplification after path-sensitive CPA",
    ),
    "store_elimination_final": lambda: StoreEliminationPass(
        "store_elimination_final",
        "Final dead-store elimination after path-sensitive CPA",
    ),
    "first_pass_methodcall": lambda: DependencyAnchorPass(
        "first_pass_methodcall",
        "Dependency anchor for the method-call stage of the first optimization pass",
    ),
    "first_pass_lifetime": lambda: DependencyAnchorPass(
        "first_pass_lifetime",
        "Dependency anchor for the lifetime stage of the first optimization pass",
    ),
    "first_pass_simplify": lambda: DependencyAnchorPass(
        "first_pass_simplify",
        "Dependency anchor for the simplify stage of the first optimization pass",
    ),
    "first_pass_clone": lambda: DependencyAnchorPass(
        "first_pass_clone",
        "Dependency anchor for the clone stage of the first optimization pass",
    ),
    "first_pass_argument_normalization": lambda: DependencyAnchorPass(
        "first_pass_argument_normalization",
        "Dependency anchor for the argument normalization stage of the first optimization pass",
    ),
    "first_pass_cull_program": lambda: DependencyAnchorPass(
        "first_pass_cull_program",
        "Dependency anchor for the cull-program stage of the first optimization pass",
    ),
    "first_pass_store_elimination": lambda: DependencyAnchorPass(
        "first_pass_store_elimination",
        "Dependency anchor for the store-elimination stage of the first optimization pass",
    ),
    "first_pass_complete": lambda: DependencyAnchorPass(
        "first_pass_complete",
        "Dependency anchor representing completion of the whole first optimization pass",
    ),
}

PASS_ALIASES = {
    "argumentnormalization": "argument_normalization",
    "cullprogram": "cull_program",
    "loadelimination": "load_elimination",
    "storeelimination": "store_elimination",
}


def register_standard_passes(pass_manager):
    """
    Register all standard PyFlow passes with the pass manager.

    This function:
    1. Registers all standard passes from STANDARD_PASSES
    2. Sets up dependency relationships between passes

    **Dependency Graph:**
    ```
    IPA
     └─> CPA
          └─> [Method Call, Simplify, Clone, Argument Normalization, Program Culling]
               └─> Simplify
                    └─> [Clone, Argument Normalization, Program Culling]
    ```

    **Dependency Rules:**
    - CPA depends on IPA (needs call graph)
    - Most optimizations depend on CPA (need type/flow information)
    - Many optimizations depend on Simplify (benefit from constant folding/DCE)

    Args:
        pass_manager: PassManager instance to register passes with
    """
    for pass_name, pass_class in STANDARD_PASSES.items():
        pass_manager.register_pass(pass_class())
    for alias, target in PASS_ALIASES.items():
        pass_manager.register_alias(alias, target)

    # Set up dependencies based on the current hardcoded pipeline
    # IPA should run before CPA (CPA needs call graph from IPA).
    # Bug G fix: the original code stored ``ipa_pass = pass_manager.passes["ipa"]``
    # but never used the variable.  The dead assignment was harmless but
    # misleading; removed to keep the code clean.
    cpa_pass = pass_manager.passes["cpa"]
    cpa_pass.info.dependencies.add("ipa")
    lifetime_pass = pass_manager.passes["lifetime"]
    lifetime_pass.info.dependencies.add("cpa")
    heap_pass = pass_manager.passes["heap"]
    heap_pass.info.dependencies.add("cpa")
    heap_pass.info.requirements.add("cpa")

    analysis_passes = {
        "ipa",
        "cpa",
        "lifetime",
        "heap",
        "ipa_refresh",
        "cpa_path_sensitive",
        "lifetime_refresh",
    }

    # CPA should run before most optimizations (optimizations need type/flow info)
    optimization_passes = [
        "methodcall",
        "simplify",
        "clone",
        "argument_normalization",
        "cull_program",
        "inlining",
        "load_elimination",
        "store_elimination",
        "dce",
    ]
    # CRITICAL FIX #2: All optimization passes must declare invalidation metadata
    # Without explicit invalidates/preserves, passes rely on conservative fallback
    # that clears all caches. This ensures correctness but is inefficient.
    # Each optimization pass now explicitly declares what it invalidates.
    for opt_name in optimization_passes:
        if opt_name in pass_manager.passes:
            opt_pass = pass_manager.passes[opt_name]
            opt_pass.info.dependencies.add("cpa")
            # All transforming passes invalidate all analysis passes by default
            # Individual passes can override by setting preserves
            opt_pass.info.invalidates.update(analysis_passes)

    # Simplification should run before many other optimizations
    # (constant folding and DCE enable better optimization)
    for opt_name in [
        "clone",
        "argument_normalization",
        "cull_program",
        "inlining",
        "load_elimination",
        "store_elimination",
    ]:
        if opt_name in pass_manager.passes:
            opt_pass = pass_manager.passes[opt_name]
            opt_pass.info.dependencies.add("simplify")

    if "clone" in pass_manager.passes:
        pass_manager.passes["clone"].info.dependencies.add("lifetime_after_simplify")
        pass_manager.passes["clone"].info.requirements.add("lifetime_after_simplify")

    pass_manager.passes["ipa_after_simplify"].info.dependencies.add("simplify")
    pass_manager.passes["cpa_after_simplify"].info.dependencies.add("ipa_after_simplify")
    pass_manager.passes["lifetime_after_simplify"].info.dependencies.add("cpa_after_simplify")

    if "inlining" in pass_manager.passes:
        # Argument normalization must precede inlining.
        pass_manager.passes["inlining"].info.dependencies.add("argument_normalization")

    # Store/load elimination consume revision-tagged lifetime facts.  Keep the
    # dependency explicit so transformations cannot observe stale snapshots.
    if "store_elimination" in pass_manager.passes:
        pass_manager.passes["store_elimination"].info.dependencies.add("lifetime")
        pass_manager.passes["store_elimination"].info.requirements.add("lifetime")
    if "load_elimination" in pass_manager.passes:
        pass_manager.passes["load_elimination"].info.dependencies.add("lifetime")
        pass_manager.passes["load_elimination"].info.requirements.add("lifetime")

    pass_manager.passes["first_pass_methodcall"].info.dependencies.add("methodcall")
    pass_manager.passes["first_pass_lifetime"].info.dependencies.update(
        {"first_pass_methodcall", "lifetime"}
    )
    pass_manager.passes["first_pass_simplify"].info.dependencies.update(
        {"first_pass_lifetime", "simplify"}
    )
    pass_manager.passes["first_pass_clone"].info.dependencies.update(
        {"first_pass_simplify", "clone"}
    )
    pass_manager.passes["first_pass_argument_normalization"].info.dependencies.update(
        {"first_pass_clone", "argument_normalization"}
    )
    pass_manager.passes["first_pass_cull_program"].info.dependencies.update(
        {"first_pass_argument_normalization", "cull_program"}
    )
    pass_manager.passes["first_pass_store_elimination"].info.dependencies.update(
        {"first_pass_cull_program", "store_elimination"}
    )
    # Store elimination remains available explicitly, but must not be forced
    # after whole-program rewrites that invalidate its lifetime facts.
    pass_manager.passes["first_pass_complete"].info.dependencies.add("cull_program")

    pass_manager.passes["cpa_path_sensitive"].info.dependencies.update(
        {"ipa_refresh", "first_pass_complete"}
    )
    pass_manager.passes["lifetime_refresh"].info.dependencies.add("cpa_path_sensitive")
    pass_manager.passes["simplify_final"].info.dependencies.update(
        {"cpa_path_sensitive", "lifetime_refresh"}
    )
    pass_manager.passes["store_elimination_final"].info.dependencies.update(
        {"simplify_final", "lifetime_refresh"}
    )
    pass_manager.passes["simplify_final"].info.invalidates.update(analysis_passes)
    pass_manager.passes["store_elimination_final"].info.invalidates.update(analysis_passes)

    pass_manager._resolve_dependencies()

    # CRITICAL FIX #2: Validate that all optimization passes have invalidation metadata
    # This must be called AFTER all metadata is configured
    pass_manager.validate_optimization_metadata()
