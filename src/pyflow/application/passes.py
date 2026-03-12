"""
Standard pass implementations for PyFlow analysis and optimization.

This module provides wrapper passes for the existing PyFlow analysis and
optimization modules, allowing them to work with the new pass manager system.
Each pass wraps an existing analysis or optimization function and provides
a standardized interface for the pass manager.

**Analysis Passes:**
- IPA: Inter-procedural analysis for call graphs and contexts
- CPA: Constraint-based analysis for type and flow constraints
- Lifetime: Analyzes lifetimes of variables and objects

**Optimization Passes:**
- Method Call: Optimizes method calls and dispatch
- Simplify: Constant folding, dead code elimination, simplification
- Clone: Code cloning to separate different invocations
- Argument Normalization: Normalizes function arguments, eliminates *args, **kwargs
- Program Culling: Removes dead functions and contexts
- Store Elimination: Eliminates redundant store operations

**Pass Dependencies:**
The register_standard_passes() function sets up dependencies:
- CPA depends on IPA
- Most optimizations depend on CPA
- Many optimizations depend on Simplify
"""

from .passmanager import AnalysisPass, OptimizationPass, PassResult
from pyflow.analysis import ipa, cpa, lifetimeanalysis
from pyflow.optimization import (
    methodcall,
    simplify,
    clone,
    argumentnormalization,
    cullprogram,
    codeinlining,
    loadelimination,
    storeelimination,
    dce,
)


class IPAAnalysisPass(AnalysisPass):
    """Inter-procedural Analysis (IPA) pass."""

    def __init__(self, name: str = "ipa", description: str | None = None):
        super().__init__(
            name,
            description or "Inter-procedural analysis for call graphs and contexts",
        )

    def run(self, compiler, program) -> PassResult:
        try:
            result = ipa.evaluate(compiler, program)
            program.ipa_analysis = result
            return PassResult(success=True, changed=False, data=result)
        except Exception as e:
            return PassResult.from_exception(e)


class CPAAnalysisPass(AnalysisPass):
    """Constraint Propagation Analysis (CPA) pass."""

    def __init__(
        self,
        name: str = "cpa",
        *,
        op_path_length: int = 0,
        first_pass: bool = True,
        description: str | None = None,
    ):
        super().__init__(
            name,
            description or "Constraint-based analysis for type and flow constraints",
        )
        self.op_path_length = op_path_length
        self.first_pass = first_pass

    def run(self, compiler, program) -> PassResult:
        try:
            cpa_result = cpa.evaluate(
                compiler,
                program,
                self.op_path_length,
                firstPass=self.first_pass,
            )
            program.cpa_analysis = cpa_result
            return PassResult(success=True, changed=False, data=cpa_result)
        except Exception as e:
            return PassResult.from_exception(e)


class LifetimeAnalysisPass(AnalysisPass):
    """Lifetime analysis pass for variable and object lifetimes."""

    def __init__(self, name: str = "lifetime", description: str | None = None):
        super().__init__(
            name,
            description or "Analyzes lifetimes of variables and objects",
        )

    def run(self, compiler, program) -> PassResult:
        try:
            result = lifetimeanalysis.evaluate(compiler, program)
            program.lifetime_analysis = result
            return PassResult(success=True, changed=False, data=result)
        except Exception as e:
            return PassResult.from_exception(e)


class MethodCallOptimizationPass(OptimizationPass):
    """Method call optimization pass."""

    def __init__(self):
        super().__init__("methodcall", "Optimizes method calls and dispatch")

    def run(self, compiler, program) -> PassResult:
        try:
            changed = bool(methodcall.evaluate(compiler, program))
            return PassResult(success=True, changed=changed)
        except Exception as e:
            return PassResult.from_exception(e)


class SimplifyOptimizationPass(OptimizationPass):
    """Simplification pass for constant folding and DCE."""

    def __init__(self, name: str = "simplify", description: str | None = None):
        super().__init__(
            name,
            description
            or "Constant folding, dead code elimination, and simplification",
        )

    def run(self, compiler, program) -> PassResult:
        try:
            changed = bool(simplify.evaluate(compiler, program))
            return PassResult(success=True, changed=changed)
        except Exception as e:
            return PassResult.from_exception(e)


class CloneOptimizationPass(OptimizationPass):
    """Code cloning pass for separating different invocations."""

    def __init__(self):
        super().__init__("clone", "Separates different invocations of the same code")

    def run(self, compiler, program) -> PassResult:
        try:
            changed = bool(clone.evaluate(compiler, program))
            return PassResult(success=True, changed=changed)
        except Exception as e:
            return PassResult.from_exception(e)


class ArgumentNormalizationPass(OptimizationPass):
    """Argument normalization pass."""

    def __init__(self):
        super().__init__(
            "argument_normalization",
            "Normalizes function arguments, eliminates *args, **kwargs",
        )

    def run(self, compiler, program) -> PassResult:
        try:
            changed = bool(argumentnormalization.evaluate(compiler, program))
            return PassResult(success=True, changed=changed)
        except Exception as e:
            return PassResult.from_exception(e)


class ProgramCullingPass(OptimizationPass):
    """Program culling pass to remove dead functions/contexts."""

    def __init__(self):
        super().__init__("cull_program", "Removes dead functions and contexts")

    def run(self, compiler, program) -> PassResult:
        try:
            changed = bool(cullprogram.evaluate(compiler, program))
            return PassResult(success=True, changed=changed)
        except Exception as e:
            return PassResult.from_exception(e)


class InliningPass(OptimizationPass):
    """Experimental code inlining pass."""

    def __init__(self):
        super().__init__("inlining", "Experimentally inline eligible function calls")

    def run(self, compiler, program) -> PassResult:
        try:
            changed = bool(codeinlining.evaluate(compiler, program))
            return PassResult(success=True, changed=changed)
        except Exception as e:
            return PassResult.from_exception(e)


class StoreEliminationPass(OptimizationPass):
    """Store elimination pass."""

    def __init__(
        self, name: str = "store_elimination", description: str | None = None
    ):
        super().__init__(
            name, description or "Eliminates redundant store operations"
        )

    def run(self, compiler, program) -> PassResult:
        try:
            changed = bool(storeelimination.evaluate(compiler, program))
            return PassResult(success=True, changed=changed)
        except Exception as e:
            return PassResult.from_exception(e)


class LoadEliminationPass(OptimizationPass):
    """Load elimination pass."""

    def __init__(self):
        super().__init__("load_elimination", "Eliminates redundant load operations")

    def run(self, compiler, program) -> PassResult:
        try:
            changed = bool(loadelimination.evaluate(compiler, program))
            return PassResult(success=True, changed=changed)
        except Exception as e:
            return PassResult.from_exception(e)


class DeadCodeEliminationPass(OptimizationPass):
    """Standalone DCE pass."""

    def __init__(self):
        super().__init__("dce", "Eliminates dead code without constant folding")

    def run(self, compiler, program) -> PassResult:
        try:
            changed = bool(dce.evaluate(compiler, program))
            return PassResult(success=True, changed=changed)
        except Exception as e:
            return PassResult.from_exception(e)


# Registry of standard passes
STANDARD_PASSES = {
    "ipa": IPAAnalysisPass,
    "cpa": CPAAnalysisPass,
    "lifetime": LifetimeAnalysisPass,
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

    analysis_passes = {
        "ipa",
        "cpa",
        "lifetime",
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
    for opt_name in optimization_passes:
        if opt_name in pass_manager.passes:
            opt_pass = pass_manager.passes[opt_name]
            opt_pass.info.dependencies.add("cpa")
            opt_pass.info.invalidates.update(analysis_passes)

    # Simplification should run before many other optimizations
    # (constant folding and DCE enable better optimization)
    simplify_pass = pass_manager.passes["simplify"]
    for opt_name in [
        "clone",
        "argument_normalization",
        "cull_program",
        "inlining",
        "load_elimination",
        "store_elimination",
        "dce",
    ]:
        if opt_name in pass_manager.passes:
            opt_pass = pass_manager.passes[opt_name]
            opt_pass.info.dependencies.add("simplify")

    if "store_elimination" in pass_manager.passes:
        pass_manager.passes["store_elimination"].info.dependencies.add("lifetime")
    if "load_elimination" in pass_manager.passes:
        pass_manager.passes["load_elimination"].info.dependencies.add("lifetime")

    pass_manager.passes["cpa_path_sensitive"].info.dependencies.add("ipa_refresh")
    pass_manager.passes["lifetime_refresh"].info.dependencies.add("cpa_path_sensitive")
    pass_manager.passes["simplify_final"].info.dependencies.update(
        {"cpa_path_sensitive", "lifetime_refresh"}
    )
    pass_manager.passes["store_elimination_final"].info.dependencies.update(
        {"simplify_final", "lifetime_refresh"}
    )
    pass_manager.passes["simplify_final"].info.invalidates.update(analysis_passes)
    pass_manager.passes["store_elimination_final"].info.invalidates.update(
        analysis_passes
    )

    pass_manager._resolve_dependencies()
