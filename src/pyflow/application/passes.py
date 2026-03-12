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
    storeelimination,
)


class IPAAnalysisPass(AnalysisPass):
    """Inter-procedural Analysis (IPA) pass."""

    def __init__(self):
        super().__init__(
            "ipa", "Inter-procedural analysis for call graphs and contexts"
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

    def __init__(self):
        super().__init__(
            "cpa", "Constraint-based analysis for type and flow constraints"
        )

    def run(self, compiler, program) -> PassResult:
        try:
            # Run CPA with default parameters
            cpa_result = cpa.evaluate(compiler, program)
            program.cpa_analysis = cpa_result
            return PassResult(success=True, changed=False, data=cpa_result)
        except Exception as e:
            return PassResult.from_exception(e)


class LifetimeAnalysisPass(AnalysisPass):
    """Lifetime analysis pass for variable and object lifetimes."""

    def __init__(self):
        super().__init__("lifetime", "Analyzes lifetimes of variables and objects")

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

    def __init__(self):
        super().__init__(
            "simplify", "Constant folding, dead code elimination, and simplification"
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


class StoreEliminationPass(OptimizationPass):
    """Store elimination pass."""

    def __init__(self):
        super().__init__("store_elimination", "Eliminates redundant store operations")

    def run(self, compiler, program) -> PassResult:
        try:
            changed = bool(storeelimination.evaluate(compiler, program))
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
    "store_elimination": StoreEliminationPass,
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

    # Set up dependencies based on the current hardcoded pipeline
    # IPA should run before CPA (CPA needs call graph from IPA).
    # Bug G fix: the original code stored ``ipa_pass = pass_manager.passes["ipa"]``
    # but never used the variable.  The dead assignment was harmless but
    # misleading; removed to keep the code clean.
    cpa_pass = pass_manager.passes["cpa"]
    cpa_pass.info.dependencies.add("ipa")
    lifetime_pass = pass_manager.passes["lifetime"]
    lifetime_pass.info.dependencies.add("cpa")

    # CPA should run before most optimizations (optimizations need type/flow info)
    for opt_name in [
        "methodcall",
        "simplify",
        "clone",
        "argument_normalization",
        "cull_program",
        "store_elimination",
    ]:
        if opt_name in pass_manager.passes:
            opt_pass = pass_manager.passes[opt_name]
            opt_pass.info.dependencies.add("cpa")

    # Simplification should run before many other optimizations
    # (constant folding and DCE enable better optimization)
    simplify_pass = pass_manager.passes["simplify"]
    for opt_name in [
        "clone",
        "argument_normalization",
        "cull_program",
        "store_elimination",
    ]:
        if opt_name in pass_manager.passes:
            opt_pass = pass_manager.passes[opt_name]
            opt_pass.info.dependencies.add("simplify")

    if "store_elimination" in pass_manager.passes:
        pass_manager.passes["store_elimination"].info.dependencies.add("lifetime")

    pass_manager._resolve_dependencies()
