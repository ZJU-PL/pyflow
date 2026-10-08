"""Builtin analysis and transformation passes."""

from .base import AnalysisPass, OptimizationPass, PassResult, UtilityPass
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
            program.session.record_result(self.name, result)
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
                self.op_path_length if self.first_pass else program.session.options.cpa_path_length,
                firstPass=self.first_pass,
            )
            program.session.record_result(self.name, cpa_result)
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
            program.session.record_result(self.name, result)
            return PassResult(success=True, changed=False, data=result)
        except Exception as e:
            return PassResult.from_exception(e)


class HeapAnalysisPass(AnalysisPass):
    """Heap alias, escape, and points-to analysis pass.

    Extracts a :class:`PointsToGraph` from the heap abstraction that
    optimization passes (load/store elimination, method devirtualization)
    can consume for alias and escape queries.
    """

    def __init__(self, name: str = "heap", description: str | None = None):
        super().__init__(
            name,
            description or "Heap alias, escape, and points-to analysis",
        )

    def run(self, compiler, program) -> PassResult:
        try:
            from pyflow.analysis.alias.flow_sensitive import HeapAnalysis

            analysis = HeapAnalysis()
            graph = analysis.analyze(compiler, program)
            program.session.record_result(self.name, graph)
            return PassResult(success=True, changed=False, data=graph)
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
            description or "Constant folding, dead code elimination, and simplification",
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
            "Specializes eligible *args when callers are already positionally compatible",
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

    def __init__(self, name: str = "store_elimination", description: str | None = None):
        super().__init__(name, description or "Eliminates redundant store operations")

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


class DependencyAnchorPass(UtilityPass):
    """No-op utility pass used to encode higher-level pipeline stages."""

    def __init__(self, name: str, description: str):
        super().__init__(name, description)

    def run(self, compiler, program) -> PassResult:
        return PassResult(success=True, changed=False)


class StatisticsPass(UtilityPass):
    """Report statistics while the initial CPA facts are still valid."""

    def __init__(self):
        super().__init__("stats", "Report context statistics before transformations")
        self.info.dependencies.add("cpa")

    def run(self, compiler, program) -> PassResult:
        from pyflow.stats import contextStats

        return PassResult(data=contextStats(compiler, program, "analysis", classOK=True))
