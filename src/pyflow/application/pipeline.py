"""Analysis pipeline for PyFlow static analysis.

The pass-manager path is the canonical execution model. A legacy compatibility
entrypoint is still kept for older callers that invoke ``evaluate(...)``
directly, but all new orchestration should flow through ``Pipeline`` with the
pass manager enabled.
"""

import time
import pyflow.util as util

# Import analysis modules (for legacy compatibility)
from pyflow.analysis import ipa
from pyflow.analysis import cpa
from pyflow.analysis import lifetimeanalysis
from pyflow.analysis.dump import dumpreport
from pyflow.analysis import programculler

# Import optimization modules (for legacy compatibility)
from pyflow.optimization import methodcall
from pyflow.optimization import cullprogram
from pyflow.optimization import simplify
from pyflow.optimization import clone
from pyflow.optimization import argumentnormalization
from pyflow.optimization import codeinlining
from pyflow.optimization import loadelimination
from pyflow.optimization import storeelimination
from pyflow.optimization import dce

# Import stats module
from .. import stats
from .. import config
import threading

from . import errors
from .passmanager import PassManager, PassPipeline
from .passes import register_standard_passes


class Pipeline(object):
    """Main analysis pipeline for PyFlow static analysis."""

    def __init__(self, use_pass_manager: bool = True):
        """Initialize the analysis pipeline.

        ``use_pass_manager=False`` remains for compatibility only.
        """
        self.use_pass_manager = use_pass_manager
        self.pass_manager = None

        if use_pass_manager:
            self.pass_manager = PassManager()
            register_standard_passes(self.pass_manager)

    def default_pass_names(
        self, *, include_experimental_inlining: bool = False
    ) -> list[str]:
        """Return the default pass-manager pipeline in execution order."""
        passes = [
            "ipa",
            "cpa",
            "methodcall",
            "simplify",
            "ipa_after_simplify",
            "cpa_after_simplify",
            "lifetime_after_simplify",
            "clone",
            "argument_normalization",
        ]
        if include_experimental_inlining:
            passes.append("inlining")
        passes.extend(
            [
                "cull_program",
                "ipa_refresh",
                "cpa_path_sensitive",
                "lifetime_refresh",
                "simplify_final",
            ]
        )
        return passes

    def run(
        self,
        program,
        compiler=None,
        name: str = "main",
        *,
        include_experimental_inlining: bool = False,
    ):
        """Run the analysis pipeline on a program.

        Args:
            program: Program object to analyze.
            compiler: Compiler instance (required for pass manager).
            name: Name for the analysis run (for logging/debugging).

        Returns:
            Dict of pass results if using pass manager, None otherwise.
        """
        if not self.use_pass_manager:
            return self._run_legacy_pipeline(compiler, program, name)
        if compiler is None:
            raise ValueError("Compiler instance required when using pass manager")
        return self._run_with_pass_manager(
            compiler,
            program,
            name,
            include_experimental_inlining=include_experimental_inlining,
        )

    def _run_with_pass_manager(
        self,
        compiler,
        program,
        name: str,
        *,
        include_experimental_inlining: bool = False,
    ):
        """
        Run pipeline using the pass manager system.

        Builds a comprehensive pipeline with standard passes in dependency order:
        1. IPA (Inter-procedural analysis) - builds call graph
        2. CPA (Constraint propagation analysis) - type and flow analysis
        3. Method call optimization - optimizes method dispatch
        4. Simplification - constant folding and dead code elimination
        5. Lifetime analysis - refreshed before lifetime-sensitive transforms
        6. Code cloning - separates different invocations
        7. Argument normalization - eliminates *args, **kwargs
        8. Program culling - removes dead functions/contexts
        9. Lifetime analysis refresh - recomputes read/modify facts
        10. Store elimination - removes redundant stores

        Args:
            compiler: Compiler context
            program: Program to analyze
            name: Name for logging

        Returns:
            Dictionary mapping pass names to PassResult objects

        Raises:
            RuntimeError: If pass manager not initialized
        """
        if not self.pass_manager:
            raise RuntimeError("Pass manager not initialized")

        # Build a comprehensive pipeline with standard passes
        pipeline = self.pass_manager.build_pipeline(
            self.default_pass_names(
                include_experimental_inlining=include_experimental_inlining
            )
        )

        # Run the pipeline
        results = self.pass_manager.run_pipeline(compiler, program, pipeline)

        failed = [pass_name for pass_name, result in results.items() if not result.success]
        if failed:
            first_failed = failed[0]
            error = results[first_failed].error or "unknown pass failure"
            raise RuntimeError(f"Pass pipeline aborted at '{first_failed}': {error}")

        # Log execution summary
        # Bug F fix: the original code used print() directly, bypassing the
        # compiler's console abstraction.  Use compiler.console.output() so
        # that the message respects verbosity settings and is captured by tests.
        successful = sum(1 for r in results.values() if r.success)
        total_time = sum(r.time for r in results.values() if hasattr(r, "time"))

        compiler.console.output(
            f"Pass Manager: {successful}/{len(results)} passes successful in {total_time:.3f}s"
        )

        return results

    def _run_legacy_pipeline(self, compiler, program, name: str):
        """Run the retained legacy compatibility pipeline."""
        return evaluate(compiler, program, name)

    # Convenience methods for pass manager operations
    def get_pass_manager(self) -> PassManager:
        """Get the pass manager instance."""
        if not self.use_pass_manager or not self.pass_manager:
            raise RuntimeError("Pass manager not enabled")
        return self.pass_manager

    def register_pass(self, pass_instance):
        """Register a custom pass with the pass manager."""
        if not self.use_pass_manager:
            raise RuntimeError("Pass manager not enabled")
        self.pass_manager.register_pass(pass_instance)

    def build_custom_pipeline(self, pass_names: list) -> PassPipeline:
        """Build a custom pipeline from pass names."""
        if not self.use_pass_manager:
            raise RuntimeError("Pass manager not enabled")
        return self.pass_manager.build_pipeline(pass_names)

    def run_custom_pipeline(self, compiler, program, pass_names: list):
        """Run a custom set of passes."""
        if not self.use_pass_manager:
            raise RuntimeError("Pass manager not enabled")
        pipeline = self.pass_manager.build_pipeline(pass_names)
        results = self.pass_manager.run_pipeline(compiler, program, pipeline)
        failed = [pass_name for pass_name, result in results.items() if not result.success]
        if failed:
            first_failed = failed[0]
            error = results[first_failed].error or "unknown pass failure"
            raise RuntimeError(f"Pass pipeline aborted at '{first_failed}': {error}")
        return results

    def list_available_passes(self) -> list:
        """List all available passes."""
        if not self.use_pass_manager:
            return []
        return self.pass_manager.list_passes()

    def get_pass_info(self, pass_name: str):
        """Get metadata for a specific pass."""
        if not self.use_pass_manager:
            return None
        return self.pass_manager.get_pass_info(pass_name)

    def clear_cache(self):
        """Clear the pass manager cache."""
        if self.use_pass_manager and self.pass_manager:
            self.pass_manager.clear_cache()


def codeConditioning(compiler, prgm, firstPass, dumpStats=False):
    """
    Code conditioning phase of the legacy pipeline.

    This function runs optimization passes to improve code quality and
    eliminate dead code. It's called after the main analysis passes (IPA/CPA).

    **Optimization Sequence:**
    1. Method call optimization (first pass only)
    2. Lifetime analysis
    3. Simplification (constant folding, DCE)
    4. Code cloning (first pass only)
    5. Argument normalization (first pass only)
    6. Program culling (first pass only)
    7. Store elimination

    **Note:** Some optimizations are conditionally enabled/disabled:
    - Load elimination: Currently disabled
    - Code inlining: Temporarily disabled
    - Brute force simplification: Disabled (requires path sensitivity)

    Args:
        compiler: Compiler context
        prgm: Program to optimize
        firstPass: Whether this is the first pass (some optimizations only run once)
        dumpStats: Whether to dump statistics after optimization
    """
    with compiler.console.scope("conditioning"):
        if firstPass:
            # Try to identify and optimize method calls
            methodcall.evaluate(compiler, prgm)

        prgm.set_analysis_result(
            "lifetime" if firstPass else "lifetime_refresh",
            lifetimeanalysis.evaluate(compiler, prgm),
        )

        if True:
            # Fold, DCE, etc.
            simplify.evaluate(compiler, prgm)

        if firstPass and dumpStats:
            stats.contextStats(compiler, prgm, "optimized", classOK=True)

        if firstPass:
            # Separate different invocations of the same code.
            clone.evaluate(compiler, prgm)

        if firstPass and dumpStats:
            stats.contextStats(compiler, prgm, "clone", classOK=True)

        if firstPass:
            # Try to eliminate kwds, vargs, kargs, and default arguments.
            # Done before inlining, as the current implementation of inlining
            # Cannot deal with complex calling conventions.
            argumentnormalization.evaluate(compiler, prgm)

        if firstPass:
            # Try to eliminate trivial functions.
            # codeinlining.evaluate(compiler, prgm)  # Temporarily disabled

            # Get rid of dead functions/contexts
            cullprogram.evaluate(compiler, prgm)

        if False:  # Temporarily disable load elimination
            loadelimination.evaluate(compiler, prgm)

        if True:
            storeelimination.evaluate(compiler, prgm)

        # Summary of optimization phase
        compiler.console.output("Optimization phase completed")

        if firstPass and dumpStats:
            stats.contextStats(compiler, prgm, "inline")

        # HACK read/modify information is imprecise, so keep re-evaluating it
        # basically, DCE improves read modify information, which in turn allows better DCE
        # NOTE that this doesn't work very well without path sensitivity
        # "modifies" are quite imprecise without it, hence DCE doesn't do much.
        if False:  # Temporarily disable brute force simplification
            bruteForceSimplification(compiler, prgm)


def bruteForceSimplification(compiler, prgm):
    """
    Brute force simplification by iterating optimization passes.

    This function runs lifetime analysis and simplification multiple times
    in an attempt to improve precision. However, this approach has limited
    effectiveness without path sensitivity, as noted in the code comments.

    **Note:** Currently disabled in the main pipeline due to limited effectiveness.

    Args:
        compiler: Compiler context
        prgm: Program to simplify
    """
    with compiler.console.scope("brute force"):
        for _i in range(2):
            prgm.set_analysis_result(
                "lifetime_refresh", lifetimeanalysis.evaluate(compiler, prgm)
            )
            simplify.evaluate(compiler, prgm)


def depythonPass(compiler, prgm, opPathLength=0, firstPass=True):
    """
    Main analysis pass of the legacy pipeline.

    This function runs the core analysis passes:
    1. IPA (Inter-procedural analysis) - builds call graph and contexts
    2. CPA (Constraint propagation analysis) - type and flow analysis
    3. Code conditioning - optimization passes

    The "depython" name refers to the original goal of translating Python
    to a lower-level representation, though PyFlow is now primarily a static
    analysis framework.

    Args:
        compiler: Compiler context
        prgm: Program to analyze
        opPathLength: Call path length for CPA (0 = no path sensitivity)
        firstPass: Whether this is the first pass (affects statistics and optimizations)
    """
    with compiler.console.scope("legacy-analysis"):
        # Run IPA analysis and store results for later access
        ipa_result = ipa.evaluate(compiler, prgm)
        if ipa_result:
            prgm.set_analysis_result(
                "ipa" if firstPass else "ipa_refresh",
                ipa_result,
            )

        prgm.set_analysis_result(
            "cpa" if firstPass else "cpa_path_sensitive",
            cpa.evaluate(compiler, prgm, opPathLength, firstPass=firstPass),
        )

        if firstPass:
            stats.contextStats(
                compiler,
                prgm,
                "firstpass" if firstPass else "secondpass",
                classOK=firstPass,
            )
        # errors.abort("testing")

        codeConditioning(compiler, prgm, firstPass, firstPass)


def evaluate(compiler, prgm, name):
    """
    Main entry point for the legacy analysis pipeline.

    This function orchestrates the complete analysis pipeline:
    1. First pass: Full analysis with all optimizations
    2. Second pass: Re-analysis with call-path sensitivity (opPathLength=3)
    3. Cleanup: Dump reports and clean up threads

    **Two-Pass Strategy:**
    The pipeline runs two passes because:
    - First pass: Establishes basic analysis results
    - Second pass: Uses call-path sensitivity to improve precision
      (intrinsics can prevent complete inlining, path sensitivity compensates)

    **Cleanup:**
    - Dumps analysis reports if configured
    - Cleans up any remaining threads if configured

    Args:
        compiler: Compiler context
        prgm: Program to analyze
        name: Name for logging and report generation

    Raises:
        CompilerAbort: If compilation is aborted (for testing/debugging)
    """
    try:
        with compiler.console.scope("compile"):
            try:
                # First compiler pass - full analysis with all optimizations
                depythonPass(compiler, prgm)

                if True:
                    # Second compiler pass with call-path sensitivity
                    # Intrinsics can prevent complete exhaustive inlining.
                    # Adding call-path sensitivity compensates.
                    depythonPass(compiler, prgm, 3, firstPass=False)
                else:
                    # HACK rerun lifetime analysis, as inlining causes problems for the function annotations.
                    prgm.set_analysis_result(
                        "lifetime_refresh", lifetimeanalysis.evaluate(compiler, prgm)
                    )

                stats.contextStats(compiler, prgm, "secondpass")

                # errors.abort('test')

                # Translation phase removed - now a static analysis framework
            finally:
                # Dump analysis reports if configured
                if config.doDump:
                    try:
                            dumpreport.evaluate(compiler, prgm, name)
                    except Exception as e:
                        if config.maskDumpErrors:
                            compiler.console.output(
                                f"Exception dumping the report: {e}"
                            )
                        else:
                            raise

                # Clean up threads if configured
                if config.doThreadCleanup:
                    active_threads = threading.active_count()
                    if active_threads > 1:
                        with compiler.console.scope("threading cleanup"):
                            compiler.console.output(
                                "Threads: %d" % (active_threads - 1)
                            )
                            for t in threading.enumerate():
                                if t is not threading.current_thread():
                                    compiler.console.output(".")
                                    t.join()
    except errors.CompilerAbort as e:
        compiler.console.output("")
        compiler.console.output(f"ABORT {e}")
