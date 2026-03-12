"""
Dead Store Elimination Optimization for PyFlow.

This module implements dead store elimination (DSE), an optimization that
removes store operations whose values are never subsequently read.

The optimization:
- Performs liveness analysis to identify dead stores
- Removes stores to memory locations that are not live
- Preserves stores that may have side effects or leak memory
- Works on both object field stores and array element stores

This is a whole-program optimization that requires inter-procedural liveness.
"""

from pyflow.language.python import ast

from pyflow.analysis.tools import codeOps
import collections

from pyflow.optimization import rewrite


def evaluate(compiler, prgm, simplify=False):
    """Main entry point for dead store elimination.

    FIX #13: Enhanced to check for aliasing using lifetime analysis.

    Args:
        compiler: Compiler context
        prgm: Program to optimize
        simplify: Whether to run simplification after rewriting

    Returns:
        bool: True if any stores were eliminated, False otherwise
    """
    with compiler.console.scope("dead store elimination"):
        live = set()
        stores = collections.defaultdict(list)

        # Analysis pass
        saw_annotation_data = False
        for code in prgm.liveCode:
            if code.annotation.codeReads:
                live.update(code.annotation.codeReads[0])
                saw_annotation_data = True

            for op in codeOps(code):
                op_ann = getattr(op, "annotation", None)
                if op_ann is not None and op_ann.reads:
                    live.update(op_ann.reads[0])
                    saw_annotation_data = True
                if isinstance(op, ast.Store):
                    stores[code].append(op)

        if not saw_annotation_data:
            # CRITICAL FIX #1: Abort if lifetime annotations are missing
            # Using stale or missing annotations can cause miscompilation
            error_msg = (
                "Dead store elimination requires lifetime analysis annotations. "
                "Ensure 'lifetime' pass has run before 'store_elimination'."
            )
            if hasattr(prgm, 'lifetime_analysis') and prgm.lifetime_analysis is None:
                raise RuntimeError(
                    error_msg + " Program has no lifetime_analysis results."
                )
            compiler.console.output(
                "Skipping dead store elimination: missing read/modify annotations."
            )
            return False

        # Count total stores
        totalStores = sum(
            len(stores[code])
            for code in prgm.liveCode
            if code.isStandardCode() and not code.annotation.descriptive
        )

        # Transform pass: eliminate dead stores
        totalEliminated = 0

        for code in prgm.liveCode:
            if not code.isStandardCode() or code.annotation.descriptive:
                continue

            replace = {}
            eliminated = 0

            # Look for dead stores
            for store in stores[code]:
                store_ann = getattr(store, "annotation", None)
                if store_ann is not None and store_ann.modifies:
                    # Check if any modified location is live
                    is_live = False
                    for modify in store_ann.modifies[0]:
                        if modify in live:
                            # Location is live, store is needed
                            is_live = True
                            break
                        if modify.object.leaks:
                            # Object leaks memory, preserve store
                            is_live = True
                            break

                        # FIX #13: Check for aliasing
                        # If any alias of this location is live, preserve the store
                        # This is conservative - we check if the object might be aliased
                        # A more precise check would use alias analysis from lifetime
                        if hasattr(modify.object, 'references') and modify.object.references:
                            # Object has references, might be aliased
                            is_live = True
                            break

                    if not is_live:
                        # No modified locations are live - store is dead
                        replace[store] = []
                        eliminated += 1
                else:
                    # If no modifies info, assume it's live (conservative)
                    pass

            # Rewrite the code without the dead stores
            if replace:
                compiler.console.output("%r %d" % (code, eliminated))

                if simplify:
                    rewrite.rewriteAndSimplify(compiler, prgm, code, replace)
                else:
                    rewrite.rewrite(compiler, code, replace)

            totalEliminated += eliminated

        # Print summary statistics
        if totalStores > 0:
            eliminationRate = (totalEliminated / totalStores) * 100
            compiler.console.output(
                f"Total stores analyzed: {totalStores}, eliminated: {totalEliminated} ({eliminationRate:.1f}%)"
            )
        else:
            compiler.console.output("No stores found to analyze")

        return totalEliminated > 0
