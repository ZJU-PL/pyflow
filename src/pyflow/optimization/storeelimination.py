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
from pyflow.ir.core import AnalysisFacts, Capabilities
from .source_candidates import record_source_candidate


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
        if not prgm.ir.facts.has(Capabilities.LIFETIME_OP_READS):
            raise RuntimeError(
                "Dead store elimination requires lifetime analysis. "
                "Ensure 'lifetime' pass has run before 'store_elimination'."
            )

        live = set()
        stores = collections.defaultdict(list)
        facts = AnalysisFacts(prgm.ir)

        # Analysis pass
        saw_lifetime_data = False
        for code in prgm.liveCode:
            for context in facts.contexts(code):
                live.update(
                    facts.code_effect(
                        Capabilities.LIFETIME_CODE_READS, code, context
                    )
                )
                saw_lifetime_data = True

            for op in codeOps(code):
                for context in facts.contexts(code):
                    live.update(
                        facts.operation_effect(
                            Capabilities.LIFETIME_OP_READS, code, op, context
                        )
                    )
                if isinstance(op, ast.Store):
                    stores[code].append(op)

        if not saw_lifetime_data:
            compiler.console.output(
                "Skipping dead store elimination: missing lifetime facts."
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
                modifies = facts.merged_operation_effect(
                    Capabilities.LIFETIME_OP_WRITES, code, store
                )
                if modifies:
                    is_live = False
                    for modify in modifies:
                        if modify in live:
                            # Location is live, store is needed
                            is_live = True
                            break
                        if modify.object.leaks:
                            # Object leaks memory, preserve store
                            is_live = True
                            break

                    if not is_live:
                        # No modified locations are live - store is dead
                        replace[store] = []
                        revision = getattr(getattr(prgm, "ir", None), "revision", None)
                        record_source_candidate(
                            compiler,
                            code,
                            store,
                            "store_elimination",
                            proof={
                                "analysis": "lifetime",
                                "ir_revision": (
                                    str(revision) if revision is not None else None
                                ),
                            },
                        )
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
