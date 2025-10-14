from pyflow.language.python import ast

from pyflow.analysis.tools import codeOps
import collections

from pyflow.optimization import rewrite


def evaluate(compiler, prgm, simplify=False):
    with compiler.console.scope("dead store elimination"):
        live = set()
        stores = collections.defaultdict(list)

        # Analysis pass
        for code in prgm.liveCode:
            if code.annotation.codeReads:
                live.update(code.annotation.codeReads[0])

            for op in codeOps(code):
                if op.annotation.reads:
                    live.update(op.annotation.reads[0])
                if isinstance(op, ast.Store):
                    stores[code].append(op)

        # Count total stores
        totalStores = sum(
            len(stores[code])
            for code in prgm.liveCode
            if code.isStandardCode() and not code.annotation.descriptive
        )

        # Transform pass
        totalEliminated = 0

        for code in prgm.liveCode:
            if not code.isStandardCode() or code.annotation.descriptive:
                continue

            replace = {}
            eliminated = 0

            # Look for dead stores
            for store in stores[code]:
                if store.annotation.modifies:
                    for modify in store.annotation.modifies[0]:
                        if modify in live:
                            break
                        if modify.object.leaks:
                            break
                    else:
                        replace[store] = []
                        eliminated += 1
                else:
                    # If no modifies info, assume it's live
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
