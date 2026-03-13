"""
Redundant Load Elimination Optimization for PyFlow.

This module implements redundant load elimination (RLE), an optimization that
removes redundant memory load operations by reusing values from dominating stores.

The optimization:
- Uses SSA form and dominance analysis to identify redundant loads
- Finds loads that are dominated by stores to the same memory location
- Replaces redundant loads with references to the dominating store's value
- Works on both object field loads and array element loads

This is a local optimization that operates on individual functions.
"""

from pyflow.language.python import ast

from pyflow.analysis.numbering.readmodify import FindReadModify
from pyflow.analysis.numbering.dominance import MakeForwardDominance
from pyflow.analysis.numbering.ssa import ForwardESSA

from pyflow.optimization import rewrite

# For debugging
from pyflow.util.io.xmloutput import XMLOutput

import collections


class RedundantLoadEliminator(object):
    """
    Eliminates redundant load operations from code.

    This class implements redundant load elimination (RLE), an optimization
    that removes loads that are redundant because a dominating store has
    already written the same value. It uses:
    - SSA numbering to identify memory operations
    - Dominance analysis to find dominating stores
    - Value numbering to determine if loads can be replaced

    The optimization works by:
    1. Identifying all load and store operations
    2. For each load, finding dominating stores to the same location
    3. Replacing the load with the store's value if safe

    Attributes:
        compiler: Compiler context
        prgm: Program being optimized
        readNumbers: SSA read numbers for each (node, variable) pair
        writeNumbers: SSA write numbers for each (node, variable) pair
        dom: Dominance information mapping nodes to (pre, post) numbers
        eliminated: Count of loads eliminated
    """

    def __init__(self, compiler, prgm, readNumbers, writeNumbers, dom):
        """
        Initialize redundant load eliminator.

        Args:
            compiler: Compiler instance
            prgm: Program being optimized
            readNumbers: Dictionary mapping (node, variable) to SSA read number
            writeNumbers: Dictionary mapping (node, variable) to SSA write number
            dom: Dictionary mapping nodes to dominance intervals (pre, post)
        """
        self.compiler = compiler
        self.prgm = prgm
        self.readNumbers = readNumbers
        self.writeNumbers = writeNumbers
        self.dom = dom

        self.eliminated = 0

    def readNumber(self, node, arg):
        """
        Get the SSA read number for a node-argument pair.

        Args:
            node: AST node
            arg: Variable/argument being read

        Returns:
            SSA read number (0 for constants)
        """
        if isinstance(arg, ast.Existing):
            return 0
        else:
            return self.readNumbers[(node, arg)]

    def writeNumber(self, node, arg):
        """
        Get the SSA write number for a node-argument pair.

        Args:
            node: AST node (Store operation)
            arg: Variable/argument being written

        Returns:
            SSA write number
        """
        return self.writeNumbers[(node, arg)]

    def dominates(self, a, b):
        """
        Check if node a dominates node b.

        Node a dominates b if all paths from the entry to b pass through a.
        This is checked using dominance intervals: a dominates b if
        a.pre < b.pre and a.post > b.post.

        Args:
            a: Potential dominator node
            b: Node to check

        Returns:
            True if a dominates b
        """
        adom = self.dom[a]
        bdom = self.dom[b]
        return adom[0] < bdom[0] and adom[1] > bdom[1]

    def findLoadStores(self):
        """
        Find all load and store operations in the code.

        Scans the read numbers to identify assignments from loads and
        store operations. These are the candidates for elimination.

        Returns:
            tuple: (loads set, stores set)
                   - loads: Set of Assign nodes with Load expressions
                   - stores: Set of Store nodes
        """
        loads = set()
        stores = set()

        # HACK to find all the interesting nodes.
        # TODO use existing code?
        for (node, src), number in self.readNumbers.items():
            if isinstance(node, ast.Assign) and isinstance(node.expr, ast.Load):
                loads.add(node)

        for (node, dst), number in self.writeNumbers.items():
            if isinstance(node, ast.Store):
                stores.add(node)

        return loads, stores

    def makeReadSig(self, op, arg):
        if isinstance(arg, ast.Existing):
            sig = arg.object
        elif isinstance(arg, ast.Local):
            # Dropping the arg from the signature allows load elimination across must-aliases
            # sig = (arg, self.readNumber(op, arg))
            sig = self.readNumber(op, arg)
        else:
            # Unsupported operand shape: conservatively skip this candidate
            return None
        return sig

    def generateSignature(self, op, node, signatures):
        exprSig = self.makeReadSig(op, node.expr)
        nameSig = self.makeReadSig(op, node.name)
        if exprSig is None or nameSig is None:
            return

        if isinstance(node, ast.Load):
            fields = [
                (field, self.readNumber(op, field))
                for field in node.annotation.reads[0]
            ]
        elif isinstance(node, ast.Store):
            fields = [
                (field, self.writeNumber(op, field))
                for field in node.annotation.modifies[0]
            ]
        else:
            # Unsupported node shape: conservatively skip
            return

        sig = (exprSig, node.fieldtype, nameSig, frozenset(fields))

        bucket = signatures[sig]
        if isinstance(node, ast.Load):
            bucket["loads"].append(op)
        else:
            bucket["stores"].append(op)

    def generateSignatures(self, code):
        loads, stores = self.findLoadStores()
        signatures = collections.defaultdict(lambda: {"loads": [], "stores": []})

        for op in loads:
            self.generateSignature(op, op.expr, signatures)
        for op in stores:
            self.generateSignature(op, op, signatures)

        return signatures

    def getReplacementSource(self, dominator):
        if dominator not in self.newName:
            if isinstance(dominator, ast.Store):
                old = dominator.value
            else:
                assert len(dominator.lcls) == 1
                old = dominator.lcls[0]

            if isinstance(old, ast.Existing):
                src = ast.Existing(old.object)
            else:
                src = ast.Local(old.name)
                self.replace[dominator] = [dominator, ast.Assign(old, [src])]

            src.annotation = old.annotation
            self.newName[dominator] = src
        else:
            src = self.newName[dominator]
        return src

    def nearestDominator(self, op, candidates):
        dominator = None
        for test in candidates:
            if test is op:
                continue
            if self.dominates(test, op):
                if dominator is None or self.dominates(dominator, test):
                    dominator = test
        return dominator

    def generateReplacements(self, signatures):
        self.newName = {}
        self.replace = {}

        for bucket in signatures.values():
            loads = bucket["loads"]
            if not loads:
                continue

            candidates = bucket["stores"] + loads
            for op in loads:
                dominator = self.nearestDominator(op, candidates)
                if dominator is None:
                    continue

                assert len(op.lcls) == 1
                src = self.getReplacementSource(dominator)
                self.replace[op] = ast.Assign(src, [op.lcls[0]])
                self.eliminated += 1
        return self.replace

    def processCode(self, code, simplify):
        signatures = self.generateSignatures(code)
        replace = self.generateReplacements(signatures)

        if simplify:
            rewrite.rewriteAndSimplify(self.compiler, self.prgm, code, replace)
        else:
            rewrite.rewrite(self.compiler, code, replace)

        return self.eliminated


def evaluateCode(compiler, prgm, code, simplify=True):
    """Eliminate redundant loads in a single code unit.

    Args:
        compiler: Compiler context
        prgm: Program being optimized
        code: Code unit to optimize
        simplify: Whether to run simplification after rewriting

    Returns:
        int: Number of loads eliminated
    """
    rm = FindReadModify().processCode(code)

    dom = MakeForwardDominance().processCode(code)

    fessa = ForwardESSA(rm)
    fessa.processCode(code)

    rle = RedundantLoadEliminator(compiler, prgm, fessa.readLUT, fessa.writeLUT, dom)
    eliminated = rle.processCode(code, simplify)
    if eliminated:
        print("\t", code, eliminated)

    return eliminated


def evaluate(compiler, prgm):
    """Main entry point for redundant load elimination.

    CRITICAL: This pass requires lifetime analysis annotations (codeReads, reads, modifies).
    Using stale annotations can cause miscompilation by reusing values from wrong contexts.

    Args:
        compiler: Compiler context
        prgm: Program to optimize

    Returns:
        bool: True if any loads were eliminated, False otherwise

    Raises:
        RuntimeError: If lifetime analysis annotations are missing or stale
    """
    with compiler.console.scope("redundant load elimination"):
        # Require a fresh lifetime pass result rather than trusting possibly-stale
        # annotations left on code objects after earlier transformations.
        if getattr(prgm, "lifetime_analysis", None) is None:
            raise RuntimeError(
                "Load elimination requires lifetime analysis. "
                "Ensure 'lifetime' pass has run before 'load_elimination'."
            )

        totalEliminated = 0
        totalLoads = 0

        for code in prgm.liveCode:
            if code.isStandardCode() and not code.annotation.descriptive:
                # Count loads before elimination
                rm = FindReadModify().processCode(code)
                fessa = ForwardESSA(rm)
                fessa.processCode(code)
                loads, stores = RedundantLoadEliminator(
                    None, None, fessa.readLUT, fessa.writeLUT, {}
                ).findLoadStores()
                codeLoads = len(loads)
                totalLoads += codeLoads

                eliminated = evaluateCode(compiler, prgm, code)
                totalEliminated += eliminated

        # Print summary statistics
        if totalLoads > 0:
            eliminationRate = (totalEliminated / totalLoads) * 100
            compiler.console.output(
                f"Total loads analyzed: {totalLoads}, eliminated: {totalEliminated} ({eliminationRate:.1f}%)"
            )
        else:
            compiler.console.output("No loads found to analyze")

        return totalEliminated > 0
