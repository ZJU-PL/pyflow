"""Program culling for dead code elimination.

This module provides functionality to identify and remove dead code from
programs by analyzing call graphs and function usage patterns.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from pyflow.analysis.astcollector import getOps
from pyflow.ir.core import AnalysisFacts


class Finder(object):
    """Base class for finding and processing program elements.

    This class provides a framework for traversing program structures
    and identifying relevant elements based on specific criteria.

    Attributes:
        processed: Set of already processed nodes.
    """

    def __init__(self, catalog):
        """Initialize the finder."""
        self.processed = set()

    def process(self, node):
        """Process a node and its children.

        Args:
            node: Node to process.
        """
        if node not in self.processed:
            self.processed.add(node)
            for child in self.children(node):
                self.process(child)

    def children(self, node):
        """Get children of a node.

        Args:
            node: Node to get children for.

        Returns:
            List of child nodes.

        Note:
            This method should be implemented by subclasses.
        """
        raise NotImplementedError


class CallGraphFinder(Finder):
    """Finds call graph relationships in programs.

    This class analyzes programs to build call graphs, identifying
    which functions are called and in what contexts.

    Attributes:
        liveFunc: Set of live functions.
        liveFuncContext: Dictionary mapping functions to their contexts.
        invokes: Dictionary mapping functions to their call sites.
        invokesContext: Dictionary mapping call sites to contexts.
    """

    def __init__(self, catalog):
        """Initialize the call graph finder."""
        Finder.__init__(self, catalog)
        self.facts = AnalysisFacts(catalog)
        self.liveFunc = set()
        self.liveFuncContext = {}
        self.invokes = {}
        self.invokesContext = {}

    def children(self, node):
        """Get children of a call graph node.

        Args:
            node: Call graph node (code, context tuple).

        Returns:
            List of child nodes.
        """
        code, context = node

        self.liveFunc.add(code)

        if code not in self.liveFuncContext:
            self.liveFuncContext[code] = set()
        self.liveFuncContext[code].add(context)

        if code not in self.invokes:
            self.invokes[code] = set()

        if node not in self.invokesContext:
            self.invokesContext[node] = set()

        children = []

        ops, _lcls = getOps(code)
        for op in ops:
            for dstf, dstc in self.facts.call_targets(code, op, context):
                child = (dstf, dstc)
                self.invokes[code].add(dstf)
                self.invokesContext[node].add(child)
                children.append(child)
        return children


def makeCGF(prgm):
    """Build a CallGraphFinder from the program interface.

    Bug fix: the original code silently swallowed *all* exceptions (both
    ``AssertionError`` and bare ``Exception``) with empty ``except`` blocks.
    This meant that bugs in annotation processing or context lookup were
    silently ignored, producing an incomplete call graph with no diagnostic.

    Missing published entry contexts and unexpected failures are reported
    explicitly instead of being recovered from legacy annotations.
    """
    import logging
    _LOG = logging.getLogger(__name__)

    cgf = CallGraphFinder(prgm.ir)
    entry_code_contexts = prgm.interface.entryCodeContexts()
    unexpected = []
    for code, context in entry_code_contexts:
        try:
            if context not in cgf.facts.contexts(code):
                raise ValueError(
                    "Entry-point context missing from published analysis contexts: "
                    f"{code!r} / {context!r}"
                )
            cgf.process((code, context))
        except Exception as e:
            unexpected.append((code, context, e))

    if unexpected:
        code, context, exc = unexpected[0]
        _LOG.error(
            "makeCGF: failed processing (%r, %r): %s",
            code,
            context,
            exc,
            exc_info=True,
        )
        raise RuntimeError(
            f"Failed to build a complete call graph for {code!r} / {context!r}: {exc}"
        ) from exc

    return cgf


def findLiveCode(prgm):
    cgf = makeCGF(prgm)

    entry = set()
    for code in prgm.interface.entryCode():
        entry.add(code)

    G = cgf.invokes
    head = None
    G[head] = entry

    prgm.liveCode = cgf.liveFunc

    return cgf.liveFunc, G


def findLiveContexts(prgm):
    cgf = makeCGF(prgm)
    prgm.liveCode = cgf.liveFunc
    return cgf.liveFuncContext


class LiveHeapFinder(TypeDispatcher):
    def __init__(self, catalog):
        TypeDispatcher.__init__(self)
        self.facts = AnalysisFacts(catalog)
        self.code = None
        self.live = set()

    def addReferences(self, refs):
        self.live.update(refs)

    @dispatch(ast.leafTypes)
    def visitLeaf(self, node):
        pass

    @dispatch(ast.Existing)
    def visitExisting(self, node):
        self.addReferences(self.facts.merged_references(self.code, node))

    @dispatch(ast.Local)
    def visitReference(self, node):
        self.addReferences(self.facts.merged_references(self.code, node))

    @defaultdispatch
    def visitDefault(self, node):
        node.visitChildren(self)

    def process(self, code):
        self.code = code
        code.visitChildrenForced(self)
        self.code = None


# HACK this may not be 100% sound, as it only considers references
# directly embedded in the code.
def findLiveHeap(prgm):
    finder = LiveHeapFinder(prgm.ir)
    for code in prgm.liveCode:
        finder.process(code)

    index = {}
    for obj in finder.live:
        group = obj.xtype.group()
        if not group in index:
            index[group] = []
        index[group].append(obj)

    return finder.live, index
