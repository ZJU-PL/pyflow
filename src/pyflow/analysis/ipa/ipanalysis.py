"""Main inter-procedural analysis implementation.

This module contains the core IPAnalysis class that orchestrates inter-procedural
analysis across function boundaries with context-sensitive precision.
"""

import time

from pyflow.optimization.callconverter import callConverter
from pyflow.analysis.storegraph import setmanager
from pyflow.util.monkeypatch import xtypes

from . import constraintextractor
from .model import objectname
from .model.context import Context
from .constraints import qualifiers
from .calling import cpa
from .escape import objectescape
from . import summary


class IPAnalysis(object):
    """Main class for inter-procedural analysis.
    
    This class performs context-sensitive inter-procedural analysis by maintaining
    separate contexts for different calling patterns and propagating information
    between function calls and returns.
    
    Attributes:
        compiler: Compiler context for the analysis.
        extractor: Program extractor for accessing source code.
        canonical: Canonical store graph for object relationships.
        existingPolicy: Policy for handling existing objects.
        externalPolicy: Policy for handling external objects.
        objs: Dictionary of analyzed objects.
        contexts: Dictionary of analysis contexts.
        root: Root context for external analysis.
        liveCode: Set of live code elements.
        valuemanager: Manager for value sets.
        criticalmanager: Manager for critical sets.
        dirtySlots: List of slots that need reprocessing.
        decompileTime: Time spent on decompilation.
        trace: Whether to enable tracing output.
        funcDefaultName: Name for function default parameters.
    """
    
    def __init__(self, compiler, canonical, existingPolicy, externalPolicy):
        """Initialize the inter-procedural analysis.
        
        Args:
            compiler: Compiler context for the analysis.
            canonical: Canonical store graph.
            existingPolicy: Policy for existing objects.
            externalPolicy: Policy for external objects.
        """
        self.compiler = compiler
        self.extractor = compiler.extractor
        self.canonical = canonical

        self.existingPolicy = existingPolicy
        self.externalPolicy = externalPolicy

        self.objs = {}
        self.contexts = {}

        self.root = self.getContext(cpa.externalContext)
        self.root.external = True

        self.liveCode = set()

        self.valuemanager = setmanager.CachedSetManager()
        self.criticalmanager = setmanager.CachedSetManager()

        self.dirtySlots = []

        self.decompileTime = 0.0

        self.trace = False

        descName = compiler.slots.uniqueSlotName(xtypes.FunctionType.__defaults__)
        self.funcDefaultName = self.pyObj(descName)

    def pyObj(self, pyobj):
        """Get program object for a Python object.
        
        Args:
            pyobj: Python object to get program object for
            
        Returns:
            program.AbstractObject: Program object representation
        """
        return self.extractor.getObject(pyobj)

    def pyObjInst(self, pycls):
        """Get abstract instance for a Python class.
        
        Args:
            pycls: Python class to get instance for
            
        Returns:
            program.AbstractObject: Abstract instance object
        """
        cls = self.pyObj(pycls)
        self.extractor.ensureLoaded(cls)
        return cls.typeinfo.abstractInstance

    def objectName(self, xtype, qualifier=qualifiers.HZ):
        """Get or create an ObjectName for an extended type.
        
        ObjectNames are canonicalized by (xtype, qualifier) pair.
        
        Args:
            xtype: ExtendedType from store graph
            qualifier: Qualifier (HZ, DN, UP, GLBL)
            
        Returns:
            ObjectName: Canonical object name
        """
        key = (xtype, qualifier)
        if key not in self.objs:
            obj = objectname.ObjectName(xtype, qualifier)
            self.objs[key] = obj
        else:
            obj = self.objs[key]
        return obj

    def getContext(self, sig):
        """Get or create an analysis context for a signature.
        
        Contexts are canonicalized by signature. If context doesn't exist,
        creates it and extracts constraints from the code.
        
        Args:
            sig: CPAContextSignature for the function
            
        Returns:
            Context: Analysis context for the signature
        """
        if sig not in self.contexts:
            context = Context(self, sig)
            self.contexts[sig] = context

            if sig and sig.code:
                constraintextractor.evaluate(self, context, sig.code)
        else:
            context = self.contexts[sig]
        return context

    def getCode(self, obj):
        """Get code object for a function object.
        
        Retrieves and processes code for a function, converting calls
        and tracking live code.
        
        Args:
            obj: ObjectName representing a function
            
        Returns:
            program.Code: Code object for the function
        """
        start = time.perf_counter()

        assert obj.isObjectName()

        code = self.extractor.getCall(obj.obj())
        if code is None:
            code = self.extractor.stubs.exports["interpreter_call"]

        callConverter(self.extractor, code)

        if code not in self.liveCode:
            self.liveCode.add(code)

        end = time.perf_counter()
        self.decompileTime += end - start

        return code

    ### Analysis methods ###

    def dirtySlot(self, slot):
        """Mark a constraint node as dirty (needs reprocessing).
        
        Args:
            slot: ConstraintNode to mark dirty
        """
        self.dirtySlots.append(slot)

    def dirtyConstraints(self):
        """Check if there are dirty constraints to process.
        
        Returns:
            bool: True if there are dirty slots
        """
        return bool(self.dirtySlots)

    def updateCallGraph(self):
        """Update the call graph by resolving dirty calls.
        
        Processes dirty calls, direct calls, and flat calls to update
        the inter-procedural call graph.
        
        Returns:
            bool: True if call graph changed
        """
        if self.trace:
            print("update")
        changed = False

        # HACK dictionary size may change...
        for context in tuple(self.contexts.values()):
            changed |= context.updateCallgraph()
        if self.trace:
            print("return", changed)
        return changed

    def updateConstraints(self):
        """Propagate constraints through the constraint graph.
        
        Processes all dirty slots by propagating their value changes
        to dependent constraints.
        """
        # if self.trace: print("resolve")
        while self.dirtySlots:
            slot = self.dirtySlots.pop()
            slot.propagate()

    def topDown(self):
        """Perform top-down analysis pass.
        
        Top-down analysis propagates information from callers to callees.
        Iterates until fixed point (no more changes).
        """
        if self.trace:
            print("top down")
        dirty = True
        while dirty:
            self.updateConstraints()
            self.updateCallGraph()
            dirty = self.dirtyConstraints()

    def propagateCriticals(self, context):
        """Propagate critical values in a context.
        
        Critical values are values that must be tracked precisely
        (e.g., for escape analysis).
        
        Args:
            context: Context to propagate criticals in
        """
        while context.dirtycriticals:
            node = context.dirtycriticals.pop()
            node.critical.propagate(context, node)

    def contextBottomUp(self, context):
        """Process a context in bottom-up order.
        
        Bottom-up analysis processes callees before callers, allowing
        summaries to be computed and propagated upward. Uses DFS to
        process contexts in reverse topological order.
        
        Args:
            context: Context to process
            
        Raises:
            AssertionError: If recursive cycle detected
        """
        if context not in self.processed:
            self.processed.add(context)
            self.path.append(context)

            # Process children first
            for invoke in context.invokeOut.values():
                dst = invoke.dst
                self.contextBottomUp(dst)
                invoke.apply()

            self.updateConstraints()

            if context.summary.dirty:
                self.propagateCriticals(context)
                objectescape.process(context)

                summary.update(context)

                self.updateConstraints()  # TODO only once?

            self.path.pop()
        else:
            assert context not in self.path, "Recursive cycle detected in call graph"

    def bottomUp(self):
        """Perform bottom-up analysis pass.
        
        Bottom-up analysis propagates information from callees to callers.
        Processes contexts in reverse topological order, computing and
        applying summaries.
        """
        print("bottom up")
        self.processed = set()
        self.path = []

        for context in self.contexts.values():
            context.summary.fresh = False

        self.contextBottomUp(self.root)

        self.updateCallGraph()
