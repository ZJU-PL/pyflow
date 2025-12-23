"""Shape analysis for PyFlow.

This package provides shape analysis capabilities that analyze the shapes and
properties of data structures in Python programs, including region-based analysis and constraint-based shape inference.
"""

from __future__ import absolute_import

# The model for the analysis

from .model import canonical

from . import regionanalysis
from . import transferfunctions
from . import constraintbuilder
from . import dataflow


class HeapInformationProvider(object):
    """Provides heap information for shape analysis.
    
    This class extracts heap-related information from the store graph and
    regions to support shape analysis operations.
    
    Attributes:
        storeGraph: Store graph containing object relationships.
        regions: Region information for heap analysis.
    """
    
    def __init__(self, storeGraph, regions):
        """Initialize the heap information provider.
        
        Args:
            storeGraph: Store graph containing object relationships.
            regions: Region information for heap analysis.
        """
        self.storeGraph = storeGraph
        self.regions = regions

    def loadSlotName(self, node):
        """Get the slot name for a load operation.
        
        Args:
            node: Node representing the load operation.
            
        Returns:
            Slot name for the load operation.
        """
        return node.annotation.reads[0][0]
        # return (node.fieldtype, node.name.object)

    def storeSlotName(self, node):
        """Get the slot name for a store operation.
        
        Args:
            node: Node representing the store operation.
            
        Returns:
            Slot name for the store operation.
        """
        return node.annotation.modifies[0][0]
        # return (node.fieldtype, node.name.object)

    def indexSlotName(self, lcl, i):
        """Get the slot name for an indexed access.
        
        Args:
            lcl: Local variable being indexed.
            i: Index value.
            
        Returns:
            Slot name for the indexed access.
        """
        iobj = self.storeGraph.extractor.getObject(i)
        fieldName = self.storeGraph.canonical.fieldName("Array", iobj)
        for ref in lcl.annotation.references[0]:
            return ref.field(fieldName, ref.region.group.regionHint)


class OrderConstraints(object):
    """Orders constraints by dependency for efficient processing.
    
    OrderConstraints performs topological sorting of constraints based on
    their dependencies. Constraints that depend on others are processed
    later, ensuring dependencies are satisfied before evaluation.
    
    Attributes:
        sys: RegionBasedShapeAnalysis instance
        entryCode: List of entry code objects
    """
    def __init__(self, sys, entryCode):
        """Initialize constraint orderer.
        
        Args:
            sys: RegionBasedShapeAnalysis instance
            entryCode: List of entry code objects
        """
        self.sys = sys
        self.entryCode = entryCode

    def processConstraint(self, c):
        """Process a constraint and assign priority.
        
        Recursively processes constraint dependencies and assigns priorities
        in reverse topological order (dependencies get lower priorities).
        
        Args:
            c: Constraint to process
        """
        if c in self.processed:
            return
        self.processed.add(c)

        point = c.outputPoint
        for next in self.sys.environment.observers.get(point, ()):
            self.processConstraint(next)

        c.priority = self.uid

        self.uid += 1

    def process(self):
        """Process all constraints starting from entry points.
        
        Traverses constraints starting from entry code call points and
        assigns priorities based on dependency order.
        """
        self.uid = 1
        self.processed = set()

        for code in self.entryCode:
            callPoint = self.sys.constraintbuilder.codeCallPoint(code)
            for c in self.sys.environment.observers.get(callPoint, ()):
                self.processConstraint(c)
        self.sort()

    def sort(self):
        """Sort constraint observers by priority.
        
        Sorts all constraint observers in each program point by their
        assigned priority, ensuring dependencies are processed first.
        """
        priority = lambda c: c.priority
        for observers in self.sys.environment.observers.values():
            observers.sort(reverse=False, key=priority)


class RegionBasedShapeAnalysis(object):
    """Main region-based shape analysis system.
    
    RegionBasedShapeAnalysis performs shape analysis on Python programs using
    a region-based approach. It tracks:
    - Object shapes: Structure and properties of data structures
    - Reference counts: How many references point to each object
    - Path information: Which paths through code access which objects
    - Configurations: Shape configurations at program points
    
    The analysis uses a worklist algorithm to iteratively refine shape
    information until a fixed point is reached.
    
    Attributes:
        extractor: Program extractor for accessing code
        canonical: CanonicalObjects for canonical naming
        worklist: Worklist for constraint processing
        environment: DataflowEnvironment managing analysis state
        constraintbuilder: ShapeConstraintBuilder for building constraints
        cpacanonical: Canonical objects from CPA analysis
        info: HeapInformationProvider for heap information
        pending: Set of code objects pending constraint building
        visited: Set of code objects already visited
        limit: Maximum number of worklist iterations
        aborted: Set of objects where analysis was aborted (hit limit)
    """
    def __init__(self, extractor, cpacanonical, info):
        """Initialize region-based shape analysis.
        
        Args:
            extractor: Program extractor
            cpacanonical: Canonical objects from CPA
            info: HeapInformationProvider
        """
        self.extractor = extractor
        self.canonical = canonical.CanonicalObjects()
        self.worklist = dataflow.Worklist()
        self.environment = dataflow.DataflowEnvironment()

        self.constraintbuilder = constraintbuilder.ShapeConstraintBuilder(
            self, self.processCode
        )

        self.cpacanonical = cpacanonical
        self.info = info

        self.pending = set()
        self.visited = set()

        self.limit = 20000

        self.aborted = set()

    def process(self, trace=False, limit=0):
        """Process constraints until fixed point or limit reached.
        
        Args:
            trace: Whether to print trace information
            limit: Maximum iterations (0 for no limit)
            
        Returns:
            bool: True if fixed point reached, False if limit hit
        """
        success = self.worklist.process(self, trace, limit)
        if not success:
            print("ITERATION LIMIT HIT")
            self.worklist.worklist[:] = []
        return success

    def processCode(self, code):
        """Mark code for constraint building.
        
        Args:
            code: Code object to process
        """
        if code not in self.visited:
            self.pending.add(code)
            self.visited.add(code)

    def build(self):
        """Build constraints for all pending code objects.
        
        Processes all code objects in the pending set, building constraints
        for each one.
        """
        while self.pending:
            current = self.pending.pop()
            print("BUILD", current)
            self.constraintbuilder.process(current)

    def buildStructures(self, entryCode):
        """Build constraint structures for entry code.
        
        Processes entry code objects, builds constraints, and orders them
        by dependency.
        
        Args:
            entryCode: List of entry code objects
        """
        for code in entryCode:
            self.processCode(code)
        self.build()

        order = OrderConstraints(self, entryCode)
        order.process()

    def addEntryPoint(self, code, selfobj, args):
        """Add an entry point and analyze it.
        
        Processes an entry point by binding existing objects and analyzing
        their shapes. Aborts if iteration limit is hit.
        
        Args:
            code: Entry point code object
            selfobj: Self object (or None)
            args: List of argument objects
        """
        self.processCode(code)
        self.build()

        callPoint = self.constraintbuilder.codeCallPoint(code)

        # TODO generate all possible aliasing configuraions?
        self.bindExisting(selfobj, "self", callPoint)
        sucess = self.process(trace=True)
        if not sucess:
            self.aborted.add(selfobj)

        for i, arg in enumerate(args):
            self.bindExisting(arg, i, callPoint)
            sucess = self.process(trace=True, limit=self.limit)
            if not sucess:
                self.aborted.add(arg)

    def bindExisting(self, obj, p, callPoint):
        slot = self.canonical.localSlot(p)
        expr = self.canonical.localExpr(slot)
        refs = self.canonical.refs(slot)

        type_ = self.cpacanonical.externalType(obj)
        region = None
        entry = refs
        current = refs
        externalReferences = True
        allocated = False

        hits = (expr,)
        misses = ()

        index = self.canonical.configuration(
            type_, region, entry, current, externalReferences, allocated
        )
        paths = self.canonical.paths(hits, misses)
        secondary = self.canonical.secondary(paths, externalReferences)

        print("BIND")
        print(callPoint)
        print(index)
        print(secondary)
        print(self.environment.merge(self, callPoint, None, index, secondary))

    def handleAllocations(self):
        for (code, op), (
            point,
            target,
        ) in self.constraintbuilder.allocationPoint.items():
            print(code)
            print(op)
            print("\t", point)
            print("\t", target)

            slot = self.canonical.localSlot(target)
            expr = self.canonical.localExpr(slot)
            refs = self.canonical.refs(slot)

            for obj in op.annotation.allocates[0]:
                print("\t\t", obj)

                type_ = obj
                region = None
                entry = refs
                current = refs
                externalReferences = False
                allocated = True

                hits = (expr,)
                misses = ()

                index = self.canonical.configuration(
                    type_, region, entry, current, externalReferences, allocated
                )
                paths = self.canonical.paths(hits, misses)
                secondary = self.canonical.secondary(paths, externalReferences)

                self.environment.merge(self, point, None, index, secondary)
                sucess = self.process(trace=True, limit=self.limit)
                if not sucess:
                    self.aborted.add(obj)
        maxObjRefs = {}
        maxFieldRefs = {}
        fieldShares = {}

        for point, context, index in self.environment._secondary.keys():
            for field, count in index.currentSet.counts.items():
                maxObjRefs[index.object] = max(maxObjRefs.get(index.object, 0), count)

                maxFieldRefs[field] = max(maxFieldRefs.get(field, 0), count)
                fieldShares[field] = (
                    fieldShares.get(field, False)
                    or count > 1
                    or len(index.currentSet.counts) > 1
                )

        print("Obj Refs")

        for obj, count in maxObjRefs.items():
            print(obj, count)

            print(obj, count, fieldShares[obj])

    def dumpStatistics(self):
        print("Entries:", len(self.environment._secondary))
        print("Unique Config:", len(self.canonical.configurationCache))
        print("Max Worklist:", self.worklist.maxLength)
        print("Steps:", "%d/%d" % (self.worklist.usefulSteps, self.worklist.steps))


import collections


def evaluate(compiler):
    """Run complete shape analysis on a program.
    
    Main entry point for shape analysis. Performs:
    1. Region analysis: Groups aliasing objects
    2. Constraint building: Builds constraints from AST
    3. Constraint ordering: Orders constraints by dependency
    4. Entry point analysis: Analyzes entry points
    5. Allocation handling: Processes object allocations
    6. Result reporting: Prints analysis results
    
    Args:
        compiler: Compiler instance with program information
        
    Returns:
        RegionBasedShapeAnalysis: Analysis results (or None)
    """
    with compiler.console.scope("shape analysis"):
        # Access interface and liveCode through program if available
        if hasattr(compiler, 'program') and compiler.program:
            interface = compiler.program.interface
            liveCode = compiler.program.liveCode
            storeGraph = compiler.program.storeGraph
        else:
            # Fallback to direct attributes (for backward compatibility)
            interface = compiler.interface
            liveCode = compiler.liveCode
            storeGraph = compiler.storeGraph
            
        regions = regionanalysis.evaluate(
            compiler.extractor, interface.entryPoint, liveCode
        )

        rbsa = RegionBasedShapeAnalysis(
            compiler.extractor,
            storeGraph.canonical,
            HeapInformationProvider(storeGraph, regions),
        )

        rbsa.buildStructures(interface.entryCode())

        for ep in interface.entryPoint:
            rbsa.addEntryPoint(
                ep.code,
                ep.selfarg.getObject(compiler.extractor),
                [arg.getObject(compiler.extractor) for arg in ep.args],
            )

        rbsa.handleAllocations()

        rbsa.dumpStatistics()

        lut = collections.defaultdict(set)
        for point, context, index in sorted(rbsa.environment._secondary.keys()):
            # if index.currentSet.containsParameter(): continue
            if index.object in rbsa.aborted:
                continue
            lut[index.object].add((point[0], index.currentSet))

        for obj, indexes in lut.items():
            print(obj)
            prevCode = None
            for code, rc in sorted(indexes):
                if rc and not rc.containsParameter():
                    if prevCode != code:
                        print("\t", code)
                        prevCode = code

                    print("\t\t", rc)
            print(print)
        print("ABORTED")
        for obj in rbsa.aborted:
            print("\t", obj)

        rbsa.summarize()

        print(rbsa.dumpStatistics())
