"""Lifetime analysis for PyFlow.

This module performs lifetime analysis to determine when variables and objects
are created, used, and destroyed. It tracks:
- Object visibility: Globally visible, externally visible, escaping objects
- Read/modify sets: Which objects are read/modified at each program point
- Scope inference: How far back on the call stack objects may propagate
- Lifetime annotations: Annotates code and operations with lifetime information

The analysis uses a database structure with schemas for efficient storage
and querying of lifetime information. It performs:
1. Object graph construction: Builds reference graph between objects
2. Visibility propagation: Determines which objects escape their scope
3. Scope inference: Determines object lifetimes across call stack
4. Read/modify analysis: Tracks which objects are read/modified
5. Annotation: Attaches lifetime information to code and operations
"""

import collections
import time

from pyflow.analysis.cpa import base
from pyflow.analysis.storegraph import storegraph
from pyflow.language.python import ast
from pyflow.language.python import annotations

from pyflow.util.PADS.StrongConnectivity import StronglyConnectedComponents

from .database import structure
from .database import tupleset
from .database import mapping
from .database import lattice

from pyflow.analysis.astcollector import getOps

contextSchema = structure.WildcardSchema()
operationSchema = structure.TypeSchema((ast.Expression, ast.Statement))
codeSchema = structure.CallbackSchema(lambda code: code.isCode())


def wrapOpContext(schema):
    """Wrap a schema with operation context mappings.
    
    Creates a nested mapping schema: code -> op -> context -> value.
    Used for operation-level dataflow information.
    
    Args:
        schema: Base schema to wrap
        
    Returns:
        MappingSchema: Wrapped schema with operation context
    """
    schema = mapping.MappingSchema(contextSchema, schema)
    schema = mapping.MappingSchema(operationSchema, schema)
    schema = mapping.MappingSchema(codeSchema, schema)
    return schema


def wrapCodeContext(schema):
    """Wrap a schema with code context mappings.
    
    Creates a nested mapping schema: code -> context -> value.
    Used for code-level dataflow information.
    
    Args:
        schema: Base schema to wrap
        
    Returns:
        MappingSchema: Wrapped schema with code context
    """
    schema = mapping.MappingSchema(contextSchema, schema)
    schema = mapping.MappingSchema(codeSchema, schema)
    return schema


opDataflowSchema = wrapOpContext(lattice.setUnionSchema)

invokesStruct = structure.StructureSchema(
    ("code", codeSchema), ("context", contextSchema)
)
invokesSchema = wrapOpContext(tupleset.TupleSetSchema(invokesStruct))

invokeSourcesStruct = structure.StructureSchema(
    ("code", codeSchema), ("operation", operationSchema), ("context", contextSchema)
)
invokeSourcesSchema = wrapCodeContext(tupleset.TupleSetSchema(invokeSourcesStruct))


def invertInvokes(invokes):
    """Invert invocation mapping to get invocation sources.
    
    Converts forward invocation mapping (caller -> callee) to backward
    mapping (callee -> caller). Used to find which call sites invoke
    a given function.
    
    Args:
        invokes: Forward invocation mapping (code, op, context) -> (dstCode, dstContext)
        
    Returns:
        Mapping: Backward mapping (dstCode, dstContext) -> (code, op, context)
    """
    invokeSources = invokeSourcesSchema.instance()

    for code, ops in invokes:
        assert code.isCode(), type(code)
        for op, contexts in ops:
            for context, invs in contexts:
                for dstCode, dstContext in invs:
                    invokeSources[dstCode][dstContext].add(code, op, context)
    return invokeSources


def filteredSCC(G):
    """Filter strongly connected components to only non-trivial ones.
    
    Finds strongly connected components (cycles) in a graph, returning
    only those with more than one node (non-trivial cycles).
    
    Args:
        G: Graph to analyze
        
    Returns:
        list: List of non-trivial strongly connected components
    """
    o = []
    for g in StronglyConnectedComponents(G):
        if len(g) > 1:
            o.append(g)
    return o


class ObjectInfo(object):
    """Information about an object's lifetime and references.
    
    ObjectInfo tracks lifetime properties for objects:
    - Reference relationships: What objects this refers to and what refers to it
    - Visibility: Whether object is globally or externally visible
    - Closure holding: Which closures may hold references to this object
    
    Attributes:
        obj: ObjectNode this info describes
        refersTo: Set of ObjectInfo for objects this object refers to
        referedFrom: Set of ObjectInfo for objects that refer to this
        localReference: Set of code objects that reference this locally
        heldByClosure: Set of ObjectInfo for closures that may hold this
        globallyVisible: Whether object is globally visible (existing objects)
        externallyVisible: Whether object is externally visible (parameters)
    """
    def __init__(self, obj):
        """Initialize object info.
        
        Args:
            obj: ObjectNode to track
        """
        self.obj = obj
        self.refersTo = set()
        self.referedFrom = set()
        self.localReference = set()
        self.heldByClosure = set()

        # Reasonable defaults
        self.globallyVisible = obj.xtype.isExisting()
        self.externallyVisible = obj.xtype.isExternal()

    def isReachableFrom(self, refs):
        """Check if this object is reachable from a set of references.
        
        Args:
            refs: Set of ObjectInfo references
            
        Returns:
            bool: True if object is held by any of the references
        """
        return bool(self.heldByClosure.intersection(refs))

    def leaks(self):
        """Check if this object leaks (escapes its scope).
        
        Returns:
            bool: True if object is globally or externally visible
        """
        return self.globallyVisible or self.externallyVisible

    def updateHeldBy(self, newHeld):
        """Update the set of closures that hold this object.
        
        Args:
            newHeld: Set of ObjectInfo for closures that may hold this
            
        Returns:
            bool: True if heldByClosure changed
            
        Raises:
            AssertionError: If object leaks (shouldn't update heldBy)
        """
        assert not self.leaks(), self.obj

        diff = newHeld - self.heldByClosure
        if diff:
            self.heldByClosure.update(diff)
            return True
        else:
            return False


class ReadModifyAnalysis(object):
    """Read/modify analysis for tracking object usage.
    
    ReadModifyAnalysis tracks which objects are read and modified at each
    program point. It propagates read/modify information through the call
    graph, filtering out objects that are killed (no longer live).
    
    Attributes:
        invokeSources: Dictionary mapping (code, context) to invocation sources
        contextReads: Dictionary mapping (code, context) to set of read objects
        contextModifies: Dictionary mapping (code, context) to set of modified objects
        opReadDB: Database mapping (code, op, context) to read sets
        opModifyDB: Database mapping (code, op, context) to modify sets
        allocations: Dictionary mapping (code, context) to allocated objects
        allReads: Set of all objects ever read
        allModifies: Set of all objects ever modified
        killed: Dictionary mapping (code, op, context) -> (dstCode, dstContext) to killed objects
    """
    def __init__(self, liveCode, invokeSources):
        """Initialize read/modify analysis.
        
        Args:
            liveCode: Set of live code objects
            invokeSources: Invocation source mapping
        """
        self.invokeSources = invokeSources

        self.contextReads = collections.defaultdict(set)
        self.contextModifies = collections.defaultdict(set)

        self.collectDB(liveCode)

    def handleModifies(self, code, op, modifies):
        if modifies[0]:
            for cindex, context in enumerate(code.annotation.contexts):
                slots = modifies[1][cindex]
                if op is not None:
                    self.opModifyDB[code][op].merge(context, slots)
                self.contextModifies[(code, context)].update(slots)
                self.allModifies.update(slots)

    def handleReads(self, code, op, reads):
        if reads[0]:
            for cindex, context in enumerate(code.annotation.contexts):
                slots = reads[1][cindex]
                filtered = set([slot for slot in slots if slot in self.allModifies])
                if op is not None:
                    self.opReadDB[code][op].merge(context, filtered)
                self.contextReads[(code, context)].update(filtered)
                self.allReads.update(slots)

    def handleAllocates(self, code, op, allocates):
        if allocates[0]:
            for cindex, context in enumerate(code.annotation.contexts):
                self.allocations[(code, context)].update(allocates[1][cindex])

    def collectDB(self, liveCode):
        """Collect read/modify/allocate information from live code.
        
        Traverses all live code and operations, collecting:
        - Read sets: Objects read at each program point
        - Modify sets: Objects modified at each program point
        - Allocations: Objects allocated at each program point
        
        Stores information in databases indexed by (code, op, context).
        
        Args:
            liveCode: Set of live code objects to process
        """
        self.allReads = set()
        self.allModifies = set()

        self.opReadDB = opDataflowSchema.instance()
        self.opModifyDB = opDataflowSchema.instance()

        self.allocations = collections.defaultdict(set)

        # Copy modifies
        for code in liveCode:
            self.handleModifies(code, None, code.annotation.codeModifies)
            ops, lcls = getOps(code)
            for op in ops:
                self.handleModifies(code, op, op.annotation.opModifies)

        # Copy reads
        for code in liveCode:
            self.handleReads(code, None, code.annotation.codeReads)
            self.handleAllocates(code, None, code.annotation.codeAllocates)

            ops, lcls = getOps(code)
            for op in ops:
                self.handleReads(code, op, op.annotation.opReads)
                self.handleAllocates(code, op, op.annotation.opAllocates)

    def process(self, killed):
        self.killed = killed
        self.processReads()
        self.processModifies()

    def processReads(self):
        """Process read sets, propagating backward through call graph.
        
        Propagates read information backward from callees to callers,
        filtering out objects that are killed (no longer live).
        """
        self.dirty = set()

        for (code, context), values in self.contextReads.items():
            if values:
                self.dirty.add((code, context))

        while self.dirty:
            current = self.dirty.pop()
            self.processContextReads(current)

    def processContextReads(self, current):
        """Process reads for a specific context.
        
        Propagates reads from current context to its invocation sources,
        filtering out killed objects.
        
        Args:
            current: (code, context) tuple to process
        """
        currentF, currentC = current

        for prev in self.invokeSources[currentF][currentC]:
            prevF, prevO, prevC = prev

            prevRead = self.opReadDB[prevF][prevO]

            killed = self.killed[(prevF, prevO, prevC)][(currentF, currentC)]

            # Propigate reads
            filtered = set(
                [
                    value
                    for value in self.contextReads[(currentF, currentC)]
                    if value.object not in killed
                ]
            )
            current = prevRead[prevC]
            diff = filtered - current if current else filtered

            if diff:
                self.contextReads[(prevF, prevC)].update(diff)
                prevRead.merge(prevC, diff)
                self.dirty.add((prevF, prevC))

    def processModifies(self):
        """Process modify sets, propagating backward through call graph.
        
        Propagates modify information backward from callees to callers,
        filtering out objects that are killed (no longer live).
        """
        self.dirty = set()

        for (code, context), values in self.contextModifies.items():
            if values:
                self.dirty.add((code, context))

        while self.dirty:
            current = self.dirty.pop()
            self.processContextModifies(current)

    def processContextModifies(self, current):
        """Process modifies for a specific context.
        
        Propagates modifies from current context to its invocation sources,
        filtering out killed objects.
        
        Args:
            current: (code, context) tuple to process
        """
        currentF, currentC = current

        for prev in self.invokeSources[currentF][currentC]:
            prevF, prevO, prevC = prev

            prevMod = self.opModifyDB[prevF][prevO]

            killed = self.killed[(prevF, prevO, prevC)][(currentF, currentC)]

            # Propigate modifies
            filtered = set(
                [
                    value
                    for value in self.contextModifies[(currentF, currentC)]
                    if value.object not in killed
                ]
            )
            # diff = filtered-self.opModifies[prev]
            current = prevMod[prevC]
            diff = filtered - current if current else filtered
            if diff:
                self.contextModifies[(prevF, prevC)].update(diff)
                prevMod.merge(prevC, diff)
                self.dirty.add((prevF, prevC))


class DFSSearcher(object):
    """Depth-first search searcher for graph traversal.
    
    Generic DFS implementation for traversing graphs. Used to traverse
    object reference graphs to build lifetime information.
    
    Attributes:
        _stack: Stack of nodes to process
        _touched: Set of nodes already visited
    """
    def __init__(self):
        """Initialize DFS searcher."""
        self._stack = []
        self._touched = set()

    def enqueue(self, *children):
        """Enqueue children for processing.
        
        Args:
            *children: Child nodes to enqueue
        """
        for child in children:
            if child not in self._touched:
                self._touched.add(child)
                self._stack.append(child)

    def process(self):
        """Process all enqueued nodes using DFS.
        
        Continues until stack is empty, visiting each node once.
        """
        while self._stack:
            current = self._stack.pop()
            self.visit(current)


class ObjectSearcher(DFSSearcher):
    """DFS searcher for building object reference graph.
    
    ObjectSearcher traverses the object reference graph, building
    refersTo and referedFrom relationships between objects.
    
    Attributes:
        la: LifetimeAnalysis instance
    """
    def __init__(self, la):
        """Initialize object searcher.
        
        Args:
            la: LifetimeAnalysis instance
        """
        DFSSearcher.__init__(self)
        self.la = la

    def visit(self, obj):
        """Visit an object and build reference relationships.
        
        For each slot in the object, follows references to other objects
        and builds bidirectional reference relationships.
        
        Args:
            obj: ObjectNode to visit
        """
        objInfo = self.la.getObjectInfo(obj)
        for slot in obj:
            for next in slot:
                nextInfo = self.la.getObjectInfo(next)
                objInfo.refersTo.add(nextInfo)
                nextInfo.referedFrom.add(objInfo)
                self.enqueue(next)


class LifetimeAnalysis(object):
    """Main lifetime analysis system.
    
    LifetimeAnalysis performs comprehensive lifetime analysis:
    1. Object graph construction: Builds reference relationships
    2. Visibility propagation: Determines escaping objects
    3. Scope inference: Determines object lifetimes across call stack
    4. Read/modify analysis: Tracks object usage
    5. Annotation: Attaches lifetime information to code
    
    Attributes:
        heapReferedToByHeap: Dictionary mapping objects to objects that refer to them
        heapReferedToByCode: Dictionary mapping objects to code that refers to them
        codeRefersToHeap: Dictionary mapping (code, context) to objects referenced
        objects: Dictionary mapping ObjectNode to ObjectInfo
        globallyVisible: Set of globally visible objects
        externallyVisible: Set of externally visible objects
        escapes: Set of escaping objects (union of globally and externally visible)
        invokes: Database mapping (code, op, context) to invoked functions
        invokeSources: Database mapping (code, context) to invocation sources
        entries: Set of entry (code, context) pairs
        live: Dictionary mapping (code, context) to live objects
        killed: Dictionary mapping (code, op, context) -> (dstCode, dstContext) to killed objects
        contextKilled: Dictionary mapping (code, context) to killed objects
        rm: ReadModifyAnalysis instance
        allocations: Dictionary mapping (code, context) to allocated objects
    """
    def __init__(self):
        """Initialize lifetime analysis."""
        self.heapReferedToByHeap = collections.defaultdict(set)
        self.heapReferedToByCode = collections.defaultdict(set)

        self.codeRefersToHeap = collections.defaultdict(set)

        self.objects = {}

        self.globallyVisible = set()
        self.externallyVisible = set()

    def getObjectInfo(self, obj):
        """Get or create ObjectInfo for an object.
        
        ObjectInfo instances are canonicalized per object.
        
        Args:
            obj: ObjectNode to get info for
            
        Returns:
            ObjectInfo: Info for the object
        """
        assert isinstance(obj, storegraph.ObjectNode), type(obj)
        if obj not in self.objects:
            info = ObjectInfo(obj)
            self.objects[obj] = info
        else:
            info = self.objects[obj]
        return info

    def findGloballyVisible(self):
        """Find all globally visible objects.
        
        Globally visible objects are existing objects (constants, globals)
        and any objects they refer to. Uses transitive closure to find
        all objects reachable from globally visible objects.
        """
        # Globally visible
        active = set()
        for info in self.objects.values():
            if info.globallyVisible:
                active.add(info)
                self.globallyVisible.add(info.obj)

        while active:
            current = active.pop()
            for ref in current.refersTo:
                if not ref.globallyVisible:
                    ref.globallyVisible = True
                    active.add(ref)
                    self.globallyVisible.add(ref.obj)

    def findExternallyVisible(self):
        """Find all externally visible objects.
        
        Externally visible objects are external objects (parameters)
        and any objects they refer to. Uses transitive closure to find
        all objects reachable from externally visible objects.
        """
        # Externally visible
        active = set()
        for info in self.objects.values():
            if info.externallyVisible:
                active.add(info)
                self.externallyVisible.add(info.obj)

        while active:
            current = active.pop()
            for ref in current.refersTo:
                if not ref.externallyVisible:
                    ref.externallyVisible = True
                    active.add(ref)
                    self.externallyVisible.add(ref.obj)

    def propagateVisibility(self):
        """Propagate visibility information and mark escaping objects.
        
        Finds globally and externally visible objects, computes escaping
        set, and annotates objects with leak information.
        """
        self.findGloballyVisible()
        self.findExternallyVisible()
        self.escapes = self.globallyVisible.union(self.externallyVisible)

        # Annotate the objects
        for info in self.objects.values():
            info.obj.leaks = info.leaks()

    def objEscapes(self, obj):
        assert not isinstance(obj, ObjectInfo), obj
        return obj in self.escapes

    def propagateHeld(self):
        dirty = set()

        for obj, info in self.objects.items():
            if not self.objEscapes(obj):
                if info.updateHeldBy(info.referedFrom):
                    for dst in info.refersTo:
                        if not self.objEscapes(dst.obj):
                            dirty.add(dst)

        while dirty:
            current = dirty.pop()
            assert not self.objEscapes(current.obj), current.obj

            # Find the new heldby
            newHeld = set()
            for prev in current.referedFrom:
                newHeld.update(prev.heldByClosure)

            if current.updateHeldBy(newHeld):
                # Mark as dirty
                for dst in current.refersTo:
                    if not self.objEscapes(dst.obj):
                        dirty.add(dst)

        # self.displayHistogram()

    def displayHistogram(self):
        # Display a histogram of the number of live heap objects
        # that may hold (directly or indirectly) a given live heap object.
        hist = collections.defaultdict(lambda: 0)
        for obj, info in self.objects.items():
            if not obj in self.escapes:
                if len(info.heldByClosure) >= 4:
                    print(obj)
                    for other in info.heldByClosure:
                        print("\t", other.obj)
                    hist[len(info.heldByClosure)] += 1
            else:
                hist[-1] += 1

        keys = sorted(hist.keys())
        for key in keys:
            print(key, hist[key])

    def inferScope(self):
        """Infer object scope (how far back on call stack objects propagate).
        
        Determines which objects are live at each program point and which
        are killed (no longer live) when crossing invocation boundaries.
        Uses iterative analysis to propagate liveness information backward
        through the call graph.
        """
        # Figure out how far back on the stack the object may propagate
        self.live = collections.defaultdict(set)
        self.killed = collections.defaultdict(lambda: collections.defaultdict(set))

        # Seed the inital dirty set
        self.dirty = set()
        for (code, context), objs in self.rm.allocations.items():
            noescape = objs - self.escapes
            self.live[(code, context)].update(noescape)
            self.dirty.update(self.invokeSources[code][context])

        while self.dirty:
            current = self.dirty.pop()
            self.processScope(current)

        self.convertKills()

    def convertKills(self):
        # Convert kills on edges to kills on nodes.
        self.contextKilled = collections.defaultdict(set)
        for dstF, contexts in self.invokeSources:
            for dstC, srcs in contexts:
                if not srcs:
                    continue

                killedAll = None
                for srcF, srcO, srcC in srcs:
                    newKilled = self.killed[(srcF, srcO, srcC)][(dstF, dstC)]
                    if killedAll is None:
                        killedAll = newKilled
                    else:
                        killedAll = killedAll.intersection(newKilled)

                if killedAll:
                    self.contextKilled[(dstF, dstC)].update(killedAll)

        for code, context in self.entries:
            self.contextKilled[(code, context)].update(self.live[(code, context)])

    def processScope(self, current):
        currentF, currentO, currentC = current
        assert currentF.isCode(), type(currentF)

        operationSchema.validate(currentO)

        newLive = set()

        live = self.live

        for dstF, dstC in self.invokes[currentF][currentO][currentC]:
            for dstLive in live[(dstF, dstC)]:
                if dstLive in live[(currentF, currentC)]:
                    continue
                if dstLive in newLive:
                    continue

                refs = self.codeRefersToHeap[(currentF, currentC)]
                refinfos = [self.getObjectInfo(ref) for ref in refs]

                # Could the object stay live?
                if dstLive in refs:
                    # Directly held
                    newLive.add(dstLive)
                elif self.getObjectInfo(dstLive).isReachableFrom(refinfos):
                    # Indirectly held
                    newLive.add(dstLive)
                else:
                    # The object will never propagate along this invocation
                    self.killed[(currentF, currentO, currentC)][(dstF, dstC)].add(
                        dstLive
                    )

        if newLive:
            # Propigate dirty
            live[(currentF, currentC)].update(newLive)
            self.dirty.update(self.invokeSources[currentF][currentC])

    def gatherInvokes(self, liveCode, entryContexts):
        invokesDB = invokesSchema.instance()

        self.entries = set()

        for code in liveCode:
            for context in code.annotation.contexts:
                if context in entryContexts:
                    self.entries.add((code, context))

            assert code.isCode(), type(code)
            ops, lcls = getOps(code)
            for op in ops:
                invokes = op.annotation.invokes
                if invokes is not None:
                    for cindex, context in enumerate(code.annotation.contexts):
                        opInvokes = invokes[1][cindex]

                        for dstF, dstC in opInvokes:
                            assert dstF.isCode(), type(dstF)
                            invokesDB[code][op][context].add(dstF, dstC)

            for lcl in lcls:
                refs = lcl.annotation.references
                if refs is None:
                    continue

                for cindex, context in enumerate(code.annotation.contexts):
                    for ref in refs[1][cindex]:
                        obj = self.getObjectInfo(ref)
                        obj.localReference.add(code)

                        self.codeRefersToHeap[(code, context)].add(ref)

        self.invokes = invokesDB
        self.invokeSources = invertInvokes(invokesDB)

    def markVisible(self, lcl, cindex):
        if lcl is not None:
            refs = lcl.annotation.references[1][cindex]
            for ref in refs:
                obj = self.getObjectInfo(ref)
                obj.externallyVisible = True

    def gatherSlots(self, liveCode, entryContexts):

        searcher = ObjectSearcher(self)

        for code in liveCode:
            callee = code.codeParameters()

            ops, lcls = getOps(code)
            for lcl in lcls:
                for ref in lcl.annotation.references[0]:
                    searcher.enqueue(ref)

            # Mark the return parameters for external contexts as visible.
            for cindex, context in enumerate(code.annotation.contexts):
                if context in entryContexts:
                    for param in callee.returnparams:
                        self.markVisible(param, cindex)

        searcher.process()

    def process(self, compiler, prgm):
        """Process lifetime analysis on a program.
        
        Main entry point for lifetime analysis. Performs:
        1. Gather slots: Build object reference graph
        2. Gather invokes: Build call graph
        3. Propagate visibility: Find escaping objects
        4. Propagate held: Find closure-held objects
        5. Infer scope: Determine object lifetimes
        6. Read/modify analysis: Track object usage
        7. Create database: Annotate code with lifetime info
        
        Args:
            compiler: Compiler instance
            prgm: Program to analyze
            
        Returns:
            LifetimeAnalysis: Self (for chaining)
        """
        with compiler.console.scope("solve"):
            entryContexts = prgm.interface.entryContexts()

            self.gatherSlots(prgm.liveCode, entryContexts)
            self.gatherInvokes(prgm.liveCode, entryContexts)

            self.propagateVisibility()
            self.propagateHeld()

            self.rm = ReadModifyAnalysis(prgm.liveCode, self.invokeSources)
            self.inferScope()
            self.rm.process(self.killed)

        with compiler.console.scope("annotate"):
            self.createDB(compiler, prgm)

        del self.rm
        return self

    def createDB(self, compiler, prgm):
        self.annotationCount = 0
        self.annotationCache = {}

        readDB = self.rm.opReadDB
        modifyDB = self.rm.opModifyDB
        self.allocations = self.rm.allocations

        for code in prgm.liveCode:
            # Annotate the code
            live = []
            killed = []
            for cindex, context in enumerate(code.annotation.contexts):
                key = (code, context)
                live.append(annotations.annotationSet(self.live[key]))
                killed.append(annotations.annotationSet(self.contextKilled[key]))

            code.rewriteAnnotation(
                live=annotations.makeContextualAnnotation(live),
                killed=annotations.makeContextualAnnotation(killed),
            )

            # Annotate the ops
            ops, lcls = getOps(code)
            for op in ops:
                # TODO is this a good HACK?
                # if not op.annotation.invokes[0]: continue

                reads = readDB[code][op]
                modifies = modifyDB[code][op]

                rout = []
                mout = []
                aout = []

                for cindex, context in enumerate(code.annotation.contexts):
                    # HACK if an operation directly reads a field, but it is never modified
                    # it still must appear in the reads annotation so cloning behaves correctly!
                    reads.merge(context, op.annotation.opReads[1][cindex])

                    creads = reads[context]
                    creads = annotations.annotationSet(creads) if creads else ()
                    rout.append(creads)

                    cmod = modifies[context]
                    cmod = annotations.annotationSet(cmod) if cmod else ()
                    mout.append(cmod)

                    kills = self.killed[(code, op, context)]

                    calloc = set()
                    for dstCode, dstContext in op.annotation.invokes[1][cindex]:
                        live = self.live[(dstCode, dstContext)]
                        killed = kills[(dstCode, dstContext)]
                        calloc.update(live - killed)

                    calloc.update(op.annotation.opAllocates[1][cindex])

                    aout.append(annotations.annotationSet(calloc))

                opReads = annotations.makeContextualAnnotation(rout)
                opModifies = annotations.makeContextualAnnotation(mout)
                opAllocates = annotations.makeContextualAnnotation(aout)

                opReads = self.annotationCache.setdefault(opReads, opReads)
                opModifies = self.annotationCache.setdefault(opModifies, opModifies)
                opAllocates = self.annotationCache.setdefault(opAllocates, opAllocates)
                self.annotationCount += 3

                op.rewriteAnnotation(
                    reads=opReads, modifies=opModifies, allocates=opAllocates
                )

        compiler.console.output(
            "Annotation compression %f - %d"
            % (
                float(len(self.annotationCache)) / max(self.annotationCount, 1),
                self.annotationCount,
            )
        )

        del self.annotationCache
        del self.annotationCount


def evaluate(compiler, prgm):
    """Run lifetime analysis on a program.
    
    Main entry point for lifetime analysis. Creates and runs a
    LifetimeAnalysis instance on the program.
    
    Args:
        compiler: Compiler instance
        prgm: Program to analyze
        
    Returns:
        LifetimeAnalysis: Analysis results
    """
    with compiler.console.scope("lifetime analysis"):
        la = LifetimeAnalysis().process(compiler, prgm)
        return la
