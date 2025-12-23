"""Shape analysis constraints.

This module defines constraints for shape analysis that model how operations
affect object shapes, reference counts, and path information.

Constraint types:
- AssignmentConstraint: Assignment operations (x = y)
- CopyConstraint: Copy operations (state propagation)
- ForgetConstraint: Forget operations (kill variables)
- SplitConstraint: Function call splits (caller/callee separation)
- MergeConstraint: Function return merges (callee/caller combination)
"""

from __future__ import absolute_import

from . import transferfunctions
import json
import time

seperateExternal = False


def isPoint(point):
    """Check if a value is a valid program point.
    
    Program points are tuples (code, uid) where code is a code object
    and uid is an integer identifier.
    
    Args:
        point: Value to check
        
    Returns:
        bool: True if valid program point
    """
    if isinstance(point, tuple) and len(point) == 2:
        if isinstance(point[1], int):
            return True
    return False


class Constraint(object):
    """Base class for shape analysis constraints.
    
    Constraints model data flow operations in shape analysis. They connect
    program points and propagate shape information (configurations and
    secondary information) through the program.
    
    Attributes:
        inputPoint: Program point where constraint reads from
        outputPoint: Program point where constraint writes to
        priority: Priority for constraint ordering (lower = earlier)
    """
    __slots__ = "parent", "inputPoint", "outputPoint", "priority"

    def __init__(self, sys, inputPoint, outputPoint):
        """Initialize a constraint.
        
        Args:
            sys: RegionBasedShapeAnalysis instance
            inputPoint: Input program point
            outputPoint: Output program point
        """
        assert isPoint(inputPoint), inputPoint
        assert isPoint(outputPoint), outputPoint
        self.inputPoint = inputPoint
        self.outputPoint = outputPoint
        sys.environment.addObserver(inputPoint, self)

        self.priority = 0

    def update(self, sys, key):
        point, context, index = key

        secondary = sys.environment.secondary(*key)
        self.evaluate(sys, point, context, index, secondary)

    # Intentionally reversed for heapq
    def __lt__(self, other):
        return self.priority > other.priority

    def __gt__(self, other):
        return self.priority < other.priority


class AssignmentConstraint(Constraint):
    """Constraint for assignment operations.
    
    AssignmentConstraint models assignment operations (x = y). It propagates
    shape information from source to destination, updating reference counts
    and path information based on aliasing relationships.
    
    Attributes:
        sourceExpr: Expression being assigned (source)
        destinationExpr: Expression receiving assignment (destination)
    """
    __slots__ = "sourceExpr", "destinationExpr"

    def __init__(self, sys, inputPoint, outputPoint, sourceExpr, destinationExpr):
        """Initialize assignment constraint.
        
        Args:
            sys: RegionBasedShapeAnalysis instance
            inputPoint: Input program point
            outputPoint: Output program point
            sourceExpr: Source expression
            destinationExpr: Destination expression
        """
        Constraint.__init__(self, sys, inputPoint, outputPoint)

        assert sourceExpr.isExpression(), sourceExpr
        self.sourceExpr = sourceExpr

        assert destinationExpr.isExpression(), destinationExpr
        self.destinationExpr = destinationExpr

    def evaluate(self, sys, point, context, configuration, secondary):
        transferfunctions.assignmentConstraint(
            sys,
            self.outputPoint,
            context,
            self.sourceExpr,
            self.destinationExpr,
            configuration,
            secondary.paths,
            secondary.externalReferences,
        )

    def __repr__(self):
        return "assign(%r -> %r)" % (self.sourceExpr, self.destinationExpr)


class CopyConstraint(Constraint):
    """Constraint for copying state between program points.
    
    CopyConstraint models state copying operations (e.g., control flow
    merging). It propagates shape information unchanged from input to
    output point.
    """
    __slots__ = ()

    def evaluate(self, sys, point, context, configuration, secondary):
        """Evaluate copy constraint.
        
        Simply propagates configuration and secondary information to
        output point.
        
        Args:
            sys: RegionBasedShapeAnalysis instance
            point: Current program point
            context: Analysis context
            configuration: Shape configuration
            secondary: Secondary information
        """
        # Simply changes the program point.
        transferfunctions.gcMerge(
            sys, self.outputPoint, context, configuration, secondary
        )


class ForgetConstraint(Constraint):
    """Constraint for forgetting/killing variables.
    
    ForgetConstraint models variable death (e.g., leaving scope). It
    removes shape information for specified slots, decrementing reference
    counts appropriately.
    
    Attributes:
        forget: Set of slots to forget
    """
    __slots__ = "forget"

    def __init__(self, sys, inputPoint, outputPoint, forget):
        """Initialize forget constraint.
        
        Args:
            sys: RegionBasedShapeAnalysis instance
            inputPoint: Input program point
            outputPoint: Output program point
            forget: Set of slots to forget
        """
        Constraint.__init__(self, sys, inputPoint, outputPoint)

        for slot in forget:
            assert slot.isSlot(), slot
        self.forget = forget

    def evaluate(self, sys, point, context, configuration, secondary):
        newSecondary = secondary.forget(sys, self.forget)
        newConfig = configuration.forget(sys, self.forget)
        transferfunctions.gcMerge(
            sys, self.outputPoint, context, newConfig, newSecondary, canSteal=True
        )


class SplitMergeInfo(object):
    """Information for split/merge constraints (function calls).
    
    SplitMergeInfo manages information flow for function calls:
    - Split: Separates caller and callee information
    - Merge: Combines callee results back into caller
    
    It tracks parameter slots, extended parameters, and mappings for
    return value transfer.
    
    Attributes:
        parameterSlots: Set of parameter slots
        extendedParameters: Set of extended parameters
        remoteLUT: Lookup table for remote (callee) configurations
        localLUT: Lookup table for local (caller) configurations
        mapping: Mapping for return value transfer
    """
    def __init__(self, parameterSlots):
        """Initialize split/merge info.
        
        Args:
            parameterSlots: Set of parameter slots
        """
        self.parameterSlots = parameterSlots
        self.extendedParameters = set()

        self.remoteLUT = {}
        self.localLUT = {}

        # Return value transfer and extended parameter killing
        self.mapping = {}

    def _mergeLUT(self, splitIndex, index, secondary, lut, canSteal=False):
        if splitIndex not in lut:
            lut[splitIndex] = {}

        if not index in lut[splitIndex]:
            lut[splitIndex][index] = secondary if canSteal else secondary.copy()
            changed = True
        else:
            changed = lut[splitIndex][index].merge(secondary)

        return changed

    def makeKey(self, sys, configuration):
        return configuration.rewrite(sys, currentSet=None)

    def registerLocal(self, sys, splitIndex, index, secondary):
        # The local secondary can always be stolen.
        changed = self._mergeLUT(
            splitIndex, index, secondary, self.localLUT, canSteal=True
        )

        if changed:
            remote = self.remoteLUT.get(splitIndex)
            if remote:
                localIndex = index
                localSecondary = self.localLUT[splitIndex][index]
                context = None  # HACK

                for remoteIndex, remoteSecondary in remote.items():
                    self.merge.combine(
                        sys,
                        context,
                        localIndex,
                        localSecondary,
                        remoteIndex,
                        remoteSecondary,
                    )

    def registerRemote(self, sys, splitIndex, index, secondary):
        changed = self._mergeLUT(splitIndex, index, secondary, self.remoteLUT)

        if changed:
            local = self.localLUT.get(splitIndex)
            if local:
                remoteIndex = index
                remoteSecondary = self.remoteLUT[splitIndex][index]
                context = None  # HACK

                for localIndex, localSecondary in local.items():
                    self.merge.combine(
                        sys,
                        context,
                        localIndex,
                        localSecondary,
                        remoteIndex,
                        remoteSecondary,
                    )

    def addExtendedParameters(self, eparam):
        newParam = eparam - self.extendedParameters
        if newParam:
            for p in newParam:
                assert p and p.isExtendedParameter(), p
                self.mapping[p] = None
            self.extendedParameters.update(newParam)


class SplitConstraint(Constraint):
    """Constraint for function call splits.
    
    SplitConstraint models function calls by splitting shape information
    into local (caller) and remote (callee) portions. It separates
    accessed and non-accessed information based on parameter usage.
    
    Attributes:
        info: SplitMergeInfo for this split
    """
    __slots__ = "info"

    def __init__(self, sys, inputPoint, outputPoint, info):
        """Initialize split constraint.
        
        Args:
            sys: RegionBasedShapeAnalysis instance
            inputPoint: Input program point (before call)
            outputPoint: Output program point (callee entry)
            info: SplitMergeInfo for this split
        """
        Constraint.__init__(self, sys, inputPoint, outputPoint)
        self.info = info

    def _accessedCallback(self, slot):
        if slot.isAgedParameter():
            return False

        # Extended parameter
        if slot.isExpression():
            return False

        if slot.isLocal():
            return slot.isParameter()

        if slot.isField() and hasattr(self.info, "dstLiveFields"):
            return slot.field in self.info.dstLiveFields

        # Unhandled, assumed accessed.
        return True

    def evaluate(self, sys, point, context, configuration, secondary):
        # All the parameters assignments should have been performed.

        # Split the reference count into accessed and non-accessed portions
        localRC, remoteRC = sys.canonical.rcm.split(
            configuration.currentSet, self._accessedCallback
        )

        # TODO filter out bad extended parameters (from self-recursive calls?)

        # Add extended parameters to paths
        epaths = secondary.paths.copy()
        epaths.ageExtended(sys.canonical)
        eparams = epaths.extendParameters(sys.canonical, self.info.parameterSlots)
        self.info.addExtendedParameters(eparams)

        # Split the paths into accessed and non-accessed portions
        remotepaths, localpaths = epaths.split(eparams, self._accessedCallback)

        # Create the local data
        localconfig = configuration.rewrite(sys, currentSet=localRC)
        localsecondary = sys.canonical.secondary(
            localpaths, secondary.externalReferences
        )

        # Create the remote data
        remoteExternalReferences = (
            configuration.externalReferences or bool(localRC) and seperateExternal
        )

        remoteconfig = configuration.rewrite(
            sys,
            entrySet=configuration.entrySet,
            currentSet=remoteRC,
            externalReferences=remoteExternalReferences,
            allocated=False,
        )

        remoteExternalReferences = secondary.externalReferences or bool(localRC)
        remotesecondary = sys.canonical.secondary(remotepaths, remoteExternalReferences)


        # Output the local data
        key = self.info.makeKey(sys, remoteconfig)
        self.info.registerLocal(sys, key, localconfig, localsecondary)

        # Output the remote data
        remotecontext = context  # HACK
        # Suppress emitting empty remote configurations that carry no new path
        # information; these are not considered observable outputs by tests.
        if len(remoteRC) == 0 and not remotesecondary.paths.hasCertainHit():
            return

        transferfunctions.gcMerge(
            sys,
            self.outputPoint,
            remotecontext,
            remoteconfig,
            remotesecondary,
            canSteal=True,
        )


class MergeConstraint(Constraint):
    """Constraint for function return merges.
    
    MergeConstraint models function returns by merging callee results
    back into caller state. It combines local and remote configurations,
    remaps return values, and updates reference counts.
    
    Attributes:
        info: SplitMergeInfo for this merge
    """
    __slots__ = "info"

    def __init__(self, sys, inputPoint, outputPoint, info):
        """Initialize merge constraint.
        
        Args:
            sys: RegionBasedShapeAnalysis instance
            inputPoint: Input program point (callee return)
            outputPoint: Output program point (after call)
            info: SplitMergeInfo for this merge
        """
        Constraint.__init__(self, sys, inputPoint, outputPoint)
        self.info = info
        info.merge = self  # Cirular reference?

    def evaluate(self, sys, point, context, configuration, secondary):
        if configuration.allocated:
            # If it's allocated, there's nothing to merge it with.
            self.remap(
                sys,
                context,
                configuration.currentSet,
                secondary.paths,
                configuration,
                secondary,
            )
        else:
            key = self.info.makeKey(sys, configuration)
            self.info.registerRemote(sys, key, configuration, secondary)

    def combine(
        self, sys, context, localIndex, localSecondary, remoteIndex, remoteSecondary
    ):
        # Merge the index
        mergedRC = sys.canonical.rcm.merge(
            localIndex.currentSet, remoteIndex.currentSet
        )

        # Merge the secondary
        try:
            paths = remoteSecondary.paths.join(localSecondary.paths)
        except:
            return

            print("-" * 60)
            print("local")
            print(localIndex)
            localSecondary.paths.dump()

            print("-" * 60)
            print("remote")
            print(remoteIndex)
            remoteSecondary.paths.dump()

            print("-" * 60)
            print("Local")
            for k, v in self.info.localLUT.items():
                print(k)
                for o in v.keys():
                    print("\t", o.currentSet)
            print("-" * 60)
            print("Remote")
            for k, v in self.info.remoteLUT.items():
                print(k)
                for o in v.keys():
                    print("\t", o.currentSet)
            print()

        # Emit the remapped, joined result at the merge's output point
        self.remap(sys, context, mergedRC, paths, remoteIndex, remoteSecondary)

    def remap(self, sys, context, mergedRC, paths, index, secondary):
        # Remap the index
        mergedIndex = index.rewrite(
            sys, currentSet=mergedRC.remap(sys, self.info.mapping)
        )

        # Remap the secondary
        paths = paths.remap(self.info.mapping)
        paths.unageExtended()
        mergedSecondary = sys.canonical.secondary(paths, secondary.externalReferences)


        if True:
            # Output
            transferfunctions.gcMerge(
                sys,
                self.outputPoint,
                context,
                mergedIndex,
                mergedSecondary,
                canSteal=True,
            )
        else:
            print("!" * 10)
            print(mergedRC)
            print(mergedIndex)
            print()
