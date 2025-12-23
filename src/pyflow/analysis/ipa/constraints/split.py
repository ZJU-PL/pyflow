"""Split constraints for IPA.

Split constraints split values by type or exact object identity.
They enable context-sensitive analysis by creating separate constraint
nodes for different types/objects, allowing different calling contexts
to be analyzed separately.
"""

from pyflow.language.python import ast
from .base import Constraint
from ..calling import cpa


class Splitter(Constraint):
    """Base class for split constraints.
    
    Splitters split a source node into multiple destination nodes based
    on some criteria (type or exact object). Callbacks are notified when
    splits change (enabling call graph updates).
    
    Attributes:
        src: Source constraint node
        dst: List of destination constraint nodes (one per split)
        callbacks: List of callbacks to notify when splits change
    """
    def __init__(self, src):
        """Initialize splitter.
        
        Args:
            src: Source ConstraintNode to split
        """
        assert src.isNode(), src
        self.src = src
        self.dst = []
        self.callbacks = []

    def addSplitCallback(self, callback):
        self.callbacks.append(callback)
        if self.objects:
            callback()

    def attach(self):
        self.src.addNext(self)

    def localName(self):
        return "split_temp"

    def makeTarget(self, context):
        lcl = context.local(ast.Local(self.localName()))
        lcl.addPrev(self)
        self.dst.append(lcl)
        return lcl

    def makeConsistent(self, context):
        # Make constraint consistent
        if self.src.values:
            self.changed(context, self.src, self.src.values)

        if self.src.critical.values:
            self.criticalChanged(context, self.src, self.src.critical.values)

    def criticalChanged(self, context, node, diff):
        for dst in self.dst:
            dst.critical.updateValues(context, dst, diff)

    def doNotify(self):
        for callback in self.callbacks:
            callback()

    def isSplit(self):
        return True


class TypeSplitConstraint(Splitter):
    """Splits values by CPA type.
    
    TypeSplitConstraint creates separate constraint nodes for each
    CPA type that flows to the source. This enables type-based context
    sensitivity: different types get different analysis contexts.
    
    If too many types appear (>= 4), becomes megamorphic and collapses
    to a single node with anyType.
    
    Attributes:
        objects: Dictionary mapping CPA type to destination node
        megamorphic: Whether this split is megamorphic (too many types)
    """
    def __init__(self, src):
        """Initialize type split constraint.
        
        Args:
            src: Source ConstraintNode to split by type
        """
        Splitter.__init__(self, src)
        self.objects = {}
        self.megamorphic = False

    def localName(self):
        return "type_split_temp"

    def types(self):
        return self.objects.keys()

    def makeMegamorphic(self):
        assert not self.megamorphic
        self.megamorphic = True
        self.objects.clear()
        self.objects[cpa.anyType] = self.src
        self.doNotify()

    def changed(self, context, node, diff):
        if self.megamorphic:
            return

        changed = False
        for obj in diff:
            cpaType = obj.cpaType()

            if cpaType not in self.objects:
                if len(self.objects) >= 4:
                    self.makeMegamorphic()
                    break
                else:
                    temp = self.makeTarget(context)
                    self.objects[cpaType] = temp
                    changed = True
            else:
                temp = self.objects[cpaType]

            temp.updateSingleValue(obj)
        else:
            if changed:
                self.doNotify()


# TODO prevent over splitting?  All objects with the same qualifier should be grouped?
class ExactSplitConstraint(Splitter):
    """Splits values by exact object identity.
    
    ExactSplitConstraint creates separate constraint nodes for each
    exact object that flows to the source. This enables object-sensitive
    analysis: different objects get different analysis contexts.
    
    Note: This can create many splits. Consider using TypeSplitConstraint
    for better scalability.
    
    Attributes:
        objects: Dictionary mapping ObjectName to destination node
    """
    def __init__(self, src):
        """Initialize exact split constraint.
        
        Args:
            src: Source ConstraintNode to split by exact object
        """
        Splitter.__init__(self, src)
        self.objects = {}

    def localName(self):
        return "exact_split_temp"

    def changed(self, context, node, diff):
        changed = False
        for obj in diff:
            if obj not in self.objects:
                temp = self.makeTarget(context)
                self.objects[obj] = temp
                changed = True
            else:
                temp = self.objects[obj]

            temp.updateSingleValue(obj)

        if changed:
            self.doNotify()
