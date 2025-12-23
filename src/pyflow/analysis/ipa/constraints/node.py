"""Constraint node representation for IPA.

Constraint nodes represent variables, fields, and intermediate values
in the inter-procedural analysis. They maintain value sets, null flags,
and critical value tracking for escape analysis.
"""

from pyflow.language.python import ast  # Debugging
from . import split
from ..calling import cpa
from ..model import objectname


class Critical(object):
    """Tracks critical values for escape analysis.
    
    Critical values are values that must be tracked precisely because
    they may escape their scope. This class maintains critical value sets
    and propagates them through the constraint graph.
    
    Attributes:
        values: Set of critical values (frozen)
        diff: Pending critical value changes (to be propagated)
        isCritical: Whether this node itself is critical
        _dirty: Whether critical values have changed
        node: ConstraintNode this critical belongs to
    """
    __slots__ = "values", "diff", "isCritical", "_dirty", "node"

    def __init__(self, context, node):
        """Initialize critical value tracking.
        
        Args:
            context: Context this critical belongs to
            node: ConstraintNode this critical belongs to
        """
        self.node = node
        cm = self.getManager(context)
        self.values = cm.empty()
        self.diff = cm.empty()
        self.isCritical = False
        self._dirty = False

    def getManager(self, context):
        return context.analysis.criticalmanager

    def markDirty(self, context, node):
        assert node is self.node

        if not self._dirty:
            assert node not in context.dirtycriticals
            self._dirty = True
            context.dirtyCritical(node, self)

    def propagate(self, context, node):
        assert node is self.node

        assert node not in context.dirtycriticals
        assert self._dirty, node
        self._dirty = False

        cm = self.getManager(context)
        diff = self.diff
        self.values = cm.inplaceUnion(self.values, diff)
        self.diff = cm.empty()

        for constraint in node.next:
            constraint.criticalChanged(context, node, diff)

    def updateValues(self, context, node, values):
        assert node is self.node

        cm = self.getManager(context)
        diff = cm.tempDiff(values, self.values)

        if diff:
            if node.next:
                self.diff = cm.inplaceUnion(self.diff, diff)
                self.markDirty(context, node)
            else:
                assert not self.diff
                self.values = cm.inplaceUnion(self.values, diff)

    def updateSingleValue(self, context, node, value):
        assert node is self.node
        cm = self.getManager(context)
        if value not in self.values and value not in self.diff:
            diff = cm.coerce([value])
            self.updateValues(context, node, diff)

    def markCritical(self, context, node):
        assert node is self.node
        if not self.isCritical:
            self.isCritical = True
            self.updateSingleValue(context, node, node.name)


class ConstraintNode(object):
    """Represents a variable, field, or intermediate value in IPA.
    
    ConstraintNodes are the fundamental units of data flow in IPA. They
    maintain:
    - Value sets: Set of ObjectNames that may flow to this node
    - Null flag: Whether this node may be null
    - Constraints: Connected via prev/next lists
    - Splits: Type-based and exact splits for call resolution
    - Flags: Escape flags and other metadata
    - Critical values: Values that must be tracked for escape analysis
    
    Attributes:
        context: Context this node belongs to
        name: Variable/field name (ast.Local, tuple, etc.)
        ci: Whether this is a context-insensitive node
        values: Set of ObjectNames (frozen, current values)
        valuediff: Pending value changes (to be propagated)
        null: Whether this node may be null
        dirty: Whether this node needs propagation
        prev: List of constraints that read from this node
        next: List of constraints that write to this node
        typeSplit: TypeSplitConstraint for type-based splitting
        exactSplit: ExactSplitConstraint for exact splitting
        flags: Escape flags and metadata
        flagsdiff: Pending flag changes
        critical: Critical value tracker
    """
    __slots__ = (
        "context",
        "name",
        "ci",
        "values",
        "valuediff",
        "null",
        "dirty",
        "prev",
        "next",
        "typeSplit",
        "exactSplit",
        "flags",
        "flagsdiff",
        "critical",
    )

    def __init__(self, context, name, ci=False):
        """Initialize a constraint node.
        
        Args:
            context: Context this node belongs to
            name: Variable/field name (ast.Local, tuple, etc.)
            ci: Whether this is context-insensitive
        """
        assert not isinstance(name, ast.DoNotCare), name

        self.context = context
        self.name = name
        self.ci = ci

        self.next = []
        self.prev = []

        # Value flow
        self.values = context.analysis.valuemanager.empty()
        self.valuediff = context.analysis.valuemanager.empty()

        self.null = False

        self.dirty = False

        self.typeSplit = None
        self.exactSplit = None

        # Flag flow
        self.flags = 0
        self.flagsdiff = 0

        self.critical = Critical(context, self)

    def clearFlags(self):
        self.flags = 0
        self.flagsdiff = 0

    def updateFlags(self, flags):
        diff = ~self.flags & flags
        new = self.flagsdiff | diff
        if new != self.flagsdiff:
            self.flagsdiff = new
            if not self.dirty:
                self.dirty = True
                self.context.dirtyFlags(self)

    def attachTypeSplit(self, callback):
        if self.typeSplit is None:
            self.typeSplit = split.TypeSplitConstraint(self)
            self.context.constraint(self.typeSplit)
        self.typeSplit.addSplitCallback(callback)

    def getFiltered(self, typeFilter):
        if typeFilter is cpa.anyType:
            return self
        else:
            return self.typeSplit.objects[typeFilter]

    def attachExactSplit(self, callback):
        if self.exactSplit is None:
            self.exactSplit = split.ExactSplitConstraint(self)
            self.context.constraint(self.exactSplit)
        self.exactSplit.addSplitCallback(callback)

    def addNext(self, constraint):
        self.next.append(constraint)

    def addPrev(self, constraint):
        self.prev.append(constraint)

    def markDirty(self):
        if not self.dirty:
            self.dirty = True
            self.context.dirtySlot(self)

    def updateValues(self, values):
        vm = self.context.analysis.valuemanager
        # Not retained, so set manager is not used
        diff = vm.tempDiff(values, self.values)

        if diff:
            for value in diff:
                assert value.isObjectName(), value

            if self.next:
                self.valuediff = vm.inplaceUnion(self.valuediff, diff)
                self.markDirty()
            else:
                assert not self.valuediff
                self.values = vm.inplaceUnion(self.values, diff)
            return True
        else:
            return False

    def updateSingleValue(self, value):
        assert value.isObjectName(), value
        if value not in self.values and value not in self.valuediff:
            vm = self.context.analysis.valuemanager
            diff = vm.coerce([value])

            if self.next:
                self.valuediff = vm.inplaceUnion(self.valuediff, diff)
                self.markDirty()
            else:
                assert not self.valuediff
                self.values = vm.inplaceUnion(self.values, diff)
            return True
        else:
            return False

    def markNull(self):
        if not self.null:
            self.null = True
            if self.next:
                # HACK this is an expensive way of communicating with the
                # few consumers that care.  Fortunately, this is rare.
                self.markDirty()

    def clearNull(self):
        # Can only be done before the node is observed.
        assert not self.next
        self.null = False

    def propagate(self):
        assert self.dirty
        self.dirty = False

        # Update the sets of objects
        # Must be done before any callback is performed, as a
        # cyclic dependency could update these values
        vm = self.context.analysis.valuemanager
        diff = self.valuediff
        self.values = vm.inplaceUnion(self.values, diff)
        self.valuediff = vm.empty()

        for constraint in self.next:
            constraint.changed(self.context, self, diff)

    def __repr__(self):
        return "slot(%r/%d)" % (self.name, id(self))

    def isNode(self):
        return True
