"""Store graph data structures for PyFlow analysis.

The store graph is the foundational data structure for all PyFlow analyses.
It represents:
- Objects: Abstract objects in memory (ObjectNode)
- Slots: Storage locations (locals, fields) (SlotNode)
- Regions: Groups of objects (RegionNode)
- StoreGraph: Root graph containing all slots and regions

The store graph uses union-find (via MergableNode) to merge equivalent
nodes during analysis, enabling efficient representation of aliasing
and object relationships.

Key concepts:
- MergableNode: Base class with union-find for node merging
- StoreGraph: Root graph managing slots and regions
- RegionNode: Groups objects by region (for region-based analysis)
- ObjectNode: Represents abstract objects with fields
- SlotNode: Represents storage locations (locals, attributes, array elements)
"""

from . import extendedtypes
from . import setmanager
from . import annotations

# HACK for assertions
from pyflow.language.python import program


class MergableNode(object):
    """Base class for nodes that can be merged during analysis.
    
    Uses union-find data structure to efficiently merge equivalent nodes.
    When nodes are merged, they point to a canonical representative via
    the forward pointer. This enables efficient alias analysis and object
    merging.
    
    Attributes:
        forward: Pointer to canonical representative (None if self is canonical)
    """
    __slots__ = "forward"

    def __init__(self):
        """Initialize a mergable node."""
        self.forward = None

    def getForward(self):
        """Get the canonical representative of this node.
        
        Follows forward pointers to find the canonical node, performing
        path compression for efficiency.
        
        Returns:
            MergableNode: Canonical representative
        """
        if self.forward:
            forward = self.forward.getForward()
            self.forward = forward
            return forward
        else:
            return self

    def setForward(self, other):
        """Set this node to point to another (for merging).
        
        Args:
            other: Node to point to
            
        Raises:
            AssertionError: If forward pointer already set
        """
        assert self.forward is None
        assert other.forward is None
        self.forward = other

    def isObjectContext(self):
        """Check if this is an object context node.
        
        Returns:
            bool: True if ObjectNode
        """
        return False

    def isSlot(self):
        """Check if this is a slot node.
        
        Returns:
            bool: True if SlotNode
        """
        return False

    def isObject(self):
        """Check if this is an object node.
        
        Returns:
            bool: True if ObjectNode
        """
        return False


# This corresponds to a group of nodes, such as in a function or in a program,
# depending on how the analysis works.
class StoreGraph(MergableNode):
    """Root store graph managing all slots and regions.
    
    StoreGraph is the root of the store graph structure. It manages:
    - Root slots: Local variables and references to existing objects
    - Regions: Groups of objects (for region-based analysis)
    - Set operations: Efficient set management for object sets
    - Type information: Type pointer and length slot names
    
    StoreGraphs can represent entire programs or individual functions,
    depending on the analysis scope.
    
    Attributes:
        slots: Dictionary mapping SlotName to SlotNode (root slots)
        regionHint: Default region for new objects
        setManager: CachedSetManager for efficient set operations
        extractor: Program extractor for accessing objects
        canonical: CanonicalObjects for canonical naming
        typeSlotName: Canonical name for type pointer field
        lengthSlotName: Canonical name for length field
    """
    __slots__ = (
        "slots",
        "regionHint",
        "setManager",
        "extractor",
        "canonical",
        "typeSlotName",
        "lengthSlotName",
    )

    def __init__(self, extractor, canonical):
        """Initialize a store graph.
        
        Args:
            extractor: Program extractor for accessing objects
            canonical: CanonicalObjects for canonical naming
        """
        MergableNode.__init__(self)

        # Root slots, such as locals and references to "existing" objects
        self.slots = {}
        self.regionHint = RegionNode(self)
        self.setManager = setmanager.CachedSetManager()
        self.extractor = extractor
        self.canonical = canonical

        # HACK this should be centeralized?
        self.typeSlotName = self.canonical.fieldName(
            "LowLevel", self.extractor.getObject("type")
        )
        self.lengthSlotName = self.canonical.fieldName(
            "LowLevel", self.extractor.getObject("length")
        )

    def existingSlotRef(self, xtype, slotName):
        assert xtype.isExisting()
        assert not slotName.isRoot()

        obj = xtype.obj
        assert isinstance(obj, program.AbstractObject), obj
        self.extractor.ensureLoaded(obj)

        slottype, key = slotName.type, slotName.name
        assert isinstance(key, program.AbstractObject), key

        if isinstance(obj, program.Object):
            if slottype == "LowLevel":
                subdict = obj.lowlevel
            elif slottype == "Attribute":
                subdict = obj.slot
            elif slottype == "Array":
                # HACK
                if isinstance(obj.pyobj, list):
                    return set(
                        [self.canonical.existingType(t) for t in obj.array.values()]
                    )

                subdict = obj.array
            elif slottype == "Dictionary":
                subdict = obj.dictionary
            else:
                assert False, slottype

            if key in subdict:
                return (self.canonical.existingType(subdict[key]),)

        # Not found
        return None

    def setTypePointer(self, obj):
        xtype = obj.xtype

        if not xtype.isExisting():
            # Makes sure the type pointer is valid.
            self.extractor.ensureLoaded(xtype.obj)

            # Get the type object
            typextype = self.canonical.existingType(xtype.obj.type)

            field = obj.field(self.typeSlotName, self.regionHint)
            field.initializeType(typextype)

    def root(self, slotName, regionHint=None):
        self = self.getForward()

        if slotName not in self.slots:
            assert slotName.isRoot(), slotName
            region = self.regionHint if regionHint is None else regionHint
            root = SlotNode(None, slotName, region, self.setManager.empty())
            self.slots[slotName] = root
            return root
        else:
            # TODO merge region?
            return self.slots[slotName]

    def __iter__(self):
        return iter(self.slots.values())

    def removeObservers(self):
        processed = set()
        for slot in self:
            slot.removeObservers(processed)


class RegionNode(MergableNode):
    """Represents a region grouping objects together.
    
    Regions group objects for region-based analysis. Objects in the same
    region are considered related (e.g., allocated in the same context).
    Regions can be merged when objects from different regions are aliased.
    
    Attributes:
        objects: Dictionary mapping ExtendedType to ObjectNode
        group: StoreGraph this region belongs to
        weight: Weight for region merging heuristics
    """
    __slots__ = "objects", "group", "weight"

    def __init__(self, group):
        """Initialize a region node.
        
        Args:
            group: StoreGraph this region belongs to
        """
        assert group is not None
        MergableNode.__init__(self)

        self.group = group

        self.objects = {}
        self.weight = 0

    def merge(self, other):
        self = self.getForward()
        other = other.getForward()

        if self != other:
            other.setForward(self)

            objects = other.objects
            other.objects = None

            for xtype, obj in objects.items():
                if xtype in self.objects:
                    self.objects[xtype] = self.objects[xtype].merge(obj)
                else:
                    self.objects[xtype] = obj

                self = self.getForward()

        return self

    def object(self, xtype):
        self = self.getForward()

        if xtype not in self.objects:
            obj = ObjectNode(self, xtype)
            self.objects[xtype] = obj

            # Note this is done after setting the dictionary,
            # as this call can recurse.
            self.group.setTypePointer(obj)

            return obj
        else:
            return self.objects[xtype]

    def __iter__(self):
        self = self.getForward()
        return self.objects.values()


class ObjectNode(MergableNode):
    """Represents an abstract object in the store graph.
    
    ObjectNode represents an abstract object with its fields (slots).
    Objects can be merged when they alias. Fields are accessed by
    SlotName (field type and name).
    
    Attributes:
        region: RegionNode this object belongs to
        xtype: ExtendedType for this object
        slots: Dictionary mapping SlotName to SlotNode (fields)
        leaks: Whether this object may leak (escape analysis)
        annotation: ObjectAnnotation with analysis results
    """
    __slots__ = "region", "xtype", "slots", "leaks", "annotation"

    def __init__(self, region, xtype):
        """Initialize an object node.
        
        Args:
            region: RegionNode this object belongs to
            xtype: ExtendedType for this object
        """
        MergableNode.__init__(self)

        assert isinstance(xtype, extendedtypes.ExtendedType), type(xtype)
        self.region = region
        self.xtype = xtype
        self.slots = {}
        self.leaks = True

        self.annotation = annotations.emptyObjectAnnotation

    def merge(self, other):
        self = self.getForward()
        other = other.getForward()

        if self != other:
            other.setForward(self)

            slots = other.slots
            other.slots = None

            for fieldName, field in slots.items():
                if fieldName in self.slots:
                    self.slots[fieldName] = self.slots[fieldName].merge(field)
                else:
                    self.slots[fieldName] = field

                self = self.getForward()

        self.region = self.region.getForward()
        return self

    def field(self, slotName, regionHint):
        if slotName not in self.slots:
            assert not slotName.isRoot()

            if regionHint is None:
                assert False
                region = RegionNode(self.region.group)
            else:
                region = regionHint

            group = region.group
            field = SlotNode(self, slotName, region, group.setManager.empty())
            self.slots[slotName] = field

            if self.xtype.isExisting():
                ref = group.existingSlotRef(self.xtype, slotName)
                if ref is not None:
                    field.initializeTypes(ref)
            return field
        else:
            # TODO merge region?
            return self.slots[slotName]

    def knownField(self, slotName):
        return self.slots[slotName]

    def __iter__(self):
        return iter(self.slots.values())

    def __repr__(self):
        return "obj(%r, %r)" % (self.xtype, id(self.region))

    def removeObservers(self, processed):
        self = self.getForward()
        if self not in processed:
            processed.add(self)

            for ref in self:
                ref.removeObservers(processed)

    def isObjectContext(self):
        return True

    def isObject(self):
        return True

    def rewriteAnnotation(self, **kwds):
        self.annotation = self.annotation.rewrite(**kwds)


class SlotNode(MergableNode):
    """Represents a storage location (local variable or object field).
    
    SlotNode represents a storage location that can hold references to
    objects. Slots maintain:
    - refs: Set of ExtendedTypes that may flow to this slot
    - null: Whether this slot may be null
    - observers: Constraints that depend on this slot (for propagation)
    
    Slots can be:
    - Root slots: Local variables or existing object references
    - Field slots: Object attributes, array elements, etc.
    
    Attributes:
        object: ObjectNode this slot belongs to (None for root slots)
        slotName: SlotName identifying this slot
        region: RegionNode for objects referenced by this slot
        refs: Frozen set of ExtendedTypes (object references)
        null: Whether this slot may be null
        observers: List of constraints observing this slot
        annotation: FieldAnnotation with analysis results
    """
    __slots__ = (
        "object",
        "slotName",
        "region",
        "refs",
        "null",
        "observers",
        "annotation",
    )

    def __init__(self, object, slot, region, refs):
        """Initialize a slot node.
        
        Args:
            object: ObjectNode this slot belongs to (None for root slots)
            slot: SlotName identifying this slot
            region: RegionNode for referenced objects
            refs: Initial set of ExtendedTypes (typically empty)
        """
        MergableNode.__init__(self)

        self.object = object
        self.slotName = slot
        self.region = region
        self.refs = refs
        self.null = True
        self.observers = []

        self.annotation = annotations.emptyFieldAnnotation

    def merge(self, other):
        self = self.getForward()
        other = other.getForward()

        if self != other:
            other.setForward(self)

            refs = other.refs
            other.refs = None

            observers = other.observers
            other.observers = None

            # May merge
            self.region = self.region.merge(other.region)
            self = self.getForward()

            group = self.region.group
            sdiff = group.setManager.diff(refs, self.refs)
            odiff = group.setManager.diff(self.refs, refs)

            if sdiff or (not self.null and other.null):
                self._update(sdiff)

            self.observers.extend(observers)

            if odiff or (self.null and not other.null):
                for o in observers:
                    o.mark()

            # Merge flags
            self.null |= other.null

        self.region = self.region.getForward()
        self.object = self.object.getForward()

        return self

    def initializeTypes(self, xtypes):
        for xtype in xtypes:
            self.initializeType(xtype)

    def initializeType(self, xtype):
        assert isinstance(xtype, extendedtypes.ExtendedType), type(xtype)

        self = self.getForward()

        # TODO use diffTypeSet from canonicalSlots?
        if xtype not in self.refs:
            self._update(frozenset((xtype,)))
            self.null = False

        # Ensure the object exists
        return self.region.object(xtype)

    def update(self, other):
        self = self.getForward()

        if self.region != other.region:
            self.region = self.region.merge(other.region)

            self = self.getForward()
            self.region = self.region.getForward()

            other = other.getForward()
            other.region = other.region.getForward()

        assert self.region == other.region, (self.region, other.region)

        group = self.region.group
        diff = group.setManager.diff(other.refs, self.refs)
        if diff:
            self._update(diff)

        return self

    def _update(self, diff):
        group = self.region.group
        self.refs = group.setManager.inplaceUnion(self.refs, diff)
        for o in self.observers:
            o.mark()

    def dependsRead(self, constraint):
        self = self.getForward()
        self.observers.append(constraint)
        if self.refs:
            constraint.mark()

    def dependsWrite(self, constraint):
        self = self.getForward()
        self.observers.append(constraint)
        if self.refs:
            constraint.mark()

    def __iter__(self):
        self = self.getForward()

        # HACK use setManager.iter?
        for xtype in self.refs:
            yield self.region.object(xtype)

    def __repr__(self):
        self = self.getForward()

        xtype = None if self.object is None else self.object.xtype
        return "slot(%r, %r)" % (xtype, self.slotName)

    def removeObservers(self, processed):
        self = self.getForward()
        if self not in processed:
            processed.add(self)
            self.observers = []

            for ref in self:
                ref.removeObservers(processed)

    def isSlot(self):
        return True

    def rewriteAnnotation(self, **kwds):
        self.annotation = self.annotation.rewrite(**kwds)
