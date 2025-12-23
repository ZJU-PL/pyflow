"""Data Flow Intermediate Representation (IR) graph structures.

This module provides the core data structures for representing data flow
in PyFlow's analysis system. The dataflow IR is a graph-based representation
that models:

- **Slots**: Storage locations (local variables, fields, predicates)
- **Operations**: Data flow operations (reads, writes, merges, splits, gates)
- **Hyperblocks**: Regions of code with shared control flow
- **Predicates**: Control flow conditions that gate operations

Key concepts:
- **Flow-sensitive slots**: Slots that can have different values in different
  control flow paths (LocalNode, FieldNode)
- **Flow-insensitive slots**: Slots with single values (ExistingNode, NullNode)
- **Operations**: Nodes that transform data (GenericOp, Merge, Split, Gate)
- **Entry/Exit**: Special operations marking function entry and exit points

The dataflow IR enables precise analysis of data flow properties including
read/modify sets, value propagation, and control flow dependencies.
"""

from pyflow.language.python import ast


class Hyperblock(object):
    """Represents a hyperblock (region) in the dataflow graph.
    
    A hyperblock represents a region of code where control flow is shared.
    Operations within the same hyperblock execute under the same control
    flow conditions. Hyperblocks are used to group operations and enable
    efficient analysis of control flow dependencies.
    
    Attributes:
        name: Unique identifier for this hyperblock
    """
    __slots__ = "name"

    def __init__(self, name):
        """Initialize a hyperblock.
        
        Args:
            name: Unique identifier (typically an integer)
        """
        self.name = name

    def __repr__(self):
        """String representation for debugging.
        
        Returns:
            str: Representation of the hyperblock
        """
        return "hyperblock(%s)" % str(self.name)


class DataflowNode(object):
    """Base class for all nodes in the dataflow graph.
    
    All nodes in the dataflow IR inherit from this class. Nodes can be
    either slots (storage locations) or operations (data transformations).
    
    Attributes:
        hyperblock: Hyperblock this node belongs to (None for global nodes)
        _annotation: Analysis annotation attached to this node
    """
    __slots__ = "hyperblock", "_annotation"

    def __init__(self, hyperblock):
        """Initialize a dataflow node.
        
        Args:
            hyperblock: Hyperblock this node belongs to (or None for global)
        """
        assert hyperblock is None or isinstance(hyperblock, Hyperblock), type(
            hyperblock
        )
        self.hyperblock = hyperblock
        self._annotation = None

    @property
    def canonicalpredicate(self):
        raise NotImplementedError(type(self))

    def isOp(self):
        return False

    def isSlot(self):
        return False

    def getAnnotation(self):
        return self._annotation

    def setAnnotation(self, value):
        self._annotation = value

    annotation = property(getAnnotation, setAnnotation)


class SlotNode(DataflowNode):
    """Base class for slot nodes (storage locations).
    
    Slots represent storage locations in the dataflow graph. They can be:
    - Local variables (LocalNode)
    - Object fields (FieldNode)
    - Predicates (PredicateNode)
    - Existing objects (ExistingNode)
    - Null values (NullNode)
    
    Slots maintain def-use chains:
    - addDefn/removeDefn: Track defining operations
    - addUse/removeUse: Track using operations
    
    Subclasses implement different slot behaviors (flow-sensitive vs
    flow-insensitive, mutable vs immutable, etc.).
    """
    __slots__ = ()

    def addUse(self, op):
        """Add a use of this slot by an operation.
        
        Args:
            op: Operation node using this slot
            
        Returns:
            SlotNode: The slot (may be modified or duplicated)
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(type(self))

    def removeUse(self, op):
        """Remove a use of this slot by an operation.
        
        Args:
            op: Operation node no longer using this slot
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(type(self))

    def addDefn(self, op):
        """Add a definition of this slot by an operation.
        
        Args:
            op: Operation node defining this slot
            
        Returns:
            SlotNode: The slot (may be modified)
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(type(self))

    def removeDefn(self, op):
        """Remove a definition of this slot by an operation.
        
        Args:
            op: Operation node no longer defining this slot
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(type(self))

    def canonical(self):
        """Get the canonical version of this slot.
        
        Some slots may have aliases or splits. This returns the canonical
        representative for analysis purposes.
        
        Returns:
            SlotNode: The canonical slot (may be self)
        """
        return self

    def mustBeUnique(self):
        """Check if this slot must have a unique definition.
        
        Some slots (like locals) can only have one definition per path.
        Others (like fields) can have multiple definitions.
        
        Returns:
            bool: True if slot must have unique definition
        """
        return True

    def isLocal(self):
        """Check if this is a local variable slot.
        
        Returns:
            bool: True if this is a LocalNode
        """
        return False

    def isField(self):
        """Check if this is a field slot.
        
        Returns:
            bool: True if this is a FieldNode
        """
        return False

    def isPredicate(self):
        """Check if this is a predicate slot.
        
        Returns:
            bool: True if this is a PredicateNode
        """
        return False

    def isNull(self):
        """Check if this is a null slot.
        
        Returns:
            bool: True if this is a NullNode
        """
        return False

    def isExisting(self):
        """Check if this is an existing object slot.
        
        Returns:
            bool: True if this is an ExistingNode
        """
        return False

    def definingOp(self):
        """Get the operation that defines this slot.
        
        Returns:
            OpNode or None: The defining operation, or None if not defined
        """
        return None

    def isEntryNode(self):
        """Check if this slot is defined at function entry.
        
        Returns:
            bool: True if slot is defined by Entry operation
        """
        return False

    def isSlot(self):
        """Type check: this is a slot node.
        
        Returns:
            bool: Always True for SlotNode instances
        """
        return True


class FlowSensitiveSlotNode(SlotNode):
    """Base class for flow-sensitive slot nodes.
    
    Flow-sensitive slots can have different values in different control
    flow paths. They maintain:
    - defn: Single defining operation (SSA-like)
    - use: Single using operation (or Split if multiple uses)
    
    When multiple uses occur, a Split node is automatically inserted
    to handle the fan-out. This maintains SSA-like properties while
    allowing efficient representation.
    
    Examples: LocalNode, FieldNode, PredicateNode
    
    Attributes:
        defn: Operation defining this slot (or None)
        use: Operation using this slot (or Split if multiple uses, or None)
    """
    __slots__ = "defn", "use"

    def __init__(self, hyperblock):
        """Initialize a flow-sensitive slot.
        
        Args:
            hyperblock: Hyperblock this slot belongs to
        """
        SlotNode.__init__(self, hyperblock)
        self.defn = None
        self.use = None

    def addDefn(self, op):
        # HACK should we allow redundant setting, or force a merge?
        assert self.defn is None or self.defn is op, (self, op)
        self.defn = op
        return self

    def removeDefn(self, op):
        assert self.defn is op
        self.defn = None

    def addUse(self, op):
        if self.use is None:
            self.use = op
            return self
        elif self.defn.isSplit():
            # This slot is the product of a split, pass the use on
            # to the original.  This prevents us from having more than
            # one level of split.
            return self.defn.read.addUse(op)
        else:
            if not self.use.isSplit():
                # Redirect the current use
                dup = self.duplicate()
                dup.use = self.use
                self.use.replaceUse(self, dup)

                # Replace the current use with a split
                split = Split(self.hyperblock)
                split.read = self
                split.addModify(dup)
                self.use = split

            # Use is a split

            # Redirect to the output of the split.
            dup = self.duplicate().addUse(op)
            assert self.use.isSplit()
            self.use.addModify(dup)

            return dup

    def removeUse(self, op):
        assert self.use is op
        self.use = None

    def redirect(self, other):
        other = other.canonical()

        if self.use is not None and self.use.isSplit():
            # Reach past the split
            # Copy, just in case
            nodes = tuple(self.use.modifies)
        else:
            nodes = (self,)

        for node in nodes:
            if node.use:
                node.use.replaceUse(node, other.addUse(node.use))
                node.use = None

    def forward(self):
        if self.use is not None:
            return (self.use,)
        else:
            return ()

    def reverse(self):
        assert self.defn is not None, self
        return (self.defn,)

    def canonical(self):
        if isinstance(self.defn, Split):
            return self.defn.read.canonical()
        else:
            return self

    def isUse(self, op):
        return op is self.use, (op, self.use)

    def isDefn(self, op):
        return op is self.defn, (op, self.defn)

    def isMutable(self):
        return True

    def definingOp(self):
        if isinstance(self.defn, Split):
            return self.defn.read.definingOp()
        else:
            return self.defn

    def isEntryNode(self):
        return self.canonical().defn.isEntry()

    def getAnnotation(self):
        return self.canonical()._annotation

    def setAnnotation(self, value):
        self.canonical()._annotation = value

    annotation = property(getAnnotation, setAnnotation)


class LocalNode(FlowSensitiveSlotNode):
    """Slot node for local variables.
    
    LocalNode represents local variables in the dataflow graph. It's
    flow-sensitive, meaning it can have different values in different
    control flow paths. Multiple AST Local nodes may map to the same
    LocalNode if they represent the same variable.
    
    Attributes:
        names: List of AST Local nodes that map to this dataflow node
    """
    __slots__ = "names"

    def __init__(self, hyperblock, names=()):
        """Initialize a local node.
        
        Args:
            hyperblock: Hyperblock for this local
            names: Initial list of AST Local nodes
        """
        FlowSensitiveSlotNode.__init__(self, hyperblock)
        self.names = [name for name in names]

    def addName(self, name):
        """Add an AST Local node to this dataflow node.
        
        Multiple AST locals may map to the same dataflow node if they
        represent the same variable.
        
        Args:
            name: AST Local node to add
        """
        # assert isinstance(name, ast.Local), name
        if name not in self.names:
            self.names.append(name)

    def duplicate(self):
        """Duplicate this local node.
        
        Creates a new LocalNode with shared names list. Used when
        splitting or creating new versions of a local.
        
        Returns:
            LocalNode: New local node
            
        Note:
            HACK: Shares the names list, so updates are visible to all versions.
            This is intentional for maintaining name consistency.
        """
        node = LocalNode(self.hyperblock)
        # HACK shares the names, so any updates will be seen by all versions of the node.
        node.names = self.names
        node.annotation = self.annotation
        return node

    def __repr__(self):
        """String representation for debugging.
        
        Returns:
            str: Representation showing local names
        """
        return "lcl(%s)" % ", ".join([repr(name) for name in self.names])

    def isLocal(self):
        """Type check: this is a local variable slot.
        
        Returns:
            bool: Always True for LocalNode instances
        """
        return True


class PredicateNode(FlowSensitiveSlotNode):
    """Slot node for predicates (control flow conditions).
    
    PredicateNode represents control flow conditions that gate operations.
    Predicates are flow-sensitive and can be merged and split like other
    slots. They're used to represent which control flow path is taken.
    
    Attributes:
        name: Name/identifier for this predicate
    """
    __slots__ = "name"

    def __init__(self, hyperblock, name):
        """Initialize a predicate node.
        
        Args:
            hyperblock: Hyperblock for this predicate
            name: Name/identifier for the predicate
        """
        FlowSensitiveSlotNode.__init__(self, hyperblock)
        self.name = name

    def duplicate(self):
        """Duplicate this predicate node.
        
        Returns:
            PredicateNode: New predicate node with same name
        """
        node = PredicateNode(self.hyperblock, self.name)
        node.annotation = self.annotation
        return node

    def __repr__(self):
        """String representation for debugging.
        
        Returns:
            str: Representation showing predicate name
        """
        return "pred(%s)" % self.name

    def isPredicate(self):
        """Type check: this is a predicate slot.
        
        Returns:
            bool: Always True for PredicateNode instances
        """
        return True

    @property
    def source(self):
        """Get the operation that defines this predicate.
        
        Returns:
            OpNode: Operation defining the predicate
        """
        return self.canonical().defn


class ExistingNode(SlotNode):
    """Slot node for existing objects (constants, globals).
    
    ExistingNode represents objects that exist before function entry
    (constants, globals, etc.). These are flow-insensitive - they have
    a single value throughout the function. They're canonicalized:
    the same object always returns the same ExistingNode.
    
    Attributes:
        name: Python object this node represents
        ref: Reference annotation from CPA analysis
        uses: List of operations using this existing object
    """
    __slots__ = "name", "ref", "uses"

    def __init__(self, name, ref):
        """Initialize an existing node.
        
        Args:
            name: Python object (program.Object)
            ref: Reference annotation from CPA
        """
        SlotNode.__init__(self, None)
        self.name = name
        self.ref = ref
        self.uses = []

    def addName(self, name):
        """Add an AST Existing node (for consistency with other slots).
        
        Args:
            name: AST Existing node (may be called when copying to local)
        """
        # May get called when an existing is copied to a local?
        if isinstance(name, ast.Existing):
            obj = name.object
            if self.name is None:
                self.name = obj
            else:
                assert self.name is obj

    def addUse(self, op):
        """Add a use of this existing object.
        
        Args:
            op: Operation using this object
            
        Returns:
            ExistingNode: Self (existing nodes are canonicalized)
        """
        self.uses.append(op)
        return self

    def removeUse(self, op):
        """Remove a use of this existing object.
        
        Args:
            op: Operation no longer using this object
        """
        self.uses.remove(op)

    def duplicate(self):
        """Duplicate this existing node (returns self - canonicalized).
        
        Returns:
            ExistingNode: Self (existing nodes are shared)
        """
        return self

    def __repr__(self):
        """String representation for debugging.
        
        Returns:
            str: Representation showing object
        """
        return "exist(%r)" % self.name

    def forward(self):
        """Get all operations using this object.
        
        Returns:
            list: List of operations using this existing object
        """
        return self.uses

    def reverse(self):
        """Get definitions (none for existing objects).
        
        Returns:
            tuple: Empty tuple (existing objects have no definitions)
        """
        return ()

    def isUse(self, op):
        """Check if an operation uses this object.
        
        Args:
            op: Operation to check
            
        Returns:
            bool: True if operation uses this object
        """
        return op in self.uses

    def isMutable(self):
        """Check if this object is mutable (always False for existing).
        
        Returns:
            bool: Always False (existing objects are immutable)
        """
        return False

    def isExisting(self):
        """Type check: this is an existing object slot.
        
        Returns:
            bool: Always True for ExistingNode instances
        """
        return True


class NullNode(SlotNode):
    __slots__ = "defn", "uses"

    def __init__(self):
        SlotNode.__init__(self, None)
        self.defn = None
        self.uses = []

    def addName(self, name):
        pass

    def addDefn(self, op):
        assert op.isEntry(), op
        assert self.defn is None
        self.defn = op
        return self

    def addUse(self, op):
        self.uses.append(op)
        return self

    def removeUse(self, op):
        self.uses.remove(op)

    def duplicate(self):
        return self

    def __repr__(self):
        return "null()"

    def forward(self):
        return self.uses

    def reverse(self):
        return ()

    def isUse(self, op):
        return op in self.uses

    def isMutable(self):
        return False

    def isNull(self):
        return True


class FieldNode(FlowSensitiveSlotNode):
    """Slot node for object fields.
    
    FieldNode represents fields of objects (attributes, array elements, etc.).
    Fields are flow-sensitive and can have different values in different
    control flow paths. Unlike locals, fields don't require unique definitions
    (multiple stores can write to the same field).
    
    Attributes:
        name: Field identifier (SlotNode from store graph)
    """
    __slots__ = "name"

    def __init__(self, hyperblock, name):
        """Initialize a field node.
        
        Args:
            hyperblock: Hyperblock for this field
            name: Field identifier (SlotNode)
        """
        FlowSensitiveSlotNode.__init__(self, hyperblock)
        self.name = name

    def addName(self, name):
        """Add a field name (for consistency).
        
        Args:
            name: Field identifier (must match existing name if set)
        """
        if self.name is None:
            self.name = name
        else:
            assert self.name is name, (self.name, name)

    def duplicate(self):
        """Duplicate this field node.
        
        Returns:
            FieldNode: New field node with same name
        """
        node = FieldNode(self.hyperblock, self.name)
        node.annotation = self.annotation
        return node

    def __repr__(self):
        """String representation for debugging.
        
        Returns:
            str: Representation showing field name
        """
        return "field(%r)" % self.name

    def mustBeUnique(self):
        """Check if field must have unique definition (False for fields).
        
        Fields can have multiple definitions (stores), unlike locals.
        
        Returns:
            bool: Always False (fields allow multiple definitions)
        """
        return False

    def isField(self):
        """Type check: this is a field slot.
        
        Returns:
            bool: Always True for FieldNode instances
        """
        return True


class OpNode(DataflowNode):
    """Base class for operation nodes in the dataflow graph.
    
    Operations represent transformations of data in the dataflow graph.
    They read from slots (inputs) and write to slots (outputs). Different
    operation types handle different transformations:
    - Entry: Function entry point
    - Exit: Function exit point
    - GenericOp: General operations (calls, loads, stores, etc.)
    - Merge: Combine values from multiple paths
    - Split: Fan out a value to multiple uses
    - Gate: Conditionally pass a value based on predicate
    """
    __slots__ = ()

    def isMerge(self):
        """Check if this is a merge operation.
        
        Returns:
            bool: True if this is a Merge node
        """
        return False

    def isSplit(self):
        """Check if this is a split operation.
        
        Returns:
            bool: True if this is a Split node
        """
        return False

    def isBranch(self):
        """Check if this is a branch operation.
        
        Returns:
            bool: True if this is a branch (TypeSwitch, Switch)
        """
        return False

    def isPredicateOp(self):
        """Check if this operation works with predicates.
        
        Returns:
            bool: True if operation manipulates predicates
        """
        return False

    def isEntry(self):
        """Check if this is an entry operation.
        
        Returns:
            bool: True if this is an Entry node
        """
        return False

    def isExit(self):
        """Check if this is an exit operation.
        
        Returns:
            bool: True if this is an Exit node
        """
        return False

    @property
    def canonicalpredicate(self):
        """Get the canonical predicate for this operation.
        
        Returns:
            PredicateNode or None: Canonical predicate, or None if no predicate
        """
        return None

    def isOp(self):
        """Type check: this is an operation node.
        
        Returns:
            bool: Always True for OpNode instances
        """
        return True


class PredicatedOpNode(OpNode):
    __slots__ = "predicate"

    def __init__(self, hyperblock):
        OpNode.__init__(self, hyperblock)
        self.predicate = None

    def setPredicate(self, p):
        assert p.hyperblock is self.hyperblock, (self.hyperblock, p.hyperblock)

        if self.predicate is not None:
            self.predicate.removeUse(self)

        self.predicate = p

        if self.predicate is not None:
            self.predicate = self.predicate.addUse(self)

    @property
    def canonicalpredicate(self):
        return self.predicate.canonical()


class Entry(OpNode):
    """Entry operation representing function entry point.
    
    The Entry node defines initial values for function parameters,
    existing objects, and fields. It has no inputs (reverse() returns empty)
    and outputs all entry values (forward() returns all modified slots).
    
    Attributes:
        modifies: Dictionary mapping variable names to their entry slot nodes
    """
    __slots__ = "modifies"

    def __init__(self, hyperblock):
        """Initialize entry operation.
        
        Args:
            hyperblock: Hyperblock for this entry
        """
        OpNode.__init__(self, hyperblock)
        self.modifies = {}

    def addEntry(self, name, slot):
        """Add an entry value definition.
        
        Defines a variable at function entry (e.g., parameters).
        
        Args:
            name: Variable name (ast.Local, ast.Existing, or SlotNode)
            slot: SlotNode to define at entry
            
        Raises:
            AssertionError: If name already has an entry
        """
        assert name not in self.modifies, name
        slot = slot.addDefn(self)
        self.modifies[name] = slot
        # self.sanityCheck()

    def removeEntry(self, name, slot):
        """Remove an entry value definition.
        
        Args:
            name: Variable name to remove
            slot: SlotNode being removed
        """
        slot.removeDefn(self)
        del self.modifies[name]

    def __repr__(self):
        """String representation for debugging.
        
        Returns:
            str: "entry()"
        """
        return "entry()"

    def forward(self):
        """Get all output slots (entry values).
        
        Returns:
            list: All slots defined at entry
        """
        return self.modifies.values()

    def reverse(self):
        """Get all input slots (none for entry).
        
        Returns:
            tuple: Empty tuple (entry has no inputs)
        """
        return ()

    def sanityCheck(self):
        """Verify entry structure integrity.
        
        Checks that all modified slots have this entry as their definition.
        """
        for slot in self.modifies.values():
            assert slot.isDefn(self)

    def isEntry(self):
        """Type check: this is an entry operation.
        
        Returns:
            bool: Always True for Entry instances
        """
        return True


class Exit(PredicatedOpNode):
    __slots__ = "reads"

    def __init__(self, hyperblock):
        PredicatedOpNode.__init__(self, hyperblock)
        self.reads = {}

    def addExit(self, name, slot):
        assert name not in self.reads
        slot = slot.addUse(self)
        self.reads[name] = slot
        # self.sanityCheck()

    def removeExit(self, name, slot):
        slot.removeUse(self)
        del self.reads[name]

    def __repr__(self):
        return "exit()"

    def forward(self):
        return ()

    def reverse(self):
        return [self.predicate] + self.reads.values()

    def sanityCheck(self):
        for slot in self.reads.values():
            assert slot.isUse(self)

    def isExit(self):
        return True

    def replaceUse(self, original, replacement):
        assert original is not None
        assert replacement is not None

        if self.predicate is original:
            self.predicate = replacement
        else:
            name = None
            for k, v in self.reads.items():
                if v is original:
                    name = k
                    break
            assert name is not None, name
            self.reads[name] = replacement

    def filterUses(self, callback):
        reads = {}
        for name, slot in self.reads.items():
            if callback(name, slot):
                reads[name] = slot
            else:
                slot.removeUse(self)
        self.reads = reads


class Gate(PredicatedOpNode):
    """Gate operation that conditionally passes a value.
    
    A Gate operation passes a value through only when its predicate is true.
    It reads a value and a predicate, and outputs a gated value. Gates are
    used to represent conditional values in the dataflow graph (e.g., values
    that depend on control flow conditions).
    
    Attributes:
        read: Input slot (value to gate)
        modify: Output slot (gated value)
        predicate: PredicateNode controlling the gate
    """
    __slots__ = "read", "modify"

    def __init__(self, hyperblock):
        """Initialize gate operation.
        
        Args:
            hyperblock: Hyperblock for this gate
        """
        PredicatedOpNode.__init__(self, hyperblock)
        self.read = None
        self.modify = None

    def isPredicateOp(self):
        """Check if this gate operates on predicates.
        
        Returns:
            bool: True if read slot is a predicate
        """
        return self.read.isPredicate()

    def addRead(self, slot):
        """Add input value to gate.
        
        Args:
            slot: SlotNode to gate
            
        Raises:
            AssertionError: If read already set
        """
        assert self.read is None
        slot = slot.addUse(self)
        assert self.read is None
        self.read = slot

    def addModify(self, slot):
        """Add output value from gate.
        
        Args:
            slot: SlotNode for gated output
            
        Raises:
            AssertionError: If modify already set
        """
        assert self.modify is None
        slot = slot.addDefn(self)
        assert self.modify is None
        self.modify = slot

    def replaceUse(self, original, replacement):
        """Replace a use (read or predicate).
        
        Args:
            original: Original slot node
            replacement: Replacement slot node
        """
        if self.predicate is original:
            self.predicate = replacement
        else:
            assert self.read is original
            self.read = replacement

    def replaceDefn(self, original, replacement):
        """Replace definition (modify slot).
        
        Args:
            original: Original modify slot
            replacement: Replacement modify slot
        """
        assert self.modify is original
        self.modify = replacement

    def __repr__(self):
        """String representation for debugging.
        
        Returns:
            str: Representation showing read and predicate
        """
        return "gate(%r, %r)" % (self.read, self.predicate)

    def forward(self):
        """Get output slots.
        
        Returns:
            tuple: Single-element tuple containing modify slot
        """
        return (self.modify,)

    def reverse(self):
        """Get input slots.
        
        Returns:
            tuple: Tuple containing read slot and predicate
        """
        assert self.read is not None
        return (self.read, self.predicate)


class Merge(OpNode):
    """Merge operation combining values from multiple paths.
    
    A Merge operation combines values from multiple control flow paths.
    It reads from multiple slots (one per path) and outputs a single merged
    value. Merges are used at control flow join points to combine values
    from different branches.
    
    Merge operations are typically gated - each input comes from a Gate
    operation that gates the value by its path's predicate.
    
    Attributes:
        reads: List of input slots (one per path)
        modify: Output slot (merged value)
    """
    __slots__ = "reads", "modify"

    def __init__(self, hyperblock):
        """Initialize merge operation.
        
        Args:
            hyperblock: Hyperblock for this merge
        """
        OpNode.__init__(self, hyperblock)
        self.reads = []
        self.modify = None

    def isMerge(self):
        """Type check: this is a merge operation.
        
        Returns:
            bool: Always True for Merge instances
        """
        return True

    def isPredicateOp(self):
        """Check if this merge operates on predicates.
        
        Returns:
            bool: True if merging predicates
        """
        return self.reads[0].isPredicate()

    def addRead(self, slot):
        """Add an input value to merge.
        
        Args:
            slot: SlotNode from one control flow path
            
        Note:
            Input slots must be from different hyperblocks (different paths)
        """
        assert slot.hyperblock is not self.hyperblock
        slot = slot.addUse(self)
        self.reads.append(slot)
        # self.sanityCheck()

    def addModify(self, slot):
        """Add output value from merge.
        
        Args:
            slot: SlotNode for merged output
            
        Note:
            Output slot must be in same hyperblock as merge
        """
        assert self.modify is None
        assert slot.hyperblock is self.hyperblock
        slot = slot.addDefn(self)
        self.modify = slot
        # self.sanityCheck()

    def replaceUse(self, original, replacement):
        hit = replaceList(self.reads, original, replacement)
        assert hit, original
        # self.sanityCheck()

    def replaceDefn(self, original, replacement):
        assert self.modify is original
        self.modify = replacement
        # self.sanityCheck()

    def __repr__(self):
        return "merge(%r, %d)" % (self.modify, len(self.reads))

    def forward(self):
        assert self.modify is not None
        return (self.modify,)

    def reverse(self):
        return self.reads

    def sanityCheck(self):
        assert self.modify not in self.reads

        for slot in self.reads:
            assert slot.isUse(self)

        assert self.modify.isDefn(self)


class Split(OpNode):
    """Split operation fanning out a value to multiple uses.
    
    A Split operation takes a single value and fans it out to multiple uses.
    It's automatically inserted when a flow-sensitive slot has multiple uses,
    maintaining SSA-like properties while allowing efficient representation.
    
    Splits can be optimized away when they have only one output (replaced
    with direct connection).
    
    Attributes:
        read: Input slot (value to split)
        modifies: List of output slots (one per use)
    """
    __slots__ = "read", "modifies"

    def __init__(self, hyperblock):
        """Initialize split operation.
        
        Args:
            hyperblock: Hyperblock for this split
        """
        OpNode.__init__(self, hyperblock)
        self.read = None
        self.modifies = []

    def isSplit(self):
        """Type check: this is a split operation.
        
        Returns:
            bool: Always True for Split instances
        """
        return True

    def isPredicateOp(self):
        """Check if this split operates on predicates.
        
        Returns:
            bool: True if read slot is a predicate
        """
        return self.read.isPredicate()

    def addRead(self, slot):
        """Add input value to split.
        
        Args:
            slot: SlotNode to split
            
        Raises:
            AssertionError: If read already set
        """
        assert self.read is None
        slot = slot.addUse(self)
        self.read = slot
        # self.sanityCheck()

    def addModify(self, slot):
        """Add an output value from split.
        
        Args:
            slot: SlotNode for one output use
        """
        slot = slot.addDefn(self)
        self.modifies.append(slot)
        # self.sanityCheck()

    def replaceUse(self, original, replacement):
        """Replace input use.
        
        Args:
            original: Original read slot
            replacement: Replacement read slot
        """
        assert self.read is original
        self.read = replacement
        # self.sanityCheck()

    def replaceDefn(self, original, replacement):
        """Replace an output definition.
        
        Args:
            original: Original modify slot
            replacement: Replacement modify slot
        """
        hit = replaceList(self.modifies, original, replacement)
        assert hit, original
        # self.sanityCheck()

    def __repr__(self):
        """String representation for debugging.
        
        Returns:
            str: Representation showing read and number of outputs
        """
        return "split(%r, %d)" % (self.read, len(self.modifies))

    def forward(self):
        """Get output slots.
        
        Returns:
            list: All modify slots (outputs)
        """
        return self.modifies

    def reverse(self):
        """Get input slots.
        
        Returns:
            tuple: Single-element tuple containing read slot
        """
        assert self.read is not None
        return (self.read,)

    def optimize(self):
        """Optimize split if it has only one output.
        
        If split has only one output, removes the split and connects
        input directly to output.
        
        Returns:
            SlotNode: Optimized slot (may be self if not optimized)
        """
        if len(self.modifies) == 1:
            new = self.read
            old = self.modifies[0]
            old.use.replaceUse(old, new)
            new.use = old.use

            self.read = None
            self.modifies = []
            return new
        else:
            return self

    def sanityCheck(self):
        assert self.read not in self.modifies

        assert self.read.isUse(self)

        for slot in self.modifies:
            assert slot.isDefn(self)


def replaceList(l, original, replacement):
    if original in l:
        index = l.index(original)
        l[index] = replacement
        return True
    else:
        return False


class GenericOp(PredicatedOpNode):
    __slots__ = (
        "op",
        "localReads",
        "localModifies",
        "heapReads",
        "heapModifies",
        "heapPsedoReads",
        "predicates",
    )

    def __init__(self, hyperblock, op):
        PredicatedOpNode.__init__(self, hyperblock)
        self.op = op
        self.reset()

    def reset(self):
        # Inputs
        self.predicate = None
        self.localReads = {}
        self.heapReads = {}
        self.heapModifies = {}
        self.heapPsedoReads = {}

        # Outputs
        self.localModifies = []
        self.predicates = []

    def destroy(self):
        self.predicate.removeUse(self)

        for slot in self.localReads.values():
            slot.removeUse(self)

        for slot in self.heapReads.values():
            slot.removeUse(self)

        for slot in self.heapPsedoReads.values():
            slot.removeUse(self)

        for slot in self.localModifies:
            slot.removeDefn(self)

        for slot in self.heapModifies.values():
            slot.removeDefn(self)

        for slot in self.predicates:
            slot.removeDefn(self)

        self.reset()

    def isBranch(self):
        return isinstance(self.op, (ast.TypeSwitch, ast.Switch))

    def isTypeSwitch(self):
        return isinstance(self.op, ast.TypeSwitch)

    def isLoad(self):
        return isinstance(self.op, ast.Load)

    def isStore(self):
        return isinstance(self.op, ast.Store)

    def replaceUse(self, original, replacement):
        if isinstance(original, PredicateNode):
            assert original is self.predicate
            self.predicate = replacement
        elif isinstance(original, (LocalNode, ExistingNode)):
            assert isinstance(replacement, (LocalNode, ExistingNode)), replacement

            # We can't simply check the game, as bizarre transforms may result in mis-named nodes.
            for name, value in self.localReads.items():
                if value is original:
                    # Found it
                    break
            else:
                # Did not find
                assert False, (original, self.localReads)

            self.localReads[name] = replacement
        else:

            if original.name in self.heapReads:
                self.heapReads[original.name] = replacement
            else:
                assert original.name in self.heapPsedoReads
                self.heapPsedoReads[original.name] = replacement
        # self.sanityCheck()

    def replaceDef(self, original, replacement):
        if isinstance(original, (LocalNode, ExistingNode)):
            assert isinstance(replacement, (LocalNode, ExistingNode)), replacement
            hit = replaceList(self.localModifies, original, replacement)
            assert hit, original
        else:
            assert original.name in self.heapModifies
            self.heapModifies[original.name] = replacement
        # self.sanityCheck()

    def addLocalRead(self, name, slot):
        assert isinstance(slot, (LocalNode, ExistingNode)), slot
        if name in self.localReads:
            assert self.localReads[name].canonical() is slot.canonical()
        else:
            slot = slot.addUse(self)
            self.localReads[name] = slot
        # self.sanityCheck()

    def addLocalModify(self, name, slot):
        assert isinstance(slot, LocalNode), slot
        slot = slot.addDefn(self)
        self.localModifies.append(slot)
        # self.sanityCheck()

    def addRead(self, name, slot):
        assert not isinstance(slot, (LocalNode, ExistingNode)), slot
        assert name not in self.heapReads
        slot = slot.addUse(self)
        self.heapReads[name] = slot
        # self.sanityCheck()

    def addModify(self, name, slot):
        assert not isinstance(slot, (LocalNode, ExistingNode)), slot
        assert name not in self.heapModifies
        slot = slot.addDefn(self)
        self.heapModifies[name] = slot
        # self.sanityCheck()

    def addPsedoRead(self, name, slot):
        assert not isinstance(slot, (LocalNode, ExistingNode)), slot
        assert name not in self.heapPsedoReads
        slot = slot.addUse(self)
        self.heapPsedoReads[name] = slot
        # self.sanityCheck()

    def __repr__(self):
        if self.predicates:
            return "op(%s)" % self.op.__class__.__name__
        else:
            return "op(%r)" % self.op

    def forward(self):
        return self.localModifies + self.heapModifies.values() + self.predicates

    def reverse(self):
        return (
            [self.predicate]
            + self.localReads.values()
            + self.heapReads.values()
            + self.heapPsedoReads.values()
        )

    def sanityCheck(self):
        for slot in self.localReads.values():
            assert slot.isUse(self)
        for slot in self.heapReads.values():
            assert slot.isUse(self)
        for slot in self.heapPsedoReads.values():
            assert slot.isUse(self)

        for slot in self.localModifies:
            assert slot.isDefn(self)
        for slot in self.heapModifies.values():
            assert slot.isDefn(self)


def refFromExisting(node):
    assert node.annotation.references, node
    return node.annotation.references.merged[0]


class DataflowGraph(object):
    """Complete dataflow graph representing a function.
    
    A DataflowGraph contains all nodes for a function's dataflow IR:
    - Entry node: Function entry point
    - Exit node: Function exit point
    - Existing nodes: Existing objects referenced in the function
    - Null node: Null value representation
    - Entry predicate: Initial control flow predicate
    
    The graph provides methods to access and create nodes, and serves
    as the container for the entire dataflow representation.
    
    Attributes:
        entry: Entry operation node
        exit: Exit operation node (created during conversion)
        existing: Dictionary mapping objects to ExistingNode instances
        null: NullNode for null values
        entryPredicate: PredicateNode for entry control flow
    """
    __slots__ = "entry", "exit", "existing", "null", "entryPredicate"

    def __init__(self, hyperblock):
        """Initialize a dataflow graph.
        
        Args:
            hyperblock: Initial hyperblock for entry node
        """
        self.entry = Entry(hyperblock)
        self.exit = None  # Defer creation, as we don't know the hyperblock.
        self.existing = {}
        self.null = NullNode()

        self.entryPredicate = None

    # Separated from __init__ method, as transformation passes may want to do this manually.
    def initPredicate(self):
        """Initialize the entry predicate.
        
        Creates the entry predicate node and adds it to the entry operation.
        This is separated from __init__ to allow transformation passes to
        control when predicates are initialized.
        """
        self.entryPredicate = PredicateNode(
            self.entry.hyperblock, repr(self.entry.hyperblock)
        )
        self.entry.addEntry("*", self.entryPredicate)

    def getExisting(self, node, ref=None):
        """Get or create an ExistingNode for an existing object.
        
        Existing objects are canonicalized - the same object always
        returns the same ExistingNode instance.
        
        Args:
            node: AST Existing node
            ref: Optional reference annotation (if None, extracted from node)
            
        Returns:
            ExistingNode: Node for the existing object
        """
        obj = node.object

        if obj not in self.existing:
            ref = ref or refFromExisting(node)
            result = ExistingNode(obj, ref)
            self.existing[obj] = result
        else:
            result = self.existing[obj]
        return result
