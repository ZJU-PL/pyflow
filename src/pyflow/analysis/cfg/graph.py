"""Control Flow Graph (CFG) representation.

This module provides the core data structures for representing control flow
graphs in PyFlow, including CFG blocks and their relationships.

A Control Flow Graph represents the control flow structure of a program:
- Nodes (blocks) represent sequences of operations
- Edges represent control flow transfers (normal, fail, error, etc.)
- Different block types handle different control flow patterns:
  * Entry/Exit: Function entry and exit points
  * Suite: Sequences of operations with normal/exceptional exits
  * Switch: Conditional branches (if/else)
  * TypeSwitch: Type-based dispatch
  * Merge: Join points where multiple control paths converge
  * Yield: Generator yield points

The CFG supports both single-entry blocks (most blocks) and multi-entry blocks
(Merge blocks that join multiple paths). Each block maintains bidirectional
connections to its predecessors and successors.
"""

class NoNormalFlow(Exception):
    """Exception raised when no normal control flow path exists.
    
    This exception is used during CFG construction to signal that a control
    flow path terminates abnormally (e.g., due to return, break, continue).
    It allows the transformer to handle control flow correctly without
    creating unnecessary edges.
    """
    pass


class CFGBlock(object):
    """Represents a basic block in a Control Flow Graph.
    
    A CFGBlock represents a sequence of instructions with a single entry point
    and potentially multiple exit points. It maintains connections to successor
    and predecessor blocks.
    
    Attributes:
        region: The region of code this block represents.
        next: Dictionary mapping exit names to successor blocks.
        data: Additional data associated with this block.
        exitNames: Tuple of valid exit names for this block type.
    """
    __slots__ = "region", "next", "data"
    exitNames = ()

    def __init__(self, region):
        """Initialize a CFG block.
        
        Args:
            region: The code region this block represents.
        """
        self.region = region
        self.next = {}

    def validExitName(self, name):
        """Check if an exit name is valid for this block type.
        
        Args:
            name: Exit name to validate.
            
        Returns:
            bool: True if the exit name is valid.
        """
        return name in self.exitNames

    def setExit(self, name, other):
        """Set the successor block for a given exit name.
        
        Args:
            name: Exit name.
            other: Successor block (can be None).
        """
        assert self.validExitName(name)
        assert name not in self.next

        if other is not None:
            self.next[name] = other
            other.addPrev(self, name)

    def getExit(self, name):
        """Get the successor block for a given exit name.
        
        Args:
            name: Exit name.
            
        Returns:
            CFGBlock or None: The successor block, if it exists.
        """
        assert self.validExitName(name)
        return self.next.get(name)

    def killExit(self, name):
        """Remove the exit connection for a given name.
        
        Args:
            name: Exit name to remove.
        """
        if name in self.next:
            self.next[name].removePrev(self, name)
            del self.next[name]

    def addPrev(self, other, name):
        """Add a predecessor block.
        
        Args:
            other: Predecessor block.
            name: Exit name from the predecessor.
            
        Note:
            This method should be implemented by subclasses.
        """
        raise NotImplementedError

    def removePrev(self, other):
        """Remove a predecessor block.
        
        Args:
            other: Predecessor block to remove.
            
        Note:
            This method should be implemented by subclasses.
        """
        raise NotImplementedError

    def replacePrev(self, other):
        """Replace a predecessor block.
        
        Args:
            other: New predecessor block.
            
        Note:
            This method should be implemented by subclasses.
        """
        raise NotImplementedError

    def forward(self):
        """Get all successor blocks.
        
        Returns:
            list: List of all successor blocks (values from self.next).
        """
        return self.next.values()

    def normalForward(self):
        """Get normal flow successor blocks (excluding exceptional exits).
        
        Returns normal flow successors, filtering out exceptional control
        flow exits like "error", "fail", and "yield". Used for dominance
        analysis and other algorithms that only consider normal flow.
        
        Returns:
            list: List of normal flow successor blocks.
        """
        result = []
        for name, next in self.next.items():
            if name not in ("error", "fail", "yield"):
                result.append(next)
        return result

    def findExit(self, e):
        """Find the exit name for a given successor block.
        
        Searches through self.next to find which exit name maps to the
        given successor block.
        
        Args:
            e: Successor block to find exit name for
            
        Returns:
            str or None: Exit name if found, None otherwise
        """
        name = None
        for k, v in self.next.items():
            if v is e:
                name = k
                break
        return name

    def redirectExit(self, oldExit, newExit):
        """Redirect an exit edge from one block to another.
        
        Finds the exit name for oldExit, removes it, and creates a new
        exit with the same name pointing to newExit.
        
        Args:
            oldExit: Old successor block
            newExit: New successor block
        """
        name = self.findExit(oldExit)
        assert name is not None

        self.killExit(name)
        self.setExit(name, newExit)

    def forwardExit(self, other, name):
        """Forward an exit from another block to this block.
        
        Takes an exit named 'name' from 'other' block and forwards it
        through this block. The exit from 'other' is removed, and this
        block's exit to 'other' is redirected to 'other's successor.
        
        Used during CFG transformations to bypass intermediate blocks.
        
        Args:
            other: Block whose exit to forward
            name: Exit name to forward from other
        """
        assert other is not None

        if name in other.next:
            next = other.next[name]
            del other.next[name]
        else:
            next = None

        selfExit = self.findExit(other)
        assert selfExit is not None
        self.killExit(selfExit)

        if next:
            self.next[selfExit] = next
            next.replacePrev(other, name, self, selfExit)

    def stealExit(self, other, name):
        """Steal an exit from another block.
        
        Removes an exit from 'other' block and adds it to this block.
        Used when merging blocks or redirecting control flow.
        
        Args:
            other: Block to steal exit from
            name: Exit name to steal
        """
        assert other is not None
        self.setExit(name, other.popExit(name))

    def popExit(self, name):
        """Remove and return an exit, cleaning up bidirectional links.
        
        Removes the exit named 'name' from this block and cleans up the
        predecessor link in the successor block.
        
        Args:
            name: Exit name to remove
            
        Returns:
            CFGBlock or None: The removed successor block, or None if not found
        """
        e = self.next.get(name)
        if e is not None:
            del self.next[name]
            e.removePrev(self, name)
        return e

    def sanityCheck(self):
        """Verify CFG structure integrity.
        
        Checks that bidirectional links are consistent:
        - All successors have this block as a predecessor
        - All predecessors have this block as their successor
        
        Raises:
            AssertionError: If CFG structure is inconsistent
            
        Note:
            TODO: Check MIMO (Multiple Input Multiple Output) cases?
        """
        for child in self.forward():
            assert self in child.reverse(), self

        for child, name in self.iterprev():
            assert child.getExit(name) is self, self

    def destroy(self):
        """Destroy this block, cleaning up all connections.
        
        Removes all exit edges and cleans up predecessor links in
        successor blocks. Used when removing blocks from the CFG.
        """
        for k, v in self.next.items():
            v.removePrev(self, k)
        self.next = {}

    def transferExit(self, dstName, other, srcName):
        """Transfer an exit from another block to this block.
        
        Moves an exit edge from 'other' block (with name 'srcName') to
        this block (with name 'dstName'). Updates predecessor links accordingly.
        
        Args:
            dstName: Exit name to use in this block
            other: Source block
            srcName: Exit name in source block
        """
        e = other.next[srcName]
        del other.next[srcName]

        assert dstName not in self.next

        self.next[dstName] = e
        e.replacePrev(other, srcName, self, dstName)

    def clonedExit(self, name, dst):
        """Set an exit without establishing bidirectional link.
        
        Used during CFG cloning when predecessor links will be established
        separately. This is a low-level operation that bypasses normal
        link maintenance.
        
        Args:
            name: Exit name
            dst: Destination block
        """
        self.next[name] = dst

    def insertAtExit(self, exitName, block, blockExitName):
        """Insert a block into an exit edge.
        
        Transforms:
            self{exitName} -> current
        into:
            self{exitName} -> block{blockExitName} -> current
        
        Used to insert intermediate blocks (e.g., for phi node expansion)
        into existing control flow edges.
        
        Args:
            exitName: Exit name from this block
            block: Block to insert
            blockExitName: Exit name from inserted block to original successor
        """
        current = self.next[exitName]
        current.replacePrev(self, exitName, block, blockExitName)

        self.next[exitName] = block
        block.addPrev(self, exitName)
        block.next[blockExitName] = current


class SingleEntryBlock(CFGBlock):
    """CFG block with a single predecessor.
    
    Most CFG blocks have a single entry point, meaning they have exactly
    one predecessor. This class maintains a single predecessor link stored
    as a tuple (block, exit_name).
    
    Examples: Suite, Switch, Entry, Exit, Yield blocks.
    """
    __slots__ = ("_prev",)

    def __init__(self, region):
        """Initialize a single-entry block.
        
        Args:
            region: Code region this block belongs to
        """
        CFGBlock.__init__(self, region)
        self._prev = (None, "")

    def addPrev(self, other, name):
        """Add a predecessor block.
        
        Args:
            other: Predecessor block
            name: Exit name from predecessor
            
        Raises:
            AssertionError: If block already has a predecessor
        """
        assert isinstance(other, CFGBlock)
        assert self._prev[0] is None, self
        self._prev = (other, name)

    def removePrev(self, other, name):
        """Remove a predecessor block.
        
        Args:
            other: Predecessor block to remove
            name: Exit name from predecessor
            
        Raises:
            AssertionError: If predecessor doesn't match
        """
        assert isinstance(other, CFGBlock)
        assert self._prev == (other, name)
        self._prev = (None, "")

    def replacePrev(self, other, otherName, replacement, replacementName):
        """Replace a predecessor block with another.
        
        Args:
            other: Old predecessor block
            otherName: Exit name from old predecessor
            replacement: New predecessor block
            replacementName: Exit name from new predecessor
            
        Raises:
            AssertionError: If old predecessor doesn't match
        """
        assert isinstance(other, CFGBlock)
        assert isinstance(replacement, CFGBlock)
        assert self._prev == (other, otherName)
        self._prev = (replacement, replacementName)

    def clonedPrev(self, prev, name):
        """Set predecessor during cloning (bypasses validation).
        
        Used during CFG cloning when predecessor links are established
        without normal validation.
        
        Args:
            prev: Predecessor block
            name: Exit name from predecessor
        """
        self._prev = (prev, name)

    def reverse(self):
        """Get all predecessor blocks.
        
        Returns:
            tuple: Single-element tuple containing the predecessor block
        """
        return (self._prev[0],)

    def iterprev(self):
        """Iterate over predecessors.
        
        Returns:
            tuple: Single-element tuple containing (predecessor, exit_name)
        """
        return (self._prev,)

    def redirectEntries(self, other):
        """Redirect all entry edges to another block.
        
        If this block has a predecessor, redirects that predecessor's
        exit to point to 'other' instead of this block.
        
        Args:
            other: Block to redirect entries to
        """
        if self._prev[0] is not None:
            self.prev.redirectExit(self, other)

    @property
    def prev(self):
        """Get the predecessor block.
        
        Returns:
            CFGBlock or None: The predecessor block, or None if none exists
        """
        return self._prev[0]


class MultiEntryBlock(CFGBlock):
    """CFG block with multiple predecessors.
    
    Some CFG blocks (notably Merge blocks) can have multiple entry points,
    representing join points where multiple control flow paths converge.
    This class maintains a list of predecessor links.
    
    Examples: Merge blocks (phi nodes require multiple predecessors).
    """
    __slots__ = ("_prev",)

    def __init__(self, region):
        """Initialize a multi-entry block.
        
        Args:
            region: Code region this block belongs to
        """
        CFGBlock.__init__(self, region)
        self._prev = []

    def clonedPrev(self, prev, name):
        """Add a predecessor during cloning.
        
        Args:
            prev: Predecessor block
            name: Exit name from predecessor
        """
        assert isinstance(prev, CFGBlock)
        self._prev.append((prev, name))

    def addPrev(self, other, name):
        """Add a predecessor block.
        
        Args:
            other: Predecessor block
            name: Exit name from predecessor
        """
        assert isinstance(other, CFGBlock)
        self._prev.append((other, name))

    def removePrev(self, other, name):
        """Remove a predecessor block.
        
        Args:
            other: Predecessor block to remove
            name: Exit name from predecessor
            
        Raises:
            ValueError: If predecessor not found
        """
        index = self._prev.index((other, name))
        del self._prev[index]

    def replacePrev(self, other, otherName, replacement, replacementName):
        """Replace a predecessor block with another.
        
        Args:
            other: Old predecessor block
            otherName: Exit name from old predecessor
            replacement: New predecessor block
            replacementName: Exit name from new predecessor
        """
        key = (other, otherName)
        if key in self._prev:
            index = self._prev.index(key)
            self._prev[index] = (replacement, replacementName)

    def reverse(self):
        """Get all predecessor blocks.
        
        Returns:
            list: List of predecessor blocks
        """
        return [p[0] for p in self._prev]

    def redirectEntries(self, other):
        """Redirect all entry edges to another block.
        
        Redirects all predecessors' exits to point to 'other' instead
        of this block, then clears the predecessor list.
        
        Args:
            other: Block to redirect entries to
        """
        old, self._prev = self._prev, []

        for prev, prevName in old:
            prev.redirectExit(self, other)

    def numPrev(self):
        """Get the number of predecessors.
        
        Returns:
            int: Number of predecessor blocks
        """
        return len(self._prev)

    def iterprev(self):
        """Iterate over predecessors.
        
        Returns:
            list: List of (predecessor, exit_name) tuples
        """
        return self._prev


class Entry(CFGBlock):
    """Entry block representing function entry point.
    
    The Entry block is the unique entry point of a CFG. It has no
    predecessors and a single "entry" exit that connects to the first
    real block of the function.
    """
    __slots__ = ()
    # Python 3: single-element tuple needs a trailing comma
    exitNames = ("entry",)

    def reverse(self):
        """Entry blocks have no predecessors.
        
        Returns:
            tuple: Empty tuple
        """
        return ()

    def iterprev(self):
        """Entry blocks have no predecessors.
        
        Returns:
            tuple: Empty tuple
        """
        return ()


class Exit(SingleEntryBlock):
    """Exit block representing function exit point.
    
    Exit blocks represent termination points of a function. There are
    typically multiple exit blocks: normalTerminal, failTerminal, and
    errorTerminal. They have no exits (they terminate the CFG).
    """
    __slots__ = ()
    exitNames = ()


class Suite(SingleEntryBlock):
    """Suite block containing a sequence of operations.
    
    Suite blocks represent basic blocks containing a sequence of AST
    operations. They have three possible exits:
    - "normal": Normal completion
    - "fail": Failure/exception path
    - "error": Error path
    
    Attributes:
        ops: List of AST operations in this block
    """
    __slots__ = "ops"
    exitNames = ("normal", "fail", "error")

    def __init__(self, region):
        """Initialize a suite block.
        
        Args:
            region: Code region this block belongs to
        """
        SingleEntryBlock.__init__(self, region)
        self.ops = []

    def simplify(self):
        """Simplify this suite block.
        
        If the suite is empty, removes it from the CFG by forwarding
        its predecessor's exit to its successor. Returns the block that
        should replace this one (or self if not simplified).
        
        Returns:
            CFGBlock: Simplified block (may be self or predecessor)
        """
        if len(self.ops) == 0:
            if self.prev:
                old = self.prev
                old.forwardExit(self, "normal")
                self.destroy()
                return old
            else:
                self.destroy()
        else:
            return self


class Switch(SingleEntryBlock):
    """Switch block representing conditional branches.
    
    Switch blocks represent if/else conditionals. They evaluate a
    condition and branch to "true" or "false" exits. Also support
    "fail" and "error" exits for exceptional cases.
    
    Attributes:
        condition: AST node representing the condition to evaluate
    """
    __slots__ = "condition"

    exitNames = ("true", "false", "fail", "error")

    def __init__(self, region, condition):
        """Initialize a switch block.
        
        Args:
            region: Code region this block belongs to
            condition: AST node for the condition
        """
        SingleEntryBlock.__init__(self, region)
        self.condition = condition


class TypeSwitch(SingleEntryBlock):
    """TypeSwitch block representing type-based dispatch.
    
    TypeSwitch blocks represent type-based conditional dispatch (e.g.,
    isinstance checks). They have integer exits (0, 1, 2, ...) for each
    case, plus "fail" and "error" exits.
    
    Attributes:
        original: Original TypeSwitch AST node with cases
    """
    __slots__ = "original"

    exitNames = ("fail", "error")

    def __init__(self, region, original):
        """Initialize a type switch block.
        
        Args:
            region: Code region this block belongs to
            original: Original TypeSwitch AST node
        """
        SingleEntryBlock.__init__(self, region)
        self.original = original

    def validExitName(self, name):
        """Check if an exit name is valid for this type switch.
        
        Valid exits are "fail", "error", or integer indices for cases.
        
        Args:
            name: Exit name to validate
            
        Returns:
            bool: True if exit name is valid
        """
        return name in self.exitNames or (
            isinstance(name, int) and name >= 0 and name < len(self.original.cases)
        )


class State(SingleEntryBlock):
    __slots__ = "name"

    # Python 3: single-element tuple needs a trailing comma
    exitNames = ("normal",)

    def __init__(self, region, name):
        SingleEntryBlock.__init__(self, region)
        self.name = name


class Merge(MultiEntryBlock):
    """Merge block representing control flow join points.
    
    Merge blocks join multiple control flow paths. They contain phi nodes
    (in SSA form) that merge values from different paths. Merge blocks
    have a single "normal" exit.
    
    Attributes:
        phi: List of phi nodes merging values from different paths
    """
    __slots__ = "phi"
    # Python 3: single-element tuple needs a trailing comma
    exitNames = ("normal",)

    def __init__(self, region):
        """Initialize a merge block.
        
        Args:
            region: Code region this block belongs to
        """
        MultiEntryBlock.__init__(self, region)
        self.phi = []

    def simplify(self):
        """Simplify this merge block.
        
        If the merge has only one predecessor and no phi nodes, it can
        be eliminated by forwarding the predecessor's exit.
        """
        if len(self._prev) == 1 and not self.phi:
            self._prev[0][0].forwardExit(self, "normal")

    def addPrev(self, other, name):
        """Add a predecessor (only allowed when no phi nodes exist).
        
        Args:
            other: Predecessor block
            name: Exit name from predecessor
            
        Raises:
            AssertionError: If phi nodes already exist
        """
        assert isinstance(other, CFGBlock)
        assert not self.phi
        MultiEntryBlock.addPrev(self, other, name)

    def removePrev(self, other, name):
        """Remove a predecessor and update phi nodes.
        
        When a predecessor is removed, all phi nodes must drop the
        corresponding argument.
        
        Args:
            other: Predecessor block to remove
            name: Exit name from predecessor
        """
        assert isinstance(other, CFGBlock)

        index = self._prev.index((other, name))
        del self._prev[index]

        self.phi = [phi.dropArgument(index) for phi in self.phi]

    def redirectEntries(self, other):
        """Redirect entries (only allowed when no phi nodes exist).
        
        Args:
            other: Block to redirect entries to
            
        Raises:
            AssertionError: If phi nodes exist
        """
        assert isinstance(other, CFGBlock)
        assert not self.phi

        old, self.prev = self.prev, []

        for prev in old:
            prev.redirectExit(self, other)


class Yield(SingleEntryBlock):
    """Yield block representing generator yield points.
    
    Yield blocks represent points where a generator yields control.
    They have a single "normal" exit that continues after the yield.
    """
    __slots__ = ()
    # Python 3: single-element tuple needs a trailing comma
    exitNames = ("normal",)


class Code(object):
    """Container for a complete CFG representing a function.
    
    A Code object contains the entire CFG for a function, including:
    - Entry and exit terminals
    - The function's code object
    - Return parameter information
    
    Attributes:
        code: AST Code object for the function
        returnParam: AST Local representing the return parameter
        entryTerminal: Entry block (function entry point)
        normalTerminal: Exit block (normal return)
        failTerminal: Exit block (failure/exception return)
        errorTerminal: Exit block (error return)
    """
    __slots__ = [
        "code",
        "returnParam",
        "entryTerminal",
        "normalTerminal",
        "failTerminal",
        "errorTerminal",
    ]

    def __init__(self):
        """Initialize a CFG code container."""
        self.entryTerminal = Entry(None)
        self.normalTerminal = Exit(None)
        self.failTerminal = Exit(None)
        self.errorTerminal = Exit(None)
