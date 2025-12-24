"""
Flow-Sensitive Data Flow (FSDF) Analysis for PyFlow.

This module implements flow-sensitive data flow analysis, which tracks how
data flows through a program while respecting control flow dependencies.
Unlike flow-insensitive analysis, FSDF maintains separate information for
different execution paths, enabling more precise analysis.

**Key Concepts:**

1. **Flow Sensitivity**: Values are tracked separately for different control
   flow paths. For example, a variable may have different values in the true
   and false branches of an if statement.

2. **Read/Modify Tracking**: Tracks which local variables and heap locations
   are read and modified by each operation, enabling precise def-use analysis.

3. **Merge and Split Points**: Identifies points where control flow merges
   (e.g., after if statements) or splits (e.g., at if conditions), which
   are critical for maintaining flow-sensitive information.

4. **Canonical Naming**: Provides canonical names for locals and heap fields
   that are context-sensitive, allowing the same variable in different
   contexts to be distinguished.

5. **Data Flow Networks**: Constructs networks representing data dependencies
   between operations, including both local variable and heap dependencies.

**Module Components:**

- ReadModifyInfo: Tracks local and heap read/modify operations
- FindMergeSplit: Identifies merge and split points in data flow
- BuildDataflowNetwork: Constructs data flow networks from AST
- Canonical naming: Provides canonical names for locals and fields
- Correlated data flow: Builds flow-sensitive data flow relationships

**Use Cases:**

- Precise def-use analysis across control flow
- Inter-procedural data flow tracking
- Context-sensitive analysis
- Program slicing
- Dead code elimination
- Optimization opportunities identification

**Algorithm Overview:**

1. Traverse AST to identify read/modify operations
2. Build data flow network connecting definitions to uses
3. Track context information for flow-sensitive analysis
4. Identify recursive call patterns (which complicate analysis)
5. Distinguish loop-allocated vs. uniquely-allocated objects
"""

from __future__ import print_function

from pyflow.util.typedispatch import *
from pyflow.language.python import ast

import collections

from .. import programculler
from pyflow.util.PADS.StrongConnectivity import StronglyConnectedComponents


def isSCC(g):
    """
    Check if a graph component is a strongly connected component (SCC).
    
    A strongly connected component has at least one edge, indicating
    mutual reachability between nodes.
    
    Args:
        g: Dictionary representing a graph component (node -> neighbors)
        
    Returns:
        True if the component has edges (is an SCC), False otherwise
    """
    for k, v in g.items():
        if v:
            return True
    return False


def findRecursiveGroups(G):
    """
    Find recursive call groups in a call graph.
    
    Uses strongly connected component analysis to identify groups of
    functions that call each other recursively. Functions in the same
    recursive group are mutually reachable in the call graph.
    
    Args:
        G: Call graph represented as a dictionary (function -> set of called functions)
        
    Returns:
        Dictionary mapping each function to the set of functions in its
        recursive group (empty if the function is not recursive)
    """
    scc = StronglyConnectedComponents(G)
    out = {}
    for g in scc:
        if isSCC(g):
            s = frozenset(g)
            for n in g:
                out[n] = s
    return out


class ReadModifyInfo(object):
    """
    Tracks read and modify operations for local variables and heap locations.
    
    This class maintains information about which variables and heap fields
    are read from and written to by a code block or operation. This is
    essential for building accurate data flow graphs and identifying
    dependencies.
    
    **Tracking:**
    - Local variables: Variables in the current function's scope
    - Heap locations: Object fields accessed through pointers/references
    
    **Use Cases:**
    - Def-use analysis: Find where variables are defined and used
    - Dependency analysis: Determine operation dependencies
    - Dead code elimination: Identify unused writes
    - Optimization: Find opportunities for load/store elimination
    
    Attributes:
        localRead: Set of local variables that are read
        localModify: Set of local variables that are modified (written)
        heapRead: Set of heap locations (field names) that are read
        heapModify: Set of heap locations (field names) that are modified
    """
    __slots__ = "localRead", "localModify", "heapRead", "heapModify"

    def __init__(self):
        """Initialize empty read/modify information."""
        self.localRead = set()
        self.localModify = set()
        self.heapRead = set()
        self.heapModify = set()

    def accumulate(self, other):
        """
        Accumulate read/modify information from another ReadModifyInfo.
        
        Merges the read and modify sets from another ReadModifyInfo into
        this one. Used when combining information from multiple code blocks
        (e.g., in a suite or loop body).
        
        Args:
            other: Another ReadModifyInfo to merge into this one
        """
        self.localRead.update(other.localRead)
        self.localModify.update(other.localModify)
        self.heapRead.update(other.heapRead)
        self.heapModify.update(other.heapModify)


class FindMergeSplit(TypeDispatcher):
    """
    Identifies read and modify operations to find merge and split points.
    
    This traverser analyzes AST nodes to determine which local variables
    and heap locations are read and modified. This information is used to:
    - Identify data dependencies
    - Find merge points (where control flow converges)
    - Find split points (where control flow diverges)
    - Build accurate data flow graphs
    
    **Merge Points:**
    Points where multiple control flow paths converge, requiring
    merging of flow-sensitive information (e.g., after if statements).
    
    **Split Points:**
    Points where control flow diverges, creating separate paths
    (e.g., at if conditions, loop headers).
    
    Attributes:
        lut: Lookup table mapping nodes to their ReadModifyInfo
    """
    @dispatch(ast.Existing, ast.leafTypes)
    def visitJunk(self, node, info):
        """Ignore existing nodes and leaf types."""
        pass

    @dispatch(ast.Local)
    def visitLocal(self, node, info):
        """
        Track local variable reads.
        
        Args:
            node: Local variable node
            info: ReadModifyInfo to update
        """
        info.localRead.add(node)

    @dispatch(list)
    def visitOther(self, node, *args):
        """Process list/tuple children."""
        for child in node:
            self(child, *args)

    @dispatch(ast.Allocate)
    def visitAllocate(self, node, info):
        """
        Process allocation nodes.
        
        Note: Heap modifications from allocations are tracked separately
        through annotations, so we don't need to track them here.
        """
        # TODO null fields?
        pass

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node, info):
        """
        Process direct call nodes.
        
        Tracks reads of arguments (self, positional, keyword, varargs, kwargs)
        but not heap modifications, which are tracked through annotations.
        """
        self(node.selfarg, info)
        self(node.args, info)
        self(node.kwds, info)
        self(node.vargs, info)
        self(node.kargs, info)

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        """
        Process assignment nodes.
        
        Tracks:
        - Reads: Variables used in the expression
        - Modifies: Local variables being assigned to
        
        Returns:
            ReadModifyInfo for this assignment
        """
        info = ReadModifyInfo()

        # Track reads from the expression
        self(node.expr, info)

        # Track modifications to target locals
        info.localModify.update(node.lcls)

        self.lut[node] = info
        return info

    @dispatch(ast.Suite)
    def visitSuite(self, node):
        """
        Process suite nodes (sequence of statements).
        
        Accumulates read/modify information from all blocks in the suite.
        This represents a merge point where information from multiple
        statements is combined.
        
        Returns:
            ReadModifyInfo accumulated from all blocks
        """
        info = ReadModifyInfo()
        for block in node.blocks:
            info.accumulate(self(block))

        self.lut[node] = info
        return info

    @dispatch(ast.For)
    def visitFor(self, node):
        """
        Process for loop nodes.
        
        Tracks:
        - Iterator read (the iterable being iterated)
        - Index modification (the loop variable)
        - Reads/modifies from loop body
        
        Returns:
            ReadModifyInfo for the entire loop
        """
        info = ReadModifyInfo()
        self(node.loopPreamble)
        info.localRead.add(node.iterator)
        info.localModify.add(node.index)
        self(node.bodyPreamble)
        self(node.body)
        self(node.else_)

        self.lut[node] = info
        return info

    def processCode(self, node):
        """
        Process a code node and build read/modify information.
        
        Args:
            node: Code node to analyze
        """
        self.lut = {}
        self(node.ast)


from pyflow.util.canonical import CanonicalObject


class LocalName(CanonicalObject):
    """
    Canonical name for a local variable in a specific context.
    
    Provides a canonical representation of a local variable that includes
    context information, allowing the same variable in different contexts
    (e.g., different function calls) to be distinguished.
    
    Attributes:
        local: The local variable
        context: Context identifier (e.g., call site information)
    """
    def __init__(self, local, context):
        """
        Initialize a canonical local name.
        
        Args:
            local: The local variable
            context: Context identifier for flow-sensitive analysis
        """
        self.local = local
        self.context = context
        self.setCanonical(local, context)

    def isUnique(self):
        """
        Check if this name is unique.
        
        Local names are always unique within their context.
        
        Returns:
            True (local names are always unique)
        """
        return True


class FieldName(CanonicalObject):
    """
    Canonical name for a heap field in a specific context.
    
    Provides a canonical representation of an object field that includes
    context information. The uniqueness flag indicates whether this field
    access is unique (e.g., from a unique allocation) or may alias with
    other accesses (e.g., from loop allocations).
    
    Attributes:
        obj: The object containing the field
        field: The field name
        context: Context identifier for flow-sensitive analysis
        unique: Whether this field access is unique (not aliased)
    """
    def __init__(self, obj, field, context, unique):
        """
        Initialize a canonical field name.
        
        Args:
            obj: The object containing the field
            field: The field name
            context: Context identifier for flow-sensitive analysis
            unique: Whether this field access is unique (True) or may alias
        """
        self.obj = obj
        self.field = field
        self.context = context
        self.unique = unique
        self.setCanonical(obj, field, context, unique)

    def isUnique(self):
        """
        Check if this field access is unique.
        
        Returns:
            True if unique (no aliasing), False if may alias
        """
        return self.unique


# class CanonicalManager(object):
# 	def __init__(self):
# 		self.cache = {}

# 	def local(self, lcl, context):
# 		name = LocalName(lcl, context)
# 		return self.cache.setdefault(name, name)

# 	def field(self, obj, field, context, unique):
# 		name = FieldName(obj, field, context, unique)
# 		if not name in self.cache:
# 			self.cache[name] = name
# 			self.index[(obj, field)].add(name)
# 		else:
# 			name = self.cache[name]

# 		return name


class Enviornment(object):
    """
    Environment for tracking variable bindings in flow-sensitive analysis.
    
    Maintains a mapping of variables to their values in a specific context,
    with support for parent environments (for nested scopes) and deferred
    evaluation (for handling recursive definitions).
    
    Attributes:
        parent: Parent environment (for nested scopes)
        env: Dictionary mapping variable names to values
        defered: Whether evaluation is deferred (for recursive definitions)
    """
    def __init__(self, parent):
        """
        Initialize an environment.
        
        Args:
            parent: Parent environment (None for root environment)
        """
        self.parent = parent
        self.env = {}
        self.defered = False


class BuildDataflowNetwork(TypeDispatcher):
    """
    Builds a data flow network from AST nodes.
    
    This class traverses the AST and builds a network representing data
    dependencies between operations. It tracks:
    - Context information for flow-sensitive analysis
    - Object allocations (distinguishing loop vs. unique allocations)
    - Constraint counts (for complexity estimation)
    - Call sites and their targets
    
    **Context Tracking:**
    Contexts represent different execution paths or call sites. Each
    context is a tuple of operation IDs that uniquely identifies a
    path through the program.
    
    **Allocation Classification:**
    - Loop allocations: Objects allocated inside loops (may alias)
    - Unique allocations: Objects allocated outside loops (unique)
    
    Attributes:
        fms: FindMergeSplit instance for read/modify analysis
        contexts: Total number of contexts encountered
        contextLUT: Lookup table mapping code nodes to context counts
        constraints: Total number of constraints (operations) encountered
        loopLevel: Current nesting level of loops
        loopAllocated: Set of objects allocated inside loops
        uniqueAllocated: Set of objects allocated outside loops
        currentContext: Current context tuple (operation IDs)
        contextStack: Stack of contexts for nested operations
    """
    def __init__(self):
        """Initialize a data flow network builder."""
        self.fms = FindMergeSplit()

        self.contexts = 0
        self.contextLUT = {}

        self.constraints = 0

        self.loopLevel = 0

        self.loopAllocated = set()
        self.uniqueAllocated = set()

        self.currentContext = ()
        self.contextStack = []

    def pushContext(self, op):
        """
        Push a new context onto the context stack.
        
        Creates a new context by appending the operation ID to the current
        context. This allows tracking of nested call sites and control flow.
        
        Args:
            op: Operation node to add to the context
        """
        self.contextStack.append(self.currentContext)
        self.currentContext += (id(op),)

    def popContext(self):
        """
        Pop the current context from the context stack.
        
        Restores the previous context after processing a nested operation.
        """
        self.currentContext = self.contextStack.pop()

    @dispatch(ast.Allocate)
    def visitAllocate(self, node):
        """
        Process allocation nodes.
        
        Classifies allocated objects as either loop-allocated or unique
        based on the current loop nesting level. This distinction is
        important for alias analysis.
        """
        if self.loopLevel:
            dst = self.loopAllocated
        else:
            dst = self.uniqueAllocated

        for obj in node.annotation.allocates[0]:
            dst.add(obj)
            # dst.add((obj, self.currentContext))

        self.constraints += 1

    @dispatch(ast.Load, ast.Store, ast.Check, ast.Return)
    def visitTrack(self, node):
        """
        Track operations that create constraints.
        
        These operations represent data flow constraints that need to be
        solved in the data flow analysis.
        """
        self.constraints += 1

    @dispatch(ast.Local, ast.Existing)
    def visitTerminal(self, node):
        """Terminal nodes don't need processing."""
        pass

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node):
        """
        Process direct call nodes.
        
        For each call target, processes the called code in a new context.
        This enables inter-procedural analysis with context sensitivity.
        """
        targets = set()
        for code, context in node.annotation.invokes[0]:
            targets.add(code)

        self.pushContext(node)
        for target in targets:
            self.processCode(target)
        self.popContext()

        self.constraints += 1

    @dispatch(ast.leafTypes, ast.CodeParameters)
    def visitLeaf(self, node):
        pass

    @dispatch(ast.Suite, ast.Switch, ast.Condition, ast.Assign, ast.Discard)
    def visitOK(self, node):
        node.visitChildren(self)

    @dispatch(ast.For, ast.While)
    def visitFor(self, node):
        """
        Process loop nodes.
        
        Increments loop level to track nesting depth, which affects
        allocation classification. Loops create split points in control flow.
        """
        # TODO evaluate preamble outside "loopLevel"
        self.loopLevel += 1
        node.visitChildren(self)
        self.loopLevel -= 1

    def processCode(self, node):
        """
        Process a code node and build the data flow network.
        
        Tracks context information and processes all child nodes to build
        a complete data flow network.
        
        Args:
            node: Code node to process
        """
        self.contexts += 1
        if node not in self.contextLUT:
            self.contextLUT[node] = 1
        else:
            self.contextLUT[node] += 1

        for child in node.children():
            self(child)


class Operation(object):
    """
    Represents an operation in the data flow network.
    
    An operation is a node in the data flow graph that:
    - Defines values (writes to variables or heap locations)
    - Uses values (reads from variables or heap locations)
    
    **Data Flow Relationships:**
    - Uses: Variables/locations read by this operation
    - Defs: Variables/locations written by this operation
    - Heap uses/defs: Heap location accesses
    
    Attributes:
        op: The AST node representing this operation
        targets: Variables/locations that are targets of this operation
        uses: List of slots (variables) used by this operation
        defs: List of slots (variables) defined by this operation
        heapuses: List of heap slots (fields) used by this operation
        heapdefs: List of heap slots (fields) defined by this operation
    """
    def __init__(self, op, targets):
        """
        Initialize an operation.
        
        Args:
            op: AST node representing the operation
            targets: List of variables/locations that are targets
        """
        self.op = op
        self.targets = targets

        self.uses = []
        self.defs = []

        self.heapuses = []
        self.heapdefs = []


class Slot(object):
    """
    Represents a slot (variable) in the data flow network.
    
    A slot tracks all operations that define (write to) and use (read from)
    a variable. This enables def-use analysis and dependency tracking.
    
    **External Definitions:**
    Variables that are defined outside the current analysis scope
    (e.g., function parameters, globals) are marked as external.
    
    Attributes:
        name: Canonical name of the variable
        externalDefinition: Whether this variable is defined externally
        defs: List of operations that define this variable
        uses: List of operations that use this variable
    """
    def __init__(self, name):
        """
        Initialize a slot.
        
        Args:
            name: Canonical name of the variable
        """
        self.name = name
        self.externalDefinition = False
        self.defs = []
        self.uses = []

    def addUse(self, op):
        """
        Add a use of this slot by an operation.
        
        Creates a bidirectional link between the slot and operation.
        
        Args:
            op: Operation that uses this slot
        """
        self.uses.append(op)
        op.uses.append(self)

    def addDef(self, op):
        """
        Add a definition of this slot by an operation.
        
        Creates a bidirectional link between the slot and operation.
        External definitions cannot have additional definitions added.
        
        Args:
            op: Operation that defines this slot
            
        Raises:
            AssertionError: If this slot has an external definition
        """
        assert not self.externalDefinition
        self.defs.append(op)
        op.defs.append(self)

    def __repr__(self):
        return "Slot(%r/%d)" % (self.name, id(self))


class HeapSlot(object):
    """
    Represents a heap slot (object field) in the data flow network.
    
    Similar to Slot but for heap locations (object fields) rather than
    local variables. Tracks operations that read from and write to heap
    locations, enabling inter-object data flow analysis.
    
    **Weak Updates:**
    Heap slots may use weak update semantics where a write also reads
    the previous value (for handling aliasing).
    
    Attributes:
        name: Canonical name of the heap location
        externalDefinition: Whether this location is defined externally
        defs: List of operations that define this location
        uses: List of operations that use this location
    """
    def __init__(self, name):
        """
        Initialize a heap slot.
        
        Args:
            name: Canonical name of the heap location
        """
        self.name = name
        self.externalDefinition = False
        self.defs = []
        self.uses = []

    def addUse(self, op):
        """
        Add a use of this heap slot by an operation.
        
        Args:
            op: Operation that uses this heap slot
        """
        self.uses.append(op)
        op.heapuses.append(self)

    def addDef(self, op):
        """
        Add a definition of this heap slot by an operation.
        
        Args:
            op: Operation that defines this heap slot
            
        Raises:
            AssertionError: If this slot has an external definition
        """
        assert not self.externalDefinition
        self.defs.append(op)
        op.heapdefs.append(self)

    def __repr__(self):
        return "HeapSlot(%r/%d)" % (self.name, id(self))


class MarkUses(TypeDispatcher):
    """
    Marks variable uses in operations for data flow network construction.
    
    This traverser identifies all local variable uses in an operation
    and records them in the data flow network, creating def-use links.
    
    Attributes:
        bcdf: BuildCorrelatedDataflow instance to record uses
        op: Current operation being processed
    """
    def __init__(self, bcdf):
        """
        Initialize a use marker.
        
        Args:
            bcdf: BuildCorrelatedDataflow instance
        """
        self.bcdf = bcdf

    @dispatch(ast.Code, ast.Existing, ast.leafTypes)
    def visitJunk(self, node):
        """Ignore code nodes, existing nodes, and leaf types."""
        pass

    @dispatch(list, tuple)
    def visitContainer(self, node):
        """Process container children."""
        node.visitChildren(self)

    @dispatch(ast.Local)
    def visitLocal(self, node):
        """
        Mark a local variable use.
        
        Args:
            node: Local variable node being used
        """
        self.bcdf.useLocal(self.op, node)

    def process(self, node):
        """
        Process a node and mark all variable uses.
        
        Args:
            node: Operation node to process
        """
        self.op = node
        node.visitChildren(self)


class BuildCorrelatedDataflow(TypeDispatcher):
    """
    Builds a correlated data flow network with def-use relationships.
    
    This class constructs a complete data flow network by:
    - Creating operation nodes for each AST operation
    - Creating slot nodes for variables and heap locations
    - Linking operations to slots through def-use relationships
    - Tracking both local variable and heap data flow
    
    **Correlated Data Flow:**
    Unlike simple def-use chains, correlated data flow tracks relationships
    between operations that may be correlated through control flow or
    aliasing, enabling more precise analysis.
    
    Attributes:
        markUses: MarkUses instance for identifying variable uses
        operations: Dictionary mapping AST nodes to Operation objects
        slots: Dictionary mapping variable names to Slot/HeapSlot objects
        returns: List of return value slots (for return statements)
    """
    def __init__(self):
        """Initialize a correlated data flow builder."""
        self.markUses = MarkUses(self)

    def getSlot(self, name):
        """
        Get or create a slot for a local variable.
        
        If the slot doesn't exist, creates it and marks it as externally
        defined (e.g., function parameter or global).
        
        Args:
            name: Variable name
            
        Returns:
            Slot object for the variable
        """
        if name not in self.slots:
            defn = Slot(name)
            defn.externalDefinition = True
            self.slots[name] = defn
        else:
            defn = self.slots[name]
        return defn

    def getHeapSlot(self, name):
        """
        Get or create a heap slot for a heap location.
        
        Args:
            name: Heap location name (canonical field name)
            
        Returns:
            HeapSlot object for the location
        """
        if name not in self.slots:
            defn = HeapSlot(name)
            defn.externalDefinition = True
            self.slots[name] = defn
        else:
            defn = self.slots[name]
        return defn

    def defineOp(self, op, targets):
        """
        Define a new operation in the data flow network.
        
        Args:
            op: AST node representing the operation
            targets: List of variables/locations that are targets
            
        Returns:
            Operation object
            
        Raises:
            AssertionError: If the operation already exists
        """
        assert op not in self.operations
        defn = Operation(op, targets)
        self.operations[op] = defn
        return defn

    def getOp(self, op):
        """
        Get an operation from the network.
        
        Args:
            op: AST node
            
        Returns:
            Operation object
        """
        defn = self.operations[op]
        return defn

    def useLocal(self, op, lcl):
        """
        Record a local variable use by an operation.
        
        Args:
            op: Operation using the variable
            lcl: Local variable being used
        """
        slot = self.getSlot(lcl)
        slot.addUse(self.getOp(op))

    def markDefs(self, node, targets):
        """
        Mark variable definitions by an operation.
        
        Creates slots for target variables and links them to the operation.
        
        Args:
            node: Operation node defining variables
            targets: List of variables being defined
        """
        op = self.getOp(node)
        for target in targets:
            slot = Slot(target)
            self.slots[target] = slot
            slot.addDef(op)

    def markHeapDefUse(self, node):
        """
        Mark heap location definitions and uses by an operation.
        
        Handles both reads and writes to heap locations. For writes,
        uses weak update semantics (read before write) to handle aliasing.
        
        Args:
            node: Operation node with heap annotations
        """
        op = self.getOp(node)

        # Track heap reads
        for name in node.annotation.reads[0]:
            self.getHeapSlot(name).addUse(op)

        # For weak updates: read before write
        # Must be done before the defs, as they will overwrite.
        for name in node.annotation.modifies[0]:
            self.getHeapSlot(name).addUse(op)

        # Track heap writes
        for name in node.annotation.modifies[0]:
            slot = HeapSlot(name)
            self.slots[name] = slot
            slot.addDef(op)

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node, targets):
        self.defineOp(node, targets)
        self.markUses.process(node)
        self.markDefs(node, targets)
        self.markHeapDefUse(node)

    @dispatch(ast.Load)
    def visitLoad(self, node, targets):
        self.defineOp(node, targets)
        self.markUses.process(node)
        self.markDefs(node, targets)
        self.markHeapDefUse(node)

    @dispatch(ast.Allocate)
    def visitAllocate(self, node, targets):
        self.defineOp(node, targets)
        self.markUses.process(node)
        self.markDefs(node, targets)
        self.markHeapDefUse(node)

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        self(node.expr, node.lcls)

    @dispatch(ast.Return)
    def visitReturn(self, node):
        assert self.returns is None
        self.defineOp(node, [])
        self.returns = [self.useLocal(node, lcl) for lcl in node.exprs]

    @dispatch(ast.Suite)
    def visitOK(self, node):
        node.visitChildren(self)

    @dispatch(str, ast.CodeParameters)
    def visitLeaf(self, node):
        pass

    def processCode(self, node):
        self.operations = {}
        self.slots = {}
        self.returns = None

        for child in node.children():
            self(child)

        print(node)

        for op in self.operations.values():
            # if not isinstance(op.op, ast.Load): continue

            print(op.op)
            print(op.targets)

            print("---")
            for use in op.uses:
                print(use, use.defs)

            print("---")
            for use in op.heapuses:
                print(use, use.defs)

            print("---")
            for defn in op.defs:
                print("---")
            for defn in op.heapdefs:
                print()
            print()

        print()


def checkRecursive(compiler):
    """
    Check for recursive function calls in the program.
    
    Recursive calls complicate flow-sensitive analysis because they create
    cycles in the call graph. This function identifies recursive groups
    using strongly connected component analysis.
    
    Args:
        compiler: Compiler instance with program information
        
    Returns:
        Dictionary mapping functions to their recursive groups, or empty
        dict if no recursion detected
    """
    liveFunctions, liveInvocations = programculler.findLiveCode(compiler)
    recursive = findRecursiveGroups(liveInvocations)
    return recursive


def evaluate(compiler):
    """
    Main entry point for flow-sensitive data flow analysis.
    
    Performs FSDF analysis on the program:
    1. Checks for recursive calls (which complicate analysis)
    2. Builds data flow network from entry points
    3. Tracks contexts, constraints, and allocations
    4. Reports statistics
    
    Args:
        compiler: Compiler instance with program to analyze
        
    Returns:
        True if analysis completed successfully, False if recursion detected
    """
    with compiler.console.scope("fsdf"):

        # Check for recursive calls
        if checkRecursive(compiler):
            compiler.console.output("recursive call detected, cannot analyze")
            return False

        # Build data flow network
        bdfn = BuildDataflowNetwork()

        for code in compiler.interface.entryCode():
            bdfn.processCode(code)

        # Report statistics
        for code, count in bdfn.contextLUT.items():
            print("\t", code, count)
        compiler.console.output("%d contexts" % bdfn.contexts)
        compiler.console.output("%d constraints" % bdfn.constraints)

        print("Loop Allocated")
        for obj in bdfn.loopAllocated:
            print("\t", obj)
        print()
        print("Unique Allocated")
        for obj in bdfn.uniqueAllocated:
            print("\t", obj)

        # TODO: Build correlated data flow network
        # 		bcd = BuildCorrelatedDataflow()
        # 		for ep in compiler.interface.entryPoint:
        # 			bcd.processCode(ep.code)

        return True
