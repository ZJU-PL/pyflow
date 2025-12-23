"""Extended Static Single Assignment (ESSA) form construction.

This module provides ForwardESSA, which constructs Extended Static Single
Assignment form from Python AST. ESSA extends traditional SSA to handle:
- Object fields: Fields are renamed separately from variables
- Existing objects: External objects get unique numbers
- Merges: Phi-like merges at control flow joins

ESSA enables precise tracking of variable and field versions through
control flow, supporting optimizations like dead code elimination and
redundant load elimination.

Key concepts:
- Renaming: Assigning unique version numbers to variables/fields
- Merges: Combining versions from multiple control flow paths
- Entry/Exit: Tracking versions at function entry and exit
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast


class ForwardESSA(TypeDispatcher):
    """Constructs Extended Static Single Assignment (ESSA) form.
    
    ForwardESSA traverses AST and assigns unique version numbers to variables
    and object fields. It handles:
    - Variable renaming: Each assignment creates a new version
    - Field renaming: Field accesses are versioned separately
    - Merge operations: Versions from different paths are merged
    - Entry/Exit tracking: Records versions at function boundaries
    
    Attributes:
        rm: ReadModifyInfo lookup table (from FindReadModify)
        uid: Unique identifier counter for version numbers
        _current: Dictionary mapping variables/fields to current version numbers
        readLUT: Dictionary mapping (node, name) to version number read
        writeLUT: Dictionary mapping (node, name) to version number written
        psedoReadLUT: Dictionary mapping (node, name) to pseudo-read version
        existing: Dictionary mapping existing objects to version numbers
        merges: Dictionary mapping (name, dstID) to set of source IDs
        returns: List of return states (for merging)
        parent: Parent node being processed (for logging reads)
        code: Current code object being processed
        returnparams: List of return parameter locals
        entry: Dictionary mapping names to entry version numbers
        exit: Dictionary mapping names to exit version numbers
    """
    def __init__(self, rm):
        """Initialize ESSA constructor.
        
        Args:
            rm: ReadModifyInfo lookup table from FindReadModify
        """
        self.rm = rm
        self.uid = 0

        self._current = {}

        self.readLUT = {}
        self.writeLUT = {}
        self.psedoReadLUT = {}
        self.existing = {}
        self.merges = {}

        self.returns = []

        self.parent = None

    def newUID(self):
        """Generate a new unique identifier.
        
        Returns:
            int: New unique version number
        """
        temp = self.uid
        self.uid = temp + 1
        return temp

    def branch(self, count):
        """Create branches for control flow splitting.
        
        Creates multiple copies of the current state for different
        control flow paths (e.g., if-then-else branches).
        
        Args:
            count: Number of branches to create
            
        Returns:
            list: List of state dictionaries, one per branch
        """
        current = self.popState()
        branches = [dict(current) for i in range(count)]
        return branches

    def setState(self, state):
        """Set the current state (must be None).
        
        Args:
            state: State dictionary to set
            
        Raises:
            AssertionError: If current state is not None
        """
        assert self._current is None
        self._current = state

    def popState(self):
        """Pop and return the current state.
        
        Returns:
            dict: Current state dictionary (or None)
        """
        old = self._current
        self._current = None
        return old

    def mergeStates(self, states):
        """Merge multiple states from different control flow paths.
        
        Merges states from different paths (e.g., after if-then-else).
        For each variable/field:
        - If all states have the same version, use that version
        - Otherwise, create a new merge version and log the merge
        
        Args:
            states: List of state dictionaries to merge
        """
        states = [state for state in states if state is not None]

        if len(states) == 0:
            merged = None
        elif len(states) == 1:
            merged = dict(states[0])
        else:
            keys = set()
            for state in states:
                keys.update(state.keys())

            merged = {}

            for key in keys:
                values = set()
                for state in states:
                    values.add(state.get(key, -1))

                if len(values) == 1:
                    dstID = values.pop()
                else:
                    dstID = self.newUID()
                    self.logMerge(key, values, dstID)
                merged[key] = dstID
        self._current = merged

    def current(self, node):
        """Get current version number for a variable or field.
        
        For Existing nodes, returns a canonical version number for the object.
        For other nodes, returns the current version from state (or -1 if not found).
        
        Args:
            node: Variable or field to get version for
            
        Returns:
            int: Current version number (or -1 if not found)
        """
        assert not isinstance(node, int), node
        if isinstance(node, ast.Existing):
            obj = node.object
            if obj not in self.existing:
                uid = self.newUID()
                self.existing[obj] = uid
            else:
                uid = self.existing[obj]
        else:
            uid = self._current.get(node, -1)
        return uid

    def setCurrent(self, node, uid):
        """Set current version number for a variable or field.
        
        Args:
            node: Variable or field to set version for
            uid: Version number to set
            
        Raises:
            AssertionError: If node is int or uid is not int
        """
        assert not isinstance(node, int), node
        assert isinstance(uid, int), uid
        self._current[node] = uid

    def rename(self, node):
        """Rename a variable or field (assign new version number).
        
        Creates a new version number for the variable/field, effectively
        marking it as modified.
        
        Args:
            node: Variable or field to rename (None is ignored)
        """
        if node is not None:
            self.setCurrent(node, self.newUID())

    def renameAll(self, names):
        """Rename multiple variables/fields.
        
        Args:
            names: Iterable of variables/fields to rename
        """
        for name in names:
            self.rename(name)

    def renameModifiedFields(self, node):
        info = self.rm[node]
        self.renameAll(info.fieldModify)

    # Give unique names to all the fields that may be passed in to the function.
    def renameEntryFields(self, node):
        info = self.rm[node]

        killed = self.code.annotation.killed.merged

        for field in info.fieldRead:
            assert not isinstance(field, ast.Local), field
            if field not in self._current and field.object not in killed:
                self.rename(field)

        for field in info.fieldModify:
            assert not isinstance(field, ast.Local), field
            if field not in self._current and field.object not in killed:
                self.rename(field)

    def logRead(self, node, name):
        """Log a read operation.
        
        Records that node reads name at its current version number.
        
        Args:
            node: AST node performing the read
            name: Variable or field being read
        """
        self.readLUT[(node, name)] = self.current(name)

    def logModify(self, node, name):
        """Log a modify operation.
        
        Records that node modifies name at its current version number.
        
        Args:
            node: AST node performing the modify
            name: Variable or field being modified
        """
        self.writeLUT[(node, name)] = self.current(name)

    def logPsedoRead(self, node, name):
        """Log a pseudo-read operation.
        
        Pseudo-reads occur when a field is modified - we need to track
        that the previous value was "read" (for correctness).
        
        Args:
            node: AST node performing the pseudo-read
            name: Variable or field being pseudo-read
        """
        self.psedoReadLUT[(node, name)] = self.current(name)

    def logReadLocals(self, parent, node):
        """Log reads of local variables in an expression.
        
        Traverses an expression tree and logs all local variable reads.
        
        Args:
            parent: Parent AST node
            node: Expression node to traverse
        """
        assert self.parent == None
        self.parent = parent
        self(node)
        self.parent = None

    # TODO fields from op?
    def logReadFields(self, node):
        """Log field reads for a node.
        
        Logs all fields that are read or modified (pseudo-read) by the node.
        
        Args:
            node: AST node to log field reads for
        """
        info = self.rm[node]

        for field in info.fieldRead:
            self.logRead(node, field)

        # TODO filter by unique?
        for field in info.fieldModify:
            self.logPsedoRead(node, field)

    # TODO fields from op?
    def logModifiedFields(self, node):
        """Log field modifications for a node.
        
        Logs all fields that are modified by the node.
        
        Args:
            node: AST node to log field modifications for
        """
        info = self.rm[node]
        for field in info.fieldModify:
            self.logModify(node, field)

    def logEntry(self):
        """Log entry state (versions at function entry).
        
        Records the version numbers of all variables and fields at function
        entry. Filters out fields from killed objects (they can't be passed in).
        """
        filtered = {}
        for name, uid in self._current.items():
            if isinstance(name, ast.Local):
                pass  # Assumed all locals are parameters
            else:
                # Fields from killed objects could not have been passed from outside.
                obj = name.object
                if obj in self.code.annotation.killed.merged:
                    continue

            filtered[name] = uid

        filtered[None] = -1

        self.entry = filtered

    def logExit(self):
        """Log exit state (versions at function exit).
        
        Merges all return states and records the version numbers of variables
        and fields at function exit. Filters:
        - Non-return locals (not in returnparams)
        - Unmodified fields (same version as entry)
        - Fields from killed objects (won't propagate)
        """
        returns = self.returns
        self.returns = []

        self.mergeStates(returns)
        state = self.popState()
        assert state is not None

        filtered = {}
        for name, uid in state.items():
            if isinstance(name, ast.Local):
                if name not in self.returnparams:
                    continue
            else:
                if name in self.entry and self.entry[name] == uid:
                    # Not modified.
                    continue

                # Fields from killed objects will not propagate
                obj = name.object
                if obj in self.code.annotation.killed.merged:
                    continue

            filtered[name] = uid

        self.exit = filtered

    def logMerge(self, name, srcIDs, dstID):
        """Log a merge operation (phi-like merge).
        
        Records that a new version dstID was created by merging versions
        srcIDs from different control flow paths.
        
        Args:
            name: Variable or field being merged
            srcIDs: Set of source version numbers
            dstID: Destination version number (merge result)
        """
        assert isinstance(dstID, int)
        key = (name, dstID)
        if key not in self.merges:
            self.merges[key] = set()
        self.merges[key].update(srcIDs)

    @dispatch(ast.Local, ast.Existing)
    def visitLocalRead(self, node):
        """Visit a local variable or existing object read.
        
        Logs the read operation with current version number.
        
        Args:
            node: Local or Existing node being read
        """
        self.logRead(self.parent, node)

    @dispatch(ast.DoNotCare)
    def visitDoNotCare(self, node):
        pass

    @dispatch(ast.Assign)
    def processAssign(self, node):
        self.logReadLocals(node, node.expr)
        self.logReadFields(node)

        if isinstance(node.expr, ast.Local) and len(node.lcls) == 1:
            # Local copy
            target = node.lcls[0]
            self.setCurrent(target, self.current(node.expr))
            self.logModify(node, target)

        else:
            for lcl in node.lcls:
                self.rename(lcl)
                self.logModify(node, lcl)

        self.renameModifiedFields(node)
        self.logModifiedFields(node)

    @dispatch(ast.OutputBlock)
    def visitOutputBlock(self, node):
        for output in node.outputs:
            self.logReadLocals(node, output.expr)

    @dispatch(ast.Discard)
    def processDiscard(self, node):
        self.logReadLocals(node, node.expr)
        self.logReadFields(node)
        self.renameModifiedFields(node)
        self.logModifiedFields(node)

    @dispatch(ast.Store)
    def processStore(self, node):
        self.logReadLocals(node, node.children())
        self.logReadFields(node)
        self.renameModifiedFields(node)
        self.logModifiedFields(node)

    @dispatch(ast.Return)
    def processReturn(self, node):
        self.logReadLocals(node, node.exprs)
        self.logReadFields(node)

        for dst, src in zip(self.returnparams, node.exprs):
            self.setCurrent(dst, self.current(src))
            self.logModify(node, dst)

        self.renameModifiedFields(node)
        self.logModifiedFields(node)

        # Kill the flow
        self.returns.append(self.popState())

    @dispatch(ast.For)
    def processFor(self, node):
        info = self.rm[node]

        # Handle loop preamble
        self(node.loopPreamble)

        # Mark iterator as read
        if node.iterator:
            self.logRead(node, node.iterator)

        # Process body preamble
        self(node.bodyPreamble)

        # Process the loop body
        self(node.body)

        # Process else clause
        self(node.else_)

    @dispatch(ast.While)
    def processWhile(self, node):
        info = self.rm[node]

        self.renameAll(info.localModify)
        self.renameAll(info.fieldModify)

        # TODO Only valid without breaks/continues?

        self(node.condition)
        self.logRead(node, node.condition.conditional)

        self(node.body)

        self.renameAll(info.localModify)
        self.renameAll(info.fieldModify)

        self(node.else_)

        self.renameAll(info.localModify)
        self.renameAll(info.fieldModify)

    @dispatch(ast.Condition)
    def processCondition(self, node):
        self(node.preamble)

    @dispatch(ast.Switch)
    def processSwitch(self, node):
        self(node.condition)

        self.logRead(node, node.condition.conditional)

        tEntry, fEntry = self.branch(2)

        self.setState(tEntry)
        self(node.t)
        tExit = self.popState()

        self.setState(fEntry)
        self(node.f)
        fExit = self.popState()

        self.mergeStates([tExit, fExit])

    @dispatch(ast.TypeSwitch)
    def processTypeSwitch(self, node):
        self.logRead(node, node.conditional)

        branches = self.branch(len(node.cases))
        exits = []

        for case, branch in zip(node.cases, branches):
            self.setState(branch)

            if case.expr:
                if False:
                    # Give the expression the same number as the conditional - they are the same.
                    # WARNING if this is used, redundant load elimination may cause a precision loss.
                    # Basically, loads inside a type switch will likely be more precise that loads outside.
                    exprID = self.current(node.conditional)
                else:
                    exprID = self.newUID()
                self.setCurrent(case.expr, exprID)
                self.logModify(node, case.expr)

            self(case.body)
            exits.append(self.popState())

        self.mergeStates(exits)

    @dispatch(str, type(None), ast.Code)
    def processLeaf(self, node):
        pass

    @dispatch(ast.Allocate, ast.Load, ast.Check, ast.DirectCall)
    def processOP(self, node):
        node.visitChildren(self)

    @dispatch(ast.Suite)
    def processOK(self, node):
        node.visitChildren(self)

    @dispatch(list, tuple)
    def processContainer(self, node):
        for child in node:
            self(child)

    def renameParam(self, p):
        if isinstance(p, ast.Local):
            self.rename(p)

    def processCode(self, code):
        """Process a code object and construct ESSA form.
        
        Main entry point for ESSA construction. Processes a code object:
        1. Renames entry fields (fields that may be passed in)
        2. Renames parameters (self, params, vparam, kparam)
        3. Logs entry state
        4. Processes AST
        5. Logs exit state
        
        Args:
            code: Code object to process
        """
        self.code = code

        self.renameEntryFields(code.ast)

        params = code.codeparameters
        self.returnparams = params.returnparams

        # Init the parameters
        self.renameParam(params.selfparam)
        for p in params.params:
            self.renameParam(p)
        assert not hasattr(params, "kwds")
        self.renameParam(params.vparam)
        self.renameParam(params.kparam)
        # TODO vparam/kparam fields?

        self.logEntry()
        self(code.ast)
        self.logExit()
