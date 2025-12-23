"""CFG to Dataflow IR conversion.

This module converts Control Flow Graphs (CFGs) into Dataflow IR representation.
The conversion process:

1. Traverses CFG operations in control flow order
2. Maintains state for each control flow path (with predicates)
3. Creates dataflow nodes (slots and operations) for each CFG operation
4. Handles control flow merging with gated merges
5. Builds complete dataflow graph with entry/exit nodes

Key concepts:
- **State**: Represents the state of variables at a point in control flow
- **Predicates**: Control flow conditions that gate operations
- **Hyperblocks**: Regions where control flow is shared
- **Gated merges**: Merges that combine values from different control paths

The conversion enables flow-sensitive data flow analysis by representing
control flow dependencies explicitly in the dataflow graph.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast

from pyflow.analysis.dataflowIR import graph
from pyflow.analysis.storegraph import storegraph

from pyflow.analysis.dataflowIR.transform import dce


class AbstractState(object):
    """Abstract base class for state representation during CFG conversion.
    
    State represents the values of variables at a point in control flow.
    Different state types handle different scenarios:
    - State: Normal state with parent for inheritance
    - DeferedEntryPoint: Entry point state (parameters, existing objects)
    - DeferedMerge: Merge point state (combines multiple paths)
    
    Attributes:
        hyperblock: Hyperblock this state belongs to
        predicate: PredicateNode representing control flow condition
        slots: Dictionary mapping variable slots to their dataflow nodes
    """
    def __init__(self, hyperblock, predicate):
        """Initialize abstract state.
        
        Args:
            hyperblock: Hyperblock for this state
            predicate: PredicateNode for control flow condition
        """
        assert predicate.hyperblock is hyperblock
        self.hyperblock = hyperblock
        self.predicate = predicate
        self.slots = {}

    def freeze(self):
        """Freeze this state (prevent further modifications).
        
        Used when state is split or merged to prevent inconsistent updates.
        """
        pass

    def split(self, predicates):
        """Split this state into multiple states for different predicates.
        
        Creates new State objects for each predicate, inheriting from this state.
        
        Args:
            predicates: List of PredicateNodes for different paths
            
        Returns:
            list: List of State objects, one per predicate
        """
        return [State(self.hyperblock, predicate, self) for predicate in predicates]

    def get(self, slot):
        """Get the dataflow node for a variable slot.
        
        If slot hasn't been seen before, generates it using generate().
        Otherwise returns cached value.
        
        Args:
            slot: Variable slot (ast.Local, ast.Existing, or SlotNode)
            
        Returns:
            SlotNode: Dataflow node for the slot
        """
        if slot not in self.slots:
            result = self.generate(slot)
            self.slots[slot] = result
        else:
            result = self.slots[slot]
        return result

    def generate(self, slot):
        """Generate a dataflow node for a slot (must be implemented by subclasses).
        
        Args:
            slot: Variable slot to generate node for
            
        Returns:
            SlotNode: Generated dataflow node
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError


class State(AbstractState):
    """Normal state with parent inheritance.
    
    State represents variable values along a control flow path. It inherits
    values from a parent state and can override them. When frozen, it cannot
    be modified (used when state is split or merged).
    
    Attributes:
        parent: Parent state to inherit values from
        frozen: Whether this state can be modified
    """
    def __init__(self, hyperblock, predicate, parent):
        """Initialize a state with parent.
        
        Args:
            hyperblock: Hyperblock for this state
            predicate: PredicateNode for control flow condition
            parent: Parent state to inherit from
        """
        AbstractState.__init__(self, hyperblock, predicate)
        self.parent = parent
        self.frozen = False

        assert self.parent.hyperblock is self.hyperblock

        parent.freeze()

    def freeze(self):
        """Freeze this state to prevent modifications."""
        self.frozen = True

    def generate(self, slot):
        """Generate node by inheriting from parent.
        
        Args:
            slot: Variable slot
            
        Returns:
            SlotNode: Node from parent state
        """
        return self.parent.get(slot)

    def set(self, slot, value):
        """Set a variable value in this state.
        
        Args:
            slot: Variable slot
            value: Dataflow node value
            
        Raises:
            AssertionError: If state is frozen
        """
        assert not self.frozen
        self.slots[slot] = value


def gate(pred, value):
    """Create a gated operation that conditionally passes a value.
    
    A gate operation passes a value through only when its predicate is true.
    This is used to represent conditional values in the dataflow graph.
    
    Args:
        pred: PredicateNode controlling the gate
        value: SlotNode value to gate
        
    Returns:
        SlotNode: Gated value (output of gate operation)
    """
    gate = graph.Gate(pred.hyperblock)
    gate.setPredicate(pred)
    gate.addRead(value)

    if isinstance(value, graph.ExistingNode):
        result = graph.LocalNode(pred.hyperblock)
    else:
        result = value.duplicate()
    gate.addModify(result)
    result = gate.modify

    return result


def gatedMerge(hyperblock, pairs):
    """Create a gated merge combining values from multiple control paths.
    
    A gated merge combines values from different control flow paths, each
    gated by its predicate. The result is a value that depends on which
    path was taken.
    
    Args:
        hyperblock: Hyperblock for the merge
        pairs: List of (predicate, value) tuples for each path
        
    Returns:
        SlotNode: Merged value (output of merge operation)
        
    Note:
        TODO: Handle single-pair case (should this create a gate instead?)
    """
    if len(pairs) == 1:
        assert False, "single gated merge?"
        pred, value = pairs[0]
        result = gate(pred, value)
    else:
        m = graph.Merge(hyperblock)

        result = pairs[0][1].duplicate()
        result.hyperblock = hyperblock
        m.modify = result.addDefn(m)

        for pred, value in pairs:
            # Create the gate
            # TODO will the predicate always have the right hyperblock?
            temp = gate(pred, value)

            # Merge the gate
            m.addRead(temp)

        result = m.modify

    return result


class DeferedMerge(AbstractState):
    def __init__(self, hyperblock, predicate, states):
        AbstractState.__init__(self, hyperblock, predicate)
        self.states = states

    def generate(self, slot):
        slots = [state.get(slot) for state in self.states]
        unique = set(slots)
        if len(unique) == 1:
            return unique.pop()

        pairs = [(state.predicate, state.get(slot)) for state in self.states]
        return gatedMerge(self.hyperblock, pairs)


class DeferedEntryPoint(AbstractState):
    def __init__(self, hyperblock, predicate, code, dataflow):
        AbstractState.__init__(self, hyperblock, predicate)
        self.code = code
        self.dataflow = dataflow

    def generate(self, slot):
        if isinstance(slot, ast.Local):
            # Parameters are explicitly set.
            # If it isn't already here, it's an undefined local.
            return self.dataflow.null
        elif isinstance(slot, ast.Existing):
            return self.dataflow.getExisting(slot)
        else:
            # Fields from killed object cannot come from beyond the entry point.
            killed = self.code.annotation.killed.merged
            if slot.object in killed:
                return self.dataflow.null
            else:
                field = graph.FieldNode(self.hyperblock, slot)
                self.dataflow.entry.addEntry(slot, field)
                return field

    def set(self, slot, value):
        self.slots[slot] = value
        self.dataflow.entry.addEntry(slot, value)


class CodeToDataflow(TypeDispatcher):
    """Converts CFG Code objects to Dataflow IR.
    
    This class traverses CFG operations and converts them to dataflow graph
    nodes. It maintains state for each control flow path and handles:
    - Variable reads and writes
    - Control flow branching (splits)
    - Control flow merging (gated merges)
    - Memory operations (loads, stores, allocations)
    - Function entry and exit
    
    Attributes:
        uid: Unique identifier counter for hyperblocks
        code: CFG Code object being converted
        dataflow: DataflowGraph being built
        entryState: Entry point state (handles parameters, existing objects)
        current: Current state being processed
        returns: List of return states (for exit construction)
        allModified: Set of all variables modified in the function
    """
    def __init__(self, code):
        """Initialize CFG to dataflow converter.
        
        Args:
            code: CFG Code object to convert
        """
        self.uid = 0
        hyperblock = self.newHyperblock()

        self.code = code
        self.dataflow = graph.DataflowGraph(hyperblock)
        self.dataflow.initPredicate()

        self.entryState = DeferedEntryPoint(
            hyperblock, self.dataflow.entryPredicate, self.code, self.dataflow
        )
        self.current = State(hyperblock, self.dataflow.entryPredicate, self.entryState)

        self.returns = []

        self.allModified = set()

    def newHyperblock(self):
        name = self.uid
        self.uid += 1
        return graph.Hyperblock(name)

    def branch(self, predicates):
        current = self.popState()
        branches = current.split(predicates)
        return branches

    def setState(self, state):
        assert self.current is None
        self.current = state

    def popState(self):
        old = self.current
        self.current = None
        return old

    def mergeStates(self, states):
        # TODO predicated merge / mux?
        states = [state for state in states if state is not None]

        if len(states) == 1:
            # TODO is this sound?  Does it interfere with hyperblock definition?
            state = states.pop()
        else:
            # TODO only create a new hyperblock when merging from different hyperblocks?
            hyperblock = self.newHyperblock()
            pairs = [(state.predicate, state.predicate) for state in states]
            predicate = gatedMerge(hyperblock, pairs)
            predicate.name = repr(hyperblock)

            state = DeferedMerge(hyperblock, predicate, states)
            state = State(hyperblock, predicate, state)

        self.setState(state)
        return state

    def get(self, slot):
        return self.current.get(slot)

    def set(self, slot, value):
        value.addName(slot)
        self.allModified.add(slot)
        return self.current.set(slot, value)

    def pred(self):
        return self.current.predicate

    def hyperblock(self):
        return self.current.hyperblock

    def localTarget(self, lcl):
        if isinstance(lcl, ast.Local):
            node = graph.LocalNode(self.hyperblock(), (lcl,))
        else:
            assert False
        return node

    def handleOp(self, node, targets):
        g = self(node)
        assert isinstance(g, graph.GenericOp), (node, g)
        for lcl in targets:
            target = self.localTarget(lcl)
            self.set(lcl, target)
            g.addLocalModify(lcl, target)

    def handleMemory(self, node, g):
        # Reads
        for read in node.annotation.reads.merged:
            slot = self.get(read)
            g.addRead(read, slot)

        # Psedo reads
        for modify in node.annotation.modifies.merged:
            slot = self.get(modify)
            g.addPsedoRead(modify, slot)

        # Modifies
        for modify in node.annotation.modifies.merged:
            slot = graph.FieldNode(self.hyperblock(), modify)
            self.set(modify, slot)
            g.addModify(modify, slot)

    def localRead(self, g, lcl):
        if isinstance(lcl, (ast.Local, ast.Existing)):
            g.addLocalRead(lcl, self.get(lcl))

    @dispatch(ast.Allocate)
    def processAllocate(self, node):
        g = graph.GenericOp(self.hyperblock(), node)
        g.setPredicate(self.pred())

        self.localRead(g, node.expr)

        self.handleMemory(node, g)
        return g

    @dispatch(ast.Load)
    def processLoad(self, node):
        g = graph.GenericOp(self.hyperblock(), node)
        g.setPredicate(self.pred())

        self.localRead(g, node.expr)
        self.localRead(g, node.name)

        self.handleMemory(node, g)
        return g

    @dispatch(ast.DirectCall)
    def processDirectCall(self, node):
        g = graph.GenericOp(self.hyperblock(), node)
        g.setPredicate(self.pred())

        self.localRead(g, node.selfarg)

        for arg in node.args:
            self.localRead(g, arg)

        self.localRead(g, node.vargs)
        self.localRead(g, node.kargs)

        self.handleMemory(node, g)
        return g

    @dispatch(ast.Local, ast.Existing)
    def visitLocalRead(self, node):
        return self.get(node)

    @dispatch(ast.Assign)
    def processAssign(self, node):
        if isinstance(node.expr, (ast.Local, ast.Existing)) and len(node.lcls) == 1:
            # Local copy
            target = node.lcls[0]
            g = self.get(node.expr)
            self.set(target, g)

        else:
            self.handleOp(node.expr, node.lcls)

    @dispatch(ast.Discard)
    def processDiscard(self, node):
        self.handleOp(node.expr, [])

    @dispatch(ast.Store)
    def processStore(self, node):
        g = graph.GenericOp(self.hyperblock(), node)
        g.setPredicate(self.pred())

        self.localRead(g, node.expr)
        self.localRead(g, node.name)
        self.localRead(g, node.value)

        self.handleMemory(node, g)
        return g

    @dispatch(ast.Return)
    def processReturn(self, node):
        for dst, src in zip(self.code.codeparameters.returnparams, node.exprs):
            self.set(dst, self.get(src))
        self.returns.append(self.popState())

    @dispatch(ast.TypeSwitch)
    def processTypeSwitch(self, node):

        g = graph.GenericOp(self.hyperblock(), node)
        g.setPredicate(self.pred())

        self.localRead(g, node.conditional)

        for i in range(len(node.cases)):
            p = graph.PredicateNode(self.hyperblock(), i)
            g.predicates.append(p.addDefn(g))
        branches = self.branch(g.predicates)
        exits = []

        for case, branch in zip(node.cases, branches):
            self.setState(branch)
            if case.expr:
                target = self.localTarget(case.expr)
                self.set(case.expr, target)
            else:
                target = None
            g.addLocalModify(case.expr, target)

            self(case.body)
            exits.append(self.popState())

        self.mergeStates(exits)

    @dispatch(str, type(None), ast.Code)
    def processLeaf(self, node):
        return None

    @dispatch(ast.Suite)
    def processOK(self, node):
        node.visitChildren(self)

    def handleExit(self):
        state = self.mergeStates(self.returns)

        killed = self.code.annotation.killed.merged

        self.dataflow.exit = graph.Exit(state.hyperblock)
        self.dataflow.exit.setPredicate(state.predicate)

        for name in self.allModified:
            if isinstance(name, ast.Local):
                if name in self.code.codeparameters.returnparams:
                    self.dataflow.exit.addExit(name, state.get(name))
            elif isinstance(name, storegraph.SlotNode):
                if name.object not in killed:
                    self.dataflow.exit.addExit(name, state.get(name))

    def setParameter(self, param):
        if isinstance(param, ast.Local):
            g = self.localTarget(param)
            self.entryState.set(param, g)

    def processCode(self):
        # Init the parameters
        params = self.code.codeparameters
        self.setParameter(params.selfparam)
        for p in params.params:
            self.setParameter(p)
        assert not hasattr(params, "kwds")
        self.setParameter(params.vparam)
        self.setParameter(params.kparam)

        self(self.code.ast)

        self.handleExit()

        return self.dataflow


def evaluateCode(compiler, code):
    ctd = CodeToDataflow(code)
    dataflow = ctd.processCode()
    dce.evaluateDataflow(dataflow)
    return dataflow
