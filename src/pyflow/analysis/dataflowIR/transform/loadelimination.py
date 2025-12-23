"""Load elimination optimization for dataflow IR.

This module implements load elimination optimization, which removes redundant
load operations when the loaded value is available from a dominating store.

The optimization:
1. Identifies load operations
2. Finds the dominating store that writes the same field
3. Verifies the store dominates the load (predicate dominance)
4. Replaces load with direct use of store's value

This optimization requires predicate dominance analysis to ensure soundness:
the store must execute before the load on all paths where the load executes.
"""

from pyflow.analysis.dataflowIR import graph
from pyflow.analysis.dataflowIR import predicate
from pyflow.analysis.dataflowIR.traverse import dfs


def findLoadSrc(g):
    """Find the source definition for a load operation.
    
    Returns the operation that defines the heap location being loaded.
    
    Args:
        g: GenericOp representing a load operation
        
    Returns:
        OpNode: Operation defining the loaded location (typically a Store)
    """
    for node in g.heapReads.values():
        defn = node.canonical().defn
        return defn


# Is the use a copy to the definition?
# It may be filtered by type switches, etc.
def isLocalSubset(defn, use):
    """Check if use is a subset/copy of definition.
    
    Determines if a use represents the same value as a definition,
    possibly through type switches or other filtering operations.
    
    Args:
        defn: Definition slot node
        use: Use slot node
        
    Returns:
        bool: True if use is subset/copy of definition
    """
    defn = defn.canonical()
    use = use.canonical()

    if defn is use:
        return True
    elif use.defn.isOp() and use.defn.isTypeSwitch():
        # Type switch may filter but preserve value
        conditional = use.defn.op.conditional
        cNode = use.defn.localReads[conditional]
        return isLocalSubset(defn, cNode)

    return False


def attemptTransform(g, pg):
    """Attempt to eliminate a load operation.
    
    Checks if a load can be eliminated by replacing it with the value
    from a dominating store. Verifies:
    1. Load has single modification target
    2. Source is a store operation
    3. Load/store parameters match (object, field type, field name)
    4. Store predicate dominates load predicate
    5. Heap read/modify sets match
    
    Args:
        g: GenericOp representing load operation
        pg: PredicateGraph for dominance checking
        
    Returns:
        bool: True if transformation was performed
    """
    # Is the load unused or invalid?
    if len(g.localModifies) != 1:
        return False

    defn = findLoadSrc(g)

    if isinstance(defn, graph.GenericOp) and defn.isStore():
        # Make sure the load / store parameters are identical
        # expr (object being accessed)
        if not isLocalSubset(
            defn.localReads[defn.op.expr].canonical(),
            g.localReads[g.op.expr].canonical(),
        ):
            return False

        # field type
        if not g.op.fieldtype == defn.op.fieldtype:
            return False

        # field name
        if (
            not g.localReads[g.op.name].canonical()
            == defn.localReads[defn.op.name].canonical()
        ):
            return False

        # Make sure the store predicate dominates the load predicate
        if not pg.dominates(defn.canonicalpredicate, g.canonicalpredicate):
            return False

        # Make sure the heap read / modify is identical
        reads = frozenset([node.canonical() for node in g.heapReads.values()])
        modifies = frozenset([node.canonical() for node in defn.heapModifies.values()])

        if reads != modifies:
            return False

        # It's sound to bypass the load.
        src = defn.localReads[defn.op.value]
        dst = g.localModifies[0]

        dst.canonical().redirect(src)
        g.localModifies = []

        return True

    return False


def collectLoads(dataflow):
    """Collect all load operations in a dataflow graph.
    
    Args:
        dataflow: DataflowGraph to search
        
    Returns:
        set: Set of GenericOp nodes representing loads
    """
    loads = set()

    def collect(node):
        if isinstance(node, graph.GenericOp) and node.isLoad():
            loads.add(node)

    dfs(dataflow, collect)

    return loads


def evaluateDataflow(dataflow):
    """Perform load elimination on a dataflow graph.
    
    Main entry point for load elimination. Builds predicate graph,
    collects loads, and attempts to eliminate each one.
    
    Args:
        dataflow: DataflowGraph to optimize
        
    Note:
        HACK: Iterates until fixed point (no more eliminations possible).
        This is needed because eliminating one load may enable eliminating another.
    """
    pg = predicate.buildPredicateGraph(dataflow)

    loads = collectLoads(dataflow)

    print("LOADS", len(loads))

    eliminated = 0

    # HACK keep evaluating each load until no further transforms are possible.
    changed = True
    while changed:
        changed = False
        for load in loads:
            if attemptTransform(load, pg):
                eliminated += 1
                changed = True

    print("ELIMINATED", eliminated)
