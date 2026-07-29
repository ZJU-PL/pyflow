"""
Data Dependence Graph (DDG) construction.

This module provides algorithms for constructing Data Dependence Graphs from
dataflow IR graphs. The construction process involves:

1. **Indexing**: Traverse the dataflow IR graph and create DDG nodes for all
   operations and slots reachable from entry/exit.

2. **Def-Use Connection**: For each slot, connect the defining operation to the
   slot and the slot to all using operations. This creates explicit def-use
   chains that represent data flow.

3. **Memory Dependencies**: Add conservative memory dependencies for heap
   operations. If an operation writes to a heap slot and a later operation
   reads or writes the same slot, add a memory edge to ensure proper ordering.

**Construction Algorithm:**
- Start from entry/exit nodes in the dataflow graph
- Traverse forward from entry to collect all reachable nodes
- For each slot with a definition, find all uses via forward() traversal
- Connect def operations to slots and slots to use operations
- For memory operations, track last writer and add dependencies

**Memory Dependencies:**
Memory dependencies are conservative (may over-approximate) because precise
alias analysis is expensive. The algorithm tracks last writer for each heap
slot and adds dependencies for:
- RAW (Read After Write): Read depends on previous write
- WAR (Write After Read): Write depends on previous read
- WAW (Write After Write): Write depends on previous write

**Input:**
The constructor takes a dataflow IR.DataflowGraph which contains:
- Entry/Exit operations
- Operations (GenericOp, Merge, Split, Gate, etc.)
- Slots (LocalNode, FieldNode, ExistingNode, NullNode)
- Forward/reverse edges connecting operations and slots
"""

from collections import deque
from typing import Any

from pyflow.ir.dataflow import graph as df
from .graph import DataDependenceGraph, DDGNode


class MalformedForwardingCycleError(ValueError):
    """Raised when a dataflow slot's forwarding chain contains a cycle."""


def _memory_slot_key(slot: Any) -> Any:
    def canonicalize(value):
        seen = []
        while value is not None:
            if any(candidate is value for candidate in seen):
                raise MalformedForwardingCycleError(
                    f"cyclic forwarding chain for {type(value).__qualname__}"
                )
            seen.append(value)
            replacement = value
            if hasattr(replacement, "getForward"):
                replacement = replacement.getForward()
            if hasattr(replacement, "canonical"):
                replacement = replacement.canonical()
            if replacement is value:
                break
            value = replacement
        return value

    canonical = canonicalize(slot)

    slot_name = canonicalize(getattr(canonical, "name", None))
    if slot_name is not None and (
        hasattr(slot_name, "object") or hasattr(slot_name, "slotName")
    ):
        return slot_name

    slot_object = canonicalize(getattr(canonical, "object", None))
    if slot_object is not None:
        return (slot_object, slot_name)

    return canonical


class DDGConstructor(object):
    """
    Constructs Data Dependence Graphs from dataflow IR graphs.

    This class implements the complete DDG construction algorithm, including
    node indexing, def-use connection, and memory dependency analysis.

    **Construction Process:**

    1. Indexing: Traverse the dataflow IR graph starting from entry/exit nodes
       and create DDG nodes for all reachable operations and slots.

    2. Def-Use Connection: For each slot with a definition, find all uses
       and connect the defining operation to using operations.

    3. Memory Dependencies: Add conservative memory dependencies for heap
       operations to ensure proper ordering (RAW, WAR, WAW).

    Attributes:
        ddg: The Data Dependence Graph being constructed
    """

    __slots__ = ("ddg",)

    def __init__(self):
        """Initialize a DDG constructor."""
        self.ddg = DataDependenceGraph()

    def construct_from_dataflow(
        self, dataflow: df.DataflowGraph
    ) -> DataDependenceGraph:
        """
        Construct a DDG from a dataflow IR graph.

        Performs the complete construction process:
        1. Indexes all operations and slots
        2. Connects def-use pairs
        3. Adds memory dependencies

        Args:
            dataflow: DataflowIR graph to build DDG from

        Returns:
            The constructed Data Dependence Graph
        """
        # Constructors are reusable, but each construction represents exactly
        # one input graph.
        self.ddg = DataDependenceGraph(getattr(dataflow, "code", None))

        # Create nodes for all ops and slots reachable from graph roots.
        self._index_dataflow(dataflow)

        # Connect def-use edges for local and heap flows
        self._connect_def_use()

        # Memory dependencies: connect writes to subsequent reads conservatively
        self._connect_memory_dependencies(dataflow)

        return self.ddg

    # Indexing helpers
    def _index_op(self, op: df.OpNode) -> DDGNode:
        """
        Index a dataflow IR operation node.

        Args:
            op: DataflowIR OpNode to index

        Returns:
            DDGNode for the operation
        """
        return self.ddg.get_or_create_op_node(op)

    def _index_slot(self, slot: df.SlotNode) -> DDGNode:
        """
        Index a dataflow IR slot node.

        Args:
            slot: DataflowIR SlotNode to index

        Returns:
            DDGNode for the slot
        """
        return self.ddg.get_or_create_slot_node(slot)

    def _index_dataflow(self, dataflow: df.DataflowGraph) -> None:
        """
        Index all operations and slots in the dataflow graph.

        Performs a forward traversal from every semantic graph root to collect
        all reachable operations and slots. This includes entry/exit,
        entry-predicate, existing values, and the null value.

        **Traversal Strategy:**
        Uses depth-first traversal starting from entry node, following
        forward() edges to discover all reachable nodes.

        Args:
            dataflow: DataflowIR graph to index
        """
        roots = [dataflow.entry, *dataflow.existing.values(), dataflow.null]
        if dataflow.entryPredicate is not None:
            roots.append(dataflow.entryPredicate)
        if dataflow.exit is not None:
            roots.append(dataflow.exit)

        # Walk from every graph root. Existing/null values are independent
        # sources and may feed operations that are not discovered from entry in
        # partially constructed or transformed dataflow graphs.
        visited = set()
        stack = list(roots)
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)

            # Index the node based on its type
            if isinstance(node, df.OpNode):
                self._index_op(node)
            elif isinstance(node, df.SlotNode):
                self._index_slot(node)

            # Continue traversal to discover more nodes
            for nxt in node.forward():
                if nxt not in visited:
                    stack.append(nxt)

    def _connect_def_use(self) -> None:
        """
        Connect definition-use pairs in the DDG.

        For each slot, creates explicit def-use edges through the slot node.
        Definitions flow from the defining operation into the slot; uses flow
        from the slot into each consuming operation.

        **Def-Use Connection:**
        - A slot's definition is stored in its `defn` attribute (the operation that defines it)
        - A slot's uses are found via `forward()` traversal (operations that read from it)
        - Creates edges: def_op -> slot -> use_op

        **Edge Labels:**
        Edges are labeled with the slot representation for debugging and
        visualization purposes.
        """
        # Materialize slot nodes in the DDG instead of leaving them isolated.
        # Definitions flow into the slot node; each use flows out of it.
        for ir_slot, slot_node in list(self.ddg.slot_node_map.items()):
            if hasattr(ir_slot, "defn") and ir_slot.defn is not None:
                def_op = ir_slot.defn
                def_ddg = self.ddg.get_or_create_op_node(def_op)
                def_ddg.add_edge_to(slot_node, "def-use", label=repr(slot_node.ir_node))

            # dataflow IR slots expose forward() which returns operations that read from them.
            for user in ir_slot.forward():
                use_ddg = self.ddg.get_or_create_op_node(user)
                slot_node.add_edge_to(use_ddg, "def-use", label=repr(slot_node.ir_node))

    def _connect_memory_dependencies(self, dataflow: df.DataflowGraph) -> None:
        """
        Add conservative memory dependencies for heap operations.

        This method adds memory dependence edges to ensure proper ordering
        of heap operations. The analysis is conservative (may over-approximate)
        because precise alias analysis is expensive.

        **Memory Dependencies:**
        - RAW (Read After Write): Read depends on previous write to same location
        - WAR (Write After Read): Write depends on previous read from same location
        - WAW (Write After Write): Write depends on previous write to same location

        **Temporal Ordering:**
        A forward fixed point propagates reaching writes and intervening reads
        over the operation graph. At joins the states are unioned, retaining
        dependencies from every feasible predecessor.

        **Slot Identification:**
        Heap slots are identified by their name (for FieldNode) or by the
        slot object itself. Operations that access the same slot name are
        considered to potentially alias.

        **Algorithm:**
        1. Build operation predecessor/successor relations
        2. Collect heap reads and writes for each operation
        3. Compute reaching writes and reads-since-write to a fixed point
        4. Add RAW, WAR, and WAW edges from each operation's input state
        """
        ir_ops = list(self.ddg.op_node_map)
        op_nodes = {ir: self.ddg.get_or_create_op_node(ir) for ir in ir_ops}
        op_set = set(ir_ops)

        def operation_successors(ir_op):
            result = set()
            for child in ir_op.forward():
                if isinstance(child, df.OpNode):
                    result.add(child)
                elif isinstance(child, df.SlotNode):
                    result.update(
                        user for user in child.forward() if isinstance(user, df.OpNode)
                    )
            return result & op_set

        successors = {ir: operation_successors(ir) for ir in ir_ops}
        predecessors = {ir: set() for ir in ir_ops}
        for source, targets in successors.items():
            for target in targets:
                predecessors[target].add(source)

        accesses = {}
        for ir in ir_ops:
            reads = []
            writes = []
            if isinstance(getattr(ir, "heapReads", None), dict):
                reads.extend(ir.heapReads.values())
            if isinstance(getattr(ir, "heapPsedoReads", None), dict):
                reads.extend(ir.heapPsedoReads.values())
            if isinstance(getattr(ir, "heapModifies", None), dict):
                writes.extend(ir.heapModifies.values())
            accesses[ir] = (
                {_memory_slot_key(slot) for slot in reads},
                {_memory_slot_key(slot) for slot in writes},
            )

        # Solve one abstract location at a time.  The previous product state
        # copied a growing location->state dictionary at every operation; its
        # peak memory was O(operations * locations).  This formulation keeps
        # only two scalar reaching sets per operation and releases them before
        # moving to the next location.
        locations = sorted(
            {key for read, write in accesses.values() for key in read | write},
            key=repr,
        )
        empty_state = (frozenset(), frozenset())

        for key in locations:
            in_states = {ir: empty_state for ir in ir_ops}
            out_states = {ir: empty_state for ir in ir_ops}
            worklist = deque(ir_ops)
            queued = set(ir_ops)

            while worklist:
                ir = worklist.popleft()
                queued.discard(ir)

                reaching_writes = set()
                reaching_reads = set()
                for predecessor in predecessors[ir]:
                    writes, reads = out_states[predecessor]
                    reaching_writes.update(writes)
                    reaching_reads.update(reads)
                incoming = (
                    frozenset(reaching_writes),
                    frozenset(reaching_reads),
                )

                reads, writes = accesses[ir]
                if key in reads:
                    outgoing = (incoming[0], incoming[1] | frozenset((ir,)))
                else:
                    outgoing = incoming
                if key in writes:
                    outgoing = (frozenset((ir,)), frozenset())

                if incoming == in_states[ir] and outgoing == out_states[ir]:
                    continue
                in_states[ir] = incoming
                out_states[ir] = outgoing
                for successor in successors[ir]:
                    if successor not in queued:
                        queued.add(successor)
                        worklist.append(successor)

            for ir in ir_ops:
                reads, writes = accesses[ir]
                if key not in reads and key not in writes:
                    continue
                op = op_nodes[ir]
                reaching_writes, reaching_reads = in_states[ir]
                if key in reads:
                    for writer in reaching_writes:
                        if writer is not ir:
                            self.ddg.add_mem_dep(
                                op_nodes[writer], op, label="RAW", location=key
                            )
                if key in writes:
                    for reader in reaching_reads:
                        if reader is not ir:
                            self.ddg.add_mem_dep(
                                op_nodes[reader], op, label="WAR", location=key
                            )
                    for writer in reaching_writes:
                        if writer is not ir:
                            self.ddg.add_mem_dep(
                                op_nodes[writer], op, label="WAW", location=key
                            )


def construct_ddg(dataflow: df.DataflowGraph) -> DataDependenceGraph:
    """
    Convenience function to construct a DDG from a dataflow IR graph.

    Creates a DDGConstructor, runs the construction algorithm, and returns
    the resulting Data Dependence Graph.

    Args:
        dataflow: The dataflow IR graph to build a DDG from

    Returns:
        The constructed Data Dependence Graph
    """
    return DDGConstructor().construct_from_dataflow(dataflow)
