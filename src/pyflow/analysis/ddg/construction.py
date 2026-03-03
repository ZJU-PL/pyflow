"""
Data Dependence Graph (DDG) construction.

This module provides algorithms for constructing Data Dependence Graphs from
dataflowIR graphs. The construction process involves:

1. **Indexing**: Traverse the dataflowIR graph and create DDG nodes for all
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
The constructor takes a dataflowIR.DataflowGraph which contains:
- Entry/Exit operations
- Operations (GenericOp, Merge, Split, Gate, etc.)
- Slots (LocalNode, FieldNode, ExistingNode, NullNode)
- Forward/reverse edges connecting operations and slots
"""

from collections import defaultdict
from typing import Optional, Any

from pyflow.analysis.dataflowIR import graph as df
from pyflow.analysis.dataflowIR import ordering
from .graph import DataDependenceGraph, DDGNode


class DDGConstructor(object):
    """
    Constructs Data Dependence Graphs from dataflowIR graphs.

    This class implements the complete DDG construction algorithm, including
    node indexing, def-use connection, and memory dependency analysis.

    **Construction Process:**

    1. Indexing: Traverse the dataflowIR graph starting from entry/exit nodes
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
        Construct a DDG from a dataflowIR graph.

        Performs the complete construction process:
        1. Indexes all operations and slots
        2. Connects def-use pairs
        3. Adds memory dependencies

        Args:
            dataflow: DataflowIR graph to build DDG from

        Returns:
            The constructed Data Dependence Graph
        """
        # Create nodes for all ops and slots reachable from entry/exit
        self._index_dataflow(dataflow)

        # Connect def-use edges for local and heap flows
        self._connect_def_use()

        # Memory dependencies: connect writes to subsequent reads conservatively
        self._connect_memory_dependencies(dataflow)

        return self.ddg

    # Indexing helpers
    def _index_op(self, op: df.OpNode) -> DDGNode:
        """
        Index a dataflowIR operation node.

        Args:
            op: DataflowIR OpNode to index

        Returns:
            DDGNode for the operation
        """
        return self.ddg.get_or_create_op_node(op)

    def _index_slot(self, slot: df.SlotNode) -> DDGNode:
        """
        Index a dataflowIR slot node.

        Args:
            slot: DataflowIR SlotNode to index

        Returns:
            DDGNode for the slot
        """
        return self.ddg.get_or_create_slot_node(slot)

    def _index_dataflow(self, dataflow: df.DataflowGraph) -> None:
        """
        Index all operations and slots in the dataflow graph.

        Performs a forward traversal from the entry node to collect all
        reachable operations and slots. Also indexes entry/exit operations
        and existing/null slots which may not be reachable via forward edges.

        **Traversal Strategy:**
        Uses depth-first traversal starting from entry node, following
        forward() edges to discover all reachable nodes.

        Args:
            dataflow: DataflowIR graph to index
        """
        # Index entry and exit operations (special nodes)
        self._index_op(dataflow.entry)
        if dataflow.exit is not None:
            self._index_op(dataflow.exit)

        # Index existing and null slots (global slots)
        for slot in dataflow.existing.values():
            self._index_slot(slot)
        self._index_slot(dataflow.null)

        # Walk from entry following forward edges to collect ops/slots
        # This discovers all nodes reachable from the entry point
        visited = set()
        stack = list(dataflow.entry.forward())
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

            # dataflowIR slots expose forward() which returns operations that read from them.
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
        Operations are processed in dataflow topological order so that
        consumers are visited after all reachable producers.

        **Slot Identification:**
        Heap slots are identified by their name (for FieldNode) or by the
        slot object itself. Operations that access the same slot name are
        considered to potentially alias.

        **Algorithm:**
        1. Compute a topological order for operations
        2. For each operation, collect heap reads and writes
        3. Track the last writer and readers since that write for each heap slot
        4. Add memory edges for RAW, WAR, WAW hazards
        """
        # Use the dataflow topological order rather than DDG discovery order.
        op_order = ordering.evaluateDataflow(dataflow)
        ops = [self.ddg.get_or_create_op_node(op) for op in op_order]

        # Track the most recent writer and the readers since that write.
        last_write = {}
        reads_since_write = defaultdict(set)

        for op in ops:
            ir = op.ir_node
            writes = []
            reads = []

            # Collect heap reads and writes from the operation
            # Different operation types expose heap access differently:
            # - GenericOp: has heapModifies/heapReads dictionaries
            # - Entry: can define entry slots
            # - Merge/Gate: can also define slots
            if hasattr(ir, "heapModifies") and isinstance(
                getattr(ir, "heapModifies"), dict
            ):
                writes.extend(ir.heapModifies.values())
            if hasattr(ir, "heapReads") and isinstance(getattr(ir, "heapReads"), dict):
                reads.extend(ir.heapReads.values())
            if hasattr(ir, "heapPsedoReads") and isinstance(
                getattr(ir, "heapPsedoReads"), dict
            ):
                reads.extend(ir.heapPsedoReads.values())

            # Key function: use slot name if available, otherwise use slot object
            key_func = lambda slot: getattr(slot, "name", None) or slot

            for slot in reads:
                k = key_func(slot)
                if k in last_write:
                    self.ddg.add_mem_dep(last_write[k], op, label="RAW")
                reads_since_write[k].add(op)

            for slot in writes:
                k = key_func(slot)
                for reader in sorted(
                    reads_since_write.pop(k, ()), key=lambda node: node.node_id
                ):
                    if reader is not op:
                        self.ddg.add_mem_dep(reader, op, label="WAR")
                if k in last_write:
                    self.ddg.add_mem_dep(last_write[k], op, label="WAW")
                last_write[k] = op


def construct_ddg(dataflow: df.DataflowGraph) -> DataDependenceGraph:
    """
    Convenience function to construct a DDG from a dataflowIR graph.

    Creates a DDGConstructor, runs the construction algorithm, and returns
    the resulting Data Dependence Graph.

    Args:
        dataflow: The dataflowIR graph to build a DDG from

    Returns:
        The constructed Data Dependence Graph
    """
    return DDGConstructor().construct_from_dataflow(dataflow)
