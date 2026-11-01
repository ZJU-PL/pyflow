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
from typing import Any, Dict, List, Set, Tuple

from pyflow.ir.core import ensure_code_indexed
from pyflow.ir.core.source import syntax_source_span
from pyflow.ir.core.storage import UnknownStorage
from pyflow.ir.dataflow import graph as df
from pyflow.ir.core.storage import AttributeStorage, GlobalStorage, LocalStorage, SubscriptStorage
from pyflow.ir.core.symbols import SymbolKind
from pyflow.language.python import ast as py_ast
from .graph import DataDependenceGraph, DDGNode


class MalformedForwardingCycleError(ValueError):
    """Raised when a dataflow slot's forwarding chain contains a cycle."""


def _memory_slot_key(slot: Any, aliases=None, parameter_symbols=()) -> Any:
    """Return a stable identity for the storage location of *slot*.

    Dataflow slots are value versions, not storage locations: a store to a
    field creates a fresh ``FieldNode`` and a later load may canonicalize to
    that version.  Memory dependences must group all versions of the same
    storage (for example ``AttributeStorage(base=c, field='x')``), otherwise
    a later write never shares a key with an earlier read/write and WAR/WAW
    edges disappear.
    """

    def canonicalize(value):
        seen: List[Any] = []
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
                try:
                    replacement = replacement.canonical()
                except AttributeError:
                    # A dead Split may have been optimized away while a
                    # removed slot still points at it.  Treat the slot as
                    # unforwarded instead of aborting DDG construction.
                    replacement = None
            if replacement is value:
                break
            value = replacement
        return value

    canonical = canonicalize(slot)

    aliases = aliases or {}
    parameter_symbols = parameter_symbols or ()

    def canonical_storage(storage, seen=None):
        # Alias maps can be cyclic (a = b.x; b = a.y).  Track the concrete
        # storage objects on the current resolution path and collapse cycles
        # to one conservative location instead of recursing forever.
        seen = set() if seen is None else seen
        marker = id(storage)
        if marker in seen:
            return ("alias-cycle",)
        seen.add(marker)
        if isinstance(storage, GlobalStorage):
            return ("global", storage.name)
        if isinstance(storage, LocalStorage):
            symbol = aliases.get(storage.symbol, storage.symbol)
            seen_symbols = set()
            while hasattr(symbol, "scope") and symbol in aliases:
                if symbol in seen_symbols:
                    return ("alias-cycle",)
                seen_symbols.add(symbol)
                replacement = aliases[symbol]
                if replacement == symbol:
                    break
                symbol = replacement
            if isinstance(symbol, tuple):
                return symbol
            if isinstance(symbol, (AttributeStorage, LocalStorage, SubscriptStorage)):
                return canonical_storage(symbol, seen)
            if symbol in parameter_symbols:
                # Parameters may alias at the call site.  Treat their field
                # bases as a single conservative parameter location.
                return ("parameter-base",)
            return LocalStorage(symbol)
        if isinstance(storage, AttributeStorage):
            return AttributeStorage(canonical_storage(storage.base, seen), storage.field)
        if isinstance(storage, SubscriptStorage):
            return SubscriptStorage(canonical_storage(storage.base, seen), storage.key)
        return storage

    slot_name = canonicalize(getattr(canonical, "name", None))
    if isinstance(slot_name, UnknownStorage):
        # Opaque calls model reads and writes with different UnknownStorage
        # kinds (call-read / call-write).  They still refer to the same
        # unrefined heap, so all unknown storage aliases conservatively.
        return UnknownStorage("unknown")
    if slot_name is not None and (hasattr(slot_name, "object") or hasattr(slot_name, "slotName")):
        return slot_name

    slot_object = canonicalize(getattr(canonical, "object", None))
    if slot_object is not None:
        return (slot_object, slot_name)

    if slot_name is not None:
        # Immutable StorageLocation identities (LocalStorage,
        # AttributeStorage, GlobalStorage, ...) already distinguish the base
        # object and the field, and they are shared by every value version.
        return canonical_storage(slot_name)

    names = canonicalize(getattr(canonical, "names", None))
    if names:
        return tuple(names)

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

    __slots__ = ("ddg", "_memory_aliases", "_parameter_symbols")

    def __init__(self):
        """Initialize a DDG constructor."""
        self.ddg = DataDependenceGraph()
        self._memory_aliases = {}
        self._parameter_symbols = set()

    def construct_from_dataflow(self, dataflow: df.DataflowGraph) -> DataDependenceGraph:
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
        # one input graph.  Index the procedure before creating DDG nodes so
        # their stable semantic identities are available; otherwise nodes are
        # created with a fallback ``ddg.N`` id and later rebuilds disagree.
        code = getattr(dataflow, "code", None)
        if code is not None:
            try:
                ensure_code_indexed(code)
            except (KeyError, ValueError, AttributeError):
                pass
        self.ddg = DataDependenceGraph(code)
        self._memory_aliases = {}
        self._parameter_symbols = set()

        # Create nodes for all ops and slots reachable from graph roots.
        self._index_dataflow(dataflow)
        self._index_memory_aliases(dataflow)

        # Connect def-use edges for local and heap flows
        self._connect_def_use()

        # Memory dependencies: connect writes to subsequent reads conservatively
        self._connect_memory_dependencies(dataflow)

        self._prune_unconnected_nodes()
        return self.ddg

    def _prune_unconnected_nodes(self) -> None:
        """Drop nodes that only carried control/order information.

        Predicate slots are not indexed as DDG data nodes.  A purely
        predicate-driven Split/Gate/Merge, or an unused null/existing slot,
        therefore has no data edge and would otherwise appear as graph noise.
        Entry and Exit anchors are retained for empty or partially modelled
        procedures.
        """
        kept = []
        removed = set()
        for node in self.ddg.nodes:
            if node.edges_in or node.edges_out or isinstance(node.ir_node, (df.Entry, df.Exit)):
                kept.append(node)
            else:
                removed.add(node)
        if not removed:
            return
        self.ddg.nodes = kept
        self.ddg.op_node_map = {
            ir: node for ir, node in self.ddg.op_node_map.items() if node not in removed
        }
        self.ddg.slot_node_map = {
            ir: node for ir, node in self.ddg.slot_node_map.items() if node not in removed
        }

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
            elif isinstance(node, df.SlotNode) and not isinstance(node, df.PredicateNode):
                # Predicates encode control/order, not data.  CPG control
                # edges carry that information; keeping predicate slots here
                # turned every sequential statement into a fake data edge.
                self._index_slot(node)

            # Continue traversal to discover more nodes
            for nxt in node.forward():
                if nxt not in visited:
                    stack.append(nxt)

    def _index_memory_aliases(self, dataflow: df.DataflowGraph) -> None:
        """Canonicalize local storage symbols that share one dataflow value.

        Copy propagation merges ``b = a`` into the LocalNode for ``a``; the
        FieldNode base still mentions the syntactic ``b`` symbol.  Build the
        symbol alias map so memory dependencies use the canonical base.
        """
        code = getattr(dataflow, "code", None)
        catalog = getattr(code, "ir_catalog", None)
        if catalog is None:
            return
        for ir_slot in self.ddg.slot_node_map:
            names = getattr(ir_slot, "names", None)
            if not names:
                continue
            symbols = []
            for name in names:
                try:
                    symbols.append(catalog.symbol_id(name, code))
                except (KeyError, ValueError):
                    continue
            if not symbols:
                continue
            canonical = symbols[0]
            for symbol in symbols:
                self._memory_aliases[symbol] = canonical
            for symbol in symbols:
                info = catalog.symbols.get(symbol)
                if info is not None and info.kind is SymbolKind.PARAMETER:
                    self._parameter_symbols.add(symbol)

        self._index_ast_aliases(code, catalog)

    def _index_ast_aliases(self, code, catalog) -> None:
        """Recover must-aliases lost by tuple lowerings.

        The dataflow graph keeps ``b = a`` as one LocalNode, but tuple
        unpacking lowers to ``tmp = (a,); b = tmp[0]``.  The DDG memory pass
        still needs to know that ``b`` denotes the same object as ``a``.
        """
        root = getattr(code, "ast", None)
        if not isinstance(root, py_ast.Suite):
            return

        def symbol(local):
            if not isinstance(local, py_ast.Local):
                return None
            try:
                return catalog.symbol_id(local, code)
            except (KeyError, ValueError):
                return None

        tuple_values = {}

        def source_symbol(expr):
            if isinstance(expr, py_ast.Local):
                return symbol(expr)
            if isinstance(expr, py_ast.GetGlobal):
                name = getattr(getattr(expr, "name", None), "object", None)
                name = getattr(name, "pyobj", None)
                return ("global", name) if isinstance(name, str) else None
            if isinstance(expr, py_ast.GetAttr):
                base = source_symbol(getattr(expr, "expr", None))
                field = getattr(getattr(expr, "name", None), "object", None)
                field = getattr(field, "pyobj", None)
                if base is None or not isinstance(field, str):
                    return None
                base_storage = (
                    LocalStorage(base)
                    if isinstance(base, object)
                    and not isinstance(base, (AttributeStorage, SubscriptStorage, tuple))
                    else base
                )
                return AttributeStorage(base_storage, field)
            if isinstance(expr, py_ast.Call):
                callee = getattr(expr, "expr", None)
                obj = getattr(getattr(callee, "object", None), "pyobj", None)
                args = list(getattr(expr, "args", ()) or ())
                if obj == "interpreter_getitem" and len(args) == 2:
                    base = args[0]
                    index = args[1]
                    if isinstance(base, py_ast.Local) and isinstance(index, py_ast.Existing):
                        index_value = getattr(index.object, "pyobj", None)
                        values = tuple_values.get(symbol(base))
                        if (
                            isinstance(index_value, int)
                            and values
                            and 0 <= index_value < len(values)
                        ):
                            return values[index_value]
            return None

        def source_tuple(expr):
            if isinstance(expr, py_ast.BuildTuple):
                values = tuple(source_symbol(arg) for arg in (expr.args or ()))
                if values and all(value is not None for value in values):
                    return values
            return None

        def targets_for(target):
            if isinstance(target, py_ast.Local):
                return [target]
            if isinstance(target, py_ast.UnpackSequence):
                return list(target.targets)
            return []

        def visit(suite):
            if not isinstance(suite, py_ast.Suite):
                return
            for op in suite.blocks:
                if isinstance(op, py_ast.Assign):
                    values = source_tuple(op.expr)
                    if len(op.lcls) == 1 and values is not None:
                        target_symbol = symbol(op.lcls[0])
                        if target_symbol is not None:
                            tuple_values[target_symbol] = values
                        continue
                    source = source_symbol(op.expr)
                    if source is not None:
                        for target in op.lcls:
                            for local in targets_for(target):
                                target_symbol = symbol(local)
                                if target_symbol is not None and target_symbol != source:
                                    self._memory_aliases[target_symbol] = source
                elif isinstance(op, py_ast.Suite):
                    visit(op)

        visit(root)

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
        Heap slots are identified by their storage location (``FieldNode.name``
        or the slot object for legacy dataflow nodes), not by a particular
        value version. Operations accessing the same location are considered
        to potentially alias.

        **Pseudo reads:**
        ``heapPsedoReads`` records the implicit read of the old value performed
        by a store. It participates in WAR state, but it is not a true read and
        must not create a RAW edge (a write followed by a write is WAW, not
        RAW).

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
                    result.update(user for user in child.forward() if isinstance(user, df.OpNode))
            return result & op_set

        # Three distinct categories: true reads (RAW), pseudo reads (WAR),
        # and writes (WAW).  Treating pseudo reads as true reads made every
        # write emit a spurious RAW edge from the previous write.
        accesses: Dict[Any, Tuple[Set[Any], Set[Any], Set[Any]]] = {}
        ops_by_location: Dict[Any, List[Any]] = {}
        for ir in ir_ops:
            values: List[Any] = []
            for attribute in ("heapReads", "heapPsedoReads", "heapModifies"):
                entries = getattr(ir, attribute, None)
                values.append(entries.values() if isinstance(entries, dict) else ())
            true_reads, pseudo_reads, writes = (
                {
                    _memory_slot_key(
                        slot,
                        self._memory_aliases,
                        self._parameter_symbols,
                    )
                    for slot in group
                }
                for group in values
            )
            accesses[ir] = (true_reads, pseudo_reads, writes)
            for key in true_reads | pseudo_reads | writes:
                ops_by_location.setdefault(key, []).append(ir)

        successors: Dict[Any, Set[Any]] = {ir: operation_successors(ir) for ir in ir_ops}

        # The dataflow graph only links operations through values.  A read
        # followed by an unrelated write to the same field therefore has no
        # path between the two operations, and WAR could never be reported.
        # Add a conservative source-order chain among heap-accessing operations
        # that share a path predicate.  Operations in different branches use
        # different canonical predicates and remain unordered relative to each
        # other.
        ordered: Dict[Any, List[Tuple[int, int, Any]]] = {}
        for ir in ir_ops:
            if not any(accesses[ir]):
                continue
            ast_node = getattr(ir, "op", None)
            span = syntax_source_span(ast_node)
            if span is None:
                continue
            predicate = getattr(ir, "predicate", None)
            canonical_predicate = None
            if predicate is not None and hasattr(predicate, "canonical"):
                try:
                    canonical_predicate = predicate.canonical()
                except Exception:
                    canonical_predicate = predicate
            key = (canonical_predicate, span.path)
            ordered.setdefault(key, []).append((span.start_line, span.start_column, ir))
        for entries in ordered.values():
            entries.sort(key=lambda entry: (entry[0], entry[1]))
            for (_, _, earlier), (_, _, later) in zip(entries, entries[1:]):
                if earlier is not later:
                    successors.setdefault(earlier, set()).add(later)

        predecessors: Dict[Any, Set[Any]] = {ir: set() for ir in ir_ops}
        for source, targets in successors.items():
            for target in targets:
                predecessors[target].add(source)

        relevant_locations: List[Any] = []
        for key, accessing_ops in ops_by_location.items():
            writes_count = sum(1 for ir in accessing_ops if key in accesses[ir][2])
            has_true_read = any(key in accesses[ir][0] for ir in accessing_ops)
            # Read-only locations and single-write locations whose only reads
            # are the store's implicit pseudo reads cannot produce a RAW, WAR,
            # or WAW edge.  Treating those pseudo reads as a reason to solve
            # the location made every distinct field store traverse its whole
            # downstream graph, which is quadratic for large modules.
            if writes_count > 0 and (has_true_read or writes_count > 1):
                relevant_locations.append(key)

        # Solve one abstract location at a time.  The forward state tracks
        # only reaching writes: a write kills all earlier writes, so this set
        # stays proportional to the number of open paths (join fan-in) rather
        # than growing along a long chain of reads.  Reads-since-write are
        # recovered backwards from each write instead; storing them in every
        # forward state caused quadratic set copying for long read sequences.
        empty_state: Any = frozenset()
        for key in sorted(relevant_locations, key=repr):
            in_writes: Dict[Any, Any] = {}
            out_writes: Dict[Any, Any] = {}
            start_ops = ops_by_location[key]
            worklist = deque(start_ops)
            queued = set(start_ops)

            while worklist:
                ir = worklist.popleft()
                queued.discard(ir)

                reaching_writes = set()
                for predecessor in predecessors[ir]:
                    reaching_writes.update(out_writes.get(predecessor, empty_state))
                incoming = frozenset(reaching_writes)

                _, _, writes = accesses[ir]
                if key in writes:
                    outgoing = frozenset((ir,))
                else:
                    outgoing = incoming

                if incoming == in_writes.get(ir, empty_state) and outgoing == out_writes.get(
                    ir, empty_state
                ):
                    continue
                in_writes[ir] = incoming
                out_writes[ir] = outgoing
                for successor in successors[ir]:
                    if successor not in queued:
                        queued.add(successor)
                        worklist.append(successor)

            def reads_reaching(write_op):
                """True/pseudo reads that reach *write_op* before any write."""
                readers = set()
                visited = set()
                pending = list(predecessors[write_op])
                while pending:
                    current = pending.pop()
                    if current in visited:
                        continue
                    visited.add(current)
                    current_writes = accesses[current][2]
                    if key not in current_writes:
                        current_reads = accesses[current][0] | accesses[current][1]
                        if key in current_reads:
                            readers.add(current)
                        pending.extend(predecessors[current])
                return readers

            for ir in start_ops:
                true_reads, _, writes = accesses[ir]
                op = op_nodes[ir]
                reaching_writes = in_writes.get(ir, empty_state)
                if key in true_reads:
                    for writer in reaching_writes:
                        if writer is not ir:
                            self.ddg.add_mem_dep(op_nodes[writer], op, label="RAW", location=key)
                if key in writes:
                    for writer in reaching_writes:
                        if writer is not ir:
                            self.ddg.add_mem_dep(op_nodes[writer], op, label="WAW", location=key)
                    for reader in reads_reaching(ir):
                        if reader is not ir:
                            self.ddg.add_mem_dep(op_nodes[reader], op, label="WAR", location=key)

        # The predicate-chain above keeps operations from different branches
        # unordered.  A write inside a conditional branch still must reach a
        # later read after the join; add a source-order fallback for that case.
        def source_line(ir):
            span = syntax_source_span(getattr(ir, "op", None))
            return span.start_line if span is not None else 0

        for key in relevant_locations:
            access_ops = ops_by_location[key]
            write_ops = [ir for ir in access_ops if key in accesses[ir][2]]
            true_reads = [ir for ir in access_ops if key in accesses[ir][0]]
            pseudo_reads = [ir for ir in access_ops if key in accesses[ir][1]]
            for reader in true_reads:
                reader_line = source_line(reader)
                if not reader_line:
                    continue
                for writer in write_ops:
                    writer_line = source_line(writer)
                    if writer is not reader and writer_line and writer_line <= reader_line:
                        self.ddg.add_mem_dep(
                            op_nodes[writer], op_nodes[reader], label="RAW", location=key
                        )
            for later in write_ops:
                later_line = source_line(later)
                if not later_line:
                    continue
                for earlier in write_ops:
                    earlier_line = source_line(earlier)
                    if earlier is not later and earlier_line and earlier_line <= later_line:
                        self.ddg.add_mem_dep(
                            op_nodes[earlier], op_nodes[later], label="WAW", location=key
                        )
                for reader in (*true_reads, *pseudo_reads):
                    reader_line = source_line(reader)
                    if reader is not later and reader_line and reader_line <= later_line:
                        self.ddg.add_mem_dep(
                            op_nodes[reader], op_nodes[later], label="WAR", location=key
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
