"""Dependences over CFG program points, including back-edges and cleanup paths.

The legacy dataflow graph remains an acyclic value summary. Source-backed DDGs
use this projection of the CFG instead; source positions are display metadata,
never execution order. Local definitions kill previous bindings. Heap writes
are weak updates because a storage identity may summarize aliased objects.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field

from pyflow.ir.cfg import graph as cfg_graph
from pyflow.ir.cfg.dump import _ssa_repr
from pyflow.ir.core import ensure_code_indexed, index_cfg
from pyflow.ir.core.build_semantics import _definition_references, _explicit_storage
from pyflow.ir.core.storage import LocalStorage, UnknownStorage
from pyflow.ir.dataflow import graph as df
from pyflow.language.python import ast
from .intrinsics import has_bounded_effects


class CFGOperation(df.GenericOp):
    __slots__ = ("cfg_block", "phase")

    def __init__(self, block, operation, phase="operation"):
        super().__init__(None, operation)
        self.cfg_block, self.phase = block, phase

    def __repr__(self):
        if isinstance(self.op, cfg_graph.CFGBlock):
            return f"op({type(self.op).__name__}.{self.phase})"
        return f"op({_ssa_repr(self.op)})"


@dataclass(eq=False, repr=False, slots=True)
class Point:
    block: object
    operation: object = None
    anchor: object = None
    uses: dict = field(default_factory=dict)
    constants: dict = field(default_factory=dict)
    definitions: dict = field(default_factory=dict)
    bindings: dict = field(default_factory=dict)
    definition_values: dict = field(default_factory=dict)
    intra_uses: list = field(default_factory=list)
    read_bindings: dict = field(default_factory=dict)
    read_symbols: dict = field(default_factory=dict)
    kills: set = field(default_factory=set)
    reads: set = field(default_factory=set)
    writes: set = field(default_factory=set)
    successors: set = field(default_factory=set)
    predecessors: set = field(default_factory=set)

    def connect(self, target):
        self.successors.add(target)
        target.predecessors.add(self)


def reaching(points, generators, kills=(), *, weak=False, readers=None):
    """Solve reaching program-point definitions to a fixed point."""
    if not generators:
        return {}
    incoming, outgoing = {}, {}
    needed = None
    if readers is not None and not weak:
        # A temporary used once must not propagate through the rest of a large
        # function. Restrict this symbol's solve to predecessor paths from its
        # reads, stopping at binding definitions and deletions.
        needed = set(readers)
        pending = [pred for reader in readers for pred in reader.predecessors]
        visited = set()
        while pending:
            point = pending.pop()
            if point in visited:
                continue
            visited.add(point)
            needed.add(point)
            if point not in generators and point not in kills:
                pending.extend(point.predecessors)
    queue = deque(point for point in generators if needed is None or point in needed)
    queued = set(queue)
    while queue:
        point = queue.popleft()
        queued.discard(point)
        before = frozenset(
            definition
            for predecessor in point.predecessors
            for definition in outgoing.get(predecessor, ())
        )
        after = before
        if point in kills:
            after = frozenset()
        if point in generators:
            after = (before | {point}) if weak else frozenset((point,))
        if incoming.get(point, frozenset()) == before and outgoing.get(point, frozenset()) == after:
            continue
        incoming[point], outgoing[point] = before, after
        for successor in point.successors:
            if successor not in queued and (needed is None or successor in needed):
                queued.add(successor)
                queue.append(successor)
    return incoming


def _build_chains(points):
    """Partition *points* into maximal straight-line chains for fast dataflow."""
    point_chain: dict[Point, int] = {}
    point_offset: dict[Point, int] = {}
    chains: list[list[Point]] = []

    def is_chain_head(point: Point) -> bool:
        if len(point.predecessors) != 1:
            return True
        pred = next(iter(point.predecessors))
        return pred is point or len(pred.successors) != 1

    def walk_chain(start: Point) -> None:
        cid = len(chains)
        chain: list[Point] = []
        current = start
        while True:
            point_chain[current] = cid
            point_offset[current] = len(chain)
            chain.append(current)
            if len(current.successors) != 1:
                break
            nxt = next(iter(current.successors))
            if nxt in point_chain or len(nxt.predecessors) != 1:
                break
            current = nxt
        chains.append(chain)

    for point in points:
        if point not in point_chain and is_chain_head(point):
            walk_chain(point)
    for point in points:
        if point not in point_chain:
            walk_chain(point)

    chain_preds = [
        tuple(dict.fromkeys(point_chain[pred] for pred in chain[0].predecessors))
        for chain in chains
    ]
    chain_succs = [
        tuple(dict.fromkeys(point_chain[succ] for succ in chain[-1].successors)) for chain in chains
    ]
    return chains, point_chain, point_offset, chain_preds, chain_succs


def _solve_chain_reaching_strong(chain_preds, chain_succs, gen_chains, kill_chains, reader_chains):
    """Exact strong reaching-definitions solve over the compressed chain graph."""
    if not gen_chains:
        return {}
    needed = set(reader_chains)
    pending = [pred for cid in reader_chains for pred in chain_preds[cid]]
    visited = set()
    while pending:
        cid = pending.pop()
        if cid in visited:
            continue
        visited.add(cid)
        needed.add(cid)
        if cid not in kill_chains:
            pending.extend(chain_preds[cid])

    incoming: dict[int, frozenset] = {}
    outgoing: dict[int, frozenset] = {}
    queue = deque(cid for cid in gen_chains if cid in needed)
    queued = set(queue)
    while queue:
        cid = queue.popleft()
        queued.discard(cid)
        before = frozenset(
            definition for pred in chain_preds[cid] for definition in outgoing.get(pred, ())
        )
        gen = gen_chains.get(cid)
        if gen is not None:
            after = frozenset((gen,))
        elif cid in kill_chains:
            after = frozenset()
        else:
            after = before
        if incoming.get(cid, frozenset()) == before and outgoing.get(cid, frozenset()) == after:
            continue
        incoming[cid], outgoing[cid] = before, after
        for succ in chain_succs[cid]:
            if succ not in queued and succ in needed:
                queued.add(succ)
                queue.append(succ)
    return incoming


def _solve_chain_reaching_weak(chain_preds, chain_succs, gen_chain_sets):
    """Exact weak reaching-definitions solve over the compressed chain graph."""
    if not gen_chain_sets:
        return {}
    incoming: dict[int, frozenset] = {}
    outgoing: dict[int, frozenset] = {}
    queue = deque(gen_chain_sets.keys())
    queued = set(queue)
    while queue:
        cid = queue.popleft()
        queued.discard(cid)
        before = frozenset(
            definition for pred in chain_preds[cid] for definition in outgoing.get(pred, ())
        )
        gen_set = gen_chain_sets.get(cid)
        after = (before | gen_set) if gen_set else before
        if incoming.get(cid, frozenset()) == before and outgoing.get(cid, frozenset()) == after:
            continue
        incoming[cid], outgoing[cid] = before, after
        for succ in chain_succs[cid]:
            if succ not in queued:
                queued.add(succ)
                queue.append(succ)
    return incoming


class CFGDependences:
    def __init__(self, constructor, cfg):
        self.owner, self.cfg, self.code = constructor, cfg, cfg.code
        self.catalog = ensure_code_indexed(self.code)
        index_cfg(self.catalog, cfg)
        self.code_id = self.catalog.procedure(self.code).code_id
        self.ddg = constructor.ddg
        self.points, self.by_block = [], {}
        self.iterators, self.bindings = {}, {}
        self.local_reaching = {}

    def point(self, block, operation=None, phase="operation", *, external=False):
        point = Point(block, operation)
        self.points.append(point)
        if operation is not None:
            point.anchor = self.ddg.get_or_create_op_node(CFGOperation(block, operation, phase))
            self.facts(point)
        if external:
            point.reads.add(UnknownStorage("unknown"))
            point.writes.add(UnknownStorage("unknown"))
        return point

    def symbol(self, local):
        return self.catalog.symbol_id(local, self.code)

    def facts(self, point):
        pending = [(False, point.operation)]
        while pending:
            define, node = pending.pop()
            if node is None or isinstance(node, (ast.Code, ast.leafTypes)):
                continue
            if define:
                if isinstance(node, ast.Local):
                    key = self.symbol(node)
                    point.definitions[key] = node
                    point.bindings[id(node)] = (key, node)
                continue
            if isinstance(node, (list, tuple)):
                pending.extend((False, child) for child in reversed(node))
                continue
            if isinstance(node, ast.Existing):
                point.constants.setdefault(node.object, node)
                continue
            if isinstance(node, ast.Local):
                key = self.symbol(node)
                point.read_bindings[id(node)] = point.definitions.get(key)
                point.read_symbols[id(node)] = key
                if key not in point.definitions:
                    point.uses[key] = node
                else:
                    point.intra_uses.append((key, point.definitions[key]))
                continue
            if isinstance(node, ast.Delete) and isinstance(node.lcl, ast.Local):
                point.kills.add(self.symbol(node.lcl))
                pending.append((False, node.lcl))
                continue
            targets = _definition_references(node)
            for index, target in enumerate(targets):
                if isinstance(node, ast.Assign):
                    value = node.expr
                elif isinstance(node, (ast.NamedExpr, ast.AnnAssign)):
                    value = node.value
                elif isinstance(node, ast.Phi):
                    value = tuple(node.arguments)
                elif isinstance(node, ast.UnpackSequence):
                    value = (node.expr, index)
                else:
                    value = None
                point.definition_values[id(target)] = value
            pending.extend((True, target) for target in targets)
            skipped = {id(target) for target in targets}
            if isinstance(node, ast.NamedExpr):
                children = (node.value,)
            elif isinstance(node, ast.Assign):
                children = (node.expr,)
            elif isinstance(node, ast.UnpackSequence):
                children = (node.expr,)
            elif isinstance(node, ast.InputBlock):
                children = ()
            elif isinstance(node, ast.Input):
                pending.append((True, node.lcl))
                children = ()
            else:
                children = getattr(node, "children", lambda: ())()
            pending.extend(
                (False, child) for child in reversed(children) if id(child) not in skipped
            )
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                from pyflow.ir.cfg.ssa import _definition_local

                local = _definition_local(self.catalog, self.code, node.name)
                pending.append((True, local))
            if isinstance(node, ast.PythonASTNode):
                reads, writes = _explicit_storage(self.catalog, self.code_id, node)
                point.reads.update(read for read in reads if not isinstance(read, LocalStorage))
                point.writes.update(writes)
                if isinstance(node, (ast.Call, ast.MethodCall, ast.DirectCall)) and not (
                    self.owner.options.assume_primitive_intrinsics and has_bounded_effects(node)
                ):
                    point.reads.add(UnknownStorage("unknown"))
                    point.writes.add(UnknownStorage("unknown"))
                if not self.owner.options.assume_primitive_intrinsics and isinstance(
                    node,
                    (
                        ast.BinaryOp,
                        ast.UnaryPrefixOp,
                        ast.ConvertToBool,
                        ast.Not,
                        ast.ShortCircutAnd,
                        ast.ShortCircutOr,
                        ast.GetAttr,
                        ast.GetSubscript,
                        ast.SetAttr,
                        ast.SetSubscript,
                        ast.DeleteAttr,
                        ast.DeleteSubscript,
                        ast.UnpackSequence,
                    ),
                ):
                    point.reads.add(UnknownStorage("unknown"))
                    point.writes.add(UnknownStorage("unknown"))

    def build_points(self):
        queue, seen, blocks = deque([self.cfg.entryTerminal]), set(), []
        while queue:
            block = queue.popleft()
            if block in seen:
                continue
            seen.add(block)
            blocks.append(block)
            queue.extend(
                target for _, target in sorted(block.next.items(), key=lambda item: str(item[0]))
            )
        for block in blocks:
            if isinstance(block, cfg_graph.Suite):
                roots = block.ops
            elif isinstance(block, cfg_graph.Merge):
                roots = block.phi
            elif isinstance(block, cfg_graph.Switch):
                roots = [block.condition]
            elif isinstance(block, cfg_graph.TypeSwitch):
                roots = [block.original.conditional]
            else:
                roots = []
            points = [self.point(block, root) for root in roots] or [self.point(block)]
            self.by_block[block] = points
            if (
                isinstance(block, cfg_graph.Switch)
                and not self.owner.options.assume_primitive_intrinsics
            ):
                # A plain Local condition also invokes the truth protocol.
                points[-1].reads.add(UnknownStorage("unknown"))
                points[-1].writes.add(UnknownStorage("unknown"))
            for left, right in zip(points, points[1:]):
                left.connect(right)
            if isinstance(block, cfg_graph.ForIter):
                advance = points[0]
                advance.anchor = self.ddg.get_or_create_op_node(
                    CFGOperation(block, block, "advance")
                )
                advance.reads.add(UnknownStorage("unknown"))
                advance.writes.add(UnknownStorage("unknown"))
                self.iterators[block] = self.point(block, block.iterator, "iterable")
                binding = self.point(block, block.index, "index")
                binding.uses.clear()
                binding.definitions[self.symbol(block.index)] = block.index
                self.bindings[block] = binding
            elif isinstance(block, cfg_graph.Entry):
                points[0].anchor = self.ddg.get_or_create_op_node(df.Entry(None))
                parameters = self.code.codeparameters
                for local in (
                    parameters.selfparam,
                    *parameters.posonlyparams,
                    *parameters.params,
                    parameters.vparam,
                    parameters.kparam,
                ):
                    if isinstance(local, ast.Local):
                        points[0].definitions[self.symbol(local)] = local
            elif isinstance(block, cfg_graph.Exit):
                points[0].anchor = self.ddg.get_or_create_op_node(df.Exit(None))
        for block in blocks:
            for label, target in block.next.items():
                source = self.by_block[block][-1]
                if isinstance(block, cfg_graph.ForIter) and label == "body":
                    source.connect(self.bindings[block])
                    source = self.bindings[block]
                destination = self.by_block[target][0]
                loop = target.next.get("normal") if isinstance(target, cfg_graph.Merge) else None
                if isinstance(target, cfg_graph.ForIter) and not isinstance(
                    target.prev, cfg_graph.Merge
                ):
                    loop = target
                if (
                    isinstance(loop, cfg_graph.ForIter)
                    and loop.prev is target
                    and block.region is not target
                ):
                    # The iterable is evaluated on entry, before loop phis and
                    # index binding, rather than on each iterator advancement.
                    evaluation = self.iterators[loop]
                    source.connect(evaluation)
                    evaluation.connect(destination)
                    for name in ("fail", "error"):
                        handler = loop.next.get(name)
                        if handler in self.by_block:
                            evaluation.connect(self.by_block[handler][0])
                else:
                    if loop is target:
                        source.connect(self.iterators[loop])
                        self.iterators[loop].connect(destination)
                    else:
                        source.connect(destination)

    def local_edges(self):
        slots = {}
        constants = {}
        references = {}
        for point in self.points:
            for obj in point.constants:
                if obj not in constants:
                    constants[obj] = self.ddg.get_or_create_slot_node(df.ExistingNode(obj, None))
                constants[obj].add_edge_to(point.anchor, "def-use", label="constant")
            bindings = dict(point.bindings)
            for key, reference in point.definitions.items():
                bindings.setdefault(id(reference), (key, reference))
            for reference_id, (key, reference) in bindings.items():
                slot = self.ddg.get_or_create_slot_node(df.LocalNode(None, (reference,)))
                references[point, reference_id] = slot
                if point.definitions.get(key) is reference:
                    slots[point, key] = slot
                point.anchor.add_edge_to(
                    slot, "def-use", label=reference.name or self.catalog.symbols[key].display_name
                )
            for key, reference in point.intra_uses:
                references[point, id(reference)].add_edge_to(
                    point.anchor, "def-use", label=self.catalog.symbols[key].display_name
                )

        chains, point_chain, point_offset, chain_preds, chain_succs = _build_chains(self.points)
        self._chains = (chains, point_chain, point_offset, chain_preds, chain_succs)

        gen_chains: dict[object, dict[int, Point]] = defaultdict(dict)
        kill_chains: dict[object, set[int]] = defaultdict(set)
        upward_uses: dict[object, list[tuple[int, Point]]] = defaultdict(list)

        for cid, chain in enumerate(chains):
            local_state: dict[object, Point | None] = {}
            for point in chain:
                for key in point.uses:
                    if key in local_state:
                        writer = local_state[key]
                        if writer is not None:
                            self.local_reaching[point, key] = frozenset((writer,))
                            slots[writer, key].add_edge_to(
                                point.anchor,
                                "def-use",
                                label=self.catalog.symbols[key].display_name,
                            )
                        else:
                            self.local_reaching[point, key] = frozenset()
                    else:
                        upward_uses[key].append((cid, point))
                for key in point.kills:
                    local_state[key] = None
                for key in point.definitions:
                    local_state[key] = point
            for key, final_writer in local_state.items():
                kill_chains[key].add(cid)
                if final_writer is not None:
                    gen_chains[key][cid] = final_writer

        for key, exposed in upward_uses.items():
            gens = gen_chains.get(key)
            if not gens:
                for _, reader in exposed:
                    self.local_reaching[reader, key] = frozenset()
                continue
            reader_cids = {cid for cid, _ in exposed}
            available_chains = _solve_chain_reaching_strong(
                chain_preds, chain_succs, gens, kill_chains[key], reader_cids
            )
            label = self.catalog.symbols[key].display_name
            for cid, reader in exposed:
                avail = available_chains.get(cid, frozenset())
                self.local_reaching[reader, key] = avail
                for writer in avail:
                    slots[writer, key].add_edge_to(reader.anchor, "def-use", label=label)

    def memory_edges(self):
        from .aliases import ValueOrigins

        origins = ValueOrigins(self)
        for point in self.points:
            for reference in point.definitions.values():
                origins.run(("definition", point, reference))

        accesses = defaultdict(set)
        inputs, versions = {}, {}
        for point in self.points:
            point.reads = {
                location
                for key in sorted(point.reads, key=repr)
                for location in origins.locations(point, key)
            }
            point.writes = {
                location
                for key in sorted(point.writes, key=repr)
                for location in origins.locations(point, key)
            }
            for key in point.reads | point.writes:
                accesses[key].add(point)
            for key in sorted(point.reads, key=repr):
                if key not in inputs:
                    inputs[key] = self.ddg.get_or_create_slot_node(df.FieldNode(None, key))
                inputs[key].add_edge_to(point.anchor, "def-use", label="heap-input")
            for key in sorted(point.writes, key=repr):
                slot = self.ddg.get_or_create_slot_node(df.FieldNode(None, key))
                versions[point, key] = slot
                point.anchor.add_edge_to(slot, "def-use", label="heap-write")

        _chains, point_chain, point_offset, chain_preds, chain_succs = getattr(
            self, "_chains", None
        ) or _build_chains(self.points)

        for key, points in accesses.items():
            writers = {point for point in points if key in point.writes}
            if not writers:
                continue
            if isinstance(key, UnknownStorage):
                by_chain: dict[int, list[Point]] = defaultdict(list)
                for point in points:
                    by_chain[point_chain[point]].append(point)
                gen_chains = {}
                for cid, cpoints in by_chain.items():
                    cpoints.sort(key=point_offset.__getitem__)
                    gen_chains[cid] = cpoints[-1]
                chain_in = _solve_chain_reaching_strong(
                    chain_preds, chain_succs, gen_chains, set(gen_chains), set(gen_chains)
                )
                for cid, cpoints in by_chain.items():
                    for earlier in chain_in.get(cid, ()):
                        self.ddg.add_mem_dep(earlier.anchor, cpoints[0].anchor, "EXTERNAL", key)
                    for prev_pt, cur_pt in zip(cpoints, cpoints[1:]):
                        self.ddg.add_mem_dep(prev_pt.anchor, cur_pt.anchor, "EXTERNAL", key)
                continue
            readers = {point for point in points if key in point.reads}
            if (
                not readers
                and len(writers) == 1
                and all(point.block.region is None for point in writers)
            ):
                continue

            writers_by_chain: dict[int, list[Point]] = defaultdict(list)
            for writer in writers:
                writers_by_chain[point_chain[writer]].append(writer)
            gen_chain_sets = {}
            for cid, cwriters in writers_by_chain.items():
                cwriters.sort(key=point_offset.__getitem__)
                gen_chain_sets[cid] = frozenset(cwriters)
            chain_in = _solve_chain_reaching_weak(chain_preds, chain_succs, gen_chain_sets)

            readers_by_chain: dict[int, list[Point]] = defaultdict(list)
            if readers:
                for reader in readers:
                    readers_by_chain[point_chain[reader]].append(reader)
                for creaders in readers_by_chain.values():
                    creaders.sort(key=point_offset.__getitem__)

            for later in points:
                cid = point_chain[later]
                later_off = point_offset[later]
                reaching_writers = set(chain_in.get(cid, ()))
                for earlier_w in writers_by_chain.get(cid, ()):
                    if point_offset[earlier_w] < later_off:
                        reaching_writers.add(earlier_w)
                    else:
                        break
                for earlier in reaching_writers:
                    if later in readers:
                        self.ddg.add_mem_dep(earlier.anchor, later.anchor, "RAW", key)
                        versions[earlier, key].add_edge_to(
                            later.anchor, "def-use", label="heap-read"
                        )
                    if later in writers:
                        self.ddg.add_mem_dep(earlier.anchor, later.anchor, "WAW", key)
                if later in writers and readers:
                    prev_w_off = -1
                    for earlier_w in writers_by_chain.get(cid, ()):
                        w_off = point_offset[earlier_w]
                        if w_off < later_off:
                            prev_w_off = w_off
                        else:
                            break
                    for earlier_r in readers_by_chain.get(cid, ()):
                        r_off = point_offset[earlier_r]
                        if prev_w_off <= r_off < later_off:
                            self.ddg.add_mem_dep(earlier_r.anchor, later.anchor, "WAR", key)
                    if prev_w_off == -1:
                        pending_c = list(chain_preds[cid])
                        seen_c: set[int] = set()
                        while pending_c:
                            pc = pending_c.pop()
                            if pc in seen_c:
                                continue
                            seen_c.add(pc)
                            pc_writers = writers_by_chain.get(pc)
                            last_w_off = point_offset[pc_writers[-1]] if pc_writers else -1
                            for earlier_r in readers_by_chain.get(pc, ()):
                                if point_offset[earlier_r] >= last_w_off:
                                    self.ddg.add_mem_dep(earlier_r.anchor, later.anchor, "WAR", key)
                            if last_w_off == -1:
                                pending_c.extend(chain_preds[pc])

    def construct(self):
        self.build_points()
        self.local_edges()
        self.memory_edges()
        return self.ddg
