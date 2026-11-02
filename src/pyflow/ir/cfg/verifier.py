"""Structural invariant checks for control-flow graphs."""

from __future__ import annotations

from pyflow.language.python import ast

from . import graph


class CFGVerificationError(ValueError):
    """Raised when a CFG is not internally self-consistent."""


def _all_blocks(cfg) -> tuple[graph.CFGBlock, ...]:
    terminals = (
        cfg.entryTerminal,
        cfg.normalTerminal,
        cfg.failTerminal,
        cfg.errorTerminal,
    )
    pending = [cfg.entryTerminal]
    seen: set[graph.CFGBlock] = set()
    ordered: list[graph.CFGBlock] = []
    while pending:
        block = pending.pop(0)
        if block in seen:
            continue
        seen.add(block)
        ordered.append(block)
        pending.extend(block.next.values())
    ordered.extend(terminal for terminal in terminals if terminal not in seen)
    return tuple(ordered)


def verify_cfg(cfg, catalog=None) -> None:
    """Verify graph symmetry, terminal shape, Phi arity, and catalog binding."""
    blocks = _all_blocks(cfg)
    block_set = set(blocks)
    terminals = {
        cfg.normalTerminal,
        cfg.failTerminal,
        cfg.errorTerminal,
    }

    if not isinstance(cfg.entryTerminal, graph.Entry):
        raise CFGVerificationError("CFG entry terminal is not an Entry block")
    if tuple(cfg.entryTerminal.iterprev()):
        raise CFGVerificationError("CFG entry terminal has predecessors")
    for terminal in terminals:
        if not isinstance(terminal, graph.Exit):
            raise CFGVerificationError("CFG exit terminal is not an Exit block")
        if terminal.next:
            raise CFGVerificationError("CFG exit terminal has successors")

    forward_edges: set[tuple[graph.CFGBlock, object, graph.CFGBlock]] = set()
    reverse_edges: set[tuple[graph.CFGBlock, object, graph.CFGBlock]] = set()
    for block in blocks:
        for label, target in block.next.items():
            if not block.validExitName(label):
                raise CFGVerificationError(
                    f"invalid exit label {label!r} for {type(block).__name__}"
                )
            if target not in block_set:
                raise CFGVerificationError("CFG edge targets an unindexed block")
            edge = (block, label, target)
            if edge in forward_edges:
                raise CFGVerificationError("duplicate CFG forward edge")
            forward_edges.add(edge)

        predecessors = tuple(block.iterprev())
        if isinstance(block, graph.SingleEntryBlock):
            live = tuple(item for item in predecessors if item[0] is not None)
            if len(live) > 1:
                raise CFGVerificationError("single-entry block has multiple predecessors")
        for source, label in predecessors:
            if source is None:
                continue
            edge = (source, label, block)
            if edge in reverse_edges:
                raise CFGVerificationError("duplicate CFG predecessor edge")
            reverse_edges.add(edge)

        if isinstance(block, graph.Merge):
            predecessor_count = len(tuple(block.iterprev()))
            for phi in block.phi:
                if not isinstance(phi, ast.Phi):
                    raise CFGVerificationError("merge contains a non-Phi operation")
                if len(phi.arguments) != predecessor_count:
                    raise CFGVerificationError(
                        "Phi argument count does not match predecessor count"
                    )
                # ``None`` is the language IR's explicit "undefined on this
                # incoming path" value (Reference? in ast.Phi), not a missing
                # construction result.  A Phi with no defined input at all is
                # nevertheless meaningless and indicates an incomplete SSA
                # fixup.
                if not any(argument is not None for argument in phi.arguments):
                    raise CFGVerificationError("Phi has no defined argument")

    missing_reverse = forward_edges - reverse_edges
    missing_forward = reverse_edges - forward_edges
    if missing_reverse:
        raise CFGVerificationError("CFG forward edge lacks predecessor backlink")
    if missing_forward:
        raise CFGVerificationError("CFG predecessor lacks forward edge")

    if catalog is not None:
        code_id = catalog.procedure(cfg.code).code_id
        catalog_blocks = {
            block_id: block for block_id, block in catalog.blocks() if block_id.code == code_id
        }
        if set(catalog_blocks.values()) != block_set:
            raise CFGVerificationError("catalog block set does not match CFG")
        catalog_edges = {
            (source, edge_id.label, target)
            for edge_id, (source, target) in catalog.edges()
            if edge_id.source.code == code_id
        }
        expected_edges = {
            (
                catalog.block_id(source, code_id),
                str(label),
                catalog.block_id(target, code_id),
            )
            for source, label, target in forward_edges
        }
        if catalog_edges != expected_edges:
            raise CFGVerificationError("catalog edge set does not match CFG")


__all__ = ["CFGVerificationError", "verify_cfg"]


class SSAVerificationError(CFGVerificationError):
    """Raised when SSA values violate dominance or phi invariants."""


def _defined_references(block):
    """Yield the references a block binds to fresh SSA values."""
    if isinstance(block, graph.Merge):
        for phi in block.phi:
            yield phi.target
    elif isinstance(block, graph.ForIter):
        yield block.index
    elif isinstance(block, graph.Suite):
        for operation in block.ops:
            for field in ("lcls", "targets"):
                references = getattr(operation, field, None)
                if references:
                    yield from references


def verify_ssa(cfg, catalog=None) -> None:
    """Verify SSA value availability, dominance, and phi uniqueness.

    Undefined reads are legal IR values and are explicitly marked on their
    :class:`Value`; they are not confused with entry values (whose definition
    is also ``None``).  A phi argument is checked on its corresponding incoming
    edge, rather than at the merge block.
    """
    from pyflow.ir.core import ensure_code_indexed
    from pyflow.ir.core.ids import ValueId

    catalog = catalog or ensure_code_indexed(cfg.code)
    blocks = _all_blocks(cfg)
    reachable = set()
    pending = [cfg.entryTerminal]
    while pending:
        block = pending.pop()
        if block in reachable:
            continue
        reachable.add(block)
        pending.extend(block.next.values())

    # Classic iterative dominators.  The graph is small compared with the
    # analysis itself and this avoids depending on mutable DJ annotations.
    dominators = {block: set(reachable) for block in reachable}
    dominators[cfg.entryTerminal] = {cfg.entryTerminal}
    changed = True
    while changed:
        changed = False
        for block in reachable:
            if block is cfg.entryTerminal:
                continue
            predecessors = [p for p, _ in block.iterprev() if p in reachable]
            common = (
                set.intersection(*(dominators[p] for p in predecessors)) if predecessors else set()
            )
            updated = {block} | common
            if updated != dominators[block]:
                dominators[block] = updated
                changed = True

    operation_blocks = {}
    operation_objects = []
    block_nodes = {}
    phi_blocks = {}
    for block in blocks:
        if catalog.has_node(block, cfg.code):
            block_nodes[catalog.node_id(block, cfg.code)] = block
        if isinstance(block, graph.Suite):
            for operation in block.ops:
                operation_objects.append((operation, block))
                if catalog.has_node(operation, cfg.code):
                    operation_blocks[catalog.node_id(operation, cfg.code)] = block
        if isinstance(block, graph.Merge):
            for phi in block.phi:
                if not catalog.has_value(phi.target, cfg.code):
                    raise SSAVerificationError("phi target has no SSA value")
                value_id = catalog.value_id(phi.target, cfg.code)
                if value_id in phi_blocks:
                    raise SSAVerificationError(f"duplicate phi target {value_id}")
                phi_blocks[value_id] = block

    # Definitions are located through the SSA bindings on defining locals,
    # not only through node ids.  Rewrites (for example lowering a ``with``
    # statement) may replace an operation with an equivalent one, leaving the
    # recorded definition NodeId stale while the value stays correctly bound.
    definition_blocks = dict(phi_blocks)
    for block in blocks:
        for reference in _defined_references(block):
            if catalog.has_value(reference, cfg.code):
                definition_blocks.setdefault(catalog.value_id(reference, cfg.code), block)

    def check_available(value_id, use_block, *, edge_predecessor=None):
        if not isinstance(value_id, ValueId):
            return
        value = catalog.values.get(value_id)
        if value is None:
            raise SSAVerificationError(f"SSA use references missing value {value_id}")
        if value.undefined:
            return
        definition_block = definition_blocks.get(value_id)
        if definition_block is None and value.definition is not None:
            definition_block = operation_blocks.get(value.definition) or block_nodes.get(
                value.definition
            )
            if definition_block is None:
                try:
                    definition_object = catalog.node(value.definition)
                except KeyError:
                    definition_object = None
                matching_blocks = [
                    owner
                    for operation, owner in operation_objects
                    if operation is definition_object
                    or operation == definition_object
                    or (
                        definition_object is not None and repr(operation) == repr(definition_object)
                    )
                ]
                definition_block = matching_blocks[0] if matching_blocks else None
            if definition_block is None:
                # A stale source NodeId can survive a CFG rewrite.  It is
                # still a definition only if its source operation has a
                # structurally identical live operation in this CFG.
                raise SSAVerificationError(f"definition of {value_id} is not present in the CFG")
        if definition_block is None:  # entry parameter or synthetic input
            return
        target = edge_predecessor or use_block
        if definition_block not in dominators.get(target, set()):
            raise SSAVerificationError(
                f"definition of {value_id} does not dominate its use in {type(target).__name__}"
            )

    for block in reachable:
        if isinstance(block, graph.Merge):
            predecessors = list(block.iterprev())
            for phi in block.phi:
                if len(phi.arguments) != len(predecessors):
                    raise SSAVerificationError("phi arity does not match predecessor count")
                for argument, (predecessor, _label) in zip(phi.arguments, predecessors):
                    if argument is None:
                        continue
                    if not catalog.has_value(argument, cfg.code):
                        raise SSAVerificationError("phi argument has no SSA value")
                    check_available(
                        catalog.value_id(argument, cfg.code),
                        block,
                        edge_predecessor=predecessor,
                    )
        if isinstance(block, graph.Suite):
            for operation in block.ops:
                if not catalog.has_node(operation, cfg.code):
                    continue
                semantics = catalog.semantics.get_operation(catalog.node_id(operation, cfg.code))
                if semantics is None:
                    continue
                for value_id in semantics.uses:
                    check_available(value_id, block)
