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
            block_id: block
            for block_id, block in catalog.blocks()
            if block_id.code == code_id
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
