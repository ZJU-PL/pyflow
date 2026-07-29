"""Revision transactions for structural CFG transformations."""

from __future__ import annotations

from pyflow.ir.core import (
    AllocationSiteId,
    CallSiteId,
    IRCatalog,
    IRRemap,
    IRRevision,
    TransformationFrame,
    ensure_code_indexed,
    index_cfg,
    verify_catalog,
)
from pyflow.language.python import ast

from . import graph as cfg_graph
from .verifier import verify_cfg


def _blocks(cfg) -> tuple[object, ...]:
    terminals = (
        cfg.entryTerminal,
        cfg.normalTerminal,
        cfg.failTerminal,
        cfg.errorTerminal,
    )
    pending = [cfg.entryTerminal]
    seen = set()
    ordered = []
    while pending:
        block = pending.pop(0)
        if block in seen:
            continue
        seen.add(block)
        ordered.append(block)
        pending.extend(
            target
            for _label, target in sorted(
                block.next.items(), key=lambda item: str(item[0])
            )
        )
    ordered.extend(terminal for terminal in terminals if terminal not in seen)
    return tuple(ordered)


def _roots(block):
    if isinstance(block, cfg_graph.Suite):
        return tuple(block.ops)
    if isinstance(block, cfg_graph.Switch):
        return (block.condition,)
    if isinstance(block, cfg_graph.TypeSwitch):
        return (block.original,)
    if isinstance(block, cfg_graph.ForIter):
        return block.iterator, block.index
    if isinstance(block, cfg_graph.Merge):
        return tuple(block.phi)
    return ()


def _ast_nodes(cfg) -> tuple[object, ...]:
    ordered = []
    seen: list[ast.PythonASTNode] = []

    def visit(node):
        if node is None or isinstance(node, ast.leafTypes):
            return
        if isinstance(node, (tuple, list)):
            for item in node:
                visit(item)
            return
        if not isinstance(node, ast.PythonASTNode):
            return
        if any(candidate is node for candidate in seen):
            return
        if isinstance(node, ast.Code) and node is not cfg.code:
            return
        seen.append(node)
        ordered.append(node)
        children = getattr(node, "children", None)
        if children is not None:
            visit(tuple(children()))

    for block in _blocks(cfg):
        visit(_roots(block))
    return tuple(ordered)


class CFGTransformTransaction:
    """Capture, commit, and verify one structural CFG transformation."""

    def __init__(self, cfg, transform: str) -> None:
        self.cfg = cfg
        self.transform = transform
        self.catalog: IRCatalog = ensure_code_indexed(cfg.code)
        index_cfg(self.catalog, cfg)
        self.before_revision: IRRevision = self.catalog.revision
        self.before_nodes = {
            node: self.catalog.node_id(node, cfg.code) for node in _ast_nodes(cfg)
        }
        self.before_blocks = {
            block: self.catalog.block_id(block, cfg.code) for block in _blocks(cfg)
        }
        self.before_edges = {
            edge_id
            for edge_id, _edge in self.catalog.edges()
            if edge_id.source.code == self.catalog.procedure(cfg.code).code_id
        }
        self.before_symbols = {symbol.id for symbol in self.catalog.symbols}
        self.before_values = {value.id for value in self.catalog.values}
        self.before_call_sites = {
            call_id
            for _node_id, semantics in self.catalog.semantics.items()
            for call_id in semantics.calls
        }
        self.before_allocation_sites = {
            allocation_id
            for _node_id, semantics in self.catalog.semantics.items()
            for allocation_id in semantics.allocations
        }
        self.before_fingerprint = self._fingerprint()

    def _fingerprint(self):
        blocks = _blocks(self.cfg)
        positions = {block: index for index, block in enumerate(blocks)}
        return (
            tuple(
                (
                    type(block).__qualname__,
                    tuple(
                        (str(label), positions.get(target, -1))
                        for label, target in sorted(
                            getattr(block, "next").items(),
                            key=lambda item: str(item[0]),
                        )
                    ),
                    tuple(repr(root) for root in _roots(block)),
                )
                for block in blocks
            ),
        )

    def commit(self, generated_from=None) -> IRRemap:
        generated_from = generated_from or {}
        index_cfg(self.catalog, self.cfg)
        after_nodes = {
            node: self.catalog.node_id(node, self.cfg.code)
            for node in _ast_nodes(self.cfg)
        }
        after_blocks = {
            block: self.catalog.block_id(block, self.cfg.code)
            for block in _blocks(self.cfg)
        }
        after_edges = {
            edge_id
            for edge_id, _edge in self.catalog.edges()
            if edge_id.source.code == self.catalog.procedure(self.cfg.code).code_id
        }
        changed = self.before_fingerprint != self._fingerprint()
        after_revision = (
            self.catalog.commit_revision() if changed else self.before_revision
        )

        if changed:
            for generated, sources in generated_from.items():
                generated_id = after_nodes.get(generated)
                if generated_id is None:
                    continue
                source_ids = tuple(
                    (
                        self.before_nodes[source]
                        if source in self.before_nodes
                        else self.catalog.node_id(source)
                    )
                    for source in sources
                    if source in self.before_nodes
                    or self.catalog.has_node(source)
                )
                self.catalog.source_map.append_provenance(
                    generated_id,
                    TransformationFrame(self.transform, inputs=source_ids),
                )
        verify_cfg(self.cfg, self.catalog)
        verify_catalog(self.catalog)

        node_targets = {
            identity: ((after_nodes[node],) if node in after_nodes else ())
            for node, identity in self.before_nodes.items()
        }
        block_targets = {
            identity: ((after_blocks[block],) if block in after_blocks else ())
            for block, identity in self.before_blocks.items()
        }
        edge_targets = {
            identity: ((identity,) if identity in after_edges else ())
            for identity in self.before_edges
        }
        after_node_ids = frozenset(after_nodes.values())
        created_nodes = after_node_ids - frozenset(self.before_nodes.values())
        created_blocks = frozenset(after_blocks.values()) - frozenset(
            self.before_blocks.values()
        )
        created_edges = after_edges - self.before_edges
        after_symbols = {symbol.id for symbol in self.catalog.symbols}
        symbol_targets = {
            identity: ((identity,) if identity in after_symbols else ())
            for identity in self.before_symbols
        }
        after_values = {value.id for value in self.catalog.values}
        value_targets = {
            identity: ((identity,) if identity in after_values else ())
            for identity in self.before_values
        }
        after_call_sites = {
            call_id
            for _node_id, semantics in self.catalog.semantics.items()
            for call_id in semantics.calls
        }
        after_allocation_sites = {
            allocation_id
            for _node_id, semantics in self.catalog.semantics.items()
            for allocation_id in semantics.allocations
        }
        call_sites = {
            source: tuple(
                target
                for node_target in node_targets.get(source.node, ())
                for target in (CallSiteId(node_target, source.ordinal),)
                if target in after_call_sites
            )
            for source in self.before_call_sites
        }
        allocation_sites = {
            source: tuple(
                target
                for node_target in node_targets.get(source.node, ())
                for target in (AllocationSiteId(node_target, source.ordinal),)
                if target in after_allocation_sites
            )
            for source in self.before_allocation_sites
        }
        return IRRemap.create(
            before=self.before_revision,
            after=after_revision,
            transform=self.transform,
            nodes=node_targets,
            blocks=block_targets,
            edges=edge_targets,
            symbols=symbol_targets,
            values=value_targets,
            call_sites=call_sites,
            allocation_sites=allocation_sites,
            created_nodes=created_nodes,
            created_blocks=created_blocks,
            created_edges=frozenset(created_edges),
            created_symbols=frozenset(after_symbols - self.before_symbols),
            created_values=frozenset(after_values - self.before_values),
            created_call_sites=frozenset(
                after_call_sites - self.before_call_sites
            ),
            created_allocation_sites=frozenset(
                after_allocation_sites - self.before_allocation_sites
            ),
        )


__all__ = ["CFGTransformTransaction"]
