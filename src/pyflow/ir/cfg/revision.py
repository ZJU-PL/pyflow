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
            target for _label, target in sorted(block.next.items(), key=lambda item: str(item[0]))
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


def _scalar_fields(node):
    values = []
    for name, value in node.fields():
        if value is None or isinstance(value, (str, int, float, bool)):
            values.append((name, value))
        elif isinstance(value, ast.PythonASTNode):
            # Child nodes are covered by the iterative walk; ``repr`` here
            # would recurse through the whole subtree again.
            values.append((name, ("node", type(value).__qualname__)))
        elif isinstance(value, (list, tuple)):
            if all(item is None or isinstance(item, (str, int, float, bool)) for item in value):
                values.append((name, tuple(value)))
            else:
                values.append((name, ("seq", len(value))))
        else:
            values.append((name, repr(value)[:120]))
    return tuple(values)


def _node_signature(root) -> tuple:
    """Structural digest of *root* without recursive ``repr``.

    ``repr`` recurses once per AST level, so a deep generated expression made
    the CFG transaction fingerprint exhaust the Python stack.  This walk uses
    an explicit stack and records types, scalar fields, and child counts.
    """
    digest = []
    seen: set[int] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node is None or isinstance(node, (str, int, float, bool)):
            digest.append(node)
            continue
        if isinstance(node, (list, tuple)):
            digest.append(("seq", len(node)))
            stack.extend(node)
            continue
        if not isinstance(node, ast.PythonASTNode):
            digest.append(("leaf", repr(node)[:120]))
            continue
        identity = id(node)
        if identity in seen:
            digest.append(("ref", identity))
            continue
        seen.add(identity)
        digest.append((type(node).__qualname__, _scalar_fields(node)))
        children = getattr(node, "children", None)
        if children is not None:
            kids = list(children())
            digest.append(("kids", len(kids)))
            stack.extend(kids)
    return tuple(digest)


def _ast_nodes(cfg) -> tuple[object, ...]:
    ordered = []
    seen_ids: set[int] = set()

    roots = []
    for block in _blocks(cfg):
        roots.extend(_roots(block))
    stack = list(reversed(roots))
    while stack:
        node = stack.pop()
        if node is None or isinstance(node, ast.leafTypes):
            continue
        if isinstance(node, (tuple, list)):
            stack.extend(reversed(node))
            continue
        if not isinstance(node, ast.PythonASTNode):
            continue
        node_id = id(node)
        if node_id in seen_ids:
            continue
        if isinstance(node, ast.Code) and node is not cfg.code:
            continue
        seen_ids.add(node_id)
        ordered.append(node)
        children = getattr(node, "children", None)
        if children is not None:
            stack.extend(reversed(list(children())))
    return tuple(ordered)


class CFGTransformTransaction:
    """Capture, commit, and verify one structural CFG transformation."""

    def __init__(self, cfg, transform: str) -> None:
        self.cfg = cfg
        self.transform = transform
        self.catalog: IRCatalog = ensure_code_indexed(cfg.code)
        index_cfg(self.catalog, cfg)
        self.code_id = self.catalog.procedure(cfg.code).code_id
        self.before_revision: IRRevision = self.catalog.revision
        self.before_nodes = {node: self.catalog.node_id(node, cfg.code) for node in _ast_nodes(cfg)}
        self.before_blocks = {
            block: self.catalog.block_id(block, cfg.code) for block in _blocks(cfg)
        }
        # A transaction rewrites one procedure.  Tracking program-wide
        # identities here made every per-function transform O(program).
        self.before_edges = {
            edge_id for edge_id, _edge in self.catalog.edges_for_code(self.code_id)
        }
        self.before_symbols = {symbol.id for symbol in self.catalog.symbols.for_code(self.code_id)}
        self.before_values = {value.id for value in self.catalog.values.for_code(self.code_id)}
        self.before_call_sites, self.before_allocation_sites = self._site_identities(self.code_id)
        self.before_fingerprint = self._fingerprint()

    def _site_identities(self, code_id) -> tuple[set, set]:
        calls: set = set()
        allocations: set = set()
        for node_id, _node in self.catalog.iter_nodes_for_code(code_id):
            semantics = self.catalog.semantics.get_operation(node_id)
            if semantics is None:
                continue
            calls.update(semantics.calls)
            allocations.update(semantics.allocations)
        return calls, allocations

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
                    tuple(_node_signature(root) for root in _roots(block)),
                )
                for block in blocks
            ),
        )

    def commit(self, generated_from=None) -> IRRemap:
        generated_from = generated_from or {}
        index_cfg(self.catalog, self.cfg)
        after_nodes = {
            node: self.catalog.node_id(node, self.cfg.code) for node in _ast_nodes(self.cfg)
        }
        after_blocks = {
            block: self.catalog.block_id(block, self.cfg.code) for block in _blocks(self.cfg)
        }
        after_edges = {edge_id for edge_id, _edge in self.catalog.edges_for_code(self.code_id)}
        changed = self.before_fingerprint != self._fingerprint()
        after_revision = self.catalog.commit_revision() if changed else self.before_revision

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
                    if source in self.before_nodes or self.catalog.has_node(source)
                )
                self.catalog.source_map.append_provenance(
                    generated_id,
                    TransformationFrame(self.transform, inputs=source_ids),
                )
        verify_cfg(self.cfg, self.catalog)
        verify_catalog(self.catalog, code_id=self.code_id)

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
        created_blocks = frozenset(after_blocks.values()) - frozenset(self.before_blocks.values())
        created_edges = after_edges - self.before_edges
        after_symbols = {symbol.id for symbol in self.catalog.symbols.for_code(self.code_id)}
        symbol_targets = {
            identity: ((identity,) if identity in after_symbols else ())
            for identity in self.before_symbols
        }
        after_values = {value.id for value in self.catalog.values.for_code(self.code_id)}
        value_targets = {
            identity: ((identity,) if identity in after_values else ())
            for identity in self.before_values
        }
        after_call_sites, after_allocation_sites = self._site_identities(self.code_id)
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
            created_call_sites=frozenset(after_call_sites - self.before_call_sites),
            created_allocation_sites=frozenset(
                after_allocation_sites - self.before_allocation_sites
            ),
        )


__all__ = ["CFGTransformTransaction"]
