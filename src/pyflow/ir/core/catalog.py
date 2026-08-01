"""Program-owned catalog for stable IR identities and metadata."""

from __future__ import annotations

from dataclasses import dataclass

from .facts import FactStore
from .ids import (
    BlockId,
    CodeId,
    ContextId,
    ContextSignature,
    EdgeId,
    IRRevision,
    NodeId,
    ScopeId,
    SourceAnchor,
    SymbolId,
)
from .semantics import IRSemantics
from .source import SourceMap, TransformationFrame
from .symbols import SymbolTable, ValueTable


class _IdentityKey:
    """Hashable object-identity key for internal catalog bookkeeping.

    PyFlow IR nodes are not uniformly identity-hashable: a few reference
    classes define structural equality.  Catalog lookup, however, is about a
    concrete occurrence.  Keeping the object alive in this wrapper also
    prevents process-address reuse while the catalog exists; the address is
    never exposed as an IR identity or in serialized output.
    """

    __slots__ = ("object",)

    def __init__(self, value: object) -> None:
        self.object = value

    def __hash__(self) -> int:
        return id(self.object)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _IdentityKey) and self.object is other.object


def _identity(value: object) -> _IdentityKey:
    return _IdentityKey(value)


@dataclass(frozen=True)
class ProcedureIR:
    code_id: CodeId
    root_scope: ScopeId
    is_async: bool = False
    is_generator: bool = False
    construct_kind: str | None = None


class IRCatalog:
    def __init__(self, revision: IRRevision = IRRevision()) -> None:
        self.revision = revision
        self.symbols = SymbolTable()
        self.values = ValueTable()
        self.source_map = SourceMap()
        self.semantics = IRSemantics(self._build_semantics)
        self.facts = FactStore(revision)

        self._procedures: dict[CodeId, ProcedureIR] = {}
        self._code_objects: dict[_IdentityKey, CodeId] = {}
        self._codes: dict[CodeId, object] = {}
        self._code_keys: dict[tuple[str, str, SourceAnchor], int] = {}
        self._nodes: dict[NodeId, object] = {}
        self._node_ids: dict[tuple[CodeId, _IdentityKey], NodeId] = {}
        self._node_occurrences: dict[
            _IdentityKey, NodeId | list[NodeId]
        ] = {}
        self._reference_symbols: dict[tuple[ScopeId, _IdentityKey], SymbolId] = {}
        self._reference_occurrences: dict[
            _IdentityKey, SymbolId | list[SymbolId]
        ] = {}
        self._reference_values: dict[tuple[CodeId, _IdentityKey], object] = {}
        self._contexts: dict[ContextId, object] = {}
        self._context_ids: dict[tuple[CodeId, _IdentityKey], ContextId] = {}
        self._next_node: dict[CodeId, int] = {}
        self._next_scope: dict[CodeId, int] = {}
        self._blocks: dict[BlockId, object] = {}
        self._block_ids: dict[tuple[CodeId, _IdentityKey], BlockId] = {}
        self._edges: dict[EdgeId, tuple[BlockId, BlockId]] = {}
        self._next_block: dict[CodeId, int] = {}

    def _build_semantics(self) -> None:
        from .build_semantics import build_semantics

        build_semantics(self)

    def commit_revision(
        self,
        *,
        preserved_capabilities=(),
    ) -> IRRevision:
        self.revision = self.revision.next()
        self.facts.advance_ir_revision(
            self.revision, preserved=preserved_capabilities
        )
        return self.revision

    def register_code(
        self,
        code: object,
        *,
        module: str,
        qualname: str,
        anchor: SourceAnchor = SourceAnchor(),
        is_async: bool = False,
        is_generator: bool = False,
        construct_kind: str | None = None,
    ) -> ProcedureIR:
        code_key = _identity(code)
        existing = self._code_objects.get(code_key)
        if existing is not None:
            return self._procedures[existing]

        key = (module, qualname, anchor)
        ordinal = self._code_keys.get(key, 0)
        self._code_keys[key] = ordinal + 1
        code_id = CodeId(module, qualname, anchor, ordinal)
        procedure = ProcedureIR(
            code_id,
            ScopeId(code_id, 0),
            is_async,
            is_generator,
            construct_kind,
        )
        self._procedures[code_id] = procedure
        self._code_objects[code_key] = code_id
        self._codes[code_id] = code
        self._next_scope[code_id] = 1
        return procedure

    def procedure(self, code_or_id: object | CodeId) -> ProcedureIR:
        code_id = (
            code_or_id
            if isinstance(code_or_id, CodeId)
            else self._code_objects[_identity(code_or_id)]
        )
        return self._procedures[code_id]

    def has_procedure(self, code_or_id: object | CodeId) -> bool:
        if isinstance(code_or_id, CodeId):
            return code_or_id in self._procedures
        return _identity(code_or_id) in self._code_objects

    def code(self, code_id: CodeId) -> object:
        return self._codes[code_id]

    def new_scope(self, code: CodeId) -> ScopeId:
        ordinal = self._next_scope.get(code, 0)
        self._next_scope[code] = ordinal + 1
        return ScopeId(code, ordinal)

    def register_node(
        self,
        code: CodeId,
        node: object,
        *,
        origin: object | None = None,
        invalidate_semantics: bool = True,
    ) -> NodeId:
        node_key = _identity(node)
        key = (code, node_key)
        existing = self._node_ids.get(key)
        if existing is not None:
            return existing
        return self.register_new_node(
            code,
            node,
            origin=origin,
            node_key=node_key,
            invalidate_semantics=invalidate_semantics,
        )

    def register_new_node(
        self,
        code: CodeId,
        node: object,
        *,
        origin: object | None = None,
        node_key: _IdentityKey | None = None,
        invalidate_semantics: bool = True,
    ) -> NodeId:
        """Register a node known to be new to its procedure."""
        if node_key is None:
            node_key = _identity(node)
        key = (code, node_key)
        ordinal = self._next_node.get(code, 0)
        self._next_node[code] = ordinal + 1
        node_id = NodeId(code, ordinal)
        self._nodes[node_id] = node
        self._node_ids[key] = node_id
        occurrences = self._node_occurrences.get(node_key)
        if occurrences is None:
            self._node_occurrences[node_key] = node_id
        elif isinstance(occurrences, list):
            occurrences.append(node_id)
        else:
            self._node_occurrences[node_key] = [occurrences, node_id]
        self.source_map.set_origin(node_id, origin)
        if invalidate_semantics:
            self.semantics.invalidate()
        return node_id

    def node_id(self, node: object, code: object | CodeId | None = None) -> NodeId:
        if code is not None:
            code_id = code if isinstance(code, CodeId) else self.procedure(code).code_id
            return self._node_ids[(code_id, _identity(node))]
        occurrences = self._node_occurrences[_identity(node)]
        if isinstance(occurrences, list):
            raise KeyError(
                "IR node occurs in multiple procedures; pass code= to node_id()"
            )
        return occurrences

    def has_node(self, node: object, code: object | CodeId | None = None) -> bool:
        if code is None:
            return _identity(node) in self._node_occurrences
        code_id = code if isinstance(code, CodeId) else self.procedure(code).code_id
        return (code_id, _identity(node)) in self._node_ids

    def node(self, node_id: NodeId) -> object:
        return self._nodes[node_id]

    def replace_node(
        self,
        code: object | CodeId,
        original: object,
        replacement: object,
        *,
        transform: str,
        detail: str = "",
    ) -> NodeId:
        """Replace one syntax object while preserving its logical occurrence.

        Semantics-preserving AST rewrites commonly reconstruct a node solely
        because one of its children changed.  The occurrence remains the same
        program point, so its ``NodeId`` remains stable.  The caller must
        rebuild structural semantics after committing all replacements.
        """
        code_id = code if isinstance(code, CodeId) else self.procedure(code).code_id
        original_identity = _identity(original)
        replacement_identity = _identity(replacement)
        original_key = (code_id, original_identity)
        node_id = self._node_ids.get(original_key)
        if node_id is None:
            node_id = self.register_node(code_id, replacement)
            self.source_map.append_provenance(
                node_id,
                TransformationFrame(transform, detail=detail),
            )
            return node_id
        if replacement is original:
            return node_id

        replacement_key = (code_id, replacement_identity)
        occupied = self._node_ids.get(replacement_key)
        if occupied is not None and occupied != node_id:
            raise ValueError(
                f"replacement node already has a different identity: {occupied}"
            )

        del self._node_ids[original_key]
        self._node_ids[replacement_key] = node_id
        self._nodes[node_id] = replacement
        self.semantics.invalidate()

        occurrences = self._node_occurrences.get(original_identity)
        if occurrences is not None:
            if isinstance(occurrences, list):
                occurrences.remove(node_id)
                if len(occurrences) == 1:
                    self._node_occurrences[original_identity] = occurrences[0]
            else:
                assert occurrences == node_id
                del self._node_occurrences[original_identity]
        replacement_occurrences = self._node_occurrences.get(replacement_identity)
        if replacement_occurrences is None:
            self._node_occurrences[replacement_identity] = node_id
        elif isinstance(replacement_occurrences, list):
            if node_id not in replacement_occurrences:
                replacement_occurrences.append(node_id)
        elif replacement_occurrences != node_id:
            self._node_occurrences[replacement_identity] = [
                replacement_occurrences,
                node_id,
            ]

        self.source_map.append_provenance(
            node_id,
            TransformationFrame(transform, inputs=(node_id,), detail=detail),
        )
        return node_id

    def register_block(self, code: object | CodeId, block: object) -> BlockId:
        code_id = code if isinstance(code, CodeId) else self.procedure(code).code_id
        key = (code_id, _identity(block))
        existing = self._block_ids.get(key)
        if existing is not None:
            return existing
        block_id = BlockId(code_id, self._next_block.get(code_id, 0))
        self._next_block[code_id] = block_id.ordinal + 1
        self._block_ids[key] = block_id
        self._blocks[block_id] = block
        return block_id

    def block_id(self, block: object, code: object | CodeId) -> BlockId:
        code_id = code if isinstance(code, CodeId) else self.procedure(code).code_id
        return self._block_ids[(code_id, _identity(block))]

    def block(self, block_id: BlockId) -> object:
        return self._blocks[block_id]

    def register_edge(
        self,
        source: BlockId,
        label: object,
        target: BlockId,
        occurrence: int = 0,
    ) -> EdgeId:
        edge_id = EdgeId(source, str(label), occurrence)
        existing = self._edges.get(edge_id)
        edge = (source, target)
        if existing is not None and existing != edge:
            raise ValueError(f"edge id already occupied: {edge_id}")
        self._edges[edge_id] = edge
        return edge_id

    def synchronize_cfg(
        self,
        code: object | CodeId,
        blocks: tuple[object, ...],
        edges: tuple[tuple[object, object, object, int], ...],
    ) -> None:
        """Make catalog block/edge identities match one current CFG exactly."""
        code_id = code if isinstance(code, CodeId) else self.procedure(code).code_id
        live_blocks = {_identity(block) for block in blocks}
        for (owner, block_key), block_id in tuple(self._block_ids.items()):
            if owner != code_id or block_key in live_blocks:
                continue
            del self._block_ids[(owner, block_key)]
            self._blocks.pop(block_id, None)
        for edge_id in tuple(self._edges):
            if edge_id.source.code == code_id:
                del self._edges[edge_id]
        for block in blocks:
            self.register_block(code_id, block)
        for source_block, label, target_block, occurrence in edges:
            source = self.block_id(source_block, code_id)
            target = self.block_id(target_block, code_id)
            self.register_edge(source, label, target, occurrence)

    def blocks(self):
        return tuple((identity, self._blocks[identity]) for identity in sorted(self._blocks))

    def edges(self):
        return tuple((identity, self._edges[identity]) for identity in sorted(self._edges))

    def source_of(
        self, node_or_id: object | NodeId, *, code: object | CodeId | None = None
    ) -> object | None:
        """Return source metadata for an IR node through the public catalog API."""
        node_id = (
            node_or_id
            if isinstance(node_or_id, NodeId)
            else self.node_id(node_or_id, code)
        )
        return self.source_map.origin(node_id)

    def provenance_of(
        self, node_or_id: object | NodeId, *, code: object | CodeId | None = None
    ):
        node_id = (
            node_or_id
            if isinstance(node_or_id, NodeId)
            else self.node_id(node_or_id, code)
        )
        return self.source_map.provenance(node_id)

    def semantics_of(
        self, node_or_id: object | NodeId, *, code: object | CodeId | None = None
    ):
        """Return mandatory context-independent semantics for an operation."""
        node_id = (
            node_or_id
            if isinstance(node_or_id, NodeId)
            else self.node_id(node_or_id, code)
        )
        return self.semantics.operation(node_id)

    def bind_symbol(
        self,
        reference: object,
        symbol_id: SymbolId,
        *,
        invalidate_semantics: bool = True,
    ) -> None:
        scope = symbol_id.scope
        reference_key = _identity(reference)
        key = (scope, reference_key)
        existing = self._reference_symbols.get(key)
        if existing is not None and existing != symbol_id:
            raise ValueError("an IR reference cannot refer to multiple symbols")
        self._reference_symbols[key] = symbol_id
        occurrences = self._reference_occurrences.get(reference_key)
        if occurrences is None:
            self._reference_occurrences[reference_key] = symbol_id
        elif isinstance(occurrences, list):
            if symbol_id not in occurrences:
                occurrences.append(symbol_id)
        elif occurrences != symbol_id:
            self._reference_occurrences[reference_key] = [occurrences, symbol_id]
        if invalidate_semantics:
            self.semantics.invalidate()

    def has_symbol(self, reference: object, code: object | CodeId | None = None) -> bool:
        if code is None:
            return _identity(reference) in self._reference_occurrences
        return (
            self.procedure(code).root_scope,
            _identity(reference),
        ) in self._reference_symbols

    def symbol_id(
        self, reference: object, code: object | CodeId | None = None
    ) -> SymbolId:
        if code is not None:
            return self._reference_symbols[
                (self.procedure(code).root_scope, _identity(reference))
            ]
        occurrences = self._reference_occurrences[_identity(reference)]
        if isinstance(occurrences, list):
            raise KeyError(
                "IR reference occurs in multiple procedures; pass code= to symbol_id()"
            )
        return occurrences

    def symbol_for(self, reference: object, code: object | CodeId | None = None):
        return self.symbols[self.symbol_id(reference, code)]

    def bind_value(self, code: object | CodeId, reference: object, value_id) -> None:
        code_id = code if isinstance(code, CodeId) else self.procedure(code).code_id
        if value_id.symbol != self.symbol_id(reference, code_id):
            raise ValueError("SSA value must belong to the reference's symbol")
        self._reference_values[(code_id, _identity(reference))] = value_id
        self.semantics.invalidate()

    def value_id(self, reference: object, code: object | CodeId):
        code_id = code if isinstance(code, CodeId) else self.procedure(code).code_id
        return self._reference_values[(code_id, _identity(reference))]

    def has_value(self, reference: object, code: object | CodeId) -> bool:
        code_id = code if isinstance(code, CodeId) else self.procedure(code).code_id
        return (code_id, _identity(reference)) in self._reference_values

    def value_for(self, reference: object, code: object | CodeId):
        return self.values[self.value_id(reference, code)]

    def declaration_of(self, reference_or_symbol: object):
        symbol_id = (
            reference_or_symbol
            if isinstance(reference_or_symbol, SymbolId)
            else self.symbol_id(reference_or_symbol)
        )
        return self.source_map.declaration(symbol_id)

    def register_context(
        self,
        code: object | CodeId,
        context: object,
        signature: ContextSignature,
    ) -> ContextId:
        code_id = code if isinstance(code, CodeId) else self.procedure(code).code_id
        key = (code_id, _identity(context))
        existing = self._context_ids.get(key)
        if existing is not None:
            return existing
        context_id = ContextId(code_id, signature)
        # Re-running an analysis creates fresh solver objects for the same
        # semantic context.  Keep every object-to-ID binding so facts from
        # multiple producers remain queryable, and retain the newest object as
        # the client-facing representative.
        self._context_ids[key] = context_id
        self._contexts[context_id] = context
        return context_id

    def context_id(self, code: object | CodeId, context: object) -> ContextId:
        code_id = code if isinstance(code, CodeId) else self.procedure(code).code_id
        return self._context_ids[(code_id, _identity(context))]

    def context(self, context_id: ContextId) -> object:
        return self._contexts[context_id]

    def procedures(self) -> tuple[ProcedureIR, ...]:
        return tuple(self._procedures[key] for key in sorted(self._procedures))

    def nodes(self) -> tuple[tuple[NodeId, object], ...]:
        return tuple((key, self._nodes[key]) for key in sorted(self._nodes))

    def iter_nodes(self):
        """Iterate nodes in deterministic catalog insertion order.

        Internal whole-catalog passes do not need the allocation and sort
        performed by :meth:`nodes`; indexing itself already inserts nodes in
        deterministic source traversal order.
        """
        return self._nodes.items()

    def contexts(self) -> tuple[tuple[ContextId, object], ...]:
        return tuple((key, self._contexts[key]) for key in sorted(self._contexts))

    def import_contexts_from(self, other: "IRCatalog") -> None:
        """Import contexts whose deterministic code identities exist here."""
        for context_id, context in other.contexts():
            if context_id.code not in self._procedures:
                continue
            self._contexts[context_id] = context
            self._context_ids[(context_id.code, _identity(context))] = context_id
