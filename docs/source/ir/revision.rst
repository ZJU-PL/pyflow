IR Revision
===========

The IR revision replaced process-local object identity, analysis annotations,
and client-specific recovery logic with deterministic typed identities,
program-owned provenance, mandatory structural semantics, revisioned
context-sensitive facts, and explicit invalidation after IR changes.

Key changes
-----------

- **Typed deterministic identities** — ``SymbolId``, ``ValueId``, ``NodeId``,
  ``BlockId``, ``EdgeId``, ``CallSiteId``, ``AllocationSiteId``, ``ContextId``,
  and ``InlineInstanceId`` replace address-derived and name-based references.
- **Program-owned source and provenance** — ``SourceMap`` in ``IRCatalog``
  replaces ad hoc ``annotation.origin`` inspection. Typed ``SourceSpan`` and
  ``TransformationFrame`` records track source and transform history.
- **Structural semantics** — ``IRSemantics`` provides one
  ``OperationSemantics`` record per normalized operation, separate from
  analysis facts.
- **Revisioned fact store** — typed ``Capability`` descriptors and
  ``FactSnapshot`` records replace stringly typed annotation fields. Each
  snapshot is tagged with the analyzed IR revision.
- **No hidden recovery** — missing semantics is a verifier error; missing
  facts produce explicit ``unavailable`` results; clients never reconstruct
  designated facts privately.
- **Corrected CFG/CDG/DDG** — edge mutation centralized and verified;
  total multi-exit/nontermination-aware CDG; DDG distinguishes value def-use
  from location-specific memory dependence.
- **Consumer migration** — IFDS, IPA, CPA, alias, lifetime, shape, and all
  downstream consumers use catalog queries with explicit precision policies.

Status
------

The core migration is complete. Remaining work is repository-wide hardening:
reducing pre-existing lint/type-check debt, benchmarking catalog/fact-store
memory and latency on large programs, and migrating unrelated traversal-local
identity indexes if they become serialized or cross-pass state.
