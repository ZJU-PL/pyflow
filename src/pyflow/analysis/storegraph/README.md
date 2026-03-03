# Store Graph Module

`pyflow.analysis.storegraph` defines the heap/state model used by the CPA and IPA layers. It gives the analysis a uniform way to talk about:

- root storage locations such as locals and existing values
- abstract heap objects
- object fields and container slots
- object identity/type naming across contexts
- incremental propagation as new references flow through the graph

At a high level, the store graph is a points-to graph with explicit storage locations. Slots hold sets of abstract object identities (`ExtendedType` instances), and those identities map to `ObjectNode`s inside a `RegionNode`.

## Module Layout

```text
storegraph/
├── __init__.py          # Package exports
├── storegraph.py        # Graph nodes and merge/update logic
├── canonicalobjects.py  # Canonical slot/context/type factories
├── extendedtypes.py     # Abstract object identity taxonomy
├── setmanager.py        # Cached frozenset operations
├── annotations.py       # Immutable per-object and per-slot metadata
└── README.md            # This file
```

## Core Model

The main runtime objects are:

- `StoreGraph`: root container for root slots, a default region, and shared set/type helpers
- `RegionNode`: groups objects that belong to the same abstract region
- `ObjectNode`: an abstract heap object keyed by an `ExtendedType`
- `SlotNode`: a storage location whose value is a set of possible object identities
- `MergableNode`: union-find base class used by every graph node that can collapse into an equivalent canonical representative

The data model is:

```text
StoreGraph
  -> root SlotNode values
  -> RegionNode
       -> ObjectNode per ExtendedType
            -> field SlotNode values
                 -> refs: frozenset[ExtendedType]
                 -> region: RegionNode for referenced objects
```

This separation matters:

- a `SlotNode` is a place that can store references
- an `ExtendedType` is the stable identity used inside points-to sets
- an `ObjectNode` is the materialized heap node for an `ExtendedType` within a region

## Canonicalization and Identity

The package relies heavily on canonical objects so that structurally equivalent names collapse to the same Python object.

`CanonicalObjects` in [`canonicalobjects.py`](pyflow/src/pyflow/analysis/storegraph/canonicalobjects.py) creates:

- root slot names
  - `localName(code, local, context)`
  - `existingName(code, obj, context)`
- field names
  - `fieldName(field_type, name_obj)`
- analysis contexts
  - `opContext(code, op, context)`
  - `codeContext(code, context)`
- abstract object identities
  - `externalType(obj)`
  - `existingType(obj)`
  - `pathType(path, obj, op)`
  - `methodType(func, inst, obj, op)`
  - `contextType(sig, obj, op)`
  - `indexedType(xtype)`

This canonicalization is not cosmetic. The graph code assumes identity equality is meaningful for names and types, which keeps points-to sets compact and merge logic cheap.

## Extended Types

`ExtendedType` objects describe object identity at the analysis level, not just Python runtime class.

The concrete variants in [`extendedtypes.py`](pyflow/src/pyflow/analysis/storegraph/extendedtypes.py) are:

- `ExternalObjectType`: objects entering from outside the current analysis boundary
- `ExistingObjectType`: pre-existing concrete objects discovered by the extractor
- `PathObjectType`: allocation-site or path-sensitive object identities
- `MethodObjectType`: bound methods keyed by function and instance
- `ContextObjectType`: context-sensitive identities for parameters and related objects
- `IndexedObjectType`: a wrapper used when one logical identity needs to be split into distinct abstract objects

Most of the graph stores `ExtendedType` values first and materializes `ObjectNode`s lazily through `RegionNode.object(xtype)`.

## Slots and Objects

### Root slots

Root slots are created through `StoreGraph.root(slot_name)`. They represent names that exist independently of any heap object, primarily:

- locals via `LocalSlotName`
- references to existing objects via `ExistingSlotName`

### Field slots

Field slots are created through `ObjectNode.field(slot_name, region_hint)`. `FieldSlotName` supports several field categories:

- `"Attribute"` for object attributes
- `"Array"` for indexed container elements
- `"Dictionary"` for dictionary entries
- `"LowLevel"` for special internal fields such as type and length pointers

If the owning object is an `ExistingObjectType`, field creation may bootstrap the slot from the extractor by calling `StoreGraph.existingSlotRef(...)`.

### Slot contents

Each `SlotNode` carries:

- `refs`: a cached `frozenset` of possible `ExtendedType` values
- `null`: whether the slot may still hold `None` / no concrete object
- `region`: the region where referenced objects should be materialized
- `observers`: solver constraints that must be marked when the slot gains information

Iteration over a slot yields `ObjectNode`s, not raw `ExtendedType`s:

```python
for obj in slot:
    ...
```

Internally, iteration resolves `slot.refs` back through `slot.region.object(xtype)`.

## Regions and Merging

Every graph node derives from `MergableNode`, which implements a simple union-find scheme through `getForward()` and `setForward()`.

Merging is central to the package:

- `RegionNode.merge(other)` merges object maps by `ExtendedType`
- `ObjectNode.merge(other)` merges field maps by `FieldSlotName`
- `SlotNode.merge(other)` merges:
  - referenced type sets
  - observer lists
  - nullability
  - target regions

After a merge, callers should treat the result of `getForward()` as the canonical node. Most public methods normalize `self` before operating, but code that caches nodes must still be aware that old instances can become forwarding stubs.

## Update and Propagation Semantics

`SlotNode` is where most incremental information flow happens.

- `initializeType(xtype)` inserts a single type and ensures the corresponding `ObjectNode` exists
- `initializeTypes(xtypes)` inserts a batch of types
- `update(other_slot)` unions another slot's references into this slot, merging regions if needed
- `dependsRead(constraint)` / `dependsWrite(constraint)` register a solver object that exposes `mark()`

When new references arrive, `_update()` unions the new set with the existing `refs` through the shared `CachedSetManager` and marks all observers.

This is the bridge between the store graph and the CPA constraint system in [`constraints.py`](pyflow/src/pyflow/analysis/cpa/constraints.py).

## Set Management

[`setmanager.py`](pyflow/src/pyflow/analysis/storegraph/setmanager.py) provides `CachedSetManager`, a small helper that interns `frozenset` results. The graph uses it for nearly every points-to set operation:

- `empty()`
- `coerce(values)`
- `inplaceUnion(a, b)`
- `diff(a, b)`
- `tempDiff(a, b)`

This avoids repeatedly allocating identical immutable sets during fixpoint propagation.

## Annotations

[`annotations.py`](pyflow/src/pyflow/analysis/storegraph/annotations.py) defines immutable metadata objects attached directly to nodes:

- `ObjectAnnotation(preexisting, unique, final, uniform, input)`
- `FieldAnnotation(unique)`

Nodes update annotations via:

- `ObjectNode.rewriteAnnotation(...)`
- `SlotNode.rewriteAnnotation(...)`

The rewrite behavior comes from the shared `Annotation` base class in `pyflow.language.asttools`.

## How the Module Is Used

The typical construction path is:

1. Create a `CanonicalObjects` instance.
2. Create a `StoreGraph(extractor, canonical)`.
3. Create root slots for locals/existing values.
4. Seed those slots with `ExtendedType` identities.
5. Follow slot iteration to materialize referenced `ObjectNode`s.
6. Create or update fields as constraints discover reads, writes, calls, and allocations.

The initial image builder in [`simpleimagebuilder.py`](pyflow/src/pyflow/analysis/cpa/simpleimagebuilder.py) is the clearest end-to-end example of this workflow.

Minimal example:

```python
from pyflow.analysis.storegraph import canonicalobjects, storegraph

canonical = canonicalobjects.CanonicalObjects()
graph = storegraph.StoreGraph(extractor, canonical)

slot_name = canonical.localName(code, local_node, analysis_context)
local_slot = graph.root(slot_name)

xtype = canonical.pathType(path, abstract_obj, op_context)
obj = local_slot.initializeType(xtype)

field_name = canonical.fieldName("Attribute", attr_name_obj)
field_slot = obj.field(field_name, graph.regionHint)
```

## Important Invariants

- Root slots must use `slotName.isRoot() == True`.
- Object fields must use non-root `FieldSlotName`s.
- `SlotNode.refs` contains `ExtendedType` instances, not `ObjectNode`s.
- `RegionNode.objects` is keyed by canonical `ExtendedType`.
- Existing objects may lazily expose pre-known fields through the extractor.
- Primitive-like objects (`float`, `int`, `bool`, `str`) are intentionally de-specialized in some canonical type builders to reduce state explosion.

## Limitations and Notes

- The code uses a few explicit `HACK` comments around extractor bootstrapping and low-level fields; those semantics are real and currently part of the implementation contract.
- `SlotNode.null` is tracked, but the package is primarily organized around object-reference flow rather than a first-class null object.
- Merge operations are destructive: after merging, stale references may still exist in caller code but should be normalized with `getForward()`.
- Observer cleanup is manual via `removeObservers()` and is typically used after analysis is complete.

## Related Code

- CPA integration: [`src/pyflow/analysis/cpa`](pyflow/src/pyflow/analysis/cpa)
- Initial graph seeding: [`simpleimagebuilder.py`](pyflow/src/pyflow/analysis/cpa/simpleimagebuilder.py)
- Dump helpers: [`dumputil.py`](pyflow/src/pyflow/analysis/dump/dumputil.py)
- IPA memory policy: [`storegraphpolicy.py`](pyflow/src/pyflow/analysis/ipa/memory/storegraphpolicy.py)
