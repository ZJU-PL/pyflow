# PyFlow Analysis Overview

This document describes the main analysis components in PyFlow and how they relate to each other.

---

## Program representation

PyFlow builds two main views of the program:

- **CFG** (`analysis/cfg/`) — Control flow graph. Construction, SSA (`cfg/ssa.py`), dominance (`cfg/dom.py`), and optimizations such as constant folding and dead branch elimination (`cfg/optimize.py`).

- **Store graph** (`analysis/storegraph/`) — Representation of objects, slots (locals, fields), and regions. Used as the shared base for points-to, shape, and lifetime analyses.

---

## Graphs built from the CFG

- **CDG** (`analysis/cdg/`) — Control Dependence Graph, from dominance frontiers.
- **DDG** (`analysis/ddg/`) — Data Dependence Graph.
- **PDG** (`analysis/pdg/`) — Program Dependence Graph (control + data dependence).

**Dataflow IR** (`analysis/dataflowIR/`) and **FSDF** (`analysis/fsdf/`) provide further IR and dataflow machinery. The **call graph** (`analysis/callgraph/`) is built via AST-based, PyCG-based, or constraint-based approaches.

---

## IFDS and Heap Abstraction

- **Heap abstraction** (`analysis/heap/`) — Canonical heap locations, alias tracking, and strong/weak update policy for IFDS clients (taint, nullness, typestate).  Precision is fixed by `HeapPolicy` before solving.  The heap model operates on the IFDS supergraph and is independent of the store graph pipeline.

- **IFDS** (`analysis/ifds/`) — Interprocedural Finite Distributive Subset solver.  The IFDS engine consumes the heap abstraction to track facts over canonical locations.  Clients live under `ifds/clients/`.

The heap package was extracted from `ifds/` into an independent module.  The core model (`heap.py`) has no IFDS dependencies; the IFDS-dependent submodules (`heap_effects.py`, `heap_summary.py`) import from IFDS utilities.

---

## Analyses on the store graph

The following pipeline runs on the store graph:

```
AST/Code → Store Graph → IPA + CPA (interprocedural) → Shape Analysis → Lifetime Analysis
```

- **CPA** (`analysis/cpa/`) — Constraint Propagation Analysis. Solves constraints for points-to and types on the store graph.

- **IPA** (`analysis/ipa/`) — Interprocedural Analysis. Handles call contexts and summaries. IPA and CPA work together: IPA manages procedure boundaries, CPA does the constraint propagation.

- **Shape analysis** (`analysis/shape/`) — Region-based shape analysis, using CPA's points-to and type results.

- **Lifetime analysis** (`analysis/lifetimeanalysis/`) — Read/modify and lifetime information, using CPA and shape analysis results.

Results pass down the pipeline: shape uses CPA; lifetime uses CPA and shape.

---

## Heap vs Shape vs Storegraph

| Module | Purpose | Data source |
|--------|---------|-------------|
| `heap` | Canonical locations, alias tracking, update policy for IFDS | IFDS supergraph (CFG-based) |
| `storegraph` | Foundational object/slot/region model | Shared by CPA/IPA/shape/lifetime |
| `shape` | Data structure shape inference, reference counts | Store graph + CPA results |
| `lifetimeanalysis` | Variable lifetime, read/modify tracking | Store graph + shape results |
