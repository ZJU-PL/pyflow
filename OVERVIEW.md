# Overview


## The Dataflow Analsyis

Flow-Sensitive

- The CFG module itself contains several analyses that operate directly on control flow graphs
  + CFG Optimization - Optimizes CFG nodes including constant folding, dead code elimination, control flow simplification, removing unnecessary nodes, etc.
  + ..
- CDG Construction (cdg/construction.py) - Builds Control Dependence Graphs from CFGs using dominance frontiers


## The Constraint-based Analysis 

Several analysis components (Context-sensitive, flow-inensitive) do not directly use CFG 
- CPA (Constraint Propagation Analysis) - Uses store graphs and constraint solving
- Shape Analysis - Uses region-based analysis
- Lifetime Analysis - Uses read/modify analysis

~~~~
AST/Code → Store Graph → CPA (Interprocedural) → Shape Analysis (uses CPA results) → Lifetime Analysis (uses CPA results)
~~~~

- IPA and CPA work together - IPA provides the interprocedural framework while CPA performs the actual constraint solving
- All analyses use the store graph as their foundation for representing object relationships
- Results flow downstream - Shape analysis uses CPA's points-to/type information, and Lifetime analysis uses both CPA and shape analysis results
