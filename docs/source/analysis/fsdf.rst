Flow-Sensitive Data Flow (FSDF)
================================

The Flow-Sensitive Data Flow module provides statement-by-statement data flow
analysis over PyFlow's data flow IR.  Unlike standard data flow which may
aggregate at basic block boundaries, FSDF tracks facts at every program point
for maximum precision.

Key Features
------------

- **Statement-Level Precision**: Propagates data flow facts through every
  operation, not just between basic blocks
- **Worklist Algorithm**: Iterates to a fixed point using a standard data
  flow worklist
- **Transfer Functions**: Models how Python operations transform data flow
  facts (gen/kill)
- **Meet Functions**: Configurable join operations for merge points

Architecture
------------

The FSDF module operates on PyFlow's internal data flow representation and
produces analysis results that downstream analyses can consume.  It integrates
with the program culler to identify live code.

See Also
--------

- :doc:`dataflowIR` — The data flow IR that FSDF operates on
- :doc:`ipa` — Inter-procedural extension of data flow analysis
- :doc:`cpa` — Constraint-based alternative to data flow analysis
