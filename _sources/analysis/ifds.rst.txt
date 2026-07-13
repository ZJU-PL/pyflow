IFDS/IDE Data Flow Engine
============================

The IFDS module provides an interprocedural, flow-sensitive data flow engine
based on the IFDS (Interprocedural Finite Distributive Subset) and IDE
(Interprocedural Distributive Environment) frameworks.

IFDS solves data flow problems over a *supergraph* that combines individual
function CFGs with call and return edges.  The IDE extension adds value
computation on top of reachability, enabling precise fact propagation
across procedure boundaries.

Key Features
------------

- **IFDSSolver**: Context-sensitive reachability over distributive flow
  functions
- **IDESolver**: Extends IFDS with edge functions for value computation
- **Supergraph Construction**: Builds CFG supergraphs from per-function CFGs
  and call graph information
- **Backward Analysis**: Backward IFDS solver for reverse data flow problems
- **Diagnostics**: Built-in diagnostic tracking for debugging solver behavior

Analysis Clients
----------------

The IFDS engine ships with several ready-to-use analysis clients:

- **Taint Analysis** (``clients/taint.py``): Interprocedural taint tracking
  from sources to sinks via flow functions
- **Nullness Analysis** (``clients/nullness.py``): Null pointer and
  ``None``-related bug detection
- **Typestate Analysis** (``clients/typestate.py``,
  ``clients/typestate_engine.py``): Resource lifecycle protocol verification
  (file descriptors, locks, sockets, transactions)
- **Shadow Scan** (``shadow_scan.py``): Differential analysis comparing two
  analysis runs

CLI Usage
---------

IFDS analyses are accessible through ``pyflow security``:

.. code-block:: bash

   # Taint analysis
   pyflow security input.py --engine ifds --function main --sources input --sinks eval

   # Typestate analysis
   pyflow security input.py --engine ifds --function main --analysis typestate

   # With specific typestate protocols
   pyflow security input.py --engine ifds --function main --analysis typestate \
       --typestate-protocol file --typestate-protocol socket

Annotation Synthesis
--------------------

The IFDS module includes an annotation synthesis engine
(``annotation_synthesis.py``) that generates syntactic annotations to prepare
code for IFDS analysis.  A fallback mechanism (``annotation_fallback.py``)
handles cases where synthesis cannot be applied.

See Also
--------

- :doc:`dataflowIR` — Data flow IR that IFDS operates on
- :doc:`cfg` — CFG construction (supergraph foundation)
- :doc:`alias/flow_sensitive` — Flow-sensitive alias analysis consumed by taint clients
