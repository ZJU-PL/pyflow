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
- **Bounded Execution**: Cancellation, time, memory, queue, path-edge, fact,
  summary, incoming-record, and context budgets through ``SolverOptions``
- **Explicit Completeness**: Results report ``complete``, ``partial``,
  ``cancelled``, or ``failed`` status with a termination reason
- **Deterministic Results**: Stable procedure, node, and fact IDs plus ordered
  graph traversal make serialized findings reproducible
- **Diagnostics**: Coded preparation diagnostics distinguish recoverable gaps
  from strict failures
- **Explanations**: ``trace_mode`` can retain finding paths or all predecessor
  paths for demand-driven explanations

Package Layout
--------------

The implementation is grouped by responsibility:

- ``core`` — IFDS/IDE problems, forward and backward solvers, supergraphs,
  and reusable transfer helpers
- ``frontend`` — CFG adaptation, annotation synthesis, and preparation
- ``analyses`` — Taint, nullness, typestate, and flow-path analyses
- ``modeling`` — Call models, library presets, typestate protocols, and model
  registries
- Package-root modules — Public API orchestration, diagnostics, queries,
  reporting, and shadow scanning

Built-in Analyses
-----------------

The IFDS engine ships with several ready-to-use analyses:

- **Taint Analysis** (``analyses/taint.py``): Interprocedural taint tracking
  from sources to sinks via flow functions
- **Nullness Analysis** (``analyses/nullness.py``): Null pointer and
  ``None``-related bug detection
- **Typestate Analysis** (``analyses/typestate.py``,
  ``modeling/typestate.py``): Resource lifecycle protocol verification
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

   # Nullness analysis
   pyflow security input.py --engine ifds --function main --analysis nullness

   # With specific typestate protocols
   pyflow security input.py --engine ifds --function main --analysis typestate \
       --typestate-protocol file --typestate-protocol socket

   # CI-friendly bounded analysis with SARIF output
   pyflow security input.py --engine ifds --function main \
       --sources input --sinks eval --ifds-mode strict \
       --ifds-max-seconds 60 --ifds-max-memory-bytes 1073741824 \
       --format sarif --output pyflow.sarif

Production Execution Contract
-----------------------------

``SolverOptions`` is shared by forward IFDS, backward IFDS, and IDE solvers.
When a configured budget is reached, the default options used by the CLI stop
the analysis and return a partial result rather than silently presenting it as
complete.  Library callers may select ``limit_behavior="raise"`` when an
exception is preferable.  ``CancellationToken`` supports cooperative
cancellation; ``trace_mode`` accepts ``none``, ``findings``, or ``all``.

The CLI uses distinct process exit codes:

- ``0``: complete with no findings
- ``1``: complete with findings
- ``2``: invalid invocation or configuration
- ``3``: partial or cancelled analysis
- ``4``: analysis failure

``--ifds-mode strict`` fails when preparation cannot construct required
analysis state.  ``best-effort`` records coded diagnostics and marks the result
partial when recovery can affect completeness.

Findings and SARIF
------------------

Taint, nullness, and typestate analyses expose normalized findings with stable
fingerprints, source spans, severity, confidence, and optional code flows.
Python-source spans include start and end positions.  SARIF output includes
rules, physical locations, thread flows, partial fingerprints, and the overall
analysis-completeness status.

Language Semantics
------------------

The CFG adapter preserves first-match typed exception handlers, exceptional
call paths, and ``finally`` execution for normal, exceptional, ``return``,
``break``, and ``continue`` control flow.  It also exposes async/generator
procedure metadata, suspension effects, and semantic roles for synchronous and
asynchronous context-manager and iteration calls.  These are conservative
building blocks; individual analyses decide which effects alter their facts.

Rule-Pack Quality and Performance
---------------------------------

Registry JSON files are versioned and validated against the shipped schema.
Run these checks before publishing model changes:

.. code-block:: bash

   make ifds-validate-rules
   make ifds-benchmark

The benchmark emits one JSON object containing the requested graph size,
elapsed time, completion status, termination reason, and solver statistics.
The IFDS test suite also includes a small concrete reference solver and
randomized differential tests for regression detection.

Annotation Synthesis
--------------------

The IFDS frontend includes an annotation synthesis engine
(``frontend/annotations.py``) that generates syntactic annotations to prepare
code for IFDS analysis. A fallback mechanism
(``frontend/annotation_fallback.py``) handles cases where synthesis cannot be
applied.

See Also
--------

- :doc:`dataflowIR` — Data flow IR that IFDS operates on
- :doc:`cfg` — CFG construction (supergraph foundation)
- :doc:`alias/flow_sensitive` — Flow-sensitive alias analysis consumed by taint analyses
