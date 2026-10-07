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
- ``analyses`` — Nullness, typestate, flow-path analyses, and reusable problem
  infrastructure
- ``modeling`` — Call models, library presets, typestate protocols, and model
  registries
- Package-root modules — Session loading, non-security analysis orchestration,
  diagnostics, queries, and common finding/trace representation

Complete security checks live in ``pyflow.checker.ifds``. They use this
framework directly; the checker package does not wrap or duplicate the solver.

Built-in Analyses
-----------------

The IFDS engine ships with several ready-to-use analyses:

- **Taint Analysis** (``pyflow.checker.ifds.taint``): Interprocedural taint
  tracking from sources to sinks via flow functions. File analysis starts at
  ``pyflow.checker.ifds.api.run_taint_analysis``.
- **Nullness Analysis** (``analyses/nullness.py``): Null pointer and
  ``None``-related bug detection
- **Typestate Analysis** (``analyses/typestate.py``,
  ``modeling/typestate.py``): Resource lifecycle protocol verification
  (file descriptors, locks, sockets, transactions)
- **Class Pollution** (``pyflow.checker.ifds.class_pollution``): Reflective
  object traversal and writes into class or namespace state
- **Shadow Scan** (``pyflow.checker.ifds.shadow_scan``): Independent regex
  scanning and comparison with IFDS findings

The former taint and shadow-scan exports from ``pyflow.analysis.ifds`` have
been removed. Build taint configurations with
``pyflow.checker.ifds.TaintConfiguration.from_registry(registry)`` rather than
the former registry ``as_config()`` method; registry loading and its
engine-neutral policy projection remain in the framework.

CLI Usage
---------

IFDS analyses are accessible through ``pyflow security``:

The IFDS frontend builds CFGs directly and publishes constraint-callgraph
targets. It does not run the IPA or CPA pipelines as a preparation step.

.. code-block:: bash

   # Taint analysis
   pyflow security input.py --engine ifds --sources input --sinks eval

   # Typestate analysis
   pyflow security input.py --engine ifds --analysis typestate

   # Nullness analysis
   pyflow security input.py --engine ifds --analysis nullness

   # With specific typestate protocols
   pyflow security input.py --engine ifds --analysis typestate \
       --typestate-protocol file --typestate-protocol socket

   # CI-friendly bounded analysis with SARIF output
   pyflow security input.py --engine ifds \
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

IR semantics and facts
----------------------

The IFDS frontend consumes context-independent operation semantics and
revisioned analysis facts from the program IR catalog.  Calls, storage effects,
and source identities are therefore shared with CFG, DDG, IPA, and CPA rather
than reconstructed from AST annotations.  Missing required facts remain
explicitly unavailable; IFDS does not synthesize a private fallback view.

See Also
--------

- :doc:`/ir/dataflow` — Data flow IR that IFDS operates on
- :doc:`/ir/cfg` — CFG construction (supergraph foundation)
- :doc:`alias/flow_sensitive` — Flow-sensitive alias analysis consumed by taint analyses
