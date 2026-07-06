Package Map
===========

This page is a contributor-oriented map of the ``a3_python`` source
tree.

Top-level modules
-----------------

* ``analyzer.py``: high-level orchestration, analysis entry points, and
  user-facing result assembly
* ``cli.py``: command-line interface
* ``confidence_scoring.py`` and ``confidence_interval.py``: ranking and
  confidence support
* ``stochastic_risk.py``: probabilistic or risk-oriented helpers used by
  advanced reasoning paths
* ``fp_context.py``: false-positive context modeling

Core packages
-------------

``frontend``
   File loading, string/file-based program ingestion, and entry-point
   discovery.

``cfg``
   CFG construction, loop analysis, dataflow support, and call-graph
   construction.

``semantics``
   The largest package in the subsystem. It includes symbolic execution,
   interprocedural bug tracking, taint propagation, summaries, crash summaries,
   intraprocedural and interprocedural detectors, and specialized analyses for
   many bug patterns.

``unsafe``
   Bug classification and unsafe-state predicates. The ``unsafe/security``
   subtree contains web, injection, XML, filesystem, crypto, and related
   security detectors.

``dse``
   Dynamic symbolic execution, concrete replay, path-condition handling, and
   selective concolic exploration.

``contracts``
   Contract schema, built-in and stdlib contracts, security contracts,
   relational contracts, and framework-specific contract catalogs.

``barriers``
   Verification-oriented reasoning: invariant synthesis, ranking functions,
   CEGIS, SOS-style methods, PDR/SPACER, abstraction/refinement, and assorted
   orchestration layers.

``z3model``
   Solver-facing abstractions for symbolic values, heaps, taint, and type
   tracking.

``ci``
   CI bootstrap, config loading, SARIF output, baseline workflows, and triage
   support.

``evaluation``
   Dataset- and experiment-oriented support, including deduplication and
   scanner helpers.

How to navigate it
------------------

If you are trying to understand the package efficiently, start here:

1. ``analyzer.py`` for the top-level execution path
2. ``semantics/symbolic_vm.py`` for the execution model
3. ``semantics/crash_summaries.py`` and ``semantics/interprocedural_bugs.py``
   for cross-function bug reasoning
4. ``unsafe/registry.py`` for the currently wired bug classes
5. ``contracts/`` and ``barriers/`` for the semantic-knowledge and proof side

If you are working on specific features, this narrower map usually helps:

* taint and security: ``contracts/security*.py``, ``semantics/*taint*.py``,
  ``unsafe/security/``
* crash and unsafe-state tracking: ``unsafe/``, ``semantics/crash_summaries.py``
* proof and verification features: ``barriers/``
* DSE and concrete replay: ``dse/``
* CI/SARIF workflows: ``ci/``
