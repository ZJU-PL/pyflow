k-CFA Alias Analysis
====================

The ``pyflow.analysis.alias.kcfa`` package provides k-CFA
(k-Context-Free Analysis) alias analysis for Python programs. It tracks how
object references flow through
a program, answering questions like "what objects can this variable point to?"

The implementation is migrated from PythonStAn as a self-contained module
under ``_pythonstan`` to avoid interference with other pyflow subsystems.

Key Features
------------

- **k-CFA Algorithm**: Configurable context sensitivity via the *k* parameter
- **Constraint-Based**: Uses set constraints to model pointer relationships
- **Monotone Semantics**: Static constraints, semantic dependencies, and
  pointer-flow deltas converge to a schedule-independent may-analysis result
- **Unified Type Model**: ``TypeUniverse`` applies MRO, metaclass, subtype,
  and raw-member operations uniformly to user and builtin type references
- **Explicit Class State**: Class construction exposes one of ``Pending``,
  ``Feasible``, ``Invalid``, or ``Unknown`` to call resolution
- **Points-To Queries**: Answer what objects a variable or expression may
  reference
- **Read-Only Result Facade**: Fixed-point field queries never allocate heap
  cells or otherwise mutate analysis state
- **Self-Contained**: Operates independently of other pyflow analysis modules

Quick Start
-----------

.. code-block:: python

   from pyflow.analysis.alias.kcfa import PointerAnalysis

   analysis = PointerAnalysis('''
   x = [1, 2, 3]
   y = x
   z = y[0]
   ''')
   results = analysis.run()
   print(results.points_to("z"))

For project analysis, solver and import-graph budgets are configurable and
completion is explicit on the returned result:

.. code-block:: python

   analysis = PointerAnalysis.from_project(
       "package/__main__.py",
       k=1,
       max_iterations=100_000,
       max_import_depth=3,
   )
   results = analysis.run()
   if not results.complete:
       print(results.stop_reason, results.statistics())

See Also
--------

- :doc:`flow_sensitive` - Flow-sensitive alias and escape analysis
- :doc:`../ipa` - Inter-procedural analysis for cross-function tracking
