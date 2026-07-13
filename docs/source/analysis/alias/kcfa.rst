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
- **Points-To Queries**: Answer what objects a variable or expression may
  reference
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

See Also
--------

- :doc:`flow_sensitive` - Flow-sensitive alias and escape analysis
- :doc:`../ipa` - Inter-procedural analysis for cross-function tracking
