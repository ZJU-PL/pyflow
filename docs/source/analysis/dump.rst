Analysis Result Dumping
=========================

The dump module provides utilities for serializing and visualizing analysis
results.  It supports multiple output formats and is used by the CLI's
``pyflow ir`` subcommand as well as programmatic debugging workflows.

Key Features
------------

- **Multi-Format Output**: Supports text, DOT (Graphviz), and JSON for
  different visualization and consumption needs
- **Graph Rendering**: Generates visual representations of CFGs, CDGs, DDGs,
  PDGs, and call graphs
- **IR Inspection**: Dumps AST, SSA, and data flow IR for inspection and
  debugging

Usage
-----

.. code-block:: bash

   # Dump CFG in DOT format
   pyflow ir input.py --dump-cfg main --dump-format dot

   # Dump SSA form
   pyflow ir input.py --dump-ssa main

   # Output to a directory
   pyflow ir input.py --dump-cfg main --dump-output ./out

See Also
--------

- :doc:`cli` — CLI reference for ``pyflow ir`` options
- :doc:`cfg` — Control Flow Graph (dump target)
- :doc:`ddg` — Data Dependence Graph (dump target)
