Graph Intermediate Representation (GIR)
=======================================

The ``pyflow.ir.gir`` package provides Lian-compatible Graph Intermediate Representation (GIR) support.
GIR is emitted directly from PyFlow's Python AST and mirrors the representation produced by Lian's Python frontend.

Overview
--------

The full lowering pipeline for a ``pyflow.language.python.ast.Code`` object consists of:

1. **Emission**: ``GirEmitter().emit_unit(code)`` constructs the initial hierarchical GIR tree.
2. **Post-processing**:
   - ``unify_python_self``: Unifies Python method receiver symbols.
   - ``adjust_variable_decls``: Adjusts and hoists variable declarations.
3. **Flattening**: ``GirFlattener`` flattens the nested tree into sequential rows with deterministic node IDs.
4. **Finalization**:
   - ``add_main_func``: Injects synthetic entry point wrappers when required.
   - ``add_unit_gir``: Associates rows with owning compilation unit and module IDs.

Command-Line Usage
------------------

Dump GIR for a specific function using ``pyflow ir``:

.. code-block:: bash

   pyflow ir input.py --dump-gir main --dump-format text
   pyflow ir input.py --dump-gir main --dump-format json --dump-output ./out

Python API
----------

Use ``build_gir`` or ``build_function_gir`` to generate GIR rows programmatically:

.. code-block:: python

   from pyflow.ir.gir import build_function_gir, build_gir
   from pyflow.ir.gir.dump import dump_gir_content

   # Generate GIR for a specific function
   rows = build_function_gir(code_object, module_id="main")

   # Format GIR as text representation
   text_output = dump_gir_content(rows, format="text")
