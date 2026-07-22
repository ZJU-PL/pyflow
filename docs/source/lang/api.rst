Language API
============

The language module's programmatic API provides the building blocks that
higher-level analysis and optimization passes build on.

For the public-facing query and entrypoint API, see :doc:`/api`.

Core Language Modules
---------------------

AST Construction
~~~~~~~~~~~~~~~~

The ``pyflow.language.python.ast`` module defines all IR node types used
throughout the analysis pipeline.  See :doc:`ast` for the complete node
reference.

.. code-block:: python

   from pyflow.language.python import ast
   from pyflow.language.python.program import Object

   const = ast.Existing(Object(42))
   local = ast.Local("x")
   assign = ast.Assign(const, [local])

Program Model
~~~~~~~~~~~~~

The ``pyflow.language.python.program`` module provides the object and type
model:

.. code-block:: python

   from pyflow.language.python.program import (
       Object,
       ImaginaryObject,
       TypeInfo,
       ProgramDescription,
   )

AST Transformations
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from pyflow.language.python.collapser import Collapser
   from pyflow.language.python.fold import apply as fold_apply
   from pyflow.language.python.defuse import DefUseVisitor

See Also
--------

- :doc:`ast` — PyFlow AST node reference
- :doc:`frontend` — Source-to-IR conversion
- :doc:`asttools` — AST utility tools (complexity, decorators, visitors)
- :doc:`/api` — Public query and entrypoint API
