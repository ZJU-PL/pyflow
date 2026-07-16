Type Information System
========================

The typeinfo module provides lightweight type-information collection for
analysis clients.  It combines PyFlow's native type-info collector with
migrated type-system facilities from Pynguin.

Key Features
------------

- **Type Evidence Collection**: Gathers type annotations, assignments, and
  usage patterns from Python source code
- **Type Inference**: Infers types from usage context when explicit
  annotations are unavailable
- **String Subtype Analysis**: Specialized inference for string subtypes
  (e.g., URLs, file paths, SQL queries)
- **Type Tracing**: Tracks how types flow through expressions and function
  boundaries
- **Configurable**: Type collection can be tuned via configuration for
  different analysis precision trade-offs

Core Components
---------------

- ``TypeEvidence`` / ``TypeInfo`` — Data classes for representing collected
  type information
- ``collect_pyflow_type_info()`` / ``collect_python_type_info()`` — Main
  entry points for gathering type facts
- ``type_inference.py`` — Type inference engine
- ``typesystem.py`` — Type system abstractions (from Pynguin)
- ``string_subtype_inference.py`` — String subtype specialization

Usage
-----

.. code-block:: python

   from pyflow.analysis.typeinfo import collect_pyflow_type_info

   type_info = collect_pyflow_type_info(program, compiler)
   for var, evidence in type_info.items():
       print(f"{var}: {evidence}")

See Also
--------

- :doc:`ipa` — Inter-procedural analysis that consumes type info
- :doc:`cpa` — Constraint-based analysis that can leverage type information
