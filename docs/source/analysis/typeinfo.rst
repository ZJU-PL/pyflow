Type Information System
========================

The ``typeinfo`` package provides type-information collection and queries for
analysis clients.  Its implementation is grouped by responsibility instead of
exposing a flat collection of unrelated modules.

Key Features
------------

- **Type Evidence Collection**: Gathers type annotations, assignments, and
  usage patterns from Python source code
- **Standalone Static Type Inference**: Deterministic abstract interpreter for
  Python source that infers types across functions and projects with argument-sensitive
  call summaries, independently of CPA/IPA
- **String Subtype Analysis**: Specialized inference for string subtypes
  (e.g., URLs, file paths, SQL queries)
- **Usage Tracing**: Records operations performed on proxied values for
  usage-based signature inference
- **Configurable**: Type collection can be tuned via configuration for
  different analysis precision trade-offs

Package Layout
--------------

- ``query`` — Evidence collection, public query models, and
  ``TypeInfoService``
- ``core`` — Proper-type representations, subtype relations, signatures, and
  the class hierarchy
- ``resolution`` — Annotation, generic, docstring, and ``.pyi`` resolution
- ``inference`` — Standalone static type inference engine, core providers,
  optional external providers, usage tracing, and string specialization
- ``generation`` — Type-guided constant and value generation helpers

``TypeEvidenceIndex`` stores source-level evidence.  ``ClassDescriptor`` is the
separate core representation of a runtime Python class.

Usage
-----

Evidence Collection
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from pyflow.analysis.typeinfo import collect_pyflow_type_info

   type_info = collect_pyflow_type_info(program_codes)
   for var, evidence in type_info.items():
       print(f"{var}: {evidence}")

Static Type Inference Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PyFlow includes a standalone static type inference engine (``StaticTypeInferenceEngine``)
and project-level orchestrator (``ProjectTypeInferenceEngine``):

.. code-block:: python

   from pyflow.analysis.typeinfo import StaticTypeInferenceEngine

   engine = StaticTypeInferenceEngine()
   result = engine.infer_source(
       "example.module",
       """
   def compute(x):
       return x * 2

   res = compute(21)
   """,
   )

   print(result.type_of("res"))  # Inferred as int
   assert result.converged

For multi-module projects, ``ProjectTypeInferenceEngine`` resolves import closures and handles cyclic dependencies:

.. code-block:: python

   from pyflow.analysis.typeinfo import ProjectTypeInferenceEngine
   from pyflow.language.modules.project_resolution import ProjectContext

   project_engine = ProjectTypeInferenceEngine(ProjectContext("/path/to/project"))
   project_result = project_engine.infer_project(["package.entrypoint"])
   assert project_result.converged

See Also
--------

- :doc:`ipa` — Inter-procedural analysis that consumes type info
- :doc:`cpa` — Constraint-based analysis that can leverage type information
