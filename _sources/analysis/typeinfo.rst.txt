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

Builtin ``tuple`` references, including ``isinstance(value, tuple)``, use
``TupleType`` rather than nominal ``Instance``. Function-local classes are
registered before resolving declarations, and lambdas discovered while
analyzing function bodies participate in the next fixed-point iteration.

Bindings in ``with ... as value`` use the return type of ``__enter__``;
``async with`` uses the awaited ``__aenter__`` result. Local and inherited
methods are supported. An unresolved entry protocol leaves the binding
unknown and marks the result ``partial``. Exit-method effects and exception
suppression are not fully modeled.

Sphinx and Epydoc parameter/return type hints are connected to both the engine
and ``TypeInfoService``. Numpydoc hints use the optional ``numpydoc`` package;
without it, those sections provide no hints. Python annotations take priority,
and observed calls/body results take priority over documentation fallbacks.
Unresolved documented alternatives are not reduced to a definite partial union.

``TypeInfoService`` isolates source and stub collection failures, preserves
facts already collected, and exposes errors through ``diagnostics()`` and
``inference_result(module).status``. A failed imported symbol without usable
facts falls back to ``Any`` and marks dependent analysis partial. Unavailable
expression facts remain unknown. This service boundary catches ordinary
exceptions, including internal assertions; cancellation and process-exit
exceptions still propagate. Direct standalone engine callers retain their
exception behavior.

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
