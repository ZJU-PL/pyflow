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

Vendored typeshed
~~~~~~~~~~~~~~~~

PyFlow ships a snapshot of mypy's typeshed under
``pyflow/stubs/typeshed`` and uses it by default:

- stdlib modules and bundled third-party stubs resolve through
  ``TypeInfoService`` without passing ``typeshed_roots``;
- ``StaticTypeInferenceEngine`` installs a shared typeshed-backed external
  symbol resolver when no explicit resolver is supplied;
- ``ProjectTypeInferenceEngine`` consults project results first, then typeshed.

The stub parser understands version-gated declarations
(``if sys.version_info``), ``@overload``, ``TypeVar``/``ParamSpec``,
``TypeAlias``, module-level value aliases (``random = _inst.random``),
``__all__``, and ``Self`` substitution.  ``StubResolver`` defaults
``python_version`` to the running interpreter; pass ``python_version=(3, 12)``
to ``TypeInfoService`` to analyse another version.

Generic calls bind constrained type variables and type variables that appear
under structural protocols (for example
``_typeshed.SupportsLenAndGetItem``), so ``random.choice([1, 2])`` is ``int``
rather than an unbound ``_T``.  TypedDict subscript/constructor operations and
NamedTuple, dataclass, attrs, pydantic-style, and msgspec ``Struct``
constructors are validated; match statements subtract earlier alternatives for
negative narrowing; literal equality guards narrow to concrete values; and
printf-style format strings report type/arity mismatches.

Parsed stubs can be persisted through a SQLite cache keyed by path,
modification time, size, target Python version, and parser format.  The cache
lives under ``PYFLOW_CACHE_DIR`` (default ``~/.cache/pyflow``) and can be
disabled with ``StubResolver(..., enable_cache=False)``.

Typeshed is the declaration source for the whole stdlib surface.  A small
receiver-aware call/member layer still overrides it where declarations cannot
express the result (for example ``collections.Counter.copy()``,
``asyncio.TaskGroup.create_task()``, ``queue.Queue[int].get()``,
``pathlib.Path.open()``, and the ``os.environ`` mapping shape).  Callers can
replace the vendored snapshot with ``typeshed_roots=[...]``.

Command-line Queries
~~~~~~~~~~~~~~~~~~~~

``pyflow typeinfo`` is the direct CLI for this subsystem; it does not require
the LSP or MCP server.  For a single file the module name is inferred, while a
project directory accepts ``--module`` for focused queries:

.. code-block:: shell

   pyflow typeinfo app.py
   pyflow typeinfo app.py --symbol Client.fetch --json --pretty
   pyflow typeinfo app.py --line 42 --column 8 --json
   pyflow typeinfo app.py --diagnostics --json
   pyflow typeinfo src/ --module package.module --diagnostics --max-modules 20

``--line`` is 1-based and ``--column`` is a 0-based character offset, matching
LSP positions.  ``--mode signatures`` (default) lists function and method
signatures; ``--mode types`` lists all queryable symbols; ``--mode summary``
prints symbol/function/expression and diagnostic counts; and
``--mode diagnostics`` prints structured diagnostics.  Human output limits each
module to 20 type facts by default to avoid flooding a terminal
(``--max-types 0`` disables the limit); JSON output is complete.  Every result
reports ``complete``/``partial`` status where applicable; unknown expression
facts are returned as JSON ``null`` plus ``complete``/``unknown`` flags rather
than being presented as a definite type.

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

Source inference models parameterized generic constructors, receiver-bound
``typing.Self``, ``typing.cast``, and ``NewType`` identity constructors. ``NewType``
values currently project to their underlying type rather than a distinct nominal
type. On Python 3.12 and later, the host parser also supports PEP 695 type aliases
and function/class type parameters. ParamSpec, variadic type parameters, and
recursive alias expansion are not fully modeled. Module-level PEP 484 and 613
aliases, including ``Name: TypeAlias = ...``, are also resolved.

Class constants and enum members are recorded. Class-style ``TypedDict``
declarations support key validation (including required and optional keys) and
key-specific indexing. Dictionary key layouts are propagated through variables,
returns, and calls so helper-returned mappings can be checked structurally.
Class-style ``NamedTuple`` declarations support field access, indexing, and
unpacking. Protocol compatibility checks declared
attributes and method signatures structurally; dynamic attributes and the full
typing specification are outside this model.

Calls validate supplied arguments against parameter annotations, including
variadic arguments. Static methods are called without an injected receiver;
class methods receive the class, and instance methods receive the instance.
Fresh list, set, and dictionary literals permit their element types to widen to
an annotated container type. Existing mutable containers retain invariant
generic checking. Explicit return annotations take precedence over identity
return specialization, and recursive return structures are widened at the
configured type-depth limit so recursive summaries can converge.
Incompatibilities produce ``annotation-mismatch`` warnings, or errors with
``InferenceOptions(strict_annotations=True)``. Inferred numeric
unions preserve runtime alternatives such as ``int | float`` even though numeric
assignment compatibility admits ``int`` where ``float`` is expected.

``contextlib.contextmanager`` and ``asynccontextmanager`` wrappers bind the yielded
type in ``with`` and ``async with``. Asynchronous iteration extracts element types
from async iterable, iterator, and generator annotations. Built-in annotation
lookup resolves common types from ``itertools``, ``pathlib``, ``datetime``,
``re``, ``uuid``, ``types``, and ``contextvars`` without importing analysed code.

Module imports bind module objects rather than same-named classes: ``import
time`` refers to the ``time`` module even though a bare ``time`` annotation
resolves to ``datetime.time``. Common stdlib members (``sys.argv``,
``os.environ``, ``math`` constants, ``time`` clocks) are modelled without
importing analysed code. Class objects obtained from stdlib modules
(``datetime.date``, ``uuid.UUID``) retain their ``type[...]`` projection inside
list, tuple, set, and dictionary literals. Source classes inherit builtin
ancestry (``ValueError`` is an ``Exception``; ``dict`` subclasses satisfy
``Mapping``) for subtype and protocol checks, and members inherited from
builtin or stdlib bases are resolved through the real MRO. When a class derives
from an unmodelled third-party base, structural and subtype checks stay
conservative instead of reporting incompatibilities that cannot be proven.
Nested collection literals are widened recursively against an annotated
container type. Plain rebindings of a name previously declared with ``name: T``
are checked against ``T`` when the new value is a literal or another name.

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

For multi-module projects, ``ProjectTypeInferenceEngine`` resolves import closures
and handles cyclic dependencies. Automatic discovery follows source paths within
the configured project directory and workspace roots, resolving symlinks before
checking containment. Imports from the standard library and external dependencies
are left to external type facts and call models. External modules may still be
listed explicitly as entry modules. For a ``src`` layout, include that directory
in ``ProjectContext(..., added_sys_path=[...])``.

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
