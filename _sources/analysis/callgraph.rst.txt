Call Graph Analysis
===================

PyFlow provides multiple algorithms for call graph construction.

Call graphs can be built from a single Python file or an entire project
directory.  When given a directory, PyFlow auto-detects the entry point by
checking (in order):

1. ``pyproject.toml`` (``[project.scripts]`` or ``[tool.poetry.scripts]``)
2. ``setup.py`` (``console_scripts`` entry points)
3. ``__main__.py`` inside the first non-hidden, non-test subdirectory
4. Well-known filenames: ``main.py``, ``app.py``, ``cli.py``, ``run.py``, ``launch.py``

A manual entry point can be specified with ``--entry``.

CLI Usage
---------

::

    # Single file
    pyflow callgraph input.py

    # Project directory (auto-detected entry)
    pyflow callgraph /path/to/project/

    # Project directory with explicit entry
    pyflow callgraph /path/to/project/ --entry src/main.py

    # Dry-run: print the entry point that would be used
    pyflow callgraph /path/to/project/ --dry-run

    # Constraint-based algorithm with stdlib excluded (default)
    pyflow callgraph input.py --algorithm constraint --skip-stdlib

    # Include standard library modules
    pyflow callgraph input.py --algorithm constraint --no-skip-stdlib

    # Native PyCG-style assignment analysis over MIR (no pycg extra required)
    pyflow callgraph input.py --algorithm pycg-mir

Options:

- ``--entry``: Entry point file relative to project root (directory input only; auto-detected when omitted)
- ``--dry-run``: Print detected entry point without running analysis
- ``--algorithm, -a``: Algorithm (``simple``, ``constraint``, ``pycg``, or ``pycg-mir``; default: ``simple``)
- ``--output, -o``: Output file path
- ``--verbose, -v``: Enable verbose output
- ``--skip-stdlib``: Skip standard library modules in constraint analysis (default: on)
- ``--no-skip-stdlib``: Include standard library modules in constraint analysis
- ``--context-sensitive``: Enable call-site context sensitivity (constraint algorithm only)
- ``--context-depth``: Call-string depth when ``--context-sensitive`` is enabled (default: 1)
- ``--fixpoint-max-iterations``: Cap fixpoint iterations (constraint algorithm only)
- ``--no-fixpoint-warning``: Disable warning when fixpoint cap is hit (constraint algorithm only)
- ``--allocation-site-sensitive-instances``: Track per-allocation instance identities (constraint algorithm only)
- ``--as-graph-output``: Write constraint value-flow assignment graph JSON (constraint algorithm only)

Analysis Approaches
-------------------

Constraint-Based Analysis (Public API Default)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Abstract Value Propagation**: Propagates abstract values (functions, classes, instances, bound methods, modules) through assignments, calls, and returns
- **Context Sensitivity**: Optional call-site context sensitivity with configurable depth for improved precision
- **Full MRO Support**: Complete C3 MRO linearization for class method lookup
- **Rich Semantics**: Handles descriptors, closures, comprehensions, and container tracking
- **Dynamic Summaries**: Generates explicit summary nodes for unresolved call targets
- **Stdlib Filtering**: Standard library modules can be skipped to reduce noise (``--skip-stdlib``)

.. code-block:: python

   from pyflow.analysis.callgraph import extract_call_graph_constraint

   # Context-insensitive (default)
   cg = extract_call_graph_constraint(source_code)

   # Context-sensitive with call-string depth of 2
   cg = extract_call_graph_constraint(
       source_code,
       context_sensitive=True,
       context_depth=2,
   )

AST-Based Analysis
~~~~~~~~~~~~~~~~~~

- **Static Analysis**: Analyzes source code AST to identify function calls
- **Precise Resolution**: Handles direct function calls and simple indirection
- **Fast Construction**: Quick analysis suitable for large codebases
- **Conservative**: May include spurious edges

Native MIR-Based PyCG Analysis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``pycg-mir`` lowers Python source into the seven-instruction MIR and performs
flow-, path-, and context-insensitive assignment-graph propagation to a fixed
point. The analysis consumes MIR directly, including explicit closure,
environment, field, container, and call operations. It does not require the
optional upstream PyCG package.

.. code-block:: python

   from pyflow.analysis.callgraph import extract_call_graph_pycg_mir
   from pyflow.ir.mir import lower_source
   from pyflow.analysis.callgraph.pycg_mir import analyze_program

   graph = extract_call_graph_pycg_mir(source_code)
   result = analyze_program(lower_source(source_code))
   print(result.converged, result.iterations)
   print(result.call_graph.get())

The direct API exposes an assignment graph, call sites, diagnostics, and
convergence information. The native graph preserves recursive self-edges.
Compiler-generated protocol helpers can be retained with
``include_synthetic=True``. See :doc:`/ir/mir` for the representation, complete
examples, and implementation limitations.

The CLI rejects constraint context-sensitivity, fixed-point control,
allocation-sensitivity, scope-selection, and assignment-graph options for this
backend. The stdlib flags affect only constraint analysis and do not extend
MIR's supported import graph. The native backend does not change the existing
public API default or the ``simple`` CLI default.

Upstream PyCG Adapter
~~~~~~~~~~~~~~~~~~~~

- **Framework Support**: Better handling of popular Python frameworks
- **Comprehensive**: Captures more call relationships than pure AST analysis

The existing ``pycg`` option uses the separately installed upstream package
(``pip install -e '.[callgraph]'``). It remains available independently from
the native ``pycg-mir`` implementation.



Applications
------------

- **Dependency Analysis**: Understand module and function dependencies
- **Optimization**: Identify inlining and specialization opportunities
- **Security Analysis**: Detect potentially dangerous call patterns
- **Code Understanding**: Visualize complex codebases
