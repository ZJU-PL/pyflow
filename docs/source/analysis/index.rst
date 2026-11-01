Analysis Modules
================

PyFlow provides a comprehensive suite of static analysis engines for
understanding Python programs. These engines consume the shared representations
documented in :doc:`/ir/index`.

For an introduction to analysis concepts, see:

* :ref:`tutorial-analyzing-python-code` - Tutorial on running analyses
* :ref:`explanation-architecture` - Architecture overview
* :ref:`explanation-algorithms` - Algorithm details

Overview
========

PyFlow's analysis modules are organized into several categories:

Graph Analysis
--------------

* :doc:`callgraph` - Call Graph construction and analysis
* :doc:`/ir/index` - CFG, CDG, DDG, PDG, CPG, data flow IR, and store graph

Data Flow Analysis
------------------

* :doc:`fsdf` - Flow-Sensitive Data Flow analysis
* :doc:`ifds` - IFDS/IDE interprocedural data flow engine (taint, nullness, typestate)
* :doc:`ipa` - Inter-procedural Analysis
* :doc:`cpa` - Constraint-based Analysis

Alias and Type Analysis
-----------------------

* :doc:`alias/index` - Flow-sensitive and k-CFA alias analyses
* :doc:`typeinfo` - Type-information collection and inference

Shape and Object Analysis
-------------------------

* :doc:`shape` - Region-based shape analysis for data structures (reference counts, path info)
* :doc:`lifetimeanalysis` - Variable lifetime analysis (read/modify tracking, post-shape pipeline)

.. seealso::

   :doc:`/explanation/memory-reasoning` — Comprehensive comparison of all six
   memory/heap reasoning systems in PyFlow, including when to use each one.

Specialized Analysis
--------------------

* :doc:`numbering` - Program point numbering
* :doc:`dump` - Analysis result dumping and visualization
* :doc:`stats` - Statistics collection and LaTeX report generation
* :doc:`incremental` - Incremental analysis caching with BLAKE2b + SQLite

Analysis Configuration
======================

PyFlow supports configurable analysis with different precision/performance trade-offs.
Analysis parameters are configured via ``AnalysisOptions`` on the program session:

.. code-block:: python

   from pyflow.application.session import AnalysisOptions

   # Configure analysis options on the program session
   program.session.configure(AnalysisOptions(cpa_path_length=3))

CLI flags can also select specific analyses:

.. code-block:: bash

   pyflow optimize input.py --analysis cpa

Running Analyses
================

Command Line
------------

PyFlow provides several CLI commands for running analyses:

* ``pyflow optimize`` - Run analysis and optimization pipeline
* ``pyflow callgraph`` - Build and analyze call graphs
* ``pyflow ir`` - Dump intermediate representations (AST, CFG, SSA, CDG, DDG)
* ``pyflow alias`` - Run alias analysis (flow-sensitive heap or k-CFA pointer)
* ``pyflow security`` - Unified security analysis dispatching to
  ast-scanner, ast-dataflow, ifds, or cpg engines
* ``pyflow supply-chain`` - Generate CycloneDX SBOMs and audit distribution metadata

Programmatic Usage
------------------

Use the Python API for programmatic analysis:

.. code-block:: python

   from pyflow.application.context import CompilerContext
   from pyflow.application.pipeline import Pipeline
   from pyflow.analysis.callgraph.constraint_based.api import extract_call_graph_constraint

   # Run analysis pipeline
   compiler = CompilerContext()
   results = Pipeline().run(program, compiler=compiler)

   # Build call graph
   graph = extract_call_graph_constraint(source_code)

Analysis Results
================

PyFlow produces detailed analysis results:

Text Output
-----------

Human-readable text output for terminal:

.. code-block:: bash

   pyflow ir input.py --dump-cfg main --dump-format text

JSON Output
-----------

Machine-readable JSON for programmatic processing:

.. code-block:: bash

   pyflow ir input.py --dump-cfg main --dump-format json --dump-output ./out

SARIF Output
------------

Standard SARIF format for CI/CD integration:

.. code-block:: bash

   pyflow security input.py --format sarif --output results.sarif

.. toctree::
    :maxdepth: 2
    :caption: Analysis Modules

    callgraph
    cfl
    fsdf
    ipa
    cpa
    alias/index
    shape
    lifetimeanalysis
    ifds
    typeinfo
    numbering
    dump
    stats
    incremental
