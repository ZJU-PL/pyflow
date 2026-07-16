Analysis Modules
================

PyFlow provides a comprehensive suite of static analysis modules for understanding
and analyzing Python programs. This section documents each analysis module and
its capabilities.

For an introduction to analysis concepts, see:

* :ref:`tutorial-analyzing-python-code` - Tutorial on running analyses
* :ref:`explanation-architecture` - Architecture overview
* :ref:`explanation-algorithms` - Algorithm details

Overview
========

PyFlow's analysis modules are organized into several categories:

IR Construction
---------------

* :doc:`cfg` - Control Flow Graph construction and analysis
* :doc:`cdg` - Control Dependence Graph analysis
* :doc:`pdg` - Program Dependence Graph construction and queries
* :doc:`ddg` - Data Dependence Graph construction and analysis
* :doc:`cpg` - Code Property Graph (unified CFG + PDG + call graph)
* :doc:`callgraph` - Call Graph construction and analysis

Data Flow Analysis
------------------

* :doc:`dataflowIR` - Data Flow Intermediate Representation
* :doc:`fsdf` - Flow-Sensitive Data Flow analysis
* :doc:`ifds` - IFDS/IDE interprocedural data flow engine (taint, nullness, typestate)
* :doc:`ipa` - Inter-procedural Analysis
* :doc:`cpa` - Constraint-based Analysis

Alias and Type Analysis
-----------------------

* :doc:`alias/index` - Flow-sensitive and k-CFA alias analyses
* :doc:`typeinfo` - Type-information collection and inference

Shape and Object Analysis
------------------------

* :doc:`storegraph` - Store graph analysis for object relationships (foundational data model for CPA/shape)
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

Context-Sensitive Analysis
--------------------------

By default, PyFlow performs context-insensitive analysis for performance. Enable
context-sensitive analysis for more precise results:

.. code-block:: bash

   pyflow optimize input.py --analysis cpa

.. code-block:: python

   context.set_config("cpa.context_sensitive", True)

Flow-Sensitive Analysis
-----------------------

Enable flow-sensitive analysis for statement-by-statement precision:

.. code-block:: python

   context.set_config("cpa.flow_sensitive", True)

Field-Sensitive Analysis
------------------------

Enable field-sensitive analysis to track individual object fields:

.. code-block:: python

   context.set_config("cpa.field_sensitive", True)

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
  ast-scanner, CPA, IFDS, or CPG engines
* ``pyflow supply-chain`` - Generate CycloneDX SBOMs and audit distribution metadata

Programmatic Usage
------------------

Use the Python API for programmatic analysis:

.. code-block:: python

   from pyflow.analysis.cpa import CPA
   from pyflow.analysis.callgraph import CallGraphAnalysis

   # Run CPA
   cpa = CPA()
   cpa_results = cpa.analyze(program)

   # Build call graph
   callgraph = CallGraphAnalysis()
   graph = callgraph.build(program)

Analysis Results
================

PyFlow produces detailed analysis results:

Text Output
-----------

Human-readable text output for terminal:

.. code-block:: bash

   pyflow ir input.py --dump-cfg main --dump-format text

JSON Output
----------

Machine-readable JSON for programmatic processing:

.. code-block:: bash

   pyflow ir input.py --dump-cfg main --dump-format json --dump-output ./out

SARIF Output
-----------

Standard SARIF format for CI/CD integration:

.. code-block:: bash

   pyflow security input.py --format sarif --output results.sarif

.. toctree::
    :maxdepth: 2
    :caption: Analysis Modules

    cfg
    cdg
    pdg
    ddg
    cpg
    callgraph
    dataflowIR
    fsdf
    ipa
    cpa
    alias/index
    storegraph
    shape
    lifetimeanalysis
    ifds
    typeinfo
    numbering
    dump
    stats
    incremental
