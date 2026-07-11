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
* :doc:`cpg` - Code Property Graph (unified CFG + PDG + call graph)
* :doc:`callgraph` - Call Graph construction and analysis

Data Flow Analysis
------------------

* :doc:`dataflowIR` - Data Flow Intermediate Representation
* :doc:`fsdf` - Flow-Sensitive Data Flow analysis
* :doc:`ipa` - Inter-procedural Analysis
* :doc:`cpa` - Constraint-based Analysis
* :doc:`ifds-heap` - IFDS heap abstraction for field-sensitive dataflow clients

Shape and Type Analysis
-----------------------

* :doc:`shape` - Shape analysis for data structures
* :doc:`storegraph` - Store graph analysis for object relationships

Specialized Analysis
--------------------

* :doc:`numbering` - Program point numbering
* :doc:`lifetimeanalysis` - Variable lifetime analysis
* :doc:`dump` - Analysis result dumping and visualization

Analysis Configuration
======================

PyFlow supports configurable analysis with different precision/performance trade-offs.

Context-Sensitive Analysis
--------------------------

By default, PyFlow performs context-insensitive analysis for performance. Enable
context-sensitive analysis for more precise results:

.. code-block:: bash

   pyflow analyze input.py --analysis cpa --cpa-config context_sensitive=true

Flow-Sensitive Analysis
-----------------------

Enable flow-sensitive analysis for statement-by-statement precision:

.. code-block:: bash

   pyflow analyze input.py --analysis cpa --cpa-config flow_sensitive=true

Field-Sensitive Analysis
------------------------

Enable field-sensitive analysis to track individual object fields:

.. code-block:: bash

   pyflow analyze input.py --analysis cpa --cpa-config field_sensitive=true

Running Analyses
================

Command Line
------------

Use the ``analyze`` command for general analysis:

.. code-block:: bash

   pyflow analyze input.py --analysis all
   pyflow analyze input.py --analysis cpa,ipa
   pyflow analyze input.py --analysis cpa --cpa-config context_sensitive=true

Specific Commands
-----------------

* ``pyflow callgraph`` - Build and analyze call graphs
* ``pyflow ir`` - Dump intermediate representations
* ``pyflow security`` - Run security analysis
* ``pyflow optimize`` - Run analysis and optimization

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

   pyflow analyze input.py --format text

JSON Output
-----------

Machine-readable JSON for programmatic processing:

.. code-block:: bash

   pyflow analyze input.py --format json --output results.json

SARIF Output
------------

Standard SARIF format for CI/CD integration:

.. code-block:: bash

   pyflow analyze input.py --format sarif --output results.sarif

.. toctree::
    :maxdepth: 2
    :caption: Analysis Modules

    cfg
    cdg
    pdg
    cpg
    callgraph
    dataflowIR
    fsdf
    ipa
    cpa
    ifds-heap
    shape
    storegraph
    numbering
    lifetimeanalysis
    dump
