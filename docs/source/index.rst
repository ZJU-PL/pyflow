Welcome to PyFlow's Documentation!
==================================

PyFlow is a static analysis and optimization framework for Python. It provides
analysis infrastructure, experimental compiler-style transformations, and
security checking for Python programs without executing them.

.. note::

   PyFlow is currently in **alpha** stage. The architecture is already
   substantial and the test suite is broad, but parts of the public interface
   and documentation are still evolving.

If you are new to PyFlow, start with the :ref:`tutorials`.

.. toctree::
    :maxdepth: 2
    :caption: Getting Started

    tutorials/index
    overview

.. toctree::
    :maxdepth: 2
    :caption: How-to Guides

    how-to/index

.. toctree::
    :maxdepth: 2
    :caption: Explanations

    explanation/index

.. toctree::
    :maxdepth: 2
    :caption: A3 Python

    a3_python/index

.. toctree::
    :maxdepth: 2
    :caption: Reference

    cli
    api
    analysis/index
    optimization/index
    lang/index
    checker/sec

================================================================================

What is PyFlow?
===============

PyFlow is designed to be a powerful tool for:

- **Static Analysis**: Deep program understanding through multiple analysis domains
- **Code Optimization**: Compiler-level optimizations for Python code
- **Security Analysis**: Automated vulnerability detection and security checking
- **Research**: Advancing static analysis techniques for dynamic languages

It is particularly well suited to:

- experimenting with static-analysis ideas for Python,
- inspecting intermediate representations such as AST/CFG/SSA,
- evaluating optimization passes over a shared program model, and
- building query or checker features on top of existing analyses.

Installation
============

Install PyFlow from source:

.. code-block:: bash

   git clone https://github.com/ZJU-PL/pyflow.git
   cd pyflow
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e .

Quick Start
===========

After installation, use PyFlow's command-line interface:

.. code-block:: bash

   # Analyze call graph
   pyflow callgraph input.py

   # Run security checks
   pyflow security input.py

   # Apply optimizations
   pyflow optimize input.py

   # Visualize intermediate representations
   pyflow ir input.py --dump-cfg function_name

   # Run alias analysis (flow-sensitive heap or k-CFA pointer)
   pyflow alias input.py

   # Explore available optimization passes
   pyflow optimize --list-opt-passes

Documentation Structure
=======================

This documentation is organized following the Diátaxis framework:

.. list-table::
   :widths: 25 75
   :header-rows: 1

   * - Section
     - Description
   * - :ref:`Tutorials <tutorials>`
     - Step-by-step guides for learning PyFlow
   * - :ref:`How-to Guides <how-to>`
     - Practical guides for accomplishing specific tasks
   * - :ref:`Explanations <explanation>`
     - In-depth discussions of concepts and architecture
   * - :ref:`Reference <reference>`
     - Complete API documentation and command reference

Core Capabilities
=================

Static Analysis
---------------

PyFlow provides comprehensive static analysis:

* **Control Flow Analysis**: CFG, CDG, PDG, DDG construction, dominance analysis, loop detection
* **Data Flow Analysis**: Forward/backward analysis, data flow IR, IFDS/IDE interprocedural engine
* **Inter-procedural Analysis**: Context-sensitive analysis across function boundaries
* **Pointer Analysis**: k-CFA constraint-based points-to analysis for Python objects
* **Constraint-based Analysis**: Constraint solving for precise object relationship modeling
* **Shape Analysis**: Data structure shape and property analysis
* **Alias Analysis**: Flow-sensitive heap analysis (alias/escape) and k-CFA pointer analysis
* **Call Graph Analysis**: Function call relationship analysis with multiple algorithms
* **Type Information**: Lightweight type-information collection and inference

Code Optimization
-----------------

PyFlow includes comprehensive optimization passes:

* **Constant Folding**: Compile-time evaluation of constant expressions
* **Dead Code Elimination**: Removal of unreachable and unused code
* **Function Inlining**: Performance optimization through inlining
* **Data Flow Optimizations**: Load/store elimination and redundancy removal
* **Control Flow Simplification**: Basic block merging and jump optimization
* **Method Call Optimization**: Optimization of method dispatch

Security Analysis
-----------------

PyFlow's security checker identifies vulnerabilities:

* **Injection Attacks**: SQL injection, command injection detection
* **Authentication Issues**: Hardcoded credentials, weak cryptography
* **Code Safety**: Dangerous function usage, unsafe imports
* **Input Validation**: Missing or improper input validation
* **Dependency Security**: Known vulnerable dependencies

Getting Help
============

* **Documentation**: See this documentation or :doc:`cli` for command reference
* **Issues**: Report bugs at https://github.com/ZJU-PL/pyflow/issues
* **Discussions**: Ask questions at https://github.com/ZJU-PL/pyflow/discussions

Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
