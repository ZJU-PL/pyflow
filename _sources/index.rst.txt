Welcome to PyFlow's Documentation!
==================================

=============
Introduction
=============

PyFlow is a comprehensive static analysis and compilation framework for Python code. It provides advanced analysis capabilities for understanding, optimizing, and securing Python programs without execution.

PyFlow is designed to be a powerful tool for:

- **Static Analysis**: Deep program understanding through multiple analysis domains
- **Code Optimization**: Compiler-level optimizations for Python code
- **Security Analysis**: Automated vulnerability detection and security checking
- **Research**: Advancing static analysis techniques for dynamic languages

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   overview
   cli
   analysis/index
   optimization/index
   checker/sec

==========================
Installing and Using PyFlow
==========================

Install PyFlow from source
---------------------------

::

  git clone https://github.com/ZJU-PL/pyflow.git
  cd pyflow
  python -m venv venv
  source venv/bin/activate  # On Windows: venv\Scripts\activate
  pip install -e .

The setup script will:
- Create a Python virtual environment if it doesn't exist
- Activate the virtual environment and install dependencies
- Install PyFlow in development mode

Basic Usage
-----------

After installation, you can use PyFlow's command-line interface:

::

  # Analyze call graph
  pyflow callgraph input.py

  # Run security checks
  pyflow check input.py

  # Apply optimizations
  pyflow optimize input.py

  # Visualize intermediate representations
  pyflow ir input.py --dump-cfg

See :doc:`cli` for detailed command documentation.

===============
Core Components
===============

Analysis Modules
----------------

PyFlow provides a rich set of analysis modules organized by purpose:

* **Control Flow Analysis**: CFG construction, dominance analysis, loop detection
* **Data Flow Analysis**: Forward/backward analysis, constant propagation, live variables
* **Inter-procedural Analysis**: Context-sensitive analysis across function boundaries
* **Constraint-based Analysis**: Constraint solving for precise object relationship modeling
* **Shape Analysis**: Data structure shape and property analysis
* **Call Graph Analysis**: Function call relationship analysis with multiple algorithms

See :doc:`analysis/index` for detailed analysis module documentation.

Optimization Framework
----------------------

PyFlow includes comprehensive optimization passes:

* **Constant Folding**: Compile-time evaluation of constant expressions
* **Dead Code Elimination**: Removal of unreachable and unused code
* **Function Inlining**: Performance optimization through inlining
* **Data Flow Optimizations**: Load/store elimination and redundancy removal
* **Control Flow Simplification**: Basic block merging and jump optimization

See :doc:`optimization/index` for complete optimization documentation.

Security Analysis
-----------------

PyFlow's security checker identifies vulnerabilities:

* **Injection Attacks**: SQL injection, command injection detection
* **Authentication Issues**: Hardcoded credentials, weak cryptography
* **Code Safety**: Dangerous function usage, unsafe imports
* **LLM Integration**: AI-assisted vulnerability detection

See :doc:`checker/sec` for security analysis documentation.

Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
