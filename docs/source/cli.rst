Command Line Interface
======================

PyFlow provides a comprehensive CLI for static analysis, optimization, and security checking of Python code.

Main Commands
=============

Analysis Commands
-----------------

**pyflow callgraph**
~~~~~~~~~~~~~~~~~~~~

Generate and analyze call graphs from Python code.

::

  pyflow callgraph input.py --format dot --output callgraph.dot
  pyflow callgraph package/ --recursive --algorithm pycg

Options:
- ``--format``: Output format (dot, json, text)
- ``--output``: Output file path
- ``--algorithm``: Call graph algorithm (ast, pycg)
- ``--recursive``: Analyze directories recursively

**pyflow ir**
~~~~~~~~~~~~~

Visualize intermediate representations and analysis results.

::

  pyflow ir input.py --dump-cfg --output cfg.dot
  pyflow ir input.py --dump-ssa --function main

Options:
- ``--dump-cfg``: Dump control flow graph
- ``--dump-ssa``: Dump SSA form
- ``--dump-analysis``: Dump analysis results
- ``--function``: Focus on specific function

Optimization Commands
---------------------

**pyflow optimize**
~~~~~~~~~~~~~~~~~~~

Apply optimization passes to Python code.

::

  pyflow optimize input.py --passes fold,dce --output optimized.py
  pyflow optimize input.py --all-passes --benchmark

Options:
- ``--passes``: Comma-separated list of optimization passes
- ``--all-passes``: Apply all available optimizations
- ``--output``: Output file for optimized code
- ``--benchmark``: Show optimization timing and effects

Available passes: fold, dce, inline, simplify, loadelim, storeelim, etc.

Security Commands
-----------------

**pyflow check**
~~~~~~~~~~~~~~~~

Run security analysis on Python code.

::

  pyflow check input.py --format sarif --output security.sarif
  pyflow check package/ --severity high --recursive

Options:
- ``--format``: Output format (text, json, sarif)
- ``--severity``: Minimum severity level (low, medium, high, critical)
- ``--output``: Output file path
- ``--config``: Configuration file path

Global Options
==============

Common options available across all commands:

- ``--verbose, -v``: Increase verbosity
- ``--quiet, -q``: Suppress output
- ``--help``: Show help information
- ``--version``: Show version information

Configuration
=============

PyFlow can be configured via:

1. **Command line options**: Direct configuration per command
2. **Configuration files**: YAML/JSON files for persistent settings
3. **Environment variables**: PYFLOW_* prefixed variables

Example configuration file:

.. code-block:: yaml

  analysis:
    callgraph:
      algorithm: pycg
      format: json
  optimization:
    passes: [fold, dce, inline]
    benchmark: true
  security:
    severity: high
    format: sarif

Integration
===========

CI/CD Integration
-----------------

PyFlow integrates with CI/CD pipelines:

.. code-block:: bash

  # GitHub Actions example
  - name: Run PyFlow analysis
    run: |
      pyflow callgraph src/ --format json --output callgraph.json
      pyflow check src/ --format sarif --output security.sarif
      pyflow optimize src/main.py --all-passes --output optimized.py

IDE Integration
---------------

PyFlow results can be integrated with IDEs through:

- SARIF format for security issues
- JSON output for custom integrations
- GraphViz DOT files for visualization
- Standard error formats for editor integration
