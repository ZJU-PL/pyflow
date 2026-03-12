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

  pyflow optimize input.py
  pyflow optimize input.py --opt-passes simplify methodcall
  pyflow optimize input.py --suggest-only
  pyflow optimize input.py --dump --output analysis.txt

Options:
- ``--opt-passes``: Space-separated list of optimization passes
- ``--list-opt-passes``: List available optimization passes
- ``--suggest-only``: Report optimization opportunities without running transforming passes
- ``--apply-optimizations``: Explicitly run optimization passes (also the default)
- ``--output``: Output file for dumped analysis results

Available passes include ``simplify``, ``methodcall``, ``clone``,
``argumentnormalization``, ``cullprogram``, ``loadelimination``,
``storeelimination``, ``dce``, and experimental ``inlining``.

Security Commands
-----------------

**pyflow security**
~~~~~~~~~~~~~~~~~~~

Run security analysis on Python code using the pattern-based checker (AST pattern matching).

::

  pyflow security input.py
  pyflow security package/ --recursive
  pyflow security src/ -v --exclude tests/

Options:
- ``-r, --recursive``: Scan directories recursively
- ``-v, --verbose``: Verbose output
- ``-d, --debug``: Debug output
- ``--exclude``: Comma-separated list of paths to exclude

The security command uses the pattern-based checker engine for fast AST pattern matching.
For deep semantic analysis, use the semantic checker via the PyFlow API.

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
    recursive: true
    exclude: [tests/, .venv/]

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
      pyflow security src/ --recursive
      pyflow optimize src/main.py --opt-passes all
      pyflow optimize src/main.py --dump --output optimization-analysis.txt

IDE Integration
---------------

PyFlow results can be integrated with IDEs through:

- SARIF format for security issues
- JSON output for custom integrations
- GraphViz DOT files for visualization
- Standard error formats for editor integration
