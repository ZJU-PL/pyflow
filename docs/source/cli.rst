Command Line Interface
======================

PyFlow provides a CLI for static analysis, optimization, IR inspection,
security checking, and dataflow-oriented analysis of Python code.

This page summarizes the most important commands. For the authoritative option
reference used by the repository today, also see ``CLI.md`` in the project root.

Main Commands
=============

Analysis Commands
-----------------

**pyflow callgraph**
~~~~~~~~~~~~~~~~~~~~

Generate and analyze call graphs from Python code.

::

  pyflow callgraph input.py --format dot --output callgraph.dot
  pyflow callgraph input.py --show-cycles --max-depth 5

Options:
- ``--format``: Output format (dot, json, text)
- ``--output``: Output file path
- ``--max-depth``: Limit call depth
- ``--show-cycles``: Report cycles in the call graph

**pyflow ir**
~~~~~~~~~~~~~

Visualize intermediate representations and analysis results.

::

  pyflow ir input.py --dump-cfg main --dump-format dot
  pyflow ir input.py --dump-ssa main

Options:
- ``--dump-ast FUNCTION``: Dump AST for a named function
- ``--dump-cfg FUNCTION``: Dump CFG for a named function
- ``--dump-ssa FUNCTION``: Dump SSA for a named function
- ``--dump-format``: Output format (text, dot, json)
- ``--dump-output``: Directory for emitted artifacts
- ``--recursive`` / ``--include`` / ``--exclude``: Control file selection

Optimization Commands
---------------------

**pyflow optimize**
~~~~~~~~~~~~~~~~~~~

Apply optimization passes to Python code.

::

  pyflow optimize input.py
  pyflow optimize input.py --opt-passes simplify methodcall
  pyflow optimize --list-opt-passes
  pyflow optimize input.py --dump-cfg main --dump-format dot

Options:
- ``--opt-passes``: Space-separated list of optimization passes
- ``--list-opt-passes``: List available optimization passes
- ``--no-opt-passes``: Run analysis without optimization passes
- ``--dump-ast FUNCTION`` / ``--dump-cfg FUNCTION``: Inspect IR around optimization
- ``--dump-format``: Output format (text, dot, json)
- ``--dump-output``: Directory for emitted artifacts

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

Dataflow Command
----------------

**pyflow dataflow**
~~~~~~~~~~~~~~~~~~~

Run IFDS/IDE-backed dataflow analyses.

::

  pyflow dataflow input.py --help

The exact analyses and options available may evolve as the dataflow subsystem
continues to mature.

Global Options
==============

Common options available across all commands:

- ``--verbose, -v``: Increase verbosity
- ``--quiet, -q``: Suppress output
- ``--help``: Show help information
- ``--version``: Show version information

Integration
===========

CI/CD Integration
-----------------

PyFlow integrates with CI/CD pipelines:

.. code-block:: bash

  # GitHub Actions example
  - name: Run PyFlow analysis
    run: |
      pyflow callgraph src/main.py --format json --output callgraph.json
      pyflow security src/ --recursive
      pyflow optimize src/main.py --opt-passes simplify dce
      pyflow ir src/main.py --dump-cfg main --dump-format dot

IDE Integration
---------------

PyFlow results can be integrated with IDEs through:

- SARIF format for security issues
- JSON output for custom integrations
- GraphViz DOT files for visualization
- Standard error formats for editor integration
