Command Line Interface
========    ==============

PyFlow provides a CLI for static analysis, optimization, IR inspection,
security checking, and heap analysis of Python code.

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

Run security analysis on Python code using one of the available engines.

::

  pyflow security input.py
  pyflow security package/ --recursive
  pyflow security src/ -v --exclude tests/
  pyflow security input.py --engine ifds --function main --sources input --sinks eval
  pyflow security input.py --engine cpg --framework flask

Options:
- ``--engine``: Analysis engine (``ast-scanner``, ``cpa``, ``ifds``, or ``cpg``)
- ``--sources`` / ``--sinks`` / ``--sanitizers``: Function names for taint-style dataflow checks
- ``--function``: Entry function for the IFDS engine
- ``--framework``: Framework rule packs for the CPG engine
- ``--format``: Output format (``text``, ``json``, or ``sarif``)
- ``--output``: Output file path
- ``-r, --recursive``: Scan directories recursively
- ``-v, --verbose``: Verbose output
- ``-d, --debug``: Debug output
- ``--exclude``: Comma-separated list of paths to exclude

The default ``ast-scanner`` engine is a fast pattern-based checker. The command
can also dispatch to CPA, IFDS, and CPG-backed security engines.

Heap Command
------------

**pyflow heap**
~~~~~~~~~~~~~~~

Run standalone heap alias/escape analysis on Python code.

::

  pyflow heap input.py
  pyflow heap src/ --recursive
  pyflow heap input.py --json
  pyflow heap input.py --verbose

Options:

- ``--recursive, -r``: Recursively analyze Python files in a directory
- ``--json``: Output machine-readable JSON instead of human-friendly text
- ``--verbose, -v``: Include per-entry details (selector path, update policy,
  points-to sets)

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
