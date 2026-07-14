Command Line Interface
========    ==============

PyFlow provides a CLI for static analysis, optimization, IR inspection,
security checking, and alias analysis of Python code.

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

  pyflow callgraph input.py --algorithm constraint --output callgraph.txt
  pyflow callgraph input.py --algorithm constraint --context-sensitive --context-depth 2

Options:
- ``--algorithm, -a``: Algorithm (``simple``, ``constraint``, or ``pycg``; default: ``simple``)
- ``--output, -o``: Output file path
- ``--verbose, -v``: Enable verbose output
- ``--context-sensitive``: Enable call-site context sensitivity (constraint algorithm only)
- ``--context-depth``: Call-string depth when ``--context-sensitive`` is enabled (default: 1)
- ``--fixpoint-max-iterations``: Cap fixpoint iterations (constraint algorithm only)
- ``--no-fixpoint-warning``: Disable warning when fixpoint cap is hit (constraint algorithm only)
- ``--allocation-site-sensitive-instances``: Track per-allocation instance identities (constraint algorithm only)
- ``--as-graph-output``: Write constraint value-flow assignment graph JSON (constraint algorithm only)

**pyflow ir**
~~~~~~~~~~~~~

Visualize intermediate representations and analysis results.

::

  pyflow ir input.py --dump-cfg main --dump-format dot
  pyflow ir input.py --dump-ssa main
  pyflow ir input.py --dump-cdg main --dump-format text
  pyflow ir input.py --dump-ddg main --dump-format text

Options:
- ``--dump-ast FUNCTION``: Dump AST for a named function
- ``--dump-cfg FUNCTION``: Dump CFG for a named function
- ``--dump-ssa FUNCTION``: Dump SSA for a named function
- ``--dump-cdg FUNCTION``: Dump Control Dependence Graph for a named function
- ``--dump-ddg FUNCTION``: Dump Data Dependence Graph for a named function
- ``--dump-format``: Output format (text, dot, json)
- ``--dump-output``: Directory for emitted artifacts
- ``--dependency-strategy``: How to handle imports (``auto``, ``stubs``, ``noop``, ``strict``, ``ast_only``)
- ``--recursive, -r``: Recursively analyze subdirectories
- ``--include`` / ``--exclude``: File patterns to include/exclude
- ``--verbose, -v``: Enable verbose output

Optimization Commands
---------------------

**pyflow optimize**
~~~~~~~~~~~~~~~~~~~

Apply optimization passes to Python code.

::

  pyflow optimize input.py
  pyflow optimize input.py --opt-passes simplify methodcall
  pyflow optimize --list-opt-passes
  pyflow optimize input.py --analysis cpa

Options:
- ``--analysis, -a``: Analysis type (``all``, ``cpa``, ``ipa``, ``shape``, ``lifetime``; default: ``all``)
- ``--dependency-strategy``: How to handle imports (``auto``, ``stubs``, ``noop``, ``strict``, ``ast_only``)
- ``--recursive, -r``: Recursively analyze subdirectories
- ``--include`` / ``--exclude``: File patterns to include/exclude
- ``--output, -o``: Output file for dumped results
- ``--dump, -d``: Dump analysis results
- ``--dump-ipa``: Dump IPA analysis results
- ``--dump-shape``: Dump Shape analysis results
- ``--suggest-only``: Generate suggestions without running transforming passes
- ``--apply-optimizations``: Explicitly run optimization passes (also the default)
- ``--no-opt-passes``: Run analysis without optimization passes
- ``--experimental-inlining``: Enable experimental inlining pass
- ``--opt-passes``: Space-separated list of optimization passes
- ``--list-opt-passes``: List available optimization passes
- ``--verbose, -v``: Enable verbose output

Available passes include ``simplify``, ``methodcall``, ``lifetime``, ``clone``,
``argument_normalization``, ``cull_program``, ``load_elimination``,
``store_elimination``, ``dce``, and experimental ``inlining``.
(Legacy names such as ``argumentnormalization`` are also accepted.)

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
- ``--analysis``: IFDS client (``taint``, ``nullness``, or ``typestate``)
- ``--ifds-mode``: ``strict`` preparation or diagnostic ``best-effort`` mode
- ``--ifds-max-seconds`` / ``--ifds-max-memory-bytes``: Wall-clock and memory budgets
- ``--ifds-max-path-edges`` / ``--ifds-max-queue-size``: Solver work budgets
- ``--ifds-max-incoming-records`` / ``--ifds-max-summary-entries``: Interprocedural table budgets
- ``--ifds-max-facts-per-node`` / ``--ifds-max-contexts-per-procedure``: Precision/cardinality budgets
- ``--ifds-context-depth``: Maximum call-string depth
- ``--ifds-trace-mode``: Retain no traces, finding traces, or all traces
- ``--framework``: Framework rule packs for the CPG engine
- ``--format``: Output format (``text``, ``json``, or ``sarif``)
- ``--output``: Output file path
- ``-r, --recursive``: Scan directories recursively
- ``-v, --verbose``: Verbose output
- ``-d, --debug``: Debug output
- ``--exclude``: Comma-separated list of paths to exclude

The default ``ast-scanner`` engine is a fast pattern-based checker. The command
can also dispatch to CPA, IFDS, and CPG-backed security engines.

Supply Chain Command
--------------------

**pyflow supply-chain**
~~~~~~~~~~~~~~~~~~~~~~~

Local supply-chain analysis for Python packages. Works on local files and
archives — no package index queries. Generates CycloneDX SBOMs and audits
distribution metadata for structural issues.

::

  pyflow supply-chain sbom package/
  pyflow supply-chain sbom package/*.whl
  pyflow supply-chain audit path/to/dist-info/
  pyflow supply-chain audit . --recursive --exclude .venv

Subcommands:

``sbom``
  Generate a CycloneDX 1.3 SBOM JSON document from local package metadata
  (METADATA, RECORD, pyproject.toml, poetry.lock, requirements.txt).

``audit``
  Report structural anomalies in archives (zip/traversal, absolute paths,
  oversized members) and distribution metadata (missing RECORD, hash
  mismatches, unlisted files).

Common options:

- ``--recursive, -r``: Scan directories recursively
- ``--exclude``: Comma-separated list of paths to exclude
- ``--output, -o``: Output file (default: stdout)

Audit format:

- ``--format text`` (default) or ``--format json``

Alias Command
--------------

**pyflow alias**
~~~~~~~~~~~~~~~~

Run alias analysis on Python code. Supports two engines:
``flow-sensitive`` (heap alias/escape) and ``kcfa`` (k-CFA pointer).

::

  pyflow alias input.py
  pyflow alias src/ --recursive
  pyflow alias input.py --engine kcfa
  pyflow alias input.py --json
  pyflow alias input.py --verbose

Options:

- ``--engine {flow-sensitive,kcfa}``: Analysis engine (default: flow-sensitive)
- ``--k N``: k-CFA context sensitivity depth (kcfa engine only, default: 1)
- ``--recursive, -r``: Recursively analyze Python files in a directory
- ``--json``: Output machine-readable JSON instead of human-friendly text
- ``--verbose, -v``: Include per-entry details

Global Options
==============

Common options available across most commands:

- ``--verbose, -v``: Increase verbosity
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
      pyflow callgraph src/main.py --output callgraph.txt
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
