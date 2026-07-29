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

Generate and analyze call graphs from Python code.  Accepts a single Python
file or a project directory.  When given a directory, the entry point is
auto-detected conservatively from ``pyproject.toml``, ``setup.py``, package
``__main__.py`` files, or well-known root filenames.  Only the strongest
available evidence tier is considered.  Its entry is selected only when it is
unambiguous; otherwise the candidates are reported and can be resolved with
``--entry``.

::

  pyflow callgraph input.py --algorithm constraint --output callgraph.txt
  pyflow callgraph input.py --algorithm constraint --context-sensitive --context-depth 2
  pyflow callgraph /path/to/project/                            # auto-detect entry
  pyflow callgraph /path/to/project/ --entry src/app.py         # explicit entry
  pyflow callgraph /path/to/project/ --dry-run                  # print entry only

Options:
- ``--entry``: Entry point file relative to project root (directory input only; auto-detected when omitted)
- ``--dry-run``: Print detected entry point without running analysis
- ``--algorithm, -a``: Algorithm (``simple``, ``constraint``, or ``pycg``; default: ``simple``)
- ``--output, -o``: Output file path
- ``--verbose, -v``: Enable verbose output
- ``--skip-stdlib``: Skip standard library modules in constraint analysis (default: on)
- ``--no-skip-stdlib``: Include standard library modules
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
  pyflow security input.py --engine ast-dataflow
  pyflow security input.py --engine ifds --sources input --sinks eval
  pyflow security project/ --engine ifds --entry app.py --sources input --sinks eval
  pyflow security input.py --engine cpg --framework flask

Options:
- ``--engine``: Analysis engine (``ast-scanner``, ``ast-dataflow``, ``ifds``, or ``cpg``)
- ``--config``: JSON config file for IFDS analysis parameters (e.g., solver budgets, trace mode)
- ``--sources`` / ``--sinks`` / ``--sanitizers``: Function names for taint-style dataflow checks
- ``--entry``: Entry file relative to the project root for the IFDS engine; auto-detected when omitted
- ``--analysis``: IFDS client (``taint``, ``nullness``, or ``typestate``)
- ``--registry-path``: Load custom rule-pack JSON file(s) or directories (both IFDS and CPG engines)
- ``--typestate-protocol``: Typestate protocols for ``--analysis typestate`` (repeatable; supports ``resource``, ``python-builtins``, ``file``, ``socket``, ``lock``, ``transaction``)
- ``--ifds-mode``: ``strict`` preparation or diagnostic ``best-effort`` mode
- ``--ifds-max-seconds`` / ``--ifds-max-memory-bytes``: Wall-clock and memory budgets
- ``--ifds-max-path-edges`` / ``--ifds-max-queue-size``: Solver work budgets
- ``--ifds-max-incoming-records`` / ``--ifds-max-summary-entries``: Interprocedural table budgets
- ``--ifds-max-facts-per-node`` / ``--ifds-max-contexts-per-procedure``: Precision/cardinality budgets
- ``--ifds-context-depth``: Maximum call-string depth
- ``--ifds-trace-mode``: Retain no traces, finding traces, or all traces
- ``--cpg-max-seconds`` / ``--cpg-max-states``: CPG time and state budgets; exhaustion is reported as ``partial``
- ``--cpg-context-depth``: Maximum CPG call-string depth (default: 3)
- ``--framework``: Framework rule packs for the CPG engine
- ``--format``: Output format: ``text``, ``json``, ``sarif``, ``csv``, ``custom``, ``html``, ``screen``, ``xml``, or ``yaml``.
- ``--output``: Output file path
- ``-r, --recursive``: Scan directories recursively
- ``-v, --verbose``: Verbose output
- ``-d, --debug``: Debug output
- ``--exclude``: Comma-separated list of paths to exclude

The default ``ast-scanner`` engine is a fast pattern-based checker. The command
can also dispatch to AST-dataflow, IFDS, and CPG-backed security engines. The
AST-dataflow and CPG JSON/SARIF output includes an explicit ``complete`` or
``partial`` status plus diagnostics when limitations affect completeness.

Supply Chain Command
--------------------

**pyflow supply-chain**
~~~~~~~~~~~~~~~~~~~~~~~

Offline supply-chain analysis for Python packages. It generates CycloneDX 1.7,
SPDX 2.3, or requirements inventories and audits dependency metadata,
archives, installed distributions, licenses, vulnerabilities, VEX, and
provenance.

::

  pyflow supply-chain sbom package/
  pyflow supply-chain sbom package/*.whl
  pyflow supply-chain audit path/to/dist-info/
  pyflow supply-chain audit . --recursive --exclude .venv

Subcommands:

``sbom``
  Generate CycloneDX 1.7, SPDX 2.3, or requirements output. ``--deterministic``
  derives document IDs from content and uses ``SOURCE_DATE_EPOCH``.
  ``--schema`` validates JSON output against a pinned local official schema.

``audit``
  Report structural anomalies, unsafe dependency sources, license-policy
  violations, local OSV matches, VEX status, provenance failures, and
  possible typosquatting. JSON, text, and SARIF output are supported.

Common options:

- ``--recursive, -r``: Scan directories recursively
- ``--exclude``: Comma-separated list of paths to exclude
- ``--output, -o``: Output file (default: stdout)
- ``--python-version``, ``--platform``, ``--implementation``: resolve PEP 508
  markers for the target runtime
- ``--extra``: select dependency extras during marker evaluation

Audit format:

- ``--format text`` (default), ``json``, or ``sarif``
- ``--osv-database`` with ``--osv-max-age-days`` and
  ``--require-osv-checksum``: use freshness- and integrity-governed offline OSV
  data
- ``--osv-trusted-digest PATH=SHA256``: bind database files to digests supplied
  by trusted CI configuration; colocated checksum sidecars alone do not prove
  database origin
- ``--vex``: apply CycloneDX VEX or OpenVEX status
- ``--policy`` / ``--baseline`` / ``--write-baseline``: manage reviewed,
  expiring finding exceptions
- ``--attestation`` / ``--trusted-builder`` / ``--require-provenance``:
  require digest-bound in-toto or SLSA provenance. An attestation establishes
  trust only when that exact file passes an independent Sigstore identity check
- ``--sigstore-bundle`` with certificate identity and issuer options: invoke
  the official Sigstore verifier for a local bundle
- ``--require-schema-validation``: fail SBOM generation unless a pinned local
  official schema bundle is supplied with ``--schema``; network reference
  resolution is disabled
- ``--reachability``: annotate vulnerabilities with conservative import
  evidence; absence of an import is explicitly not treated as proof of safety

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
