Command Line Interface
========    ==============

PyFlow provides a CLI for static analysis, optimization, IR inspection,
security checking, concolic test-input generation, and alias analysis of
Python code.

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
  pyflow callgraph input.py --algorithm pycg-mir               # native MIR analysis
  pyflow callgraph /path/to/project/                            # auto-detect entry
  pyflow callgraph /path/to/project/ --entry src/app.py         # explicit entry
  pyflow callgraph /path/to/project/ --dry-run                  # print entry only

Options:
- ``--entry``: Entry point file relative to project root (directory input only; auto-detected when omitted)
- ``--dry-run``: Print detected entry point without running analysis
- ``--algorithm, -a``: Algorithm (``simple``, ``constraint``, ``pycg``, or ``pycg-mir``; default: ``constraint``)
- ``--recursive, -r``: Analyze all project source files with constraint analysis, including libraries without a unique entry
- ``--include-external``: Include third-party dependency source (default: project sources only)
- ``--format {text,json}``: Text is the default; JSON maps caller names to sorted callee lists, with empty lists for leaf nodes
- ``--output, -o``: Output file path
- ``--verbose, -v``: Enable verbose output
- ``--skip-stdlib``: Skip standard library modules in constraint analysis (default: on)
- ``--no-skip-stdlib``: Include standard library modules in constraint analysis
- ``--context-sensitive``: Enable call-site context sensitivity (constraint algorithm only)
- ``--context-depth``: Call-string depth when ``--context-sensitive`` is enabled (default: 1)
- ``--fixpoint-max-iterations``: Cap fixpoint iterations (constraint algorithm only)
- ``--no-fixpoint-warning``: Disable warning when fixpoint cap is hit (constraint algorithm only)
- ``--allocation-site-sensitive-instances``: Track per-allocation instance identities (constraint algorithm only)
- ``--as-graph-output``: Write constraint value-flow assignment graph JSON (constraint algorithm only)

``pycg-mir`` runs native flow-, path-, and context-insensitive PyCG-style
analysis over MIR and does not require the optional upstream ``pycg`` package.
The stdlib flags affect only constraint analysis and do not extend MIR's
supported import graph.
See :doc:`ir/mir` for its APIs and supported scope.

**pyflow ir**
~~~~~~~~~~~~~

Visualize intermediate representations and analysis results.

::

  pyflow ir input.py --dump-cfg main --dump-format dot
  pyflow ir input.py --dump-ssa main
  pyflow ir input.py --dump-cdg main --dump-format text
  pyflow ir input.py --dump-ddg main --dump-format text
  pyflow ir input.py --dump-mir --dump-format json --dump-output out/
  pyflow ir input.py --dump-mir input.main --dump-format text

Options:
- ``--dump-mir [SCOPE]``: Dump MIR or an unambiguous scope; short names prefer source definitions over runtime helpers
- ``--mir-view {source,full}``: Hide runtime CFGs for inspection or include the complete program. Text/DOT default to ``source``; JSON defaults to ``full`` for compatibility. Explicit ``source`` JSON is an inspection view with ``view`` and ``omitted_runtime_cfgs`` metadata, not a standalone executable MIR program
- ``--mir-import-policy {strict,opaque}``: Source views lower input files only and retain imports/unmodeled expressions as opaque boundaries, with partial-coverage diagnostics. Full views remain strict and follow local imports
- ``--dump-ast FUNCTION``: Dump AST for a named function
- ``--dump-cfg FUNCTION``: Dump CFG using a qualified name or a unique short name (for example ``Class.method``). Ambiguous or missing names report candidates
- ``--dump-ssa FUNCTION``: Dump SSA for a named function
- ``--dump-cdg FUNCTION``: Dump Control Dependence Graph for a named function
- ``--dump-ddg FUNCTION``: Dump Data Dependence Graph for a named function
- ``--dump-gir FUNCTION``: Dump Graph IR (GIR) for a named function
- ``--dump-format``: Output format (text, dot, json)
- ``--dump-output``: Directory for emitted artifacts
- ``--dependency-strategy``: How to handle imports (``auto``, ``stubs``, ``noop``, ``strict``, ``ast_only``)
- ``--recursive, -r``: Recursively analyze subdirectories
- ``--include`` / ``--exclude``: File patterns to include/exclude
- ``--verbose, -v``: Enable verbose output

MIR dumps lower source directly without importing or executing analyzed
modules. They support text, JSON, and DOT output. With directory input,
the output directory preserves the source directory structure.

**pyflow concolic**
~~~~~~~~~~~~~~~~~~~

Generate branch-covering inputs for a single function by replaying concrete
inputs and using Z3 to flip each observed branch. The default entry function
is ``main``. Requires the optional ``z3-solver`` dependency
(``pip install -e ".[concolic]"``).

::

  pyflow concolic target.py --entry parse --inputs '[0, 0]' --json
  pyflow concolic src/ --scan-project --max-functions 20
  pyflow concolic target.py --emit-pytest tests/test_target_gen.py

Options:
- ``--entry NAME``: Function to explore (default: ``main``)
- ``--inputs JSON_ARRAY``: Initial arguments as a JSON array (default: zero for each parameter)
- ``--max-iterations N``: Maximum concrete executions (default: 50)
- ``--max-loop-iterations N``: Concrete loop cap per ``while`` statement (default: 100)
- ``--check-contracts``: Solve supported PEP 316 ``post:`` clauses for a counterexample
- ``--refine-opaque-calls``: Execute safe unsupported library calls concretely and refine symbolic relations from observations
- ``--scan-project``: Discover and measure functions beneath the input path (with ``--max-functions``, ``--input-complexity``, ``--function-timeout``, ``--allow-side-effects``, ``--include-private``, ``--json-output PATH``)
- ``--emit-pytest PATH``: Write a minimized, CPython-replay-validated pytest module
- ``--search-strategy``: Pending-state selection (``fifo``, ``breadth_first``, ``coverage``; default: ``coverage``)
- ``--total-timeout`` / ``--per-run-timeout`` / ``--solver-timeout`` / ``--solver-rlimit`` / ``--max-solver-calls``: Wall-clock and solver budgets
- ``--json``: Emit generated inputs and execution results as JSON

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
- ``--emit-optimized PATH``: Write a syntax-valid optimized Python copy to PATH (output directory for directory input)
- ``--opt-level {0,1,2}``: Source optimization level (0=format only, 1=safe local rewrites, 2=guarded propagation; default: 1)
- ``--report-optimizations PATH``: Write JSON source-optimization report to PATH (requires ``--emit-optimized``)
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
- ``--config``: JSON config file for IFDS parameters; defaults to ``pyflow.json`` in the target directory (or the parent of a file target)
- ``--sources`` / ``--sinks`` / ``--sanitizers``: Function names for taint-style dataflow checks
- ``--entry``: Entry file relative to the project root for IFDS; repeat to select multiple files. All discovered entries are analyzed when omitted
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
- ``--ifds-unknown-call-policy``: Handle unresolved calls with ``drop``, ``preserve`` (the CLI default), or ``havoc`` semantics
- ``--cpg-max-seconds`` / ``--cpg-max-states``: CPG time and state budgets; exhaustion is reported as ``partial``
- ``--cpg-context-depth``: Maximum CPG call-string depth (default: 3)
- ``--framework``: Framework rule packs for the CPG engine
- ``--format``: Output format: ``text``, ``json``, ``sarif``, ``csv``, ``custom``, ``html``, ``screen``, ``xml``, or ``yaml``.
- ``--output``: Output file path
- ``--exit-code-policy``: ``report`` (default) returns zero for complete/partial reports; ``findings`` enables CI gating (1 for findings, 3 for partial/cancelled analysis). Both policies return 2 for invalid input and 4 for failed analysis
- ``-r, --recursive``: Directory targets automatically enable recursive scanning; IFDS retains entry discovery/selection
- ``-v, --verbose``: Verbose output
- ``-d, --debug``: Debug output
- ``--exclude``: Repeatable paths/globs, accepting commas and multiple values; relative directory names work with or without ``./``
- ``--no-default-excludes``: Include tests, hidden directories, virtual environments, and build outputs during directory discovery
- ``--severity`` / ``--confidence``: Minimum severity or confidence to report
- ``--skip-rule`` / ``--skip``: Disable rule IDs or scanner rule names (repeatable; commas accepted)
- ``--no-deduplicate``: Show every overlapping AST rule individually
- ``--baseline``: Previous JSON report; suppress matching rule/file/line findings
- ``--fail-on`` / ``--fail-on-severity``: Return 1 when a reported finding reaches the selected severity, after report filtering
- ``--json-schema {legacy,unified}``: Existing JSON formats remain the default. Unified JSON has a common versioned envelope and normalized finding fields for every engine
- ``--ast-unknown-call-policy {preserve,havoc}``: Preserve real input kinds by default, disclosing unknown effects as partial coverage, or introduce all possible kinds conservatively
- ``--ast-entry-source-kind``: Source kind for AST entry parameters (repeatable; default: user_input)

IFDS taint rule packs may model library calls that preserve or transform taint
without declaring them as sources or sinks. Propagation ports support
parameters, receivers, returns, yields, raises, sinks, and access paths::

  {
    "call": "framework.Value.wrap",
    "propagations": [
      {"from": {"parameter": 0, "path": ["payload"]},
       "to": {"parameter": 1, "path": ["copy"]}},
      {"from": "receiver", "to": "return",
       "maps": {"html": "html_safe"}}
    ]
  }

Sanitizers may additionally declare kind mappings, removals, guards, input
mutation, and explicit assumptions. These richer propagation and sanitizer
contracts are consumed by IFDS. The engine-neutral source/sink projection used
by AST-dataflow and CPG remains backward compatible and ignores unsupported
contract details.

The default ``ast-scanner`` engine is a fast pattern-based checker. A variable
URL is a low-confidence review hint, not proof of a user-controlled SSRF flow.
HTTP checks inspect the URL argument rather than payloads, headers, or request
methods. Use AST-dataflow, IFDS, or CPG to examine source-to-sink flows.
``copy.copy`` and ``copy.deepcopy`` preserve input taint and are not filesystem
sinks; ``shutil.copy`` remains a filesystem sink.

All security JSON reports include an explicit status. AST-dataflow, IFDS, and
CPG also include diagnostics when limitations affect completeness. Automated
drivers should use ``--exit-code-policy report`` and read ``status``,
``findings``/``results``, and ``diagnostics`` from the report instead of
interpreting findings or ``partial`` as process failures.
Internal rule failures also make reports partial, with rule ID, filename,
line, and reason in JSON errors and SARIF invocation notifications. Scanner
issue totals count findings; weighted scores are reserved for verbose scores.
Progress and diagnostics use stderr, including when reports go to stdout.
Known equivalent AST rules at an identical source span are folded into one
finding with the strongest severity/confidence. For Flask debug mode, the
B202/F101/F109 evidence is retained in JSON ``related_rules``, SARIF
``properties.relatedRules``, and text's related-rule list. Distinct AST nodes
on one line and unrelated vulnerability families are retained. Report metrics
count the displayed findings, with ``raw_findings`` and ``folded_findings``
recording the underlying rule counts. ``--no-deduplicate`` restores raw output.

For IFDS, ``pyflow.json`` in the target directory (or a file target's parent)
provides defaults. ``--config`` selects another file, and CLI flags override
configured values. For example::

  {
    "analysis": "taint",
    "entry": ["app.py"],
    "frameworks": ["stdlib", "flask"],
    "unknown_call_policy": "preserve",
    "solver_options": {"max_seconds": 30, "max_path_edges": 100000}
  }
IFDS text output includes normalized rule IDs, severity, and primary source
locations. CPG reports and SARIF retain source filenames and line numbers from
the IR's source origins. Missing source information is reported explicitly.

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
  An incomplete inventory or high-severity dependency finding returns 2 after
  emitting the SBOM, with an explanation on stderr. Use ``--allow-incomplete``
  to accept that inventory and return 0. Diagnostics never enter JSON stdout.

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

Capability Commands
-------------------

**pyflow capabilities**
~~~~~~~~~~~~~~~~~~~~~~~

Report potential use or exposure of security-sensitive capabilities using
context-sensitive pointer analysis. Findings do not establish an authorization
policy violation.

::

  pyflow capabilities app.py
  pyflow capabilities project/ --entry app.py --format json
  pyflow capabilities project/ --entry app.py --context-depth 2
  pyflow capabilities project/ --entry app.py --format sarif --output capabilities.sarif

Options:

- ``--entry``: Entry file relative to project root
- ``--recursive, -r``: Analyze all project Python files instead of selecting one entry
- ``--context-depth {0,1,2,3}``: Context sensitivity depth (default: 1)
- ``--context-policy POLICY``: Specific context policy (e.g. ``1-cfa``, ``2-cfa``, ``1c1o``, ``1-param``)
- ``--capability-model PATH``: Custom capability model JSON file (repeatable)
- ``--no-public-exports``: Do not report capabilities exposed as public module globals
- ``--report-callable-boundaries``: Include potential transfers through returns, yields, and exceptions (default: off)
- ``--format {text,json,sarif}``: Output format (default: ``text``)
- ``--output, -o PATH``: Write output to file

Capability reports return 0 by default, including reports with findings or
partial coverage. Use ``--exit-code-policy findings`` to return 1 in those
cases. Invalid input and failed analysis return 2 with either policy.

**pyflow capability-run**
~~~~~~~~~~~~~~~~~~~~~~~~~

Observe classified CPython audit events and optionally deny operations outside
a capability allow list. Python-level audit hooks do not sandbox malicious
code, and unclassified events are ignored.

::

  pyflow capability-run --allow file.read --allow 'network.*' script.py
  pyflow capability-run --observe-only --audit-log audit.json script.py

Options:

- ``--allow CAPABILITY``: Allowed capability or glob pattern (repeatable)
- ``--audit-log PATH``: Write observed audit events to JSON log
- ``--observe-only``: Record classified events without denying operations

Server and Query Commands
-------------------------

**pyflow lsp**
~~~~~~~~~~~~~~

Start the Language Server Protocol (LSP) server over stdio using Content-Length framed JSON-RPC 2.0.

::

  pyflow lsp --root /path/to/project --mode full

Options:

- ``--root PATH``: Project root directory
- ``--mode {basic,full,advanced}``: Analysis depth mode (default: ``full``)

**pyflow mcp**
~~~~~~~~~~~~~~

Start the Model Context Protocol (MCP) server over stdio using newline-delimited JSON-RPC 2.0.

::

  pyflow mcp --root /path/to/project --mode full

Options:

- ``--root PATH``: Project root directory
- ``--mode {basic,full,advanced}``: Analysis depth mode (default: ``full``)

**pyflow query**
~~~~~~~~~~~~~~~~

Run one-shot semantic queries against Python code without starting a daemon.

::

  pyflow query . --get-callgraph --pretty
  pyflow query . --get-callers package.module.function
  pyflow query module.py --get-type module 12 8
  pyflow query . --mode advanced --get-aliases variable_name

Names returned by ``--list-functions`` work for CFG and call queries,
including file-qualified module functions such as ``color.blend_rgb``.
Compiler scope markers are kept in internal identifiers and omitted from
public aliases; ambiguous short or nested names still require qualification.

Options:

- ``--list-functions``: List functions in source index
- ``--get-cfg FUNCTION``: Extract CFG using a listed function name, a qualified name, or an unambiguous suffix such as ``Class.method``. Ambiguous or missing names report candidates
- ``--get-callgraph``: Compute call graph
- ``--get-callers SYMBOL``: Find callers of a function
- ``--get-callees SYMBOL``: Find callees of a function
- ``--get-type MODULE LINE COL``: Query inferred type at source location
- ``--include-diagnostics``: With ``--get-type``, return an object containing
  ``type``, ``status`` (``complete``, ``partial``, or ``unavailable``), and
  structured ``diagnostics``. Without this option, the existing type/null JSON
  shape is preserved and partial type analysis is reported on stderr
- ``--get-aliases SYMBOL``: Query aliases and points-to information
- ``--mode {basic,full,advanced}``: Analysis mode (default: ``full``)
- ``--pretty``: Pretty-print JSON output
- ``--output, -o PATH``: Write query result to file

CLI output supports pipelines such as ``pyflow alias app.py --json | head``.
Closing the consumer ends output without a ``BrokenPipeError`` traceback.
The guard lives in ``main()`` and also covers legacy console scripts and
module execution, including output buffered until shutdown.

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
