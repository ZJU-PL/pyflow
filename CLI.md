# PyFlow CLI Options

This document matches the current `pyflow` command surface.

## Commands

- `optimize`: Run the analysis and optimization pipeline
- `callgraph`: Build a call graph from a Python file or project directory
- `ir`: Dump AST, CFG, SSA, CDG, or DDG forms for specific functions
- `alias`: Run alias analysis (flow-sensitive heap or k-CFA pointer)
- `security`: Unified security analysis (dispatches to any of four engines)

## Optimize

```bash
pyflow optimize [OPTIONS] INPUT_PATH
```

`INPUT_PATH` may be a Python file or directory.

Key options:
- `--analysis`, `-a`: `all`, `cpa`, `ipa`, `shape`, or `lifetime`
- `--dependency-strategy`: `auto`, `stubs`, `noop`, `strict`, or `ast_only`
- `--recursive`, `-r`
- `--include PATTERN [PATTERN ...]`
- `--exclude PATTERN [PATTERN ...]`
- `--dump`, `-d`
- `--dump-ipa`
- `--dump-shape`
- `--suggest-only`
- `--apply-optimizations`
- `--experimental-inlining`
- `--opt-passes PASS1 [PASS2 ...]`
- `--list-opt-passes`
- `--no-opt-passes`
- `--output`, `-o`
- `--verbose`, `-v`

Available optimization passes:
`methodcall`, `lifetime`, `simplify`, `clone`, `argument_normalization`,
`cull_program`, `inlining` *(experimental, disabled by default)*, `load_elimination`, `store_elimination`, `dce`

## IR

```bash
pyflow ir [OPTIONS] INPUT_PATH
```

`INPUT_PATH` may be a Python file or directory.

Key options:
- `--dump-ast FUNCTION`
- `--dump-cfg FUNCTION`
- `--dump-ssa FUNCTION`
- `--dump-cdg FUNCTION`
- `--dump-ddg FUNCTION`
- `--dump-format`, choices: `text`, `dot`, `json`
- `--dump-output DIRECTORY`
- `--dependency-strategy`: `auto`, `stubs`, `noop`, `strict`, or `ast_only`
- `--recursive`, `-r`
- `--include PATTERN [PATTERN ...]`
- `--exclude PATTERN [PATTERN ...]`
- `--verbose`, `-v`

## Callgraph

```bash
pyflow callgraph [OPTIONS] INPUT
```

`INPUT` may be a Python file or a project directory.  When given a directory,
the entry point is auto-detected from ``pyproject.toml``, ``setup.py``,
``__main__.py``, or well-known filenames (``main.py``, ``app.py``, etc.).
Use ``--entry`` to override auto-detection.

```bash
pyflow callgraph input.py
pyflow callgraph /path/to/project/
pyflow callgraph /path/to/project/ --entry src/main.py
pyflow callgraph /path/to/project/ --dry-run
```

Key options:
- `--entry`: Entry point file relative to project root (directory input only)
- `--dry-run`: Print detected entry point without running analysis
- `--algorithm`, `-a`: `simple`, `constraint`, or `pycg`
- `--output`, `-o`
- `--verbose`, `-v`
- `--skip-stdlib`: Skip standard library modules in constraint analysis (default: on)
- `--no-skip-stdlib`: Include standard library modules
- `--context-sensitive`
- `--context-depth`
- `--fixpoint-max-iterations`
- `--no-fixpoint-warning`
- `--allocation-site-sensitive-instances`
- `--as-graph-output PATH`

`--as-graph-output` is only supported with `--algorithm constraint`.

## Alias

```bash
pyflow alias [OPTIONS] INPUT_PATH
```

`INPUT_PATH` may be a Python file or directory.

Key options:
- `--engine {flow-sensitive,kcfa}`: Analysis engine (default: flow-sensitive).
  `flow-sensitive` runs heap alias/escape analysis; `kcfa` runs k-CFA pointer analysis.
- `--k N`: k-CFA context sensitivity depth (kcfa engine only, default: 1)
- `--recursive`, `-r`: Recursively analyze Python files in a directory
- `--json`: Output machine-readable JSON instead of human-friendly text
- `--verbose`, `-v`: Include per-entry details

## Supply Chain

```bash
pyflow supply-chain <sbom|audit> [TARGETS ...]
```

Local-first supply-chain analysis for Python packages. It performs no package
index queries. Scans package metadata (METADATA and RECORD), PEP 621 and Poetry
projects, requirements/constraints files, `pylock.toml`, `uv.lock`,
`poetry.lock`, `pdm.lock`, `Pipfile.lock`, setup metadata, and package archives.
Known-vulnerability matching accepts caller-controlled local OSV JSON, JSONL,
or directory snapshots.

### Commands

- \`sbom\`: Generate CycloneDX 1.7, SPDX 2.3, or requirements output
- \`audit\`: Report dependency, license, archive, integrity, install-script,
  source-provenance, and known-vulnerability findings

### Common options

- \`--recursive\`, \`-r\`: Scan directories recursively
- \`--exclude PATH1,PATH2,...\`: Comma-separated paths to exclude
- \`--output\`, \`-o FILE\`: Output file (default: stdout)
- \`--max-archive-depth N\`: Limit nested archive inspection (default: 3)
- \`--max-archive-mb N\`: Limit compressed archive input size (default: 5000)
- \`--max-archive-members N\`: Limit entries per archive (default: 10000)
- \`--max-archive-member-mb N\`: Limit one expanded archive member
- \`--max-archive-expanded-mb N\`: Limit total expanded archive content
- \`--max-compression-ratio N\`: Reject suspiciously compressed members
- \`--max-manifest-mb N\`: Limit metadata and manifest input size
- \`--max-scan-entries N\`: Limit total directory entries inspected
- \`--python-version\`, \`--platform\`, \`--implementation\`: Target PEP 508
  marker environment
- \`--extra NAME\`: Select a dependency extra; repeatable

### SBOM-specific options

- \`--format\`: `cyclonedx-json`, `spdx-json`, or `requirements`
- \`--deterministic\`: Derive IDs from content and use `SOURCE_DATE_EPOCH`
- \`--schema FILE\`: Validate JSON against a pinned local official schema
- \`--allow-incomplete\`: Do not return exit code 2 for high-severity scan
  errors that may make the inventory incomplete

### Audit-specific options

- \`--format\`: \`text\` (default), \`json\`, or \`sarif\`
- \`--license-policy FILE\`: JSON license allowlist, either an array or an
  object with `allowed_licenses` and optional `allowed_exceptions` arrays
- \`--skip-license-audit\`: Disable missing/disallowed license findings
- \`--osv-database PATH\`: Local OSV JSON, JSONL, or directory; repeatable
- \`--osv-max-age-days N\`: Enforce vulnerability snapshot freshness
- \`--require-osv-checksum\`: Require SHA-256 sidecars for OSV files
- \`--vex FILE\`: Apply CycloneDX VEX or OpenVEX; repeatable
- \`--reachability\`: Add conservative source-import evidence without treating
  absent imports as proof of non-reachability
- \`--import-map FILE\`: Distribution-to-import-name mapping for reachability
- \`--policy FILE\`: Apply reviewed exceptions with mandatory reason and expiry
- \`--baseline FILE\`, \`--write-baseline FILE\`: Read or create finding-ID
  baselines
- \`--protected-package NAME\`: Detect edit-distance typosquatting; repeatable
- \`--attestation FILE\`, \`--trusted-builder ID\`: Verify digest-bound
  in-toto/SLSA provenance
- \`--require-provenance\`, \`--require-dsse\`: Enforce provenance presence
  and envelope policy. Cryptographic identity verification is performed by the
  Sigstore options below.
- \`--sigstore-bundle ARTIFACT=BUNDLE\`, \`--cert-identity\`,
  \`--cert-oidc-issuer\`: Verify local Sigstore bundles with the official CLI
- \`--fail-on LEVEL\`: Lowest severity producing a non-zero exit; one of
  `low`, `medium`, `high`, `critical`, or `none` (default: `high`)

## Security

```bash
pyflow security [OPTIONS] [TARGET ...]
```

Unified security analysis frontend. Dispatches to one of four engines depending on
``--engine``. ``TARGET`` may be one or more Python files or directories.

### Engine selection

- ``--engine ast-scanner`` — fast AST pattern matching (Bandit-style), no
  analysis pipeline required (default).
- ``--engine ast-dataflow`` — fixed-point taint dataflow over the Python AST
  and interprocedural function summaries. It preserves source kinds, applies
  kind-scoped sanitizers, and reports typed findings with completion diagnostics.
- ``--engine ifds`` — IFDS solver over CFG supergraphs.  Interprocedural,
  flow-sensitive.  **Requires ``--function``.**
- ``--engine cpg`` — CPG-based context-sensitive taint analysis with heap-aware
  alias tracking.

### Common options

- ``--sources NAME [NAME ...]`` — taint source function names
- ``--sinks NAME [NAME ...]`` — taint sink function names
- ``--sanitizers NAME [NAME ...]`` — taint sanitizer function names
- ``--format``: ``text``, ``json``, or ``sarif``
- ``--output``, ``-o FILE``
- ``--recursive``, ``-r``
- ``--exclude PATH1,PATH2,...``
- ``--verbose``, ``-v``
- ``--debug``, ``-d``

### Engine-specific options

- ``--analysis`` (IFDS only): ``taint`` (default) or ``typestate`` — selects the
  IFDS analysis to run
- ``--function FUNCTION`` — entry function (required for ``--engine ifds``)
- ``--framework FRAMEWORK [FRAMEWORK ...]`` — framework rule pack(s) for taint
  sources/sinks/sanitizers (shared by the ``ast-dataflow``, ``cpg``, and ``ifds``
  engines).
  Pass with no values to auto-detect packs from imports.
  (choices: ``aiohttp``, ``cloud``, ``concurrency``, ``django``, ``falcon``,
  ``fastapi``, ``flask``, ``injection``, ``network``, ``nosql``, ``pandas``,
  ``requests``, ``serialization``, ``sql``, ``sqlalchemy``, ``stdlib``,
  ``tornado``, ``wtforms``, ``xml``)
- ``--registry-path`` — load custom rule-pack JSON file(s) or directories
  (``ast-dataflow``, ``cpg``, and ``ifds`` engines)
  using the strict schema-v2 format documented in
  ``docs/taint-rule-packs-v2.md``. Only schema version 2 is accepted.
- ``--typestate-protocol PROTOCOLS`` — typestate protocols for
  ``--analysis typestate``. May be repeated; supports ``resource``,
  ``python-builtins``, ``file``, ``socket``, ``lock``, ``transaction``
- ``--cpg-max-states N`` / ``--cpg-max-seconds N`` — stop CPG propagation at
  an explicit budget and return ``partial`` status rather than silent truncation
- ``--cpg-context-depth N`` — CPG call-string depth (default: 3)

The ``security`` command exits with ``1`` when findings are reported and ``0``
otherwise.
