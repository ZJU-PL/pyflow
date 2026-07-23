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

Local-only supply-chain analysis for Python packages. Works offline — no
package index queries. Scans package metadata (METADATA, RECORD,
pyproject.toml, poetry.lock, requirements.txt), archives (wheel, zip, tar),
and distribution metadata for structural issues.

### Commands

- \`sbom\`: Generate a CycloneDX 1.3 SBOM document from local metadata
- \`audit\`: Report structural anomalies in archives and distribution metadata

### Common options

- \`--recursive\`, \`-r\`: Scan directories recursively
- \`--exclude PATH1,PATH2,...\`: Comma-separated paths to exclude
- \`--output\`, \`-o FILE\`: Output file (default: stdout)

### Audit-specific options

- \`--format\`: \`text\` (default) or \`json\`

## Security

```bash
pyflow security [OPTIONS] [TARGET ...]
```

Unified security analysis frontend. Dispatches to one of four engines depending on
``--engine``. ``TARGET`` may be one or more Python files or directories.

### Engine selection

- ``--engine ast-scanner`` — fast AST pattern matching (Bandit-style), no
  analysis pipeline required (default).
- ``--engine cpa`` — CPA-backed taint propagation on the AST using PyFlow's
  analysis pipeline (IPA/CPA/StoreGraph).
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
  sources/sinks/sanitizers (supports both ``--engine cpg`` and ``--engine ifds``).
  Pass with no values to auto-detect packs from imports.
  (choices: ``aiohttp``, ``cloud``, ``concurrency``, ``django``, ``falcon``,
  ``fastapi``, ``flask``, ``injection``, ``network``, ``nosql``, ``pandas``,
  ``requests``, ``serialization``, ``sql``, ``sqlalchemy``, ``stdlib``,
  ``tornado``, ``wtforms``, ``xml``)
- ``--registry-path`` — load custom rule-pack JSON file(s) or directories (both IFDS and CPG engines)
- ``--typestate-protocol PROTOCOLS`` — typestate protocols for
  ``--analysis typestate``. May be repeated; supports ``resource``,
  ``python-builtins``, ``file``, ``socket``, ``lock``, ``transaction``

The ``security`` command exits with ``1`` when findings are reported and ``0``
otherwise.
