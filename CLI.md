# PyFlow CLI Options

This document matches the current `pyflow` command surface.

## Commands

- `optimize`: Run the analysis and optimization pipeline
- `callgraph`: Build a call graph from a single Python file
- `ir`: Dump AST, CFG, SSA, CDG, or DDG forms for specific functions
- `heap`: Run heap analysis commands
- `taint`: Unified taint analysis (dispatches to any of four engines)

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
`cull_program`, `inlining`, `load_elimination`, `store_elimination`, `dce`

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
pyflow callgraph [OPTIONS] INPUT_FILE
```

`INPUT_FILE` must be a Python file.

Key options:
- `--algorithm`, `-a`: `simple`, `constraint`, or `pycg`
- `--output`, `-o`
- `--verbose`, `-v`
- `--context-sensitive`
- `--context-depth`
- `--fixpoint-max-iterations`
- `--no-fixpoint-warning`
- `--allocation-site-sensitive-instances`
- `--as-graph-output PATH`

`--as-graph-output` is only supported with `--algorithm constraint`.

## Taint

```bash
pyflow taint [OPTIONS] [TARGET ...]
```

Unified taint analysis frontend. Dispatches to one of four engines depending on
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

- ``--function FUNCTION`` — entry function (required for ``--engine ifds``)
- ``--framework FRAMEWORK [FRAMEWORK ...]`` — framework rule pack(s) for CPG
  (choices: ``django``, ``flask``, ``fastapi``, ``sqlalchemy``, ``stdlib``,
  ``cloud``, ``injection``, ``network``, ``nosql``, ``requests``, ``sql``)
- ``--registry`` — activate all framework rule packs (only for ``--engine ifds``)

The ``taint`` command exits with ``1`` when findings are reported and ``0``
otherwise.
