# PyFlow CLI Options

This document matches the current `pyflow` command surface.

## Commands

- `optimize`: Run the analysis and optimization pipeline
- `callgraph`: Build a call graph from a single Python file
- `ir`: Dump AST, CFG, SSA, CDG, or DDG forms for specific functions
- `security`: Run pattern-based or semantic security checks
- `dataflow`: Run IFDS/IDE-backed dataflow analyses

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

## Security

```bash
pyflow security [OPTIONS] [TARGET ...]
```

Key options:
- `--engine`: `pattern` or `semantic`
- `--taint-engine`: `ast`, `ipa`, or `both`
- `--micro-bench PATH`
- `--format`: `text`, `json`, or `sarif`
- `--output`, `-o`
- `--exclude PATH1,PATH2,...`
- `--recursive`, `-r`
- `--verbose`, `-v`
- `--debug`, `-d`

## Dataflow

```bash
pyflow dataflow [OPTIONS] INPUT_PATH
```

Key options:
- `--function FUNCTION`
- `--analysis`: currently `taint`
- `--sources NAME [NAME ...]`
- `--sinks NAME [NAME ...]`
- `--sanitizers NAME [NAME ...]`
- `--format`: `text` or `json`
- `--recursive`, `-r`
- `--dependency-strategy`: `auto`, `stubs`, `noop`, `strict`, or `ast_only`
- `--verbose`, `-v`

`dataflow` exits with `1` when taint findings are reported and `0` otherwise.
