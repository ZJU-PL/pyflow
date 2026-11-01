# PyFlow CLI Options

This document matches the current `pyflow` command surface.

## Commands

- `optimize`: Run the analysis and optimization pipeline
- `callgraph`: Build a call graph from a Python file or project directory
- `ir`: Dump MIR programs or AST, CFG, SSA, CDG, DDG, and GIR functions
- `alias`: Run alias analysis (flow-sensitive heap or k-CFA pointer)
- `concolic`: Generate branch-covering inputs and check simple postconditions
- `security`: Unified security analysis (dispatches to any of four engines)

## Optimize

```bash
pyflow optimize [OPTIONS] INPUT_PATH
```

`INPUT_PATH` may be a Python file or directory.

Class-only modules also run the analysis pipeline. Annotated assignments
(`x: int = 1024` and annotation-only declarations) preserve their targets,
annotation effects, and initializer dependencies through simplify/DCE.
Argument normalization leaves a candidate unchanged when required analysis
facts are unavailable and reports the skipped candidate count.

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
- `--emit-optimized PATH`: Write optimized Python copies; without output flags the command prints an analysis summary and suggested output commands
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
- `--dump-mir [SCOPE]`: Dump the seven-instruction MIR program, optionally selecting a scope
- `--mir-view {source,full}`: Text/DOT default to compact source inspection; JSON defaults to the full view
- `--mir-import-policy {strict,opaque}`: Imports default to opaque boundaries. JSON exports are marked `status: partial` whenever anything is unmodelled; pass `--mir-import-policy strict` (which follows imports) to require complete semantics
- `--list-functions`: List available function names discovered in the input
- `--dump-ast [FUNCTION]`: Dump AST for the specified function, or all functions if omitted or '*'
- `--dump-cfg [FUNCTION]`: Dump CFG for a qualified function or unambiguous short name, or all functions if omitted or '*'
- `--dump-ssa [FUNCTION]`: Dump SSA form for the specified function, or all functions if omitted or '*'
- `--dump-cdg [FUNCTION]`: Dump Control Dependence Graph for the specified function, or all functions if omitted or '*'
- `--dump-ddg [FUNCTION]`: Dump Data Dependence Graph for the specified function, or all functions if omitted or '*'
- `--dump-gir [FUNCTION]`: Dump Lian-compatible GIR for the specified function, or all functions if omitted or '*'
- `--dump-format`, choices: `text`, `dot`, `json`
- `--dump-output DIRECTORY`: Persist artifacts here; omitted dumps go to stdout and leave the working directory untouched
- `--dependency-strategy`: `auto`, `stubs`, `noop`, `strict`, or `ast_only`
- `--recursive`, `-r`
- `--include PATTERN [PATTERN ...]`
- `--exclude PATTERN [PATTERN ...]`
- `--verbose`, `-v`

MIR dumps lower source directly without executing target modules. Omitting
`SCOPE` dumps source CFGs for text/DOT, or the full program for JSON. Use
`--mir-view full` to inspect runtime CFGs. Source views lower only the selected
input files, retaining imports and unsupported expressions as explicit opaque
boundaries; diagnostics mark these views partial and are appended to text
artifacts (JSON embeds them under `diagnostics`). They are inspection artifacts,
not executable or semantically complete programs. A complete export requires
`--mir-import-policy strict`, which follows and validates the import graph and
therefore rejects modules that have no MIR model.
A scope can be a qualified name or an unambiguous function name.
MIR supports `text`, `json`, and `dot` output. For recursive directory input,
output paths preserve the source directory structure.

```bash
pyflow ir input.py --dump-mir --dump-output out/
pyflow ir input.py --dump-mir input.worker --dump-format json --dump-output out/
pyflow ir project/ --dump-mir --recursive --dump-format dot --dump-output out/
```

## Callgraph

```bash
pyflow callgraph [OPTIONS] INPUT
```

`INPUT` may be a Python file or a project directory.  When given a directory,
the entry point is auto-detected from ``pyproject.toml``, ``setup.py``,
``__main__.py``, or well-known filenames (``main.py``, ``app.py``, etc.).
Use ``--entry`` to override auto-detection.

Discovery also recognizes root/nested ``__main__.py``, conventional files
under ``src``/``lib``, and a unique script with an ``if __name__ == '__main__'``
guard at the project/import root. Nested guarded scripts are listed as candidates
and require explicit selection. Hidden environments and tests are excluded. Multiple candidates still
require selection; library projects can use ``callgraph -r`` or ``capabilities -r``.
Selection prefers metadata, then ``__main__.py``, then main guards; legacy
filename conventions are a final fallback. Application-specific names such as
``train.py`` and ``server.py`` do not establish an entry without other evidence.

```bash
pyflow callgraph input.py
pyflow callgraph /path/to/project/
pyflow callgraph /path/to/project/ --entry src/main.py
pyflow callgraph /path/to/project/ --dry-run
pyflow callgraph input.py --algorithm pycg-mir
pyflow callgraph input.py --format json
```

Key options:
- `--entry`: Entry point file relative to project root (directory input only)
- `--dry-run`: Print detected entry point without running analysis
- `--algorithm`, `-a`: `simple`, `constraint`, `pycg`, or `pycg-mir` (default: `constraint`)
- `--recursive`, `-r`: Analyze every project source file with constraint analysis; works for libraries without a unique entry
- `--include-external`: Include third-party dependency source (default: project sources only)
- `--format {text,json}`: Text is the default; JSON is a deterministic `{caller: [callees]}` map, including empty callee lists for leaf nodes
- `--output`, `-o`
- `--verbose`, `-v`
- `--skip-stdlib`: Skip standard library modules in constraint analysis (default: on)
- `--no-skip-stdlib`: Include standard library modules in constraint analysis
- `--context-sensitive`
- `--context-depth`
- `--fixpoint-max-iterations`
- `--no-fixpoint-warning`
- `--allocation-site-sensitive-instances`
- `--as-graph-output PATH`

`--as-graph-output` is only supported with `--algorithm constraint`.

`pycg-mir` is the native PyCG-style assignment-graph fixed-point analysis over
MIR. It is flow-, path-, and context-insensitive, and requires no optional
upstream `pycg` package. The separate `pycg` algorithm continues to use that
optional package. Context-sensitivity and fixed-point control options, including
`--context-sensitive` and `--fixpoint-max-iterations`, are rejected for
`pycg-mir`; direct MIR analysis APIs expose convergence information and iteration
limits. See [the MIR documentation](docs/source/ir/mir.rst) for details and limitations.
The stdlib flags affect only constraint analysis and do not extend MIR's
supported import graph.

## Query

```bash
pyflow query color.py --list-functions
pyflow query color.py --get-cfg color.blend_rgb
pyflow query color.py --get-type color 580 5 --include-diagnostics
```

Listed names and unambiguous short names work for CFG queries. Type queries
preserve their existing type/null JSON by default. `--include-diagnostics`
adds `type`, `status`, and structured `diagnostics`; partial type analysis
also produces a warning on stderr when the option is omitted. A position with
no expression type returns null. Source/stub collection failures preserve
usable facts and appear in diagnostics instead of aborting type queries.

## Alias

```bash
pyflow alias [OPTIONS] INPUT_PATH
```

`INPUT_PATH` may be a Python file or directory.

Key options:
- `--engine {flow-sensitive,kcfa}`: Analysis engine (default: flow-sensitive).
  `flow-sensitive` runs heap alias/escape analysis; `kcfa` runs k-CFA pointer analysis.
- `--k N`: k-CFA context sensitivity depth (kcfa engine only, default: 1)
- `--max-seconds N`: Time budget across all input files (default: 30). Exhaustion reports partial analysis and preserves completed files
- `--recursive`, `-r`: Recursively analyze Python files in a directory
- `--json`: Output machine-readable JSON instead of human-friendly text
- `--verbose`, `-v`: Include per-entry details

## Concolic

```bash
pyflow concolic [OPTIONS] INPUT_PATH
```

Explores feasible paths in one function by replaying concrete integer inputs
and using Z3 to flip each observed branch. The default entry function is
`main`; use `--entry` to select another function. It requires the optional
`z3-solver` dependency, available through `pip install -e ".[concolic]"`.

```bash
pyflow concolic target.py --entry parse --inputs '[0, 0]' --json
```

Key options:
- `--entry NAME`: Function to explore (default: `main`)
- `--inputs JSON_ARRAY`: Initial integer arguments; defaults to zero for each
  positional parameter
- `--max-iterations N`: Maximum concrete executions (default: 50)
- `--max-loop-iterations N`: Concrete loop cap per `while` statement
  (default: 100)
- `--check-contracts`: Solve supported PEP 316 `post:` clauses for a
  counterexample
- `--json`: Emit generated inputs and execution results as JSON

The supported subset includes integer, float, string, and list parameters;
it also handles byte-string literals and common byte operations. Arithmetic
(including `//`, `%`, and `int(a / b)`), comparisons, and Boolean
operators; `if`, `while`, `for`, `break`, `continue`, and conditional
expressions; local function/method/class calls with defaults, keyword
arguments, positional-only and keyword-only parameters, and `*args`/`**kwargs`;
lambda, nested callable values, and function decorators (including
transparent `functools.cache`/`lru_cache`/`wraps`); list/tuple/dictionary literals,
unpacking, subscripts, slices, mutation, dictionary union, set algebra and common set methods,
list sorting with `key`/`reverse`, f-strings, assignment expressions, percent formatting, assertions, and
`match`/`case` (including dataclass and literal-`__match_args__`
class patterns); `len`, `int`, `str`, `list`, `dict`, `range`,
`sum`, `min`, `max`, `abs`, `bool`, `float`, `pow`, `round`, `divmod`, `ord`,
`chr`, `set`, `tuple`, `iter`, `next`, `enumerate`, `zip`, `sorted`, `any`, and
`all`; `repr`, `ascii`, `format`, `type`,
`isinstance`, `getattr`, `hasattr`, and `setattr`; list/set/
dictionary/generator comprehensions; local, package, and
relative imports (including local `importlib.import_module()`), and safe computed module constants; eagerly
materialized `yield`/`yield from` generators with consumable iterator behavior, eager async functions, `async for`, and async
comprehensions and `async with`; and
`re.compile(...).match/search(...).group()`; inherited classes and class variables, `super()`,
static/class methods, properties (including `cached_property`), supported class decorators, and basic dataclasses (including `asdict`,
`astuple`, and `replace`); context managers;
and `try`/`except`/`finally`, simple `except*`, and exception chaining for conversion, lookup, and explicit target
exceptions. Structured summaries currently cover `base64`, `bisect`, `collections.Counter`/`namedtuple`, `copy`,
`dataclasses`, deterministic `datetime`, `functools.partial`, `hashlib`,
`heapq`, `itertools`, `json`, `math`, `operator`, `os.path`, lexical
`pathlib.Path`, basic `enum.Enum`/`IntEnum`/`StrEnum`, `statistics`, `urllib.parse`, and `contextlib.suppress`/`nullcontext` plus supported `contextmanager`/`asynccontextmanager` decorators. Unsupported operations produce a clear error
rather than silently executing arbitrary target code.

With `--check-contracts`, a single-line PEP 316 clause such as
`post: __return__ >= 0` is evaluated after every run. Parameters and
`__return__` are available to the clause; discovered violations are emitted as
structured counterexamples. Snapshot values such as `__old__` are not yet
supported.

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

SBOM generation defaults to reporting success even for unpinned or incomplete
inventories. Completeness remains visible in document metadata and stderr.
`--exit-code-policy strict` / `--require-complete` enforce completeness with
exit code 2; missing or unreadable input remains an error under either policy.

- \`--format\`: `cyclonedx-json`, `spdx-json`, or `requirements`
- \`--deterministic\`: Derive IDs from content and use `SOURCE_DATE_EPOCH`
- \`--schema FILE\`: Validate JSON against a pinned local official schema
- \`--allow-incomplete\`: Compatibility override for strict completeness gating of high-severity scan
  findings that may make the inventory incomplete

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
  flow-sensitive. Files are entries; directory entries are discovered automatically. Use repeatable ``--entry PATH`` to select them.
- ``--engine cpg`` — CPG-based context-sensitive taint analysis with heap-aware
  alias tracking.

### Common options

- ``--sources NAME [NAME ...]`` — taint source function names
- ``--sinks NAME [NAME ...]`` — taint sink function names
- ``--sanitizers NAME [NAME ...]`` — taint sanitizer function names
- ``--format``: ``text``, ``json``, ``sarif``, ``csv``, ``custom``, ``html``, ``screen``, ``xml``, or ``yaml`` (IFDS/CPG support text, JSON, and SARIF)
- ``--json-schema {legacy,unified}``: Keep existing engine-specific JSON by default, or use a common versioned envelope with ``findings``, lowercase severity/confidence, location, errors, diagnostics, and statistics
- ``--output``, ``-o FILE``
- ``--recursive``, ``-r``: Directory targets are scanned recursively automatically by every scanning engine; IFDS continues to discover/select entry files
- ``--exclude PATH1,PATH2,...``: Repeatable, supports multiple paths and globs; ``tests``, ``./tests``, ``tests/``, and absolute paths work
- ``--no-default-excludes``: Include tests, hidden directories, virtual environments, and build outputs during directory discovery
- ``--severity {low,medium,high,critical}``: Minimum severity to report
- ``--confidence {low,medium,high}``: Minimum confidence to report
- ``--skip-rule RULE [RULE ...]`` / ``--skip``: Disable rule IDs or scanner rule names; repeated flags and commas work
- ``--no-deduplicate``: Report overlapping AST rules individually instead of folding known equivalent vulnerability families at the same AST location
- ``--baseline REPORT.json``: Suppress previous findings by rule, source file, and line
- ``--fail-on {none,low,medium,high,critical}`` / ``--fail-on-severity``: Return 1 for reported findings at this threshold
- ``--exit-code-policy {report,findings}``: Report normally by default, or enable scanner-style findings/completeness gating
- ``--verbose``, ``-v``
- ``--debug``, ``-d``

### Engine-specific options

- ``--analysis`` (IFDS only): ``taint`` (default), ``nullness``, ``typestate``, or ``class-pollution`` — selects the
  IFDS analysis to run
- ``--entry PATH`` — IFDS entry file relative to the project root (repeatable)
- ``--config PATH`` — IFDS JSON configuration; defaults to ``pyflow.json`` in the target project/file directory
- ``--ast-unknown-call-policy {preserve,havoc}``: AST-dataflow defaults to preserving real input kinds across unknown calls and reports those assumptions as partial; ``havoc`` introduces all possible source kinds conservatively
- ``--ast-entry-source-kind KIND``: AST-dataflow entry parameter kind (repeatable; default: ``user_input``)
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
  a budget and return ``partial`` status (defaults: 50000 states, 30 seconds per target including construction)
- ``--cpg-context-depth N`` — CPG call-string depth (default: 3)

The default ``report`` policy returns 0 for complete/partial reports. Invalid
input returns 2, failed analysis returns 4. ``findings`` returns 1 for findings
and 3 for partial/cancelled coverage. ``--fail-on`` applies to findings after
severity/confidence, rule, and baseline filtering. A report marked ``partial``
must not be treated as a complete clean scan. Rule failures include rule IDs,
filenames, and lines in JSON ``errors`` and SARIF invocation notifications.
Progress and diagnostics use stderr, so JSON stdout can be piped directly.
This includes callers using older console scripts that invoke ``main()`` and
module execution via ``python -m pyflow.cli.main``; broken pipes are handled
before interpreter shutdown.

Known AST overlaps such as Flask debug mode (B202/F101/F109) produce one finding
at an exact source span, retaining the strongest severity/confidence and all
rule evidence in ``related_rules`` (SARIF: ``properties.relatedRules``). Text
reports list the related IDs. Different calls on the same line and unrelated
vulnerability families remain separate. Severity/confidence filters, rule
suppression, and baselines still apply. Report metrics count displayed findings;
``raw_findings`` and ``folded_findings`` disclose the underlying rule counts.

Example project configuration (CLI arguments override configured values):

```json
{
  "analysis": "taint",
  "entry": ["app.py"],
  "frameworks": ["stdlib", "flask"],
  "unknown_call_policy": "preserve",
  "solver_options": {"max_seconds": 30, "max_path_edges": 100000}
}
```

```bash
pyflow security project/ -r --severity medium --skip-rule A105 --fail-on high
pyflow security project/ -r --format json --json-schema unified > report.json
pyflow security project/ -r --baseline report.json --format json --json-schema unified
pyflow callgraph library/ -r
pyflow capabilities library/ -r --import-depth 0 --format json
```

``capabilities -r`` analyzes every discovered project source file as its own
entry (one whole-project analysis each); without it, ``--entry`` selects one
root. Explicit file targets are analyzed even when they live in directories
normally excluded from discovery. JSON and text reports include the entry
coverage (`entries_total`, `entries_analyzed`, `entries_failed`,
`entries_skipped`), so a budget-truncated run is never mistaken for a complete
project inventory.

Capabilities use `--max-iterations` (default: 20000 per entry) and
`--max-seconds` (default: 30 across all entries). Budget exhaustion preserves
completed reports and adds partial diagnostics. Each report also carries a
`coverage` block with the solver's completeness flags; `complete` means only
that no unknown/unsupported/budget diagnostic was emitted. Alias and capabilities time
budgets interrupt synchronous Unix CLI work, including frontend work; other
platforms/embedded threads rely on cooperative engine limits and an elapsed
time check. JSON progress is sent to stderr.

AWS secret/region checks require SDK and binding evidence; non-secret strings,
`None` defaults, and unrelated resource methods are not AWS findings. Explicit
valid regions, including `us-east-1`, are accepted. Django authentication hints
require request/response evidence and are low-confidence review suggestions;
URL or middleware access controls can still provide authentication.
