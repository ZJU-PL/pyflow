# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `pyflow capabilities` now audits every function and method scope in the
  entry module by default, so uncalled library functions and framework
  handlers are reported.  `--reachable-only` restores call-graph reachability.
  `-r` defaults to `--import-depth 0`, and package-directory targets use their
  parent as the import root.
- Capability models now cover additional stdlib and ecosystem file APIs,
  including `os.chdir`/`link`/`symlink`/`utime`, `os.fdopen`, path link and
  metadata methods, `PIL.Image.open`, `pandas.read_*`, `numpy.load`,
  `aiofiles.open`, `openpyxl.load_workbook`, `boto3.client`, and
  `yaml.load_all`.
- `pyflow supply-chain audit --reachability-source` separates application code
  from an installed package tree during vulnerability reachability annotation.

### Fixed

- k-CFA pointer analysis no longer diverges on same-name imports
  (`from datetime import datetime`), grows unbounded native access paths, or
  loses positional-only/default argument flow.  It now models dataclass and
  NamedTuple fields, enum members, property getters, starred/sliced/mutated
  containers, in-place operators, star imports, `typing.cast`, `copy.*`,
  `itertools.chain`, and `globals()`/`locals()` more precisely.  Constant
  container indices remain precise for literals, and `pyflow alias --engine
  kcfa` now resolves project imports with `--project-root` / `--import-depth`.
- Capability analysis no longer treats `pathlib.Path` values as resource
  handles, no longer reports method-chain aliases such as
  `sys.argv.__getitem__.<return>` as environment reads, and no longer reports
  return-only calls (`copy.copy`, `typing.cast`) as unanalysed escape
  boundaries.  Handle methods returned by `Path.open()` and
  `tempfile.NamedTemporaryFile()` are now reported.
- Single-file capability audits retry with project imports when the fast
  entry-only pass finds nothing but the file imports project-local modules;
  findings are scoped to the requested file unless ``--include-imports`` is
  passed.  This avoids both empty reports for local clients and dependency
  finding floods in small files.
- Capability registry path matching and solver statistics are cached.  Large
  heaps previously rescanned every registry pattern for the same object path
  and recomputed full points-to statistics several times per report.
- Class-heavy modules no longer spend most of their time dumping complete AST
  bodies for every synthesized solver identity; stable tokens use source spans
  when available.  Incomplete-variable reasons are also deduplicated with a
  set, avoiding quadratic list scans in native-call-heavy analyses.
- Runtime auditing no longer classifies importlib's own source/pyc reads,
  compilation, or bytecode unmarshalling as user `file.read`, `code.execute`,
  or `deserialization.unsafe` operations; only user code executed during an
  import is attributed to the importer.  `capability-run` disables bytecode
  cache writes for the guarded run.
- Runtime allow-lists treat static `network.io` as covering the underlying
  `network.socket`/`network.dns` audit events, so policies derived from static
  findings can permit HTTP requests without separately allowing socket events.
- Runtime auditing now records and enforces every capability required by an
  operation; `r+`/`w+` and `os.O_RDWR` require both `file.read` and
  `file.write`, rather than being recorded as write-only.
- Environment item access no longer emits duplicate read and call findings for
  `os.environ.__getitem__`/`__setitem__`.
- Path-method findings now canonicalize synthetic `pathlib.Path.<return>`
  access paths, matching direct `pathlib.Path.exists`/`read_text` findings.
- Single-file fast paths now cover any absolute-import module with no
  registry capability call and no capability-module import, not only
  re-export-only files; relative imports remain fully analyzed.
- Re-export-only modules with no calls and no capability-module imports skip
  the full local import graph, avoiding multi-second scans for package
  `__init__` files.
- Single-file audits of large modules with no registry-relevant calls use an
  entry-only, reachable-only fast path instead of resolving the entire local
  package graph; explicit `--include-imports` retains the deeper scan.
- Uncalled-scope auditing matches registry names exactly (or by explicit
  wildcard prefix) instead of seeding every function containing a name such as
  `get_start`, and generic method names (`items`, `get`, `read`, ...) require
  a full registry-path match.  This stops ordinary `dict.items()` calls from
  triggering expensive scope audits in ML modules.
- Native helper chains such as `im = im.convert(...)` now collapse repeated
  `method.<return>` cycles instead of growing an unbounded access path and
  exhausting the solver budget.  This restores findings for files that
  previously spent the whole budget without producing a result.
- Network response-data filtering now keys off response extraction methods
  rather than the number of native-return hops, so chained client methods such
  as `client.with_options().get()` keep their `network.io` finding.
- Capability findings no longer split one async context-manager request into
  `$await_result`/`__aenter__`/wildcard aliases, and response parsing
  (`post(...).json()`, `resp["token"]`, chained `.json().get()`) or derived
  environment strings (`os.environ.get(...).split(...)`) are no longer
  reported as fresh capability transfers.  Uncalled functions with annotated `Path` parameters now resolve
  path methods.
- Capability source reading honors UTF-8 BOM and PEP 263 coding cookies, and a
  `RecursionError` on deeply nested expressions is reported as an unsupported
  entry instead of crashing the CLI.  Recursive diagnostics are deduplicated.
- Typeinfo fixed-point iteration now guards `*args` and `**kwargs` against
  recursive container re-wrapping on unresolved annotations, propagates walrus
  `:=` bindings across non-first `BoolOp` operands and comprehensions, invalidates
  stale `is_subtype` LRU caches across fixed-point iterations and member assignments,
  treats `.pyi` declarations and docstring-only functions as stubs rather than
  implicit `None` returns, resolves re-exported package classes without synthesizing
  incompatible nominal types, accepts `TupleType` in `list[tuple]` container checks,
  chains generic type parameter substitutions for inherited methods and constructors,
  resolves TypedDict subscripts with literal key variables, indexes expressions
  inside f-strings, fixes subtype distance for virtual ABCs, checks
  `issubclass(observed, Callable)` in `validate_observed_types`, honors
  `# type: ignore` across all type-checking diagnostics, resolves common standard
  library namespaces (`argparse`, `decimal`, `enum`, `urllib.parse`, `ssl`, `socket`,
  `hashlib`, etc.) in type annotations, enables covariant tuple subtyping in generic
  containers, enables the numeric tower on `TypeInfoService`, and
  validates nested `TypedDict` literal shapes against inner `TypedDict` annotations,
  suppresses `unmodeled-context-manager` diagnostics when no `as` target variable is
  bound, recognizes Click CLI entrypoint functions invoked without arguments,
  inspects routine and method descriptor members on builtin class descriptors,
  permits empty dictionary literals in union yields to satisfy optional Mapping
  annotations, admits empty dictionary literals for mapping protocols,
  and tracks local variables initialized from fresh collections across returns
  while preserving the invariance of parameter aliases.
- Typeinfo now preserves `Any` through operators, keeps unresolved external
  annotation alternatives instead of replacing them with parameter defaults,
  treats `AnyStr` as a constrained type variable, and models `Literal` values
  through display, container checks, `TypedDict` fields, and overload
  selection.  This removes several false `annotation-mismatch` diagnostics on
  Flask, Rich, and FastAPI-style code.
- Typeinfo builtin and container models now handle `dict.copy()`, `dict(mapping)`,
  `list.sort()`/`reverse()`, `frozenset` methods, `max`/`min(default=)`,
  `sum(start=)`, `round(ndigits=)`, `dict.fromkeys(value=)`, negative powers,
  complex `abs`, and `pathlib.Path` division/home/cwd without losing types or
  truncating following statements.
- Typeinfo query results now record assignment/parameter targets, prefer the
  identifier at the start of attribute/operator expressions, honor `type:
  ignore` on return statements, and accept character columns for `pyflow query
  --get-type`.  `--include-diagnostics` is filtered to the queried module.
- Project-level type inference now reads files using PEP 263 encodings and
  isolates per-module failures such as `RecursionError` instead of aborting the
  whole project.
- Typeinfo stub loading now follows the standard typeshed third-party layout,
  resolves stub re-exports and star imports, and substitutes type arguments for
  generic stub methods.  Walrus, match-pattern, starred-unpacking, and nested
  class bindings are also narrowed or registered correctly.
- Additional typeinfo regressions found across Home Assistant, Scrapy, yt-dlp,
  scikit-learn, and other corpus projects are fixed: key-specific TypedDict
  methods and copies, dataclass `KW_ONLY`/`InitVar` pseudo-fields, NamedTuple
  helper members, enum subscription and literal overloads, `ParamSpec`
  forwarding, method-call argument locations for `type: ignore`, and loop
  `break`/`continue` environments.  Common stdlib models now cover datetime,
  regex, pathlib, os.path, itertools, functools.partial, queue,
  concurrent.futures, asyncio, contextlib, subprocess, shutil, logging,
  tempfile, contextvars, threading, and abstract containers.

- Deeply nested expressions no longer exhaust the Python stack while generating
  IR: the scope/name collectors, source-span scan, nested-code discovery,
  yield probe, comprehension capture probe, semantic-fact builders, catalog
  indexing, CFG fingerprint, flow analysis, and SSA scans now use explicit
  worklists, and binary/unary/attribute/subscript/call chains are lowered
  iteratively.  A 6,400-term `a + b + ...` expression now builds a CFG
  (previously ~450); SSA renaming is still bounded by the generic AST rebuild.
- Walrus bindings inside comprehensions and generator expressions now bind in
  the containing function (PEP 572): the comprehension writes a closure cell and
  the enclosing statement refreshes its local from it, so a later read no longer
  observes an undefined value.  The class-pollution analysis follows the same
  cell, keeping its comprehension getter summary intact.
- Whole-program IR dumps (`pyflow ir --dump-* '*' --dump-output DIR`) no longer
  overwrite artifacts when distinct procedures share a function name (for
  example `__getattr__` in several modules); colliding labels get a stable
  numeric suffix.
- SSA construction now records walrus targets embedded in `switch` conditions,
  `for` iterables, and type-switch cases, so a definition can no longer leak
  past the join where it should have a phi (for example `if (x := g()): break`
  inside a loop).  `verify_ssa` also recognizes expression-level definitions,
  including the synthetic walrus introduced by chained comparisons, so
  `pyflow ir --dump-ssa` no longer rejects valid functions.
- Per-function CFG/SSA work is now scoped to the procedure being rewritten:
  catalog semantics, symbol/value indexes, block/edge indexes, and catalog
  verification are no longer recomputed over the whole program.  Dumping SSA
  for 100 trivial functions dropped from ~20 s to ~0.5 s and now scales
  linearly.  The CFG/SSA dumper also stops deep-copying the program catalog
  through nested `Code.ir_catalog` references.
- Augmented assignment evaluates its receiver and subscript once: `f().attr += 1`
  and `a[i()] += 1` no longer duplicate the call in the read and write halves.
- The dataflow IR (and therefore the DDG) binds the names of local `def` and
  `class` statements, so a factory returning a nested class/function no longer
  models the result as undefined.
- Class bodies resolve names from enclosing-function cells (CPython
  `LOAD_CLASSDEREF`) instead of lowering them to global reads.
- `try`/`except*` lowers each clause independently, so every matching handler is
  reachable from one exception group instead of only the first match.
- CPG construction now materializes non-leaf AST nodes and connects the full
  source parent/child relation, so `ast_children()` is usable for expressions
  instead of being limited to the few AST nodes that happened to have PDGs.
- Nested functions, lambdas, comprehensions, and lambdas/comprehensions in
  default arguments are now registered as IR code objects, so `pyflow ir` and
  CPG construction no longer silently omit nested code.
- DDG memory dependences now include attribute, subscript, and closure-cell
  reads/writes nested inside compound expressions (for example `y = obj.attr + 1`),
  reflect lowered `getattr`/`setattr`/`getitem`/`setitem`/`delitem` intrinsics,
  and use a wildcard location for dynamic subscript keys.  Unhashable literal
  keys no longer abort semantic construction.
- Fixed cyclic AST alias resolution in DDG memory keys (`a = b.x` followed by
  `b = a.y`) that previously raised `RecursionError` on real projects such as
  Hugging Face Transformers.
- DDG stable IDs/JSON node identities are now unique when several value versions
  share one catalog symbol or AST operation.
- CPG call edges now resolve method calls and direct calls to comprehensions,
  and no longer map `self.method()` in one class to a same-named method of an
  unrelated class.  `callees()` also accepts a function name, mirroring
  `callers()`.
- Predicate/control slots are no longer projected as CPG data dependences, and
  predicate-only control operations are pruned from the DDG.
- Reconciled documentation across Sphinx sources, CLI references, and tutorials with actual CLI options, default parameters, query APIs, and output schemas.
- Fixed DDG memory dependencies for lowered IR: slot keys now identify storage
  locations rather than individual value versions, so field reads/writes produce
  RAW, WAR, and WAW edges instead of dropping WAR/WAW and mislabeling WAW as RAW.
- Prevented stores from emitting spurious RAW edges through their implicit
  pseudo-read, and made memory-dependence propagation sparse and near-linear on
  large modules (for example, Rich's `examples/table_movie.py` dropped from
  roughly 12s to about 1s).
- Constraint call-graph presolve no longer treats an async or generator call
  as executing the callee body's `return`, so values like a coroutine's return
  are not attributed to the caller before the coroutine is awaited.
- DDG alias indexing and def-use edge labels now reuse per-shared-local-name
  work, keeping construction linear when copy propagation merges many locals
  into one node.
- Fixed a DCE/DDG crash (`'NoneType' object has no attribute 'canonical'`) when
  `Split.optimize()` removed an output slot but left a dangling split definition.
- CPG `defs` and `uses` indexes now expose source variables only, omit internal
  dataflow labels and compiler temporaries, and do not return duplicate nodes.
- CPG construction now reports `cpg-pdg-data-dependence-fallback` when DDG-derived
  data dependences are unavailable and only semantic def/use edges are used.
- Resolved Graphviz DOT generation syntax errors in `pydot.py` by properly quoting attribute values and node identifiers containing colons and special characters.
- Modeled the PEP 572 walrus operator (`:=`, `ast.NamedExpr`) during DataflowGraph and DDG construction to ensure local targets are defined and def-use chains are preserved.
- Handled `ast.Delete` in CFG SSA so that variable deletion unbinds locals and introduces `None` (undefined) into downstream control-flow joins and Phi nodes.
- Preserved generator function bodies in Dataflow DCE by recognizing yield expressions as observable live roots.
- Optimized DDG memory dependency fixed-point analysis to skip read-only and single-write memory locations and seed worklists with accessing operations.
- Enriched CFG clang-style text and JSON exports with loop index, iterator, and condition details for `ForIter`, `TypeSwitch`, and `State` blocks.
- Fixed GIR emission for `For`/`AsyncFor` loops with attribute or subscript targets (such as `for opt.weights in weights:`) and unpacked comprehension tuple targets into declared local variables.
- Preserved default argument expressions in `MakeFunction` for lambdas during AST conversion so def-use analysis and dataflow solvers track default value references.
- Optimized CFG transformation transaction AST node collection (`_ast_nodes`) with O(1) set lookups to eliminate quadratic scaling on large functions.
- Resolved a `RecursionError` during DataflowGraph construction on deeply nested context manager and exception blocks by traversing `State` parent chains iteratively with path compression.

- Supply-chain scans now report empty inventories, follow explicitly targeted
  virtualenvs and symlinked manifests, resolve setup.py requirements across
  platform files with bounded reads, and model Poetry/uv/Pipfile metadata,
  scopes, extras, markers, and indexes.
- Installed-tree audits ignore optional bytecode caches, shared namespace
  packages, data files, and metadata dependencies instead of emitting thousands
  of false positives; editable/VCS installs and unlisted startup hooks are now
  reported.
- Supply-chain SBOM and policy output preserves direct URLs and multiple
  markers, avoids conflicting requirement pins and wheel self-dependencies,
  records environment/completeness metadata, emits valid SPDX license values,
  and uses stable finding fingerprints and redacted requirement details.
- Bind static-method calls without injecting a receiver, and bound recursive return
  structures so recursive collection analyses converge.
- Accept wider annotated collection element types for fresh list, set, and dict
  expressions while preserving invariant checking for existing mutable values.
- Propagate dictionary key shapes through calls and returns for structural
  TypedDict validation, and resolve PEP 484/613 aliases.
- Resolve common standard-library annotation types from `itertools`, `pathlib`,
  `datetime`, `re`, `uuid`, `types`, and `contextvars`.
- Bound automatic project type-inference discovery to project and workspace roots,
  avoiding recursive interpretation of standard-library and external packages.
- Model generic constructor specialization, Self, PEP 695 declarations, cast,
  NewType identity constructors, TypedDict fields, structural protocols, class
  constants, enums, NamedTuple sequences, and generator context managers.
- Validate annotated call arguments and preserve explicit return contracts,
  distinct numeric return alternatives, empty tuple annotations, and async
  iteration element types.
- Combine observed string prefixes and suffixes as regex alternatives and resolve
  built-in PyFlow string subtype annotations.

## [0.1.2] - 2026-10-08

### Added

- Seven-instruction MIR and native PyCG-style call graph analysis.

### Changed

- Reorganized checker infrastructure and analysis architecture.
- Improved frontend and call graph construction performance.
- Updated pass scheduling to rerun invalidated analyses before consumers and
  record execution order, cache hits, timings, and IR versions.
- Standardized Python source and test formatting with a pinned Black version.

## [0.1.0]

### Added

- Initial alpha release of PyFlow, a program analysis framework for Python.
- CFG, call graph, IFDS/dataflow, IPA, CPA, shape, and lifetime analysis
  infrastructure.
- Optimization pipeline with modular passes (simplify, method-call optimization,
  cloning, argument normalization, load/store elimination).
- Pattern-based and semantic security analysis.
- Supply-chain analysis (SBOM generation, distribution integrity auditing,
  dependency metadata extraction).
- CLI tools for optimization, call graph, IR dumps, security, supply-chain,
  and alias analysis.
- Comprehensive test suite with unit, integration, and API regression tests.
