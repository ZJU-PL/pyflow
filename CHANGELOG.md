# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `pyflow supply-chain audit --reachability-source` separates application code
  from an installed package tree during vulnerability reachability annotation.

### Fixed

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
