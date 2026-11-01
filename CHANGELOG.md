# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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
