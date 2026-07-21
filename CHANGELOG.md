# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

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
