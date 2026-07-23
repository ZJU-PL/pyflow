
# PyFlow: Static Analysis for Python

PyFlow is a program analysis framework for Python. It combines
program analysis infrastructure, experimental optimization passes, and security
checking in a single research-oriented toolkit.

Current status: **alpha**. The project already contains substantial analysis
and testing infrastructure, but APIs, pass behavior, and CLI details are still
evolving.

If you use pyflow in your research or work, please cite the following:
~~~~
@misc{pyflow2025,
  title = {pyflow: A Program Analysis Framework for Python},
  author = {ZJU Programming Languages and Automated Reasoning Group},
  year = {2025},
  url = {https://github.com/ZJU-PL/pyflow},
  note = {Program analysis, compiler}
}
~~~~


## What PyFlow includes

- **Program analysis**: CFG, call graph, IFDS/dataflow, IPA, CPA, shape, and
  lifetime analysis infrastructure
- **Optimization pipeline**: modular passes such as simplify, method-call
  optimization, cloning, argument normalization, and load/store elimination
- **Security checking**: pattern-based and semantic security analysis
- **Supply-chain analysis**: local SBOM generation, distribution integrity
  auditing, and dependency metadata extraction
- **CLI tooling**: commands for optimization, call graph generation, IR dumps,
  security, supply-chain, and alias analysis

## Installation and Usage

### Prerequisites
- Python 3.10 or newer
- Graphviz (for visualization features)

### Install from source
```bash
git clone https://github.com/ZJU-PL/pyflow.git
cd pyflow
pip install -e .
```

For development, install the dev extras:
```bash
pip install -e ".[dev]"
```

If you want the optional PyCG-backed call-graph algorithm, install:
```bash
pip install -e ".[dev,callgraph]"
```


### Usage


```bash
# Basic optimization pipeline
pyflow optimize input.py

# Dump IR for a specific function
pyflow ir input.py --dump-ast function_name

# Generate a call graph
pyflow callgraph input.py

# Generate a PyCG-backed call graph
pyflow callgraph input.py --algorithm pycg

# Run security analysis (fast AST scan)
pyflow security input.py

# Run security analysis with CPA-backed engine
pyflow security input.py --engine cpa

# Run IFDS-backed interprocedural security analysis
pyflow security input.py --engine ifds --function main --sources input --sinks eval

# Run CPG-based context-sensitive security analysis
pyflow security input.py --engine cpg --framework flask

# Run alias analysis (flow-sensitive heap or k-CFA pointer)
pyflow alias input.py --verbose

# Generate a CycloneDX SBOM from local package metadata
pyflow supply-chain sbom package/

# Audit archives and distribution metadata for issues
pyflow supply-chain audit . --recursive

# Match exact dependency versions against a local OSV database snapshot
pyflow supply-chain audit . --recursive --osv-database osv-data/

# Use a CI failure threshold while retaining lower-severity findings
pyflow supply-chain audit . --recursive --fail-on high --format json

# Enforce fresh, checksum-pinned OSV data and apply VEX
pyflow supply-chain audit . -r --osv-database osv-data/ \
  --osv-max-age-days 2 --require-osv-checksum --vex product.vex.json

# Generate reproducible output and validate against a pinned official schema
pyflow supply-chain sbom . -r --deterministic --schema bom-1.7.schema.json

# Emit SARIF and use expiring policy exceptions or a reviewed baseline
pyflow supply-chain audit . -r --format sarif --policy supply-chain-policy.json
```

The scanner is offline by design. Production CI is responsible for refreshing
and authenticating OSV snapshots; ``--osv-max-age-days`` and
``--require-osv-checksum`` enforce that contract. Install the optional
``supply-chain`` dependency group for JSON Schema and Sigstore tooling.

See [CLI.md](CLI.md) for the command reference and `docs/` for broader project
documentation.

### Running Tests

```bash
# Run the default unit-focused test suite
pytest

# Run integration tests explicitly
pytest -m integration tests/integration

# Run focused areas
pytest tests/frontend
pytest tests/api
pytest tests/checker
```

## Development

The repository is organized around a few major subsystems:

- `src/pyflow/analysis`: core analysis engines such as call graph, CFG, DDG, IFDS, alias (flow-sensitive heap + k-CFA pointer), IPA, CPA, PDG, shape, and lifetime analysis.
- `src/pyflow/application`: orchestration code including compiler context, pipeline execution, and the pass manager.
- `src/pyflow/api`: query-facing interfaces and entrypoint construction.
- `src/pyflow/checker`: pattern-based, semantic, and supply-chain analysis modules plus output formatters.
- `src/pyflow/cli`: command-line entrypoints for optimization, call graph, IR, alias, security, and supply-chain analysis.
- `src/pyflow/frontend`: source-driven extraction, dependency resolution, object loading, and stub handling.
- `src/pyflow/language`: Python IR/AST support, module-handling utilities, and AST tooling (cyclomatic complexity, decorator/visitor utilities).
- `src/pyflow/optimization`: optimization and simplification passes.
- `src/pyflow/stats`: statistics collection and reporting for analysis results.
- `src/pyflow/stubs`: builtin/runtime modeling used during analysis.
- `src/pyflow/util`: foundational utility library (OrderedSet, canonical objects, TVL, type dispatch, graph algorithms).
- `tests`: focused coverage for analysis, frontend, checker, integration, and API regressions.

## Project maturity and expectations

PyFlow is best viewed today as an ambitious, actively developed framework for
research, experimentation, and advanced static-analysis prototyping. The codebase
has broad subsystem coverage and a large test suite, but documentation and some
subsystems are still catching up with the implementation. If you are evaluating
the project, expect strong technical depth with some rough edges.
