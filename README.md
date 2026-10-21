
# PyFlow: Static Analysis for Python

PyFlow is a program analysis framework for Python. It combines
program analysis infrastructure, experimental optimization passes, and security
checking in a single research-oriented toolkit.

Current status: **alpha**. The project already contains substantial analysis
and testing infrastructure, but APIs, pass behavior, and CLI details are still
evolving.

If you use pyflow in your research or work, please cite the following:
~~~~
@misc{pyflow2026,
  title         = {PyFlow: An Inter-procedural Static Analysis Framework for Python},
  author        = {Gu, Zinan and Yan, Haoxiang and Yao, Peisen},
  year          = {2026},
  eprint        = {2608.07026},
  archivePrefix = {arXiv},
  doi           = {10.48550/arXiv.2608.07026},
  url           = {https://arxiv.org/abs/2608.07026}
}
~~~~


## What PyFlow includes

- **Intermediate representations**: seven-instruction MIR, CFG, CDG, DDG, PDG,
  CPG, lowered data flow IR, and a shared store graph model
- **Program analysis**: call graph, IFDS, alias, IPA, CPA, shape, lifetime,
  and type-analysis infrastructure
- **Optimization pipeline**: modular passes such as simplify, method-call
  optimization, cloning, argument normalization, and load/store elimination
- **Security checking**: ast pattern, ast-dataflow, cpg, and ifds security analysis
- **Supply-chain analysis**: local SBOM generation, distribution integrity
  auditing, and dependency metadata extraction
- **CLI tooling**: commands for optimization, call graph generation, IR dumps,
  security, supply-chain, alias analysis, and concolic test-input generation

## Examples and test inputs

- [`examples/`](examples/README.md): runnable examples of using PyFlow's Python
  APIs and extending analyses.
- [`tests/fixtures/`](tests/fixtures/README.md): Python inputs for analysis and
  module-discovery tests. Small test-specific snippets also live alongside
  their suites.

## Evaluation results

Security engines evaluated on the 240-file PySASTBench microbenchmark (960 runs):

```bash
.venv/bin/python evaluation/pysastbench/bench_micro.py --timeout 45 --workers 8
```

| Engine | Precision | Recall | F1 | Accuracy | Partial / 240 |
|---|---:|---:|---:|---:|---:|
| ast-scanner | 0.636 | 0.350 | 0.452 | 0.575 | 0 |
| ast-dataflow | 0.857 | 0.450 | 0.590 | 0.688 | 238 |
| cpg | 0.828 | 0.683 | 0.749 | 0.771 | 240 |
| ifds | 0.837 | 0.858 | 0.848 | 0.846 | 0 |

This snapshot used Python 3.13.7 and had no timeouts or parse failures. Exact
source, dataset, and harness hashes plus per-CWE counts are in the
[measurement snapshot](evaluation/pysastbench/results/user-evaluation-summary.json).
Defaults now distinguish recognized HTTP handlers from arbitrary library entry
parameters; these measurements are not directly comparable to the old table.
Partial reports contribute detections but do not establish that negative files
are safe. Recall remains limited, particularly for some AST dataflow categories.
See the [evaluation guide](evaluation/pysastbench/README.md) and
[user evaluation follow-up](docs/user-evaluation-followup.md).

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

The native MIR-based PyCG algorithm is included in the standard installation.
If you want the optional upstream PyCG-backed call-graph algorithm, install:
```bash
pip install -e ".[dev,callgraph]"
```


### Usage


```bash
# Dump IR for a specific function
pyflow ir input.py --dump-ast function_name

# Lower source to the seven-instruction MIR without executing the source
pyflow ir input.py --dump-mir --dump-format json --dump-output out/

# Generate a call graph
pyflow callgraph input.py

# Generate a native PyCG-style call graph from MIR
pyflow callgraph input.py --algorithm pycg-mir

# Generate a call graph with the optional upstream PyCG package
pyflow callgraph input.py --algorithm pycg

# Run security analysis (fast AST scan)
pyflow security input.py

# Run AST-based interprocedural taint dataflow
pyflow security input.py --engine ast-dataflow

# Run IFDS-backed interprocedural security analysis
pyflow security input.py --engine ifds --sources input --sinks eval

# Run CPG-based security analysis
pyflow security input.py --engine cpg --framework flask

# Run alias analysis (flow-sensitive heap or k-CFA pointer)
pyflow alias input.py --verbose

# Generate branch-covering integer inputs for a pure function named main
pyflow concolic input.py --inputs '[0]' --json

# Start the LSP server (Content-Length framed JSON-RPC)
pyflow lsp --root . --mode full

# Start the MCP server (newline-delimited JSON-RPC over stdio)
pyflow mcp --root . --mode full

# Run a one-shot semantic query
pyflow query . --get-callers package.module.function --pretty

# Generate a CycloneDX SBOM from local package metadata
pyflow supply-chain sbom package/
```

See [CLI.md](CLI.md) for the command reference,
[docs/source/ir/mir.rst](docs/source/ir/mir.rst) for MIR, the native PyCG API,
and implementation limits,
[docs/source/lsp.rst](docs/source/lsp.rst) for LSP, MCP, and semantic-query
integration, and `docs/` for broader project
documentation.

### Running Tests

```bash
# Run the default unit-focused test suite
pytest

# Run integration tests explicitly
pytest -m integration tests/integration

# Run focused areas
pytest tests/ir
pytest tests/frontend
pytest tests/api
pytest tests/checker
```

### Publishing

See [RELEASING.md](RELEASING.md) for versioning, validation, and publishing to
PyPI through GitHub Actions Trusted Publishing.
