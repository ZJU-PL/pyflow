
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

- **Intermediate representations**: CFG, CDG, DDG, PDG, CPG, lowered data
  flow IR, and a shared store graph model
- **Program analysis**: call graph, IFDS, alias, IPA, CPA, shape, lifetime,
  and type-analysis infrastructure
- **Optimization pipeline**: modular passes such as simplify, method-call
  optimization, cloning, argument normalization, and load/store elimination
- **Security checking**: ast pattern, ast-dataflow, cpg, and ifds security analysis
- **Supply-chain analysis**: local SBOM generation, distribution integrity
  auditing, and dependency metadata extraction
- **CLI tooling**: commands for optimization, call graph generation, IR dumps,
  security, supply-chain, alias analysis, and concolic test-input generation

## Evaluation results

Security analysis engines evaluated on the PySASTBench microbenchmark
(ICSE 26):

```bash
python3 evaluation/pysastbench/bench_micro.py --timeout 45 --workers 16
```

| Engine       | Precision | Recall | F1    | Accuracy |
|--------------|-----------|--------|-------|----------|
| ast-scanner  | 0.623     | 0.400  | 0.487 | 0.579    |
| ast-dataflow | 0.849     | 0.842  | 0.845 | 0.846    |
| cpg          | 0.792     | 0.792  | 0.792 | 0.792    |
| ifds         | 0.852     | 0.767  | 0.807 | 0.817    |

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
# Dump IR for a specific function
pyflow ir input.py --dump-ast function_name

# Generate a call graph
pyflow callgraph input.py

# Generate a PyCG-backed call graph
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
