
# PyFlow: Static Analysis and Optimization for Python

PyFlow is a static analysis and optimization framework for Python. It combines
program analysis infrastructure, experimental optimization passes, and security
checking in a single research-oriented toolkit.

Current status: **alpha**. The project already contains substantial analysis
and testing infrastructure, but APIs, pass behavior, and CLI details are still
evolving.

If you use pyflow in your research or work, please cite the following:
~~~~
@misc{pyflow2025,
  title = {pyflow: A Program Analysis and Optimization Framework for Python},
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
- **CLI tooling**: commands for optimization, call graph generation, IR dumps,
  security analysis, and dataflow analysis

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
```

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

- `src/pyflow/analysis`: core analysis engines such as call graph, CFG, IFDS, heap, IPA, CPA, shape, and lifetime analysis.
- `src/pyflow/application`: orchestration code including compiler context, pipeline execution, and the pass manager.
- `src/pyflow/api`: query-facing interfaces and entrypoint construction.
- `src/pyflow/checker`: pattern-based and semantic bug-finding layers plus output formatters.
- `src/pyflow/cli`: command-line entrypoints for optimization, call graph, IR, heap analysis, and unified security analysis.
- `src/pyflow/frontend`: source-driven extraction, dependency resolution, object loading, and stub handling.
- `src/pyflow/language`: Python IR/AST support and module-handling utilities.
- `src/pyflow/optimization`: optimization and simplification passes.
- `src/pyflow/stubs`: builtin/runtime modeling used during analysis.
- `tests`: focused coverage for analysis, frontend, checker, integration, and API regressions.

## Project maturity and expectations

PyFlow is best viewed today as an ambitious, actively developed framework for
research, experimentation, and advanced static-analysis prototyping. The codebase
has broad subsystem coverage and a large test suite, but documentation and some
subsystems are still catching up with the implementation. If you are evaluating
the project, expect strong technical depth with some rough edges.
