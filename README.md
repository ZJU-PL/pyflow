
# PyFlow: A Static Analysis Framework for Python

pyflow is a program analysis and optimization framework for Python.

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


### Usage


```bash
# Basic optimization
pyflow optimize input.py

# Dump AST for a specific function
pyflow optimize input.py --dump-ast function_name
```

See [CLI.md](CLI.md) for detailed documentation of all CLI options.

### Running Tests

```bash
# Run all tests
pytest

# Run focused areas
pytest tests/frontend
pytest tests/integration/
pytest tests/api
pytest tests/checker
```

## Development

### Project Structure

- `src/pyflow/analysis`: core analysis engines such as call graph, CFG, IFDS, IPA, CPA, shape, and lifetime analysis.
- `src/pyflow/application`: orchestration code including compiler context, pipeline execution, and the pass manager.
- `src/pyflow/api`: query-facing interfaces and entrypoint construction.
- `src/pyflow/checker`: pattern-based and semantic bug-finding layers plus output formatters.
- `src/pyflow/cli`: command-line entrypoints for optimization, call graph, IR, security, and dataflow commands.
- `src/pyflow/frontend`: source-driven extraction, dependency resolution, object loading, and stub handling.
- `src/pyflow/language`: Python IR/AST support and module-handling utilities.
- `src/pyflow/optimization`: optimization and simplification passes.
- `src/pyflow/stubs`: builtin/runtime modeling used during analysis.
- `tests`: focused coverage for analysis, frontend, checker, integration, and API regressions.

