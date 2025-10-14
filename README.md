
# PyFlow: Novel Static Analysis Techniques for Python


## Overview

### The Constraint-based Analysis 

Context-Sensitive, Flow-Sensitive

Workflow:

~~~~
AST/Code → Store Graph → CPA (Interprocedural) → Shape Analysis (uses CPA results) → Lifetime Analysis (uses CPA results)
~~~~

- IPA and CPA work together - IPA provides the interprocedural framework while CPA performs the actual constraint solving
- All analyses use the store graph as their foundation for representing object relationships
- Results flow downstream - Shape analysis uses CPA's points-to/type information, and Lifetime analysis uses both CPA and shape analysis results


### What about the  Dataflow Analsyis over CFG

Flow-Sensitive

- The CFG module itself contains several analyses that operate directly on control flow graphs
  + CFG Optimization (cfg/optimize.py) - Optimizes CFG nodes including constant folding, dead code elimination, and control flow simplification
  + CFG Simplification (cfg/simplify.py) - Simplifies CFG structures by removing unnecessary nodes and merging equivalent blocks
  + ..
- CDG Construction (cdg/construction.py) - Builds Control Dependence Graphs from CFGs using dominance frontiers


However, the major analysis components do not directly use CFG:
- CPA (Constraint Propagation Analysis) - Uses store graphs and constraint solving, not CFG
- IPA (Interprocedural Analysis) - Works with call graphs and contexts, not CFG
- Shape Analysis - Uses region-based analysis, not CFG
- Lifetime Analysis - Uses read/modify analysis, not CFG
- Store Graph Analysis - Works with object relationships, not CFG


## Installation and Usage

### Prerequisites
- Python 3.8 or newer
- Graphviz (for visualization features)

### Install from source
```bash
git clone https://github.com/ZJU-Automated-Reasoning-Group/pyflow.git
cd pyflow
pip install -e .
```

### Basic Usage
```bash
# Analyze Python file with novel constraint-based analysis
pyflow analyze complex_program.py --constraints

# Run shape analysis on data structures
pyflow analyze data_structures.py --shape

# Incremental analysis for metaprogramming changes
pyflow analyze incremental_example.py --incremental
```

## Research Framework Usage

### Novel Analysis Capabilities

```bash
# Run constraint-based analysis (Research Contribution #1)
pyflow analyze program.py --constraints --flow-sensitive

# Execute shape analysis (Research Contribution #2)
pyflow analyze data_structures.py --shape-analysis --context-sensitive

# Perform incremental analysis (Research Contribution #3)
pyflow analyze decorators.py --incremental --metaprogramming-aware

# Run all research techniques together
pyflow analyze complex_program.py --research-mode
```

### Traditional Usage (Legacy Support)

PyFlow also provides traditional static analysis capabilities:

```bash
# Basic optimization
pyflow optimize input.py

# Dump AST for a specific function
pyflow optimize input.py --dump-ast function_name

# Generate call graph
pyflow callgraph input.py --format dot --output callgraph.dot
```

See [CLI.md](CLI.md) for detailed documentation of all CLI options.

### Running Tests

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
```

### Using PyFlow Programmatically

```python
from pyflow import Program, Pipeline, Context

# Create a program instance
program = Program()

# Set up analysis pipeline
pipeline = Pipeline()

# Run analysis
context = Context()
# ... configure and run analysis
```

## Development

### Research Project Structure

```
pyflow/
├── src/pyflow/                    # Main source code
│   ├── analysis/                  # RESEARCH: Novel analysis implementations
│   │   ├── cpa/                   # Research Contribution #1: Constraint-based analysis
│   │   ├── shape/                 # Research Contribution #2: Shape analysis
│   │   └── incremental/           # Research Contribution #3: Incremental analysis
│   ├── decompiler/                # Bytecode decompilation (legacy support)
│   ├── application/               # Application layer
│   ├── language/                  # Language-specific modules
│   ├── optimization/              # Optimization passes
│   └── util/                      # Utility modules
├── tests/                         # Test suite with research benchmarks
├── scripts/                       # Command-line tools
├── docs/                          # Documentation
├── examples/                      # Research examples and benchmarks
└── RESEARCH.md                    # Detailed research contribution documentation
```

### Research Components by Contribution

**Contribution #1 - Constraint-Based Analysis:**
- Location: `src/pyflow/analysis/cpa/`
- Key files: `constraintextractor.py`, `constraints.py`, `base.py`
- Novel algorithms: Flow-sensitive constraint resolution, higher-order type constraints

**Contribution #2 - Shape Analysis:**
- Location: `src/pyflow/analysis/shape/`
- Key files: `model/canonical.py`, `transferfunctions.py`, `regionanalysis.py`
- Novel algorithms: Python-specific abstract domain, container sharing analysis

**Contribution #3 - Incremental Analysis:**
- Location: `src/pyflow/analysis/incremental/`
- Key files: `state.py`, `changes.py`, `metaprogramming.py`
- Novel algorithms: State preservation across transformations

### Running Development Tools

```bash
# Format code
black src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/

# Run tests with coverage
pytest --cov=pyflow
```


