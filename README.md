
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
- Python 3.8 or newer
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

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
```

## Development

### Project Structure

```
pyflow/
├── src/pyflow/                          # Main source code
│   ├── analysis/                        # Core analysis modules
│   │   ├── astcollector.py              # AST collection utilities
│   │   ├── callgraph/                   # Call graph analysis
│   │   ├── cdg/                         # Control Dependence Graph
│   │   ├── cfg/                         # Control Flow Graph analysis
│   │   ├── cfgIR/                       # CFG Intermediate Representation
│   │   ├── cpa/                         # Constraint Propagation Analysis
│   │   ├── cpasignature.py              # CPA signature analysis
│   │   ├── dataflowIR/                  # Dataflow IR analysis
│   │   ├── ddg/                         # Data Dependence Graph
│   │   ├── dump/                        # Analysis result dumping
│   │   ├── fsdf/                        # Flow-Sensitive Data Flow
│   │   ├── ipa/                         # Interprocedural Analysis
│   │   ├── lifetimeanalysis/            # Variable lifetime analysis
│   │   ├── numbering/                   # Node numbering utilities
│   │   ├── programculler.py             # Program culling utilities
│   │   ├── shape/                       # Shape analysis
│   │   ├── storegraph/                  # Store graph analysis
│   │   └── tools.py                     # Analysis tools
│   ├── application/                     # Application layer
│   │   ├── context.py                   # Analysis context management
│   │   ├── errors.py                    # Error handling
│   │   ├── interface/                   # User interface components
│   │   ├── makefile.py                  # Build system integration
│   │   ├── passes.py                    # Analysis passes
│   │   ├── passmanager.py               # Pass management system
│   │   ├── pipeline.py                  # Analysis pipeline
│   │   └── program.py                   # Program representation
│   ├── checker/                       # Code checking and validation
│   │   ├── checkers/                  # Individual checkers
│   │   ├── core/                      # Core checking infrastructure
│   │   ├── formatters/                # Output formatters
│   │   └── llm/                       # LLM integration
│   ├── cli/                           # Command-line interface
│   │   ├── callgraph.py               # Call graph CLI commands
│   │   ├── ir.py                      # IR visualization commands
│   │   ├── main.py                    # Main CLI entry point
│   │   ├── optimize.py                # Optimization commands
│   │   └── security.py                # Security analysis commands
│   ├── config.py                      # Configuration management
│   ├── frontend/                      # Frontend processing
│   ├── import_graph/                  # Import graph analysis
│   │   └── import_graph.py            # Import relationship analysis
│   ├── language/                      # Language-specific modules
│   │   └── python/                    # Python-specific analysis
│   ├── lib/                           # Third-party libraries
│   │   ├── antlr3/                    # ANTLR3 runtime
│   │   └── PADS/                      # Basic data structures and alg.
│   ├── optimization/                  # Optimization passes
│   ├── stats/                         # Statistics collection
│   │   └── stats.py                   # Statistics utilities
│   ├── stubs/                         # Type stub files
│   ├── testspider.py                  # Test spider utilities
│   └── util/                          # Utility modules
├── tests/                             # Test suite
│   ├── cpa/                           # CPA-specific tests
│   ├── full/                          # Full program tests
│   ├── fullcompiler.py                # Full compiler tests
│   ├── ipa/                           # IPA-specific tests
│   ├── ir/                            # IR-specific tests
│   ├── shape/                         # Shape analysis tests
│   ├── test_*.py                      # Individual test files
│   └── __pycache__/                   # Python bytecode cache
├── docs/                              # Documentation
│   ├── analysis/                      # Analysis documentation
│   ├── utils/                         # Utility documentation
│   ├── conf.py                       # Sphinx configuration
│   ├── index.rst                     # Main documentation index
│   └── overview.rst                   # Overview documentation
├── examples/                          # Research examples and benchmarks
│   ├── __pycache__/                   # Python bytecode cache
│   └── *.py                          # Example files
├── scripts/tools/                     # Command-line tools
├── __pycache__/                       # Python bytecode cache
├── venv/                             # Virtual environment
├── CLI.md                           # CLI documentation
├── LICENSE.txt                      # License file
├── README.md                        # This file
├── pyproject.toml                   # Python project configuration
├── requirements*.txt                 # Dependencies
├── setup.py                         # Setup script
└── Makefile                         # Build automation
```


## Related Work

- https://github.com/lkgv/PythonStAn
  + Dataflow Analysis: Liveness analysis, reaching definition analysis, and def-use chains
  + Pointer Analysis: k-CFA based pointer analysis with configurable context sensitivity
  + Control Flow Analysis: CFG generation, interprocedural control flow graphs (ICFG)
  + Abstract Interpretation: AI-based analysis with configurable abstract domains
  + Scope Analysis: Module and function scope management
- https://github.com/SMAT-Lab/Scalpel: Basic IR construction