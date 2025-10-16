
# PyFlow: A Static Analysis Framework for Python


## Overview



### The Dataflow Analsyis over CFG

Flow-Sensitive

- The CFG module itself contains several analyses that operate directly on control flow graphs
  + CFG Optimization - Optimizes CFG nodes including constant folding, dead code elimination, control flow simplification, removing unnecessary nodes, etc.
  + ..
- CDG Construction (cdg/construction.py) - Builds Control Dependence Graphs from CFGs using dominance frontiers


### The Constraint-based Analysis 

However, several analysis components (Context-Sensitive, Flow-inensitive) do not directly use CFG 
- CPA (Constraint Propagation Analysis) - Uses store graphs and constraint solving
- Shape Analysis - Uses region-based analysis
- Lifetime Analysis - Uses read/modify analysis


Workflow:

~~~~
AST/Code → Store Graph → CPA (Interprocedural) → Shape Analysis (uses CPA results) → Lifetime Analysis (uses CPA results)
~~~~

- IPA and CPA work together - IPA provides the interprocedural framework while CPA performs the actual constraint solving
- All analyses use the store graph as their foundation for representing object relationships
- Results flow downstream - Shape analysis uses CPA's points-to/type information, and Lifetime analysis uses both CPA and shape analysis results



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

### Project Structure

```
pyflow/
├── src/pyflow/                           # Main source code
│   ├── analysis/                         # Core analysis modules
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
│   ├── application/                      # Application layer
│   │   ├── context.py                   # Analysis context management
│   │   ├── errors.py                    # Error handling
│   │   ├── interface/                   # User interface components
│   │   ├── makefile.py                  # Build system integration
│   │   ├── passes.py                    # Analysis passes
│   │   ├── passmanager.py               # Pass management system
│   │   ├── pipeline.py                  # Analysis pipeline
│   │   └── program.py                   # Program representation
│   ├── checker/                         # Code checking and validation
│   │   ├── checkers/                    # Individual checkers
│   │   ├── core/                        # Core checking infrastructure
│   │   ├── formatters/                  # Output formatters
│   │   └── llm/                         # LLM integration
│   ├── cli/                            # Command-line interface
│   │   ├── callgraph.py                # Call graph CLI commands
│   │   ├── ir.py                       # IR visualization commands
│   │   ├── main.py                     # Main CLI entry point
│   │   ├── optimize.py                 # Optimization commands
│   │   └── security.py                 # Security analysis commands
│   ├── config.py                        # Configuration management
│   ├── decompiler/                      # Bytecode decompilation (legacy support)
│   │   ├── bytecodedecompiler.py       # Main decompiler
│   │   ├── destacker/                  # Stack destacking
│   │   ├── disassembler.py             # Code disassembly
│   │   ├── errors.py                   # Decompiler errors
│   │   ├── flowblockdump.py            # Flow block dumping
│   │   ├── flowblocks.py               # Flow block analysis
│   │   ├── programextractor_v2.py      # Program extraction v2
│   │   ├── README.md                   # Decompiler documentation
│   │   ├── ssitransform/               # SSI transformation
│   │   └── structuralanalyzer.py       # Structural analysis
│   ├── frontend/                        # Frontend processing
│   ├── import_graph/                    # Import graph analysis
│   │   └── import_graph.py             # Import relationship analysis
│   ├── language/                        # Language-specific modules
│   │   └── python/                     # Python-specific analysis
│   ├── lib/                            # Third-party libraries
│   │   ├── antlr3/                     # ANTLR3 runtime
│   │   └── PADS/                       # Basic data structures and alg.
│   ├── optimization/                    # Optimization passes
│   ├── stats/                          # Statistics collection
│   │   └── stats.py                    # Statistics utilities
│   ├── stubs/                          # Type stub files
│   ├── testspider.py                   # Test spider utilities
│   └── util/                           # Utility modules
├── tests/                              # Test suite
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


