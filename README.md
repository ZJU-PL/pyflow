# Copyright 2025 rainoftime

A static compiler for Python.

## Description

PyFlow is a static analysis and compilation tool for Python code. It provides various analysis capabilities including:

- Control flow analysis
- Data flow analysis  
- Inter-procedural analysis
- Shape analysis
- Optimization passes
- Bytecode decompilation

## Installation

### Prerequisites

- Python 3.6 or newer
- Graphviz (for visualization features)

### Install from source

```bash
# Clone the repository
git clone https://github.com/ZJU-Automated-Reasoning-Group/pyflow.git
cd pyflow

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

## Usage

### Command Line Interface

PyFlow provides a powerful CLI with options similar to clang:

```bash
# Basic optimization
pyflow optimize input.py

# Dump AST for a specific function
pyflow optimize input.py --dump-ast function_name

# Dump CFG for a specific function  
pyflow optimize input.py --dump-cfg function_name

# Run specific optimization passes
pyflow optimize input.py --passes inlining simplify dce

# List all available passes
pyflow optimize --list-passes

# Analysis only (no optimization)
pyflow optimize input.py --no-passes
```

See [CLI_OPTIONS.md](CLI_OPTIONS.md) for detailed documentation of all CLI options.

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
├── src/pyflow/          # Main source code
│   ├── analysis/          # Static analysis modules
│   ├── application/       # Application layer
│   ├── decompiler/        # Bytecode decompilation
│   ├── language/          # Language-specific modules
│   ├── optimization/      # Optimization passes
│   └── util/              # Utility modules
├── tests/                 # Test suite
├── scripts/               # Command-line tools
├── docs/                  # Documentation
└── examples/              # Example code
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


