# Call Graph Analysis Module

This module provides call graph analysis for Python code with multiple algorithm options:

## Available Algorithms

- **constraint_based**: Interprocedural abstract-value propagation (default when available)
- **ast_based**: Fast, lightweight AST-based analysis using Python's `ast` module
- **pycg**: More sophisticated analysis using the PyCG library (if available)

## Module Structure

```
callgraph/
├── __init__.py          # Main module exports
├── constraint_based/    # Constraint-style value-flow implementation
│   ├── __init__.py      # Public API
│   ├── api.py           # Wrapper helpers
│   ├── engine.py        # Solver/worklist engine (mixins composition)
│   ├── model.py         # Abstract values + data model
│   ├── _loader.py       # Module loading and import resolution
│   ├── _collector.py    # Symbol collection and scope initialization
│   ├── _analyzer.py     # Fixpoint loop and block/scope analysis
│   ├── _evaluator.py    # Expression evaluation
│   ├── _resolver.py     # Target invocation, MRO, and attribute resolution
│   └── DESIGN_NOTE.md   # Algorithm design/tradeoffs
├── ast_based.py         # AST-based algorithm
├── pycg_based.py        # PyCG-based algorithm
├── formats.py           # Output format generators
└── README.md            # This file
```

## Usage

### Basic Usage
```python
from pyflow.analysis.callgraph import extract_call_graph, analyze_file

# Default analysis (constraint-based when available)
graph = extract_call_graph(source_code)
output = analyze_file("example.py")
```

### Using PyCG Algorithm
```python
from pyflow.analysis.callgraph import extract_call_graph_pycg, analyze_file_pycg

# PyCG-based analysis
graph = extract_call_graph_pycg(source_code)
output = analyze_file_pycg("example.py")
```

### Constraint-Based Modes
```python
from pyflow.analysis.callgraph import extract_call_graph_constraint

# Context-insensitive (default)
cg0 = extract_call_graph_constraint(source_code)

# Call-site context-sensitive
cg1 = extract_call_graph_constraint(
    source_code,
    context_sensitive=True,
    context_depth=1,
    fixpoint_max_iterations=5000,
    warn_on_fixpoint_truncation=True,
    use_type_hints=True,
    refine_type_guards=True,
)
```

### Output Formats
```python
from pyflow.analysis.callgraph import generate_text_output, generate_dot_output, generate_json_output

# Generate different output formats
text_output = generate_text_output(graph, None)
dot_output = generate_dot_output(graph, None)
json_output = generate_json_output(graph, None)
```

## CLI Usage

```bash
# Default algorithm (constraint_based in this package)
pyflow callgraph example.py

# PyCG algorithm
pyflow callgraph --algorithm pycg example.py

# Save to file
pyflow callgraph --output graph.txt example.py
```

## Current Limitations

- No IPA/CPA integration
- Limited to single-file analysis
