# Call Graph Analysis Module

This module provides call graph analysis for Python code with multiple algorithm options:

## Available Algorithms

- **ast_based**: Fast, lightweight AST-based analysis using Python's `ast` module
- **pycg**: More sophisticated analysis using the PyCG library (if available)

## Module Structure

```
callgraph/
├── __init__.py          # Main module exports
├── ast_based.py         # AST-based algorithm
├── pycg_based.py        # PyCG-based algorithm
├── formats.py           # Output format generators
└── README.md            # This file
```

## Usage

### Basic Usage
```python
from pyflow.analysis.callgraph import extract_call_graph, analyze_file

# AST-based analysis
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
# AST-based algorithm (default)
pyflow callgraph example.py

# PyCG algorithm
pyflow callgraph --algorithm pycg example.py

# Save to file
pyflow callgraph --output graph.txt example.py
```

## Current Limitations

- No IPA/CPA integration
- Limited to single-file analysis


