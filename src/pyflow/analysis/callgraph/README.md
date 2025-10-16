# Call Graph Analysis Module

This module provides call graph analysis for Python code with multiple algorithm options:

## Available Algorithms

- **simple**: Fast, lightweight AST-based analysis using Python's `ast` module
- **pycg**: More sophisticated analysis using the PyCG library (if available)

## Module Structure

```
callgraph/
├── __init__.py          # Main module exports
├── simple.py            # Simple AST-based algorithm
├── pycg_based.py        # PyCG-based algorithm
├── formats.py           # Output format generators
├── types.py             # Shared data types and classes
└── README.md            # This file
```

## Usage

### Basic Usage
```python
from pyflow.analysis.callgraph import extract_call_graph, analyze_file

# Simple analysis
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
# Simple algorithm (default)
pyflow callgraph example.py

# PyCG algorithm
pyflow callgraph --algorithm pycg example.py

# Save to file
pyflow callgraph --output graph.txt example.py
```

## Current Limitations

- No IPA/CPA integration
- Basic AST parsing (not pyflow AST)
- Limited to single-file analysis

## Future Integration Steps

1. **Fix Program class** - store compiler context (`src/pyflow/application/program.py`)
2. **Add CPA integration** - populate call annotations via `ExtractDataflow`
3. **Add IPA integration** - use `CallGraphFinder` for context-sensitive analysis
4. **Use pyflow AST** - convert via `src/pyflow/language/python/parser.py`
5. **Add context tracking** - use `liveFuncContext` and `invokesContext`
6. **Multi-file analysis** - handle imports and cross-file dependencies
