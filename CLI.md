# PyFlow CLI Options

This document describes the CLI options available in PyFlow, following the style of clang.

## Commands

PyFlow provides four main commands:
- `optimize`: Run static analysis and optimization on Python code
- `callgraph`: Build and visualize call graphs from Python code
- `ir`: Dump AST, CFG, and SSA forms for specific functions
- `security`: Check security bugs

## Optimize Command

### Basic Usage
```bash
pyflow optimize [OPTIONS] INPUT_PATH
```

Where `INPUT_PATH` is a Python file, directory, or library to optimize.

### AST and CFG Dumping

#### --dump-ast FUNCTION
Dump the Abstract Syntax Tree (AST) for the specified function name.

**Example:**
```bash
pyflow optimize examples/test_function.py --dump-ast fibonacci
```

#### --dump-cfg FUNCTION
Dump the Control Flow Graph (CFG) for the specified function name.

**Example:**
```bash
pyflow optimize examples/test_function.py --dump-cfg quicksort
```

#### --dump-format FORMAT
Specify the output format for AST/CFG dumps. Available formats:
- `text` (default): Human-readable text format
- `dot`: Graphviz DOT format for visualization
- `json`: JSON format for programmatic processing

**Example:**
```bash
pyflow optimize examples/test_function.py --dump-ast fibonacci --dump-format dot
```

#### --dump-output DIRECTORY
Specify the output directory for AST/CFG dumps. Defaults to the current directory.

**Example:**
```bash
pyflow optimize examples/test_function.py --dump-ast fibonacci --dump-output ./output/
```

### Optimization Passes Selection

#### --opt-passes PASS1 [PASS2 ...]
Run only the specified optimization passes. Available passes:
- `methodcall`: Fuse method calls and optimize method dispatch
- `lifetime`: Lifetime analysis for variables and objects
- `simplify`: Constant folding and dead code elimination
- `clone`: Separate different invocations of the same code
- `argumentnormalization`: Normalize function arguments (eliminate *args, **kwargs)
- `inlining`: Inline function calls where beneficial
- `cullprogram`: Remove dead functions and contexts
- `loadelimination`: Eliminate redundant load operations

## IR Command

### Basic Usage
```bash
pyflow ir [OPTIONS] INPUT_PATH
```

Where `INPUT_PATH` is a Python file or directory to analyze.

### IR Dumping Options

#### --dump-ast FUNCTION
Dump the Abstract Syntax Tree (AST) for the specified function name.

**Example:**
```bash
pyflow ir examples/test_function.py --dump-ast fibonacci
```

#### --dump-cfg FUNCTION
Dump the Control Flow Graph (CFG) for the specified function name.

**Example:**
```bash
pyflow ir examples/test_function.py --dump-cfg quicksort
```

#### --dump-ssa FUNCTION
Dump the Static Single Assignment (SSA) form for the specified function name.

**Example:**
```bash
pyflow ir examples/test_function.py --dump-ssa fibonacci
```

#### --dump-format FORMAT
Specify the output format for IR dumps. Available formats:
- `text` (default): Human-readable text format
- `dot`: Graphviz DOT format for visualization
- `json`: JSON format for programmatic processing

**Example:**
```bash
pyflow ir examples/test_function.py --dump-ast fibonacci --dump-format dot
```

#### --dump-output DIRECTORY
Specify the output directory for IR dumps. Defaults to the current directory.

**Example:**
```bash
pyflow ir examples/test_function.py --dump-ast fibonacci --dump-output ./output/
```

### File Selection Options

#### --recursive, -r
Recursively analyze subdirectories.

#### --include PATTERN [PATTERN ...]
File patterns to include in analysis (default: *.py).

#### --exclude PATTERN [PATTERN ...]
Patterns to exclude from analysis (e.g., 'test_*', '__pycache__').

### Examples

Dump all three forms for a function:
```bash
pyflow ir examples/test_function.py --dump-ast fibonacci --dump-cfg fibonacci --dump-ssa fibonacci
```

Dump CFG in DOT format for visualization:
```bash
pyflow ir examples/test_function.py --dump-cfg quicksort --dump-format dot
```

Analyze all Python files in a directory:
```bash
pyflow ir src/ --recursive --dump-ast my_function
```

## Call Graph Command

### Basic Usage
```bash
pyflow callgraph [OPTIONS] INPUT_PATH
```

Where `INPUT_PATH` is a Python file or directory to analyze.

**Examples:**
```bash
# Run only specific passes
pyflow optimize examples/test_function.py --opt-passes methodcall inlining

# Run multiple passes
pyflow optimize examples/test_function.py --opt-passes simplify dce storeelimination
```

#### --list-opt-passes
List all available optimization passes and their descriptions.

**Example:**
```bash
pyflow optimize --list-opt-passes
```

#### --no-opt-passes
Skip all optimization passes and run only analysis (no optimization).

**Example:**
```bash
pyflow optimize examples/test_function.py --no-opt-passes
```

### General Options

#### --verbose, -v
Enable verbose output during analysis and optimization.

#### --analysis, -a
Type of analysis to run. Choices:
- `all` (default): Run all analysis types
- `cpa`: Control flow analysis
- `ipa`: Inter-procedural analysis  
- `shape`: Shape analysis
- `lifetime`: Lifetime analysis

#### --dump, -d
Dump analysis results to files.

#### --output, -o
Output file for results.

#### --recursive, -r
Recursively analyze subdirectories.

#### --exclude
Patterns to exclude from analysis (e.g., 'test_*', '__pycache__').

#### --include
File patterns to include in analysis (default: *.py).

## Callgraph Command

### Basic Usage
```bash
pyflow callgraph [OPTIONS] INPUT_FILE
```

Where `INPUT_FILE` is a Python file to analyze for call graph generation.

### Options

#### --format, -f
Output format for the call graph. Choices:
- `text` (default): Human-readable text format
- `dot`: Graphviz DOT format for visualization
- `json`: JSON format for programmatic processing

#### --output, -o
Output file for the call graph (default: stdout).

#### --max-depth, -d
Maximum call depth to analyze.

#### --show-cycles
Detect and show cycles in the call graph.

#### --verbose, -v
Enable verbose output.

### Examples

```bash
# Generate text call graph
pyflow callgraph examples/test_function.py

# Generate DOT format for visualization
pyflow callgraph examples/test_function.py --format dot --output callgraph.dot

# Find cycles with limited depth
pyflow callgraph examples/test_function.py --show-cycles --max-depth 5
```

