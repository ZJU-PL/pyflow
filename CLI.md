# PyFlow CLI Options

This document describes the new CLI options added to PyFlow, following the style of clang.

## AST and CFG Dumping

### --dump-ast FUNCTION
Dump the Abstract Syntax Tree (AST) for the specified function name.

**Example:**
```bash
pyflow optimize examples/test_function.py --dump-ast fibonacci
```

### --dump-cfg FUNCTION
Dump the Control Flow Graph (CFG) for the specified function name.

**Example:**
```bash
pyflow optimize examples/test_function.py --dump-cfg quicksort
```

### --dump-format FORMAT
Specify the output format for AST/CFG dumps. Available formats:
- `text` (default): Human-readable text format
- `dot`: Graphviz DOT format for visualization
- `json`: JSON format for programmatic processing

**Example:**
```bash
pyflow optimize examples/test_function.py --dump-ast fibonacci --dump-format dot
```

### --dump-output DIRECTORY
Specify the output directory for AST/CFG dumps. Defaults to the current directory.

**Example:**
```bash
pyflow optimize examples/test_function.py --dump-ast fibonacci --dump-output ./output/
```

## Optimization Passes Selection

### --passes PASS1 [PASS2 ...]
Run only the specified optimization passes. Available passes:
- `methodcall`: Fuse method calls and optimize method dispatch
- `lifetime`: Lifetime analysis for variables and objects
- `simplify`: Constant folding and dead code elimination
- `clone`: Separate different invocations of the same code
- `argumentnormalization`: Normalize function arguments (eliminate *args, **kwargs)
- `inlining`: Inline function calls where beneficial
- `cullprogram`: Remove dead functions and contexts
- `loadelimination`: Eliminate redundant load operations
- `storeelimination`: Eliminate redundant store operations
- `dce`: Dead code elimination

**Examples:**
```bash
# Run only specific passes
pyflow optimize examples/test_function.py --passes methodcall inlining

# Run multiple passes
pyflow optimize examples/test_function.py --passes simplify dce storeelimination
```

### --list-passes
List all available optimization passes and their descriptions.

**Example:**
```bash
pyflow optimize --list-passes
```

### --no-passes
Skip all optimization passes and run only analysis (no optimization).

**Example:**
```bash
pyflow optimize examples/test_function.py --no-passes
```

## Combined Usage Examples

### Dump AST and CFG for multiple functions
```bash
pyflow optimize examples/test_function.py \
  --dump-ast fibonacci \
  --dump-ast quicksort \
  --dump-cfg binary_search \
  --dump-format dot \
  --dump-output ./graphs/
```

### Run specific optimization passes with AST dumping
```bash
pyflow optimize examples/test_function.py \
  --passes inlining simplify dce \
  --dump-ast fibonacci \
  --verbose
```

### Analysis-only mode with CFG dumping
```bash
pyflow optimize examples/test_function.py \
  --no-passes \
  --dump-cfg quicksort \
  --dump-format json
```

## Integration with Existing Options

These new options work seamlessly with existing PyFlow CLI options:

- `--verbose`: Shows detailed output during AST/CFG dumping and pass execution
- `--analysis`: Controls which analysis types to run
- `--dump`: Still works for dumping general analysis results
- `--recursive`: Applies to directory analysis with the new options

## Output Files

When using dump options, PyFlow creates files with the following naming convention:
- AST dumps: `{function_name}_ast.{format}`
- CFG dumps: `{function_name}_cfg.{format}`

For example, dumping the AST of the `fibonacci` function in DOT format creates: `fibonacci_ast.dot`
