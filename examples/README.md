# PyFlow Examples

This directory contains example Python programs that demonstrate PyFlow's static analysis capabilities. Each example is designed to showcase different aspects of PyFlow's analysis tools.

## Examples Overview

### 1. Basic Arithmetic (`basic_arithmetic.py`)
**Purpose**: Demonstrates simple function calls and arithmetic operations
**Analysis Types**: All analysis types
**Key Features**:
- Function definitions and calls
- Basic arithmetic operations
- Return value handling

**Usage**:
```bash
pyflow optimize basic_arithmetic.py
pyflow callgraph basic_arithmetic.py
```

### 2. Control Flow (`control_flow.py`)
**Purpose**: Demonstrates control flow structures and branching
**Analysis Types**: Control flow analysis (CPA), call graph analysis
**Key Features**:
- Conditional statements (if/elif/else)
- While loops
- For loops
- Continue and break statements
- Function calls within control structures

**Usage**:
```bash
pyflow optimize control_flow.py --analysis cpa
pyflow callgraph control_flow.py
```

### 3. Data Structures (`data_structures.py`)
**Purpose**: Demonstrates object-oriented programming and data structure operations
**Analysis Types**: Shape analysis, inter-procedural analysis (IPA)
**Key Features**:
- Class definitions and methods
- Object instantiation and manipulation
- List operations and data flow
- Method calls and attribute access

**Usage**:
```bash
pyflow optimize data_structures.py --analysis shape
pyflow callgraph data_structures.py
```

### 4. Recursive Functions (`recursive_functions.py`)
**Purpose**: Demonstrates recursive algorithms and inter-procedural analysis
**Analysis Types**: Inter-procedural analysis (IPA), call graph analysis
**Key Features**:
- Recursive function calls
- Base cases and recursive cases
- Complex call graphs
- Tree traversal algorithms

**Usage**:
```bash
pyflow optimize recursive_functions.py --analysis ipa
pyflow callgraph recursive_functions.py
```

### 5. Exception Handling (`exception_handling.py`)
**Purpose**: Demonstrates exception handling, error flows, and control flow analysis
**Analysis Types**: Control flow analysis (CPA), inter-procedural analysis (IPA)
**Key Features**:
- Try/except/finally blocks
- Exception propagation
- Custom exceptions
- Error handling patterns
- Nested exception contexts

**Usage**:
```bash
pyflow optimize exception_handling.py --analysis cpa
pyflow callgraph exception_handling.py
```

### 6. Generators and Iterators (`generators_iterators.py`)
**Purpose**: Demonstrates Python generators, iterators, and iteration protocols
**Analysis Types**: Inter-procedural analysis (IPA), call graph analysis
**Key Features**:
- Generator functions and expressions
- Iterator protocols
- Async generators
- Generator composition
- Memory-efficient processing

**Usage**:
```bash
pyflow optimize generators_iterators.py --analysis ipa
pyflow callgraph generators_iterators.py
```

### 7. Decorators and Metaclasses (`decorators_metaclasses.py`)
**Purpose**: Demonstrates Python decorators, metaclasses, and advanced OOP features
**Analysis Types**: Inter-procedural analysis (IPA), call graph analysis
**Key Features**:
- Function and class decorators
- Metaclass programming
- Property decorators
- Decorator factories
- Context manager decorators

**Usage**:
```bash
pyflow optimize decorators_metaclasses.py --analysis ipa
pyflow callgraph decorators_metaclasses.py
```

### 8. Lambda Functions and Closures (`lambda_closures.py`)
**Purpose**: Demonstrates lambda functions, closures, and functional programming
**Analysis Types**: Inter-procedural analysis (IPA), call graph analysis
**Key Features**:
- Lambda expressions
- Closure creation and usage
- Higher-order functions
- Functional programming patterns
- State management with closures

**Usage**:
```bash
pyflow optimize lambda_closures.py --analysis ipa
pyflow callgraph lambda_closures.py
```

### 9. Type Annotations (`type_annotations.py`)
**Purpose**: Demonstrates Python type annotations, type hints, and type checking
**Analysis Types**: Inter-procedural analysis (IPA), type analysis
**Key Features**:
- Basic and complex type annotations
- Generic types and type variables
- Protocol definitions
- Union and Optional types
- Type aliases and overloads

**Usage**:
```bash
pyflow optimize type_annotations.py --analysis ipa
pyflow callgraph type_annotations.py
```

### 10. Async/Await (`async_await.py`)
**Purpose**: Demonstrates Python async/await, coroutines, and concurrency
**Analysis Types**: Inter-procedural analysis (IPA), call graph analysis
**Key Features**:
- Async functions and coroutines
- Async generators and iterators
- Concurrent execution patterns
- Async context managers
- Error handling in async code

**Usage**:
```bash
pyflow optimize async_await.py --analysis ipa
pyflow callgraph async_await.py
```

### 11. Complex Nested Structures (`complex_nested.py`)
**Purpose**: Demonstrates complex nested structures, edge cases, and advanced features
**Analysis Types**: All analysis types
**Key Features**:
- Complex inheritance hierarchies
- Nested data structures
- Advanced decorator patterns
- Complex error handling
- Generic programming

**Usage**:
```bash
pyflow optimize complex_nested.py --analysis all
pyflow callgraph complex_nested.py
```

### 12. Imports and Modules (`imports_modules.py`)
**Purpose**: Demonstrates Python import system, module loading, and dynamic imports
**Analysis Types**: Inter-procedural analysis (IPA), module analysis
**Key Features**:
- Dynamic module importing
- Module introspection
- Plugin systems
- Import hooks
- Dependency analysis

**Usage**:
```bash
pyflow optimize imports_modules.py --analysis ipa
pyflow callgraph imports_modules.py
```

## Running Examples

### Prerequisites
Make sure you have PyFlow installed and the virtual environment activated:

```bash
# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Verify installation
pyflow --version
```

### Basic Analysis
Run static analysis on any example:

```bash
# Analyze a single file
pyflow optimize examples/basic_arithmetic.py

# Analyze with specific analysis type
pyflow optimize examples/control_flow.py --analysis cpa

# Analyze with verbose output
pyflow optimize examples/data_structures.py --verbose

# Dump results to files
pyflow optimize examples/recursive_functions.py --dump --output results/
```

### Call Graph Generation
Generate call graphs for any example:

```bash
# Generate DOT format (default)
pyflow callgraph examples/basic_arithmetic.py

# Generate JSON format
pyflow callgraph examples/control_flow.py --format json

# Generate text format
pyflow callgraph examples/data_structures.py --format text

# Show cycles in call graph
pyflow callgraph examples/recursive_functions.py --show-cycles
```

### Batch Analysis
Analyze all examples at once:

```bash
# Analyze entire examples directory
pyflow optimize examples/ --recursive

# Generate call graphs for all examples
for file in examples/*.py; do
    pyflow callgraph "$file" --output "${file%.py}_callgraph.dot"
done
```

## Analysis Types Explained

- **CPA (Control Point Analysis)**: Analyzes control flow and branching behavior
- **IPA (Inter-Procedural Analysis)**: Analyzes function calls and data flow across function boundaries
- **Shape Analysis**: Analyzes data structures and object shapes
- **Lifetime Analysis**: Analyzes variable lifetimes and memory usage

## Expected Output

Each example should produce:
1. **Analysis results**: Information about functions, variables, and control flow
2. **Call graphs**: Visual representation of function call relationships
3. **Dumped files**: Detailed analysis results in various formats (when using `--dump`)

## Troubleshooting

If you encounter issues:

1. **Import errors**: Make sure you're in the project root directory
2. **Analysis failures**: Check that the virtual environment is activated
3. **Missing dependencies**: Run `pip install -e .` to install PyFlow
4. **Permission errors**: Ensure you have write permissions in the output directory

For more information, see the main [README.md](../README.md) and [CLI_README.md](../CLI_README.md).
