"""
PyFlow Application Layer.

This package contains the high-level application components for PyFlow,
providing the main interface for static analysis and optimization of Python
programs. It includes program representation, pipeline management, pass
management, and error handling.

**Core Components:**

1. **Program Representation** (`program.py`):
   - `Program`: Central data structure representing a Python program
   - `InterfaceDeclaration`: Declarations of functions, classes, and entry points

2. **Pipeline Management** (`pipeline.py`):
   - `Pipeline`: Main analysis pipeline orchestrating passes
   - Supports both legacy hardcoded pipeline and new pass manager system

3. **Pass Manager System** (`passmanager.py`):
   - `PassManager`: LLVM-inspired pass manager for flexible pass composition
   - `Pass`, `AnalysisPass`, `OptimizationPass`: Base classes for passes
   - `PassPipeline`: Represents sequences of passes to execute
   - Dependency resolution, caching, and invalidation

4. **Standard Passes** (`passes.py`):
   - Wrappers for existing analysis and optimization modules
   - IPA, CPA, Lifetime Analysis
   - Method call optimization, simplification, cloning, etc.

5. **Context Management** (`context.py`):
   - `CompilerContext`: Compilation context with console, slots, stats
   - `Slots`: Unique slot name management

6. **Makefile DSL** (`makefile.py`):
   - Domain-specific language for configuring analysis runs
   - Declares modules, entry points, and configuration

7. **Error Handling** (`errors.py`):
   - Custom exception classes for compilation errors

**Architecture:**
The application layer sits on top of the analysis and optimization modules,
providing a unified interface for running static analysis. The pass manager
system enables flexible composition of analysis passes while maintaining
correctness through dependency tracking and caching.

**Usage:**
```python
from pyflow.application import Program, Pipeline, CompilerContext
from pyflow.util.application.console import Console

# Create context and program
compiler = CompilerContext(Console())
program = Program()

# Configure program (add entry points, etc.)
# ...

# Run analysis pipeline
pipeline = Pipeline(use_pass_manager=True)
results = pipeline.run(program, compiler)
```
"""

from .program import Program
from .pipeline import Pipeline
from .context import Context
from .errors import CompilerAbort

# Pass manager system
from .passmanager import (
    PassManager, PassPipeline, Pass, PassResult, PassInfo,
    AnalysisPass, OptimizationPass, TransformationPass,
    PassKind, PassCache, create_analysis_pass, create_optimization_pass
)
from .passes import register_standard_passes

__all__ = [
    "Program", "Pipeline", "Context", "CompilerAbort",
    # Pass manager system
    "PassManager", "PassPipeline", "Pass", "PassResult", "PassInfo",
    "AnalysisPass", "OptimizationPass", "TransformationPass",
    "PassKind", "PassCache", "create_analysis_pass", "create_optimization_pass",
    "register_standard_passes"
]
