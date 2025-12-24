"""
Coverage-Guided Fuzzing Framework for Python.

This package provides a coverage-guided fuzzing framework inspired by AFL
and libFuzzer. The fuzzer uses code coverage feedback to guide input
generation, focusing on inputs that explore new code paths.

**Key Components:**

1. **Fuzzer** (`fuzzer.py`):
   - Main fuzzing engine with coverage tracking
   - Multiprocessing-based execution
   - Memory and timeout management

2. **Corpus** (`corpus.py`):
   - Manages seed inputs and generated test cases
   - Implements mutation strategies (bit flips, byte operations, etc.)
   - Saves interesting inputs that increase coverage

3. **Tracer** (`tracer.py`):
   - Line-level code coverage tracking using sys.settrace
   - Tracks coverage across file boundaries
   - Provides coverage metrics

4. **Dictionary** (`dictionnary.py`):
   - Optional dictionary of interesting keywords/tokens
   - Can be used to guide mutations

5. **Main** (`main.py`):
   - Command-line interface and decorator
   - Parses arguments and starts fuzzing

**Fuzzing Algorithm:**
1. Start with seed corpus (user-provided inputs)
2. For each input:
   - Execute target function with input
   - Measure code coverage
   - If coverage increased, save input to corpus
3. Generate new inputs by mutating corpus inputs
4. Repeat until timeout, crash, or memory limit

**Usage:**
```python
from pyflow.fuzzer import PythonFuzz

@PythonFuzz
def fuzz_target(buf):
    # Function to fuzz
    my_function(buf)

if __name__ == '__main__':
    fuzz_target()
```

**Mutation Strategies:**
- Bit flips
- Byte operations (set, swap, add/subtract)
- Integer operations (uint16, uint32, uint64)
- Range operations (remove, insert, duplicate, copy)
- Interesting value replacement
- ASCII digit mutation
"""

__all__ = ['PythonFuzz', 'Fuzzer', 'Corpus', 'Dictionary']

