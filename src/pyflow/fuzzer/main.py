"""
Command-line interface and decorator for PyFlow fuzzer.

This module provides the PythonFuzz decorator that makes it easy to fuzz
Python functions. When applied to a function, it creates a command-line
interface for running the fuzzer.

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

Then run from command line:
```bash
python fuzz_target.py corpus/ --timeout 30 --runs 10000
```
"""

import argparse
from pyflow.fuzzer.fuzzer import Fuzzer


class PythonFuzz(object):
    """
    Decorator for creating fuzzable Python functions.
    
    When applied to a function, this decorator creates a command-line
    interface for running coverage-guided fuzzing on that function.
    
    **Target Function Signature:**
    The target function should take a single bytearray argument:
    ```python
    def fuzz_target(buf):
        # Process buf
        pass
    ```
    
    **Command-Line Arguments:**
    - dirs: Seed corpus directories/files
    - --exact-artifact-path: Path for crashes
    - --regression: Run in regression mode
    - --rss-limit-mb: Memory limit (default: 2048)
    - --max-input-size: Max input size (default: 4096)
    - --dict: Dictionary file path
    - --close-fd-mask: Close stdout/stderr (0-3)
    - --runs: Maximum runs (-1 = unlimited)
    - --timeout: Timeout per test (default: 30)
    """
    def __init__(self, func):
        """
        Initialize the decorator.
        
        Args:
            func: Target function to fuzz (takes bytearray input)
        """
        self.function = func

    def __call__(self, *args, **kwargs):
        """
        Command-line interface entry point.
        
        Parses command-line arguments and starts the fuzzer with the
        configured target function.
        """
        parser = argparse.ArgumentParser(description='Coverage-guided fuzzer for python packages')
        parser.add_argument('dirs', type=str, nargs='*',
                            help="one or more directories/files to use as seed corpus. the first directory will be used to save the generated test-cases")
        parser.add_argument('--exact-artifact-path', type=str, help='set exact artifact path for crashes/ooms')
        parser.add_argument('--regression',
                            type=bool,
                            default=False,
                            help='run the fuzzer through set of files for regression or reproduction')
        parser.add_argument('--rss-limit-mb', type=int, default=2048, help='Memory usage in MB')
        parser.add_argument('--max-input-size', type=int, default=4096, help='Max input size in bytes')
        parser.add_argument('--dict', type=str, help='dictionary file')
        parser.add_argument('--close-fd-mask', type=int, default=0, help='Indicate output streams to close at startup')
        parser.add_argument('--runs', type=int, default=-1, help='Number of individual test runs, -1 (the default) to run indefinitely.')
        parser.add_argument('--timeout', type=int, default=30,
                            help='If input takes longer then this timeout the process is treated as failure case')
        args = parser.parse_args()
        
        # Create and start fuzzer
        f = Fuzzer(self.function, args.dirs, args.exact_artifact_path,
                          args.rss_limit_mb, args.timeout, args.regression, args.max_input_size,
                          args.close_fd_mask, args.runs, args.dict)
        f.start()


if __name__ == '__main__':
    PythonFuzz()
