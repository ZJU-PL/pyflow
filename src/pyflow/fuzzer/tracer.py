"""
Code Coverage Tracer for Fuzzing.

This module provides line-level code coverage tracking using Python's
sys.settrace mechanism. It tracks which lines are executed during fuzzing
to guide input generation.

**Coverage Tracking:**
- Tracks line-level coverage (which lines are executed)
- Tracks transitions between files
- Provides total coverage count (number of unique line transitions)

**Coverage Representation:**
Coverage is stored as (prev_line, curr_line) pairs for each file.
This captures both which lines are executed and the transitions between
lines, providing more detailed coverage information than just line sets.

**Usage:**
The tracer is set up using sys.settrace(trace) in the worker process.
After each test execution, get_coverage() returns the total number of
unique line transitions seen so far.
"""

import collections
import sys

# Global state for coverage tracking
prev_line = 0
prev_filename = ''
# Coverage data: filename -> set of (prev_line, curr_line) transitions
data = collections.defaultdict(set)

def trace(frame, event, arg):
    """
    Trace function for sys.settrace.
    
    This function is called by Python for each line execution when
    sys.settrace(trace) is active. It tracks line transitions to measure
    code coverage.
    
    **Coverage Model:**
    - Tracks transitions: (previous_line, current_line) pairs
    - Handles file boundaries: concatenates filenames for inter-file transitions
    - Only processes 'line' events (ignores call, return, etc.)
    
    Args:
        frame: Current execution frame
        event: Event type ('line', 'call', 'return', etc.)
        arg: Event argument (unused for 'line' events)
        
    Returns:
        The trace function itself (to continue tracing)
    """
    # Only track line events (actual line executions)
    if event != 'line':
        return trace

    global prev_line
    global prev_filename

    func_filename = frame.f_code.co_filename
    func_line_no = frame.f_lineno

    if func_filename != prev_filename:
        # File boundary: track transition from previous file to current file
        # We concatenate filenames to track inter-file transfers
        # This is a simple approach that works for coverage-guided fuzzing
        data[func_filename + prev_filename].add((prev_line, func_line_no))
    else:
        # Same file: track line transition within file
        data[func_filename].add((prev_line, func_line_no))

    # Update previous state for next transition
    prev_line = func_line_no
    prev_filename = func_filename

    return trace


def get_coverage():
    """
    Get total code coverage count.
    
    Returns the total number of unique line transitions seen so far.
    This is used by the fuzzer to determine if a test case increased coverage.
    
    Returns:
        Total number of unique (prev_line, curr_line) transitions
    """
    return sum(map(len, data.values()))
