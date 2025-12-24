"""
Coverage-Guided Fuzzer Implementation.

This module provides the main Fuzzer class that orchestrates coverage-guided
fuzzing. It uses multiprocessing to isolate test execution and tracks code
coverage to guide input generation.

**Fuzzing Architecture:**
- Main process: Generates inputs, tracks coverage, manages corpus
- Worker process: Executes target function, measures coverage
- Communication: Pipe for sending inputs and receiving coverage

**Fuzzing Loop:**
1. Generate input (from corpus or mutation)
2. Send input to worker process
3. Worker executes target function with input
4. Worker measures coverage and sends back
5. If coverage increased, add input to corpus
6. Repeat until timeout, crash, or memory limit

**Safety Features:**
- Timeout per test case
- Memory limit (RSS)
- Process isolation (crashes don't kill main process)
- Coverage tracking to focus on interesting inputs
"""

import os
import time
import sys
import psutil
import hashlib
import logging
import multiprocessing as mp

from pyflow.fuzzer.corpus import Corpus
from pyflow.fuzzer.tracer import trace, get_coverage


# Set multiprocessing start method to 'fork' on Unix (faster than 'spawn')
if sys.platform != 'win32':
    mp.set_start_method('fork')

# Configure logging
logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
logging.getLogger().setLevel(logging.DEBUG)

# Time window for periodic statistics logging (in seconds)
SAMPLING_WINDOW = 5


def worker(target, child_conn, close_fd_mask):
    """
    Worker process for executing fuzz targets.
    
    This function runs in a separate process to isolate test execution.
    It:
    1. Sets up coverage tracing
    2. Silences output (if configured)
    3. Receives inputs from main process
    4. Executes target function with input
    5. Sends coverage back to main process
    
    **Isolation:**
    Running in a separate process ensures that crashes, exceptions, or
    hangs in the target function don't kill the main fuzzer process.
    
    **Coverage Tracking:**
    sys.settrace(trace) enables line-level coverage tracking. After each
    execution, get_coverage() returns the total number of unique line
    transitions seen.
    
    Args:
        target: Target function to fuzz (takes bytearray input)
        child_conn: Child end of pipe for receiving inputs
        close_fd_mask: Bitmask for closing stdout/stderr (1=stdout, 2=stderr)
    """
    # Silence the fuzzee's noise (optional)
    class DummyFile:
        """No-op file object to discard output."""
        def write(self, x):
            pass
    
    logging.captureWarnings(True)
    logging.getLogger().setLevel(logging.ERROR)
    
    # Optionally close stdout/stderr to reduce noise
    if close_fd_mask & 1:
        sys.stdout = DummyFile()
    if close_fd_mask & 2:
        sys.stderr = DummyFile()

    # Enable coverage tracing
    sys.settrace(trace) 
    
    # Main worker loop
    while True:
        # Receive input from main process
        buf = child_conn.recv_bytes()
        try:
            # Execute target function with input
            target(buf)
        except Exception as e:
            # Exception occurred - send it back and exit
            logging.exception(e)
            child_conn.send(e)
            break
        else:
            # Success - send coverage count back
            child_conn.send_bytes(b'%d' % get_coverage())


class Fuzzer(object):
    """
    Coverage-guided fuzzer for Python functions.
    
    This class implements a coverage-guided fuzzer similar to AFL/libFuzzer.
    It uses code coverage feedback to guide input generation, focusing on
    inputs that explore new code paths.
    
    **Fuzzing Strategy:**
    - Starts with seed corpus (user-provided inputs)
    - Generates new inputs by mutating corpus inputs
    - Tracks code coverage for each execution
    - Adds inputs that increase coverage to corpus
    - Continues until timeout, crash, or memory limit
    
    **Process Model:**
    - Main process: Input generation, corpus management, statistics
    - Worker process: Test execution, coverage measurement
    - Communication via multiprocessing.Pipe
    
    **Safety Limits:**
    - Timeout per test case (kills hanging tests)
    - Memory limit (RSS) to prevent OOM
    - Maximum number of runs (optional)
    
    Attributes:
        _target: Target function to fuzz
        _dirs: Directories for corpus (seed inputs and generated test cases)
        _exact_artifact_path: Exact path for saving crashes (optional)
        _rss_limit_mb: Memory limit in MB
        _timeout: Timeout per test case in seconds
        _regression: Whether running in regression mode
        _close_fd_mask: Bitmask for closing stdout/stderr
        _corpus: Corpus manager for inputs
        _total_executions: Total number of test executions
        _executions_in_sample: Executions in current sampling window
        _last_sample_time: Time of last statistics log
        _total_coverage: Total unique line transitions seen
        _p: Worker process handle
        runs: Maximum number of runs (-1 = unlimited)
    """
    def __init__(self,
                 target,
                 dirs=None,
                 exact_artifact_path=None,
                 rss_limit_mb=2048,
                 timeout=120,
                 regression=False,
                 max_input_size=4096,
                 close_fd_mask=0,
                 runs=-1,
                 dict_path=None):
        """
        Initialize a fuzzer.
        
        Args:
            target: Target function to fuzz (takes bytearray input)
            dirs: Directories/files for seed corpus (first dir saves generated inputs)
            exact_artifact_path: Exact path for crashes (optional)
            rss_limit_mb: Memory limit in MB (default: 2048)
            timeout: Timeout per test case in seconds (default: 120)
            regression: Whether running in regression mode (default: False)
            max_input_size: Maximum input size in bytes (default: 4096)
            close_fd_mask: Bitmask for closing stdout/stderr (default: 0)
            runs: Maximum number of runs (-1 = unlimited, default: -1)
            dict_path: Path to dictionary file (optional)
        """
        self._target = target
        self._dirs = [] if dirs is None else dirs
        self._exact_artifact_path = exact_artifact_path
        self._rss_limit_mb = rss_limit_mb
        self._timeout = timeout
        self._regression = regression
        self._close_fd_mask = close_fd_mask
        self._corpus = Corpus(self._dirs, max_input_size, dict_path)
        self._total_executions = 0
        self._executions_in_sample = 0
        self._last_sample_time = time.time()
        self._total_coverage = 0
        self._p = None
        self.runs = runs

    def log_stats(self, log_type):
        """
        Log fuzzing statistics.
        
        Logs current fuzzing statistics including:
        - Total executions
        - Coverage count
        - Corpus size
        - Executions per second
        - Memory usage (RSS)
        
        Args:
            log_type: Type of log entry ("NEW" for coverage increase, "PULSE" for periodic)
            
        Returns:
            Current RSS memory usage in MB
        """
        # Calculate total RSS (main process + worker process)
        rss = (psutil.Process(self._p.pid).memory_info().rss + psutil.Process(os.getpid()).memory_info().rss) / 1024 / 1024

        endTime = time.time()
        execs_per_second = int(self._executions_in_sample / (endTime - self._last_sample_time))
        self._last_sample_time = time.time()
        self._executions_in_sample = 0
        logging.info('#{} {}     cov: {} corp: {} exec/s: {} rss: {} MB'.format(
            self._total_executions, log_type, self._total_coverage, self._corpus.length, execs_per_second, rss))
        return rss

    def write_sample(self, buf, prefix='crash-'):
        """
        Write a test case to disk (crash, timeout, or OOM).
        
        Saves the input that caused a crash, timeout, or OOM to disk.
        Uses SHA256 hash as filename to avoid duplicates. If the input
        is small (< 200 bytes), also logs its hex representation.
        
        Args:
            buf: Input bytearray to save
            prefix: Filename prefix ('crash-', 'timeout-', etc.)
        """
        m = hashlib.sha256()
        m.update(buf)
        if self._exact_artifact_path:
            crash_path = self._exact_artifact_path
        else:
            # Save to crashes/ directory
            dir_path = 'crashes'
            isExist = os.path.exists(dir_path)
            if not isExist:
              os.makedirs(dir_path)
              logging.info("The crashes directory is created")

            crash_path = dir_path + "/" + prefix + m.hexdigest()
        with open(crash_path, 'wb') as f:
            f.write(buf)
        logging.info('sample was written to {}'.format(crash_path))
        # Log hex representation for small inputs (useful for debugging)
        if len(buf) < 200:
            logging.info('sample = {}'.format(buf.hex()))

    def start(self):
        """
        Start the fuzzing loop.
        
        This is the main fuzzing loop that:
        1. Spawns worker process
        2. Generates inputs from corpus
        3. Sends inputs to worker
        4. Receives coverage feedback
        5. Adds interesting inputs to corpus
        6. Logs statistics periodically
        7. Handles timeouts, crashes, and memory limits
        
        **Exit Conditions:**
        - Maximum runs reached
        - Timeout on test case
        - Exception in target function (crash)
        - Memory limit exceeded (OOM)
        
        **Coverage-Guided Strategy:**
        Only inputs that increase code coverage are added to the corpus.
        This focuses fuzzing on exploring new code paths.
        """
        logging.info("#0 READ units: {}".format(self._corpus.length))
        exit_code = 0
        
        # Create pipe for communication with worker
        parent_conn, child_conn = mp.Pipe()
        
        # Spawn worker process
        self._p = mp.Process(target=worker, args=(self._target, child_conn, self._close_fd_mask))
        self._p.start()

        # Main fuzzing loop
        while True:
            # Check if maximum runs reached
            if self.runs != -1 and self._total_executions >= self.runs:
                self._p.terminate()
                logging.info('did %d runs, stopping now.', self.runs)
                break

            # Generate next input (from corpus or mutation)
            buf = self._corpus.generate_input()
            
            # Send input to worker
            parent_conn.send_bytes(buf)
            
            # Wait for response with timeout
            if not parent_conn.poll(self._timeout):
                # Timeout: worker didn't respond in time
                self._p.kill()
                logging.info("=================================================================")
                logging.info("timeout reached. testcase took: {}".format(self._timeout))
                self.write_sample(buf, prefix='timeout-')
                break

            try:
                # Receive coverage count from worker
                total_coverage = int(parent_conn.recv_bytes())
            except ValueError:
                # Exception occurred (worker sent exception object, not coverage)
                self.write_sample(buf)
                exit_code = 76  # Exit code for crash
                break

            # Update statistics
            self._total_executions += 1
            self._executions_in_sample += 1
            rss = 0
            
            # Check if coverage increased
            if total_coverage > self._total_coverage:
                # New coverage: add input to corpus and log
                rss = self.log_stats("NEW")
                self._total_coverage = total_coverage
                self._corpus.put(buf)
            else:
                # No new coverage: log periodically
                if (time.time() - self._last_sample_time) > SAMPLING_WINDOW:
                    rss = self.log_stats('PULSE')

            # Check memory limit
            if rss > self._rss_limit_mb:
                logging.info('MEMORY OOM: exceeded {} MB. Killing worker'.format(self._rss_limit_mb))
                self.write_sample(buf)
                self._p.kill()
                break

        # Clean up worker process
        self._p.join()
        sys.exit(exit_code)
