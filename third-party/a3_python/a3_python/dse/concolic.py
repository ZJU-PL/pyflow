"""
Concolic (concrete + symbolic) execution for trace validation.

DSE is used ONLY as a refinement oracle:
- To validate that symbolic counterexample traces are realizable
- To produce concrete repro inputs for bug reports
- To witness behaviors for contract refinement

DSE is NEVER used to:
- Prove infeasibility (failure to find inputs does NOT mean trace is spurious)
- Shrink over-approximations without independent justification
"""

import types
import sys
import io
import traceback
from dataclasses import dataclass
from typing import Any, Optional, List, Dict, Tuple
import z3

from ..semantics.state import Frame


@dataclass
class ConcreteInput:
    """
    Concrete input values for program execution.
    
    Represents a complete assignment to all symbolic variables.
    """
    args: List[Any]  # Function arguments
    globals_dict: Dict[str, Any]  # Global variables
    env: Dict[str, str]  # Environment variables
    stdin: str  # Standard input
    module_name: Optional[str] = None  # Module name for __name__
    file_path: Optional[str] = None  # File path for __file__
    
    @staticmethod
    def empty() -> 'ConcreteInput':
        """Empty input (no arguments, minimal globals)."""
        return ConcreteInput(
            args=[],
            globals_dict={},
            env={},
            stdin="",
            module_name="__main__",
            file_path=None
        )
    
    @staticmethod
    def for_module(module_name: str, file_path: str, 
                   globals_dict: Optional[Dict[str, Any]] = None) -> 'ConcreteInput':
        """Create input for module-level code execution."""
        return ConcreteInput(
            args=[],
            globals_dict=globals_dict or {},
            env={},
            stdin="",
            module_name=module_name,
            file_path=file_path
        )


@dataclass
class ConcreteTrace:
    """
    A concrete execution trace.
    
    Records the actual execution path and final state.
    """
    executed_offsets: List[int]  # Bytecode offsets executed
    final_state: Optional[Any]  # Final return value or exception
    exception_raised: Optional[Exception]  # Exception if raised
    stdout: str  # Captured stdout
    stderr: str  # Captured stderr
    
    def is_normal_return(self) -> bool:
        """Check if execution returned normally (no exception)."""
        return self.exception_raised is None
    
    def matches_offsets(self, expected_offsets: List[int]) -> bool:
        """
        Check if this trace matches expected bytecode offsets.
        
        Note: This is a conservative check. Traces may differ in loop unrolling
        or exception handler details while still being semantically equivalent.
        """
        # For now, exact match required
        return self.executed_offsets == expected_offsets


@dataclass
class DSEResult:
    """
    Result of a DSE trace validation attempt.
    
    This represents what we learned from trying to concretize a symbolic trace.
    """
    status: str  # "realized" | "failed" | "timeout" | "error"
    concrete_input: Optional[ConcreteInput]  # Input if realized
    concrete_trace: Optional[ConcreteTrace]  # Trace if executed
    message: str  # Human-readable description
    
    # Metadata for analysis/refinement
    z3_model: Optional[z3.ModelRef] = None  # Z3 model that generated the input
    solver_time_sec: float = 0.0  # Time spent in Z3
    execution_time_sec: float = 0.0  # Time spent in concrete execution
    
    @staticmethod
    def realized(concrete_input: ConcreteInput, concrete_trace: ConcreteTrace,
                 z3_model: Optional[z3.ModelRef] = None) -> 'DSEResult':
        """Trace was successfully realized with concrete inputs."""
        return DSEResult(
            status="realized",
            concrete_input=concrete_input,
            concrete_trace=concrete_trace,
            message="Symbolic trace realized with concrete inputs",
            z3_model=z3_model
        )
    
    @staticmethod
    def failed(message: str) -> 'DSEResult':
        """
        Failed to realize the trace within budget.
        
        CRITICAL: This does NOT mean the trace is infeasible!
        It only means we couldn't find concrete inputs in the time/space budget.
        """
        return DSEResult(
            status="failed",
            concrete_input=None,
            concrete_trace=None,
            message=f"Failed to realize trace: {message}"
        )
    
    @staticmethod
    def error(message: str) -> 'DSEResult':
        """Error during DSE (internal failure, not program failure)."""
        return DSEResult(
            status="error",
            concrete_input=None,
            concrete_trace=None,
            message=f"DSE error: {message}"
        )


class ConcreteExecutor:
    """
    Concrete bytecode executor for trace validation.
    
    Executes Python code objects with concrete inputs and traces the execution.
    This is the "dynamic" part of dynamic symbolic execution.
    """
    
    def __init__(self, max_steps: int = 10000):
        """
        Initialize concrete executor.
        
        Args:
            max_steps: Maximum bytecode instructions to execute (prevents infinite loops)
        """
        self.max_steps = max_steps
    
    def execute(self, code_obj: types.CodeType, concrete_input: ConcreteInput) -> ConcreteTrace:
        """
        Execute a code object with concrete inputs and record the trace.
        
        Args:
            code_obj: Compiled Python code object
            concrete_input: Concrete input values
            
        Returns:
            ConcreteTrace recording the execution
            
        Raises:
            No exceptions (captures all exceptions in trace)
        """
        executed_offsets = []
        exception_raised = None
        final_state = None
        
        # Capture stdout/stderr
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        
        # Save and extend sys.path for imports
        old_path = sys.path.copy()
        
        try:
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture
            
            # Set up sys.path for imports if we have a file path
            if concrete_input.file_path:
                # Add directory containing the file to sys.path
                import os
                file_dir = os.path.dirname(os.path.abspath(concrete_input.file_path))
                if file_dir not in sys.path:
                    sys.path.insert(0, file_dir)
            
            # Build execution environment with proper module globals
            globals_dict = self._build_globals(concrete_input, code_obj)
            
            # Execute with tracing
            final_state = self._execute_traced(code_obj, concrete_input.args, 
                                               globals_dict, executed_offsets)
            
        except Exception as e:
            exception_raised = e
            
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            sys.path = old_path  # Restore sys.path
        
        return ConcreteTrace(
            executed_offsets=executed_offsets,
            final_state=final_state,
            exception_raised=exception_raised,
            stdout=stdout_capture.getvalue(),
            stderr=stderr_capture.getvalue()
        )
    
    def _build_globals(self, concrete_input: ConcreteInput, code_obj: types.CodeType) -> Dict[str, Any]:
        """
        Build a proper globals dictionary for code execution.
        
        Includes standard module-level globals like __name__, __file__, etc.
        This prevents spurious NameError/KeyError from missing standard globals.
        """
        globals_dict = concrete_input.globals_dict.copy()
        
        # Always include builtins
        globals_dict['__builtins__'] = __builtins__
        
        # Add standard module globals if not already present
        if '__name__' not in globals_dict:
            globals_dict['__name__'] = concrete_input.module_name or '__main__'
        
        if '__file__' not in globals_dict and concrete_input.file_path:
            globals_dict['__file__'] = concrete_input.file_path
        
        # Add __package__ for proper relative imports
        if '__package__' not in globals_dict:
            # Derive package from module name if possible
            module_name = concrete_input.module_name or '__main__'
            if '.' in module_name:
                globals_dict['__package__'] = module_name.rsplit('.', 1)[0]
            else:
                globals_dict['__package__'] = None
        
        # Add __spec__ (module spec) - set to None for simplicity
        if '__spec__' not in globals_dict:
            globals_dict['__spec__'] = None
        
        # Add __doc__ if not present
        if '__doc__' not in globals_dict:
            globals_dict['__doc__'] = code_obj.co_name if hasattr(code_obj, 'co_name') else None
        
        # Add __cached__ (compiled bytecode cache path)
        if '__cached__' not in globals_dict:
            globals_dict['__cached__'] = None
        
        # Add __loader__ (module loader)
        if '__loader__' not in globals_dict:
            globals_dict['__loader__'] = None
        
        return globals_dict
    
    def _execute_traced(self, code_obj: types.CodeType, args: List[Any],
                       globals_dict: Dict[str, Any], trace: List[int]) -> Any:
        """
        Execute code object and record bytecode offsets.
        
        Uses sys.settrace to track bytecode execution.
        """
        executed_lines = []
        
        def trace_fn(frame, event, arg):
            """Trace function to record execution."""
            if event == 'line' and frame.f_code == code_obj:
                # Record the bytecode offset
                offset = frame.f_lasti
                if offset >= 0:  # -1 means "about to start"
                    trace.append(offset)
                    
                # Check step limit
                if len(trace) >= self.max_steps:
                    raise RuntimeError(f"Execution exceeded {self.max_steps} steps")
            
            return trace_fn
        
        # Set up tracing
        old_trace = sys.gettrace()
        sys.settrace(trace_fn)
        
        try:
            # Create a function from the code object and execute it
            func = types.FunctionType(code_obj, globals_dict)
            result = func(*args)
            return result
        finally:
            sys.settrace(old_trace)


class TraceValidator:
    """
    Validates symbolic traces by attempting to find concrete inputs.
    
    This is the core DSE oracle: given a symbolic path (as Z3 constraints),
    attempt to find concrete inputs that realize that path.
    """
    
    def __init__(self, timeout_sec: int = 10):
        """
        Initialize trace validator.
        
        Args:
            timeout_sec: Z3 solver timeout
        """
        self.timeout_sec = timeout_sec
        self.executor = ConcreteExecutor()
    
    def validate_path(self, path_condition: z3.ExprRef, 
                     code_obj: types.CodeType,
                     symbolic_inputs: Dict[str, z3.ExprRef],
                     expected_offsets: Optional[List[int]] = None) -> DSEResult:
        """
        Attempt to validate a symbolic path by finding concrete inputs.
        
        This is the key DSE operation:
        1. Solve path_condition for concrete values of symbolic_inputs
        2. Execute code_obj with those concrete values
        3. Check if the concrete trace matches the symbolic path
        
        Args:
            path_condition: Z3 constraint representing the symbolic path
            code_obj: Code object to execute
            symbolic_inputs: Mapping from input names to symbolic variables
            expected_offsets: Expected bytecode offsets (optional)
            
        Returns:
            DSEResult indicating success/failure and concrete trace if found
        """
        import time
        
        solver_start = time.time()
        
        # Solve for concrete inputs
        solver = z3.Solver()
        solver.set("timeout", self.timeout_sec * 1000)  # milliseconds
        solver.add(path_condition)
        
        result = solver.check()
        solver_time = time.time() - solver_start
        
        if result == z3.unsat:
            # Path is infeasible - this is actually useful information!
            # It means our symbolic execution found an infeasible path
            return DSEResult.failed(
                "Path condition is unsatisfiable (infeasible symbolic path)"
            )
        
        if result == z3.unknown:
            return DSEResult.failed(
                f"Z3 solver returned unknown (timeout or incomplete theory)"
            )
        
        # result == z3.sat - extract model
        model = solver.model()
        
        # Convert Z3 model to concrete inputs
        try:
            concrete_input = self._extract_concrete_input(model, symbolic_inputs)
        except Exception as e:
            return DSEResult.error(f"Failed to extract concrete inputs: {e}")
        
        # Execute with concrete inputs
        exec_start = time.time()
        try:
            concrete_trace = self.executor.execute(code_obj, concrete_input)
        except Exception as e:
            return DSEResult.error(f"Concrete execution failed: {e}")
        exec_time = time.time() - exec_start
        
        # Verify trace matches expectations (if provided)
        if expected_offsets is not None:
            if not concrete_trace.matches_offsets(expected_offsets):
                # The concrete trace diverged from the symbolic trace
                # This can happen due to:
                # - Over-approximate symbolic semantics
                # - Non-determinism in the program
                # - Bugs in our symbolic executor
                return DSEResult.failed(
                    f"Concrete trace diverged from symbolic trace. "
                    f"Expected {len(expected_offsets)} offsets, "
                    f"got {len(concrete_trace.executed_offsets)}."
                )
        
        # Success! We realized the trace
        result = DSEResult.realized(concrete_input, concrete_trace, model)
        result.solver_time_sec = solver_time
        result.execution_time_sec = exec_time
        return result
    
    def _extract_concrete_input(self, model: z3.ModelRef,
                                symbolic_inputs: Dict[str, z3.ExprRef]) -> ConcreteInput:
        """
        Extract concrete input values from a Z3 model.
        
        Converts Z3 values (integers, booleans, etc.) to Python values.
        """
        args = []
        globals_dict = {}
        
        for name, sym_var in symbolic_inputs.items():
            # Evaluate the symbolic variable in the model
            value = model.eval(sym_var, model_completion=True)
            
            # Convert Z3 value to Python value
            py_value = self._z3_to_python(value)
            
            # Categorize as argument or global
            # For now, simple heuristic: names starting with 'arg' are arguments
            if name.startswith('arg'):
                args.append(py_value)
            else:
                globals_dict[name] = py_value
        
        return ConcreteInput(
            args=args,
            globals_dict=globals_dict,
            env={},
            stdin=""
        )
    
    def _z3_to_python(self, z3_value) -> Any:
        """Convert a Z3 value to a Python value."""
        if z3.is_int_value(z3_value):
            return z3_value.as_long()
        elif z3.is_bool(z3_value):
            return z3.is_true(z3_value)
        elif z3.is_string_value(z3_value):
            return z3_value.as_string()
        else:
            # For other types, try to convert to string
            # This is a conservative fallback
            return str(z3_value)
    
    def attempt_refinement(self, unknown_call: str, 
                          observed_behaviors: List[Tuple[ConcreteInput, Any]]) -> str:
        """
        Suggest contract refinement based on observed behaviors.
        
        CRITICAL: This must maintain soundness (over-approximation).
        We can only refine if we have *independent justification* that
        the observed behaviors are exhaustive or representative.
        
        For now, this just logs observations and returns suggestions
        (not automatic refinement).
        
        Args:
            unknown_call: Name of the unknown function
            observed_behaviors: List of (input, output) pairs witnessed via DSE
            
        Returns:
            Human-readable suggestion for refinement (requires manual validation)
        """
        # Analyze observed behaviors
        return_types = set()
        exceptions_seen = set()
        
        for input_val, output in observed_behaviors:
            if isinstance(output, Exception):
                exceptions_seen.add(type(output).__name__)
            else:
                return_types.add(type(output).__name__)
        
        suggestion = f"DSE observed behaviors for {unknown_call}:\n"
        suggestion += f"  Return types: {return_types}\n"
        suggestion += f"  Exceptions: {exceptions_seen}\n"
        suggestion += "\nTo refine contract:\n"
        suggestion += "  1. Verify these behaviors are sound (over-approximate actual behavior)\n"
        suggestion += "  2. Consult documentation/source code for independent justification\n"
        suggestion += "  3. Update contract conservatively in contracts/stdlib.py\n"
        suggestion += "  4. NEVER shrink contract based solely on DSE failure to find behaviors\n"
        
        return suggestion
