"""
Constraint solver for extracting path constraints from symbolic traces.

This module provides:
1. Extraction of Z3 constraints from SymbolicMachineState path conditions
2. Solving constraints to generate concrete inputs that satisfy the path
3. Mapping Z3 model values back to Python concrete values

This is the bridge between symbolic execution (Z3 formulas) and
dynamic execution (concrete Python values).
"""

import z3
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

from ..semantics.symbolic_vm import SymbolicMachineState, SymbolicPath
from ..z3model.values import SymbolicValue, ValueTag
from .concolic import ConcreteInput


@dataclass
class PathConstraints:
    """
    Extracted path constraints from a symbolic execution path.
    
    This represents all the constraints that must be satisfied for
    the path to be feasible and reach a specific program state.
    """
    path_condition: z3.ExprRef  # Main path condition (conjunction of all branch conditions)
    symbolic_inputs: Dict[str, SymbolicValue]  # Mapping of input variable names to symbolic values
    z3_solver: z3.Solver  # Solver with all constraints added
    
    def __repr__(self) -> str:
        return f"PathConstraints(inputs={list(self.symbolic_inputs.keys())}, constraints={self.path_condition})"


class ConstraintExtractor:
    """
    Extracts path constraints from symbolic execution states.
    
    This converts the accumulated path_condition in a SymbolicMachineState
    into a form that can be solved to generate concrete inputs.
    """
    
    def __init__(self):
        self.solver = z3.Solver()
    
    def extract_from_path(self, path: SymbolicPath) -> PathConstraints:
        """
        Extract all constraints from a symbolic execution path.
        
        Args:
            path: A symbolic execution path with accumulated path conditions
            
        Returns:
            PathConstraints object containing the Z3 constraints and symbolic inputs
        """
        state = path.state
        path_condition = state.path_condition
        
        # Extract symbolic inputs from the state
        # These are the variables we need to solve for
        symbolic_inputs = self._extract_symbolic_inputs(state)
        
        # Create a fresh solver for this path
        solver = z3.Solver()
        solver.add(path_condition)
        
        return PathConstraints(
            path_condition=path_condition,
            symbolic_inputs=symbolic_inputs,
            z3_solver=solver
        )
    
    def _extract_symbolic_inputs(self, state: SymbolicMachineState) -> Dict[str, SymbolicValue]:
        """
        Extract symbolic input variables from the machine state.
        
        Looks for:
        - Function arguments (from locals)
        - Global variables that are symbolic
        - Environment variables (if modeled)
        
        Returns mapping of variable names to their symbolic values.
        """
        symbolic_inputs = {}
        
        if not state.frame_stack:
            return symbolic_inputs
        
        # Get the bottom frame (entry point)
        entry_frame = state.frame_stack[0]
        
        # Extract symbolic locals (function arguments)
        for name, value in entry_frame.locals.items():
            if self._is_symbolic(value):
                symbolic_inputs[f"local_{name}"] = value
        
        # Extract symbolic globals (if any)
        for name, value in entry_frame.globals.items():
            if self._is_symbolic(value):
                symbolic_inputs[f"global_{name}"] = value
        
        return symbolic_inputs
    
    def _is_symbolic(self, value: SymbolicValue) -> bool:
        """
        Check if a SymbolicValue contains symbolic (non-concrete) Z3 expressions.
        
        Returns True if the value is truly symbolic (not a constant).
        """
        if value.tag == ValueTag.INT:
            # Check if the integer payload is a symbolic Z3 expression
            if isinstance(value.payload, (int, bool)):
                return False
            if z3.is_expr(value.payload):
                # Check if it's a constant or variable
                return not z3.is_int_value(value.payload)
        elif value.tag == ValueTag.BOOL:
            if isinstance(value.payload, bool):
                return False
            if z3.is_expr(value.payload):
                return not z3.is_bool(value.payload) or not z3.is_true(value.payload) and not z3.is_false(value.payload)
        elif value.tag == ValueTag.STR:
            # Strings are typically concrete for now
            return False
        
        # Other types: assume symbolic if not clearly concrete
        return True


class ConstraintSolver:
    """
    Solves path constraints to generate concrete inputs.
    
    Takes PathConstraints and produces ConcreteInput instances
    that satisfy the constraints (if satisfiable).
    """
    
    def __init__(self, timeout_ms: int = 5000):
        """
        Initialize constraint solver.
        
        Args:
            timeout_ms: Z3 solver timeout in milliseconds
        """
        self.timeout_ms = timeout_ms
    
    def solve(self, constraints: PathConstraints) -> Optional[ConcreteInput]:
        """
        Solve path constraints to generate concrete input.
        
        Args:
            constraints: Extracted path constraints
            
        Returns:
            ConcreteInput if satisfiable, None if unsatisfiable
        """
        solver = constraints.z3_solver
        solver.set("timeout", self.timeout_ms)
        
        # Check satisfiability
        result = solver.check()
        
        if result == z3.sat:
            model = solver.model()
            return self._model_to_concrete_input(model, constraints.symbolic_inputs)
        elif result == z3.unsat:
            # Path is infeasible
            return None
        else:
            # Unknown (timeout or other issue)
            # Treat as failure - we couldn't find a solution
            return None
    
    def _model_to_concrete_input(self, model: z3.ModelRef,
                                  symbolic_inputs: Dict[str, SymbolicValue]) -> ConcreteInput:
        """
        Convert a Z3 model to a ConcreteInput.
        
        Extracts concrete values for all symbolic input variables from the model.
        
        Args:
            model: Z3 model (satisfying assignment)
            symbolic_inputs: Mapping of variable names to symbolic values
            
        Returns:
            ConcreteInput with concrete values extracted from the model
        """
        args = []
        globals_dict = {}
        
        for name, sym_value in symbolic_inputs.items():
            concrete_value = self._extract_value_from_model(model, sym_value)
            
            # Categorize by prefix
            if name.startswith("local_"):
                var_name = name[6:]  # Remove "local_" prefix
                # For now, assume locals are function arguments (in order)
                args.append(concrete_value)
            elif name.startswith("global_"):
                var_name = name[7:]  # Remove "global_" prefix
                globals_dict[var_name] = concrete_value
        
        return ConcreteInput(
            args=args,
            globals_dict=globals_dict,
            env={},
            stdin=""
        )
    
    def _extract_value_from_model(self, model: z3.ModelRef, sym_value: SymbolicValue) -> Any:
        """
        Extract a concrete Python value from a Z3 model for a symbolic value.
        
        Args:
            model: Z3 model
            sym_value: Symbolic value to extract
            
        Returns:
            Concrete Python value (int, bool, str, etc.)
        """
        payload = sym_value.payload
        
        if sym_value.tag == ValueTag.INT:
            if isinstance(payload, int):
                return payload
            elif z3.is_expr(payload):
                # Evaluate in model
                val = model.evaluate(payload, model_completion=True)
                if z3.is_int_value(val):
                    return val.as_long()
                else:
                    # Couldn't evaluate, default to 0
                    return 0
        
        elif sym_value.tag == ValueTag.BOOL:
            if isinstance(payload, bool):
                return payload
            elif z3.is_expr(payload):
                val = model.evaluate(payload, model_completion=True)
                if z3.is_bool(val):
                    return z3.is_true(val)
                else:
                    return False
        
        elif sym_value.tag == ValueTag.STR:
            if isinstance(payload, str):
                return payload
            # Z3 string handling is more complex, default to empty string
            return ""
        
        elif sym_value.tag == ValueTag.NONE:
            return None
        
        # For other types (OBJ, etc.), we can't easily extract concrete values
        # Return a placeholder
        return None


def extract_and_solve_path(path: SymbolicPath, timeout_ms: int = 5000) -> Optional[ConcreteInput]:
    """
    Convenience function: extract constraints from a path and solve them.
    
    Args:
        path: Symbolic execution path
        timeout_ms: Z3 solver timeout
        
    Returns:
        ConcreteInput if path is satisfiable, None otherwise
    """
    extractor = ConstraintExtractor()
    constraints = extractor.extract_from_path(path)
    
    solver = ConstraintSolver(timeout_ms=timeout_ms)
    return solver.solve(constraints)


def validate_path_with_input(path: SymbolicPath, concrete_input: ConcreteInput) -> bool:
    """
    Validate that a concrete input satisfies the path constraints.
    
    This is a sanity check: given a SymbolicPath and a ConcreteInput,
    verify that the input actually satisfies the path condition.
    
    Args:
        path: Symbolic path with path conditions
        concrete_input: Concrete input to validate
        
    Returns:
        True if input satisfies path constraints, False otherwise
    """
    # Create a solver and add the path condition
    solver = z3.Solver()
    solver.add(path.state.path_condition)
    
    # TODO: Add constraints binding symbolic variables to concrete values
    # For now, just check if the path condition is satisfiable
    result = solver.check()
    return result == z3.sat
