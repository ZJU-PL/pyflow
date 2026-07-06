"""
CEGIS (CounterExample-Guided Inductive Synthesis) for barrier certificates.

This module implements a counterexample-guided refinement loop for
synthesizing barrier certificate parameters. Unlike the template
enumeration in synthesis.py, CEGIS uses counterexamples from failed
verification attempts to guide the search toward valid parameters.

Theory:
-------
CEGIS alternates between:
1. SYNTHESIS: Find candidate parameters (coefficients) for a barrier template
2. VERIFICATION: Check if the barrier is inductive using Z3
3. REFINEMENT: If verification fails, extract counterexample and add constraints

The loop continues until either:
- A valid barrier is found (SAFE proof)
- The parameter space is exhausted (UNKNOWN)
- Timeout is reached (UNKNOWN)

Soundness:
----------
- Only reports SAFE when Z3 proves inductiveness of Init/Unsafe/Step conditions
- Uses counterexamples to constrain parameter search, never to weaken safety
- All generated barriers are checked for inductiveness before reporting success
"""

from dataclasses import dataclass, field
from typing import Callable, Optional, Iterator
import z3
import time
import types

from .invariants import (
    BarrierCertificate,
    InductivenessChecker,
    InductivenessResult,
)
from .templates import (
    quadratic_barrier,
    polynomial_barrier,
    bivariate_quadratic_barrier,
)
from .program_analysis import (
    analyze_program_structure,
    ProgramStructure,
)
from ..semantics.symbolic_vm import SymbolicMachineState


@dataclass
class CEGISConfig:
    """
    Configuration for CEGIS loop.
    
    Attributes:
        max_iterations: Maximum CEGIS iterations
        max_counterexamples: Maximum counterexamples to collect per iteration
        timeout_per_check_ms: Z3 timeout for each inductiveness check
        timeout_total_ms: Total timeout for entire CEGIS loop
        parameter_solver_timeout_ms: Timeout for parameter synthesis step
        epsilon: Safety margin for barriers
    """
    max_iterations: int = 50
    max_counterexamples: int = 10
    timeout_per_check_ms: int = 5000
    timeout_total_ms: int = 60000
    parameter_solver_timeout_ms: int = 10000
    epsilon: float = 0.5


@dataclass
class Counterexample:
    """
    A counterexample from failed verification.
    
    Attributes:
        kind: Which condition failed ('init', 'unsafe', 'step')
        model: Z3 model showing the violation
        state_values: Concrete values of state variables
        variable_value: Concrete value of the tracked variable (if extractable)
        barrier_value: Value of B at this state (if computable)
    """
    kind: str  # 'init', 'unsafe', 'step'
    model: z3.ModelRef
    state_values: dict[str, any]
    variable_value: Optional[float] = None
    barrier_value: Optional[float] = None


@dataclass
class CEGISResult:
    """
    Result of CEGIS synthesis.
    
    Attributes:
        success: Whether a valid barrier was found
        barrier: The synthesized barrier (if success)
        inductiveness: Inductiveness check result (if success)
        iterations: Number of CEGIS iterations completed
        counterexamples_collected: Total counterexamples used
        synthesis_time_ms: Total time spent
        termination_reason: Why CEGIS terminated
        counterexamples: List of counterexamples encountered (for debugging)
    """
    success: bool
    barrier: Optional[BarrierCertificate] = None
    inductiveness: Optional[InductivenessResult] = None
    iterations: int = 0
    counterexamples_collected: int = 0
    synthesis_time_ms: float = 0.0
    termination_reason: str = "unknown"
    counterexamples: list[Counterexample] = field(default_factory=list)
    
    def summary(self) -> str:
        """Human-readable summary."""
        if self.success:
            return (
                f"CEGIS SUCCESS: {self.barrier.name} "
                f"({self.iterations} iterations, {self.counterexamples_collected} CEs, "
                f"{self.synthesis_time_ms:.1f}ms) - {self.termination_reason}"
            )
        else:
            return (
                f"CEGIS FAILED: {self.termination_reason} "
                f"({self.iterations} iterations, {self.counterexamples_collected} CEs, "
                f"{self.synthesis_time_ms:.1f}ms)"
            )
    
    def counterexample_summary(self) -> str:
        """Summary of counterexamples encountered."""
        if not self.counterexamples:
            return "No counterexamples"
        
        by_kind = {}
        for ce in self.counterexamples:
            by_kind.setdefault(ce.kind, []).append(ce)
        
        lines = [f"Counterexamples: {len(self.counterexamples)} total"]
        for kind, ces in by_kind.items():
            lines.append(f"  {kind}: {len(ces)}")
            # Show first few with values
            for ce in ces[:3]:
                if ce.variable_value is not None:
                    lines.append(f"    var={ce.variable_value}, B={ce.barrier_value}")
                elif ce.state_values:
                    # Show first few state values
                    sample = dict(list(ce.state_values.items())[:3])
                    lines.append(f"    {sample}")
        
        return "\n".join(lines)


class CEGISBarrierSynthesizer:
    """
    CEGIS-based barrier certificate synthesizer.
    
    This implements a counterexample-guided loop for finding barrier
    certificate parameters. Unlike simple template enumeration, CEGIS
    uses failures to guide the search.
    
    The basic loop:
    1. Choose a barrier template family (e.g., quadratic: ax² + bx + c)
    2. Synthesize candidate parameters using Z3 SMT solving
    3. Verify the candidate barrier for inductiveness
    4. If verification fails, extract counterexample and add constraints
    5. Repeat until success or resource exhaustion
    """
    
    def __init__(self, config: Optional[CEGISConfig] = None):
        """
        Args:
            config: CEGIS configuration (uses defaults if None)
        """
        self.config = config or CEGISConfig()
        self.checker = InductivenessChecker(
            timeout_ms=self.config.timeout_per_check_ms
        )
    
    def synthesize(
        self,
        template_family: str,
        initial_state_builder: Callable[[], SymbolicMachineState],
        unsafe_predicate: Callable[[SymbolicMachineState], z3.ExprRef],
        step_relation: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef],
        variable_name: str,
        variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    ) -> CEGISResult:
        """
        Synthesize barrier parameters using CEGIS.
        
        Args:
            template_family: Template family name ('quadratic', 'cubic', etc.)
            initial_state_builder: Function that returns a symbolic initial state
            unsafe_predicate: Function that returns U(σ) as Z3 bool
            step_relation: Function that returns (s → s') as Z3 bool
            variable_name: Name of the program variable to track
            variable_extractor: Function to extract variable from state
        
        Returns:
            CEGISResult with synthesized barrier (if found)
        """
        start_time = time.time()
        
        # Track CEGIS state
        iterations = 0
        counterexamples = []
        
        # Create parameter synthesis context
        # We'll synthesize the coefficients as Z3 variables and constrain them
        param_solver = z3.Solver()
        param_solver.set("timeout", self.config.parameter_solver_timeout_ms)
        
        # Create parameter variables based on template family
        params = self._create_parameter_variables(template_family)
        
        # Add basic parameter constraints (e.g., coefficients in reasonable range)
        self._add_parameter_constraints(param_solver, params, template_family)
        
        # CEGIS main loop
        while iterations < self.config.max_iterations:
            iterations += 1
            
            # Check total timeout
            elapsed_ms = (time.time() - start_time) * 1000
            if elapsed_ms > self.config.timeout_total_ms:
                return CEGISResult(
                    success=False,
                    iterations=iterations,
                    counterexamples_collected=len(counterexamples),
                    synthesis_time_ms=elapsed_ms,
                    termination_reason="timeout",
                    counterexamples=counterexamples
                )
            
            # SYNTHESIS PHASE: Find candidate parameters
            if param_solver.check() != z3.sat:
                # No more parameter assignments satisfy constraints
                return CEGISResult(
                    success=False,
                    iterations=iterations,
                    counterexamples_collected=len(counterexamples),
                    synthesis_time_ms=(time.time() - start_time) * 1000,
                    termination_reason="parameter_space_exhausted",
                    counterexamples=counterexamples
                )
            
            # Extract parameter values from model
            param_model = param_solver.model()
            param_values = self._extract_parameter_values(param_model, params)
            
            # Build candidate barrier with these parameters
            candidate_barrier = self._build_barrier(
                template_family,
                variable_name,
                variable_extractor,
                param_values
            )
            
            # VERIFICATION PHASE: Check inductiveness
            induct_result = self.checker.check_inductiveness(
                candidate_barrier,
                initial_state_builder,
                unsafe_predicate,
                step_relation
            )
            
            if induct_result.is_inductive:
                # SUCCESS! Found a valid barrier
                elapsed_ms = (time.time() - start_time) * 1000
                return CEGISResult(
                    success=True,
                    barrier=candidate_barrier,
                    inductiveness=induct_result,
                    iterations=iterations,
                    counterexamples_collected=len(counterexamples),
                    synthesis_time_ms=elapsed_ms,
                    termination_reason="inductive_barrier_found",
                    counterexamples=counterexamples
                )
            
            # REFINEMENT PHASE: Extract counterexamples and add constraints
            # We need to eliminate this bad parameter assignment
            new_counterexamples = self._extract_counterexamples(
                induct_result,
                variable_extractor=variable_extractor,
                barrier=candidate_barrier
            )
            counterexamples.extend(new_counterexamples)
            
            if len(counterexamples) > self.config.max_counterexamples:
                counterexamples = counterexamples[-self.config.max_counterexamples:]
            
            # Add constraint to exclude this parameter assignment
            # (We want different parameters on next iteration)
            exclusion_constraint = self._build_exclusion_constraint(params, param_values)
            param_solver.add(exclusion_constraint)
            
            # Optionally, add counterexample-guided constraints
            # This is where CEGIS shines: use the failure to guide search
            ce_constraints = self._build_counterexample_constraints(
                params, new_counterexamples, template_family, variable_name
            )
            for constraint in ce_constraints:
                param_solver.add(constraint)
        
        # Max iterations reached
        elapsed_ms = (time.time() - start_time) * 1000
        return CEGISResult(
            success=False,
            iterations=iterations,
            counterexamples_collected=len(counterexamples),
            synthesis_time_ms=elapsed_ms,
            termination_reason="max_iterations_reached",
            counterexamples=counterexamples
        )
    
    def _create_parameter_variables(self, template_family: str) -> dict[str, z3.ExprRef]:
        """
        Create Z3 variables for barrier parameters based on template family.
        
        Returns dict mapping parameter name to Z3 variable.
        """
        if template_family == "linear":
            # B(x) = a·x + b
            return {
                "coeff_x": z3.Real("coeff_x"),
                "constant": z3.Real("constant"),
            }
        elif template_family == "quadratic":
            # B(x) = a·x² + b·x + c
            return {
                "coeff_x2": z3.Real("coeff_x2"),
                "coeff_x": z3.Real("coeff_x"),
                "constant": z3.Real("constant"),
            }
        elif template_family == "cubic":
            # B(x) = a·x³ + b·x² + c·x + d
            return {
                "coeff_x3": z3.Real("coeff_x3"),
                "coeff_x2": z3.Real("coeff_x2"),
                "coeff_x": z3.Real("coeff_x"),
                "constant": z3.Real("constant"),
            }
        elif template_family == "quartic":
            # B(x) = a·x⁴ + b·x³ + c·x² + d·x + e
            return {
                "coeff_x4": z3.Real("coeff_x4"),
                "coeff_x3": z3.Real("coeff_x3"),
                "coeff_x2": z3.Real("coeff_x2"),
                "coeff_x": z3.Real("coeff_x"),
                "constant": z3.Real("constant"),
            }
        else:
            raise ValueError(f"Unknown template family: {template_family}")
    
    def _add_parameter_constraints(
        self,
        solver: z3.Solver,
        params: dict[str, z3.ExprRef],
        template_family: str
    ):
        """
        Add basic parameter constraints (ranges, non-degeneracy conditions).
        """
        # Constrain parameters to reasonable ranges
        # This prevents numerical issues and focuses search
        for param_name, param_var in params.items():
            # All coefficients in [-100, 100]
            solver.add(param_var >= -100.0)
            solver.add(param_var <= 100.0)
        
        # For polynomials, ensure leading coefficient is non-zero
        # (otherwise it degenerates to lower degree)
        if template_family == "linear" and "coeff_x" in params:
            # For linear, just ensure non-trivial: |a| ≥ 0.01
            solver.add(z3.Or(params["coeff_x"] >= 0.01, params["coeff_x"] <= -0.01))
        elif template_family == "quadratic" and "coeff_x2" in params:
            # |a| ≥ 0.01
            solver.add(z3.Or(params["coeff_x2"] >= 0.01, params["coeff_x2"] <= -0.01))
        elif template_family == "cubic" and "coeff_x3" in params:
            solver.add(z3.Or(params["coeff_x3"] >= 0.01, params["coeff_x3"] <= -0.01))
        elif template_family == "quartic" and "coeff_x4" in params:
            solver.add(z3.Or(params["coeff_x4"] >= 0.01, params["coeff_x4"] <= -0.01))
    
    def _extract_parameter_values(
        self,
        model: z3.ModelRef,
        params: dict[str, z3.ExprRef]
    ) -> dict[str, float]:
        """
        Extract concrete parameter values from Z3 model.
        """
        values = {}
        for param_name, param_var in params.items():
            val = model.eval(param_var, model_completion=True)
            # Convert Z3 rational to float
            if z3.is_rational_value(val):
                values[param_name] = float(val.as_fraction())
            else:
                values[param_name] = float(val.as_long()) if z3.is_int_value(val) else 0.0
        return values
    
    def _build_barrier(
        self,
        template_family: str,
        variable_name: str,
        variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
        param_values: dict[str, float]
    ) -> BarrierCertificate:
        """
        Build a concrete barrier certificate from template + parameters.
        """
        if template_family == "linear":
            # Use polynomial_barrier with linear coefficients
            coeffs = [
                param_values["constant"],
                param_values["coeff_x"],
            ]
            return polynomial_barrier(
                variable_name,
                variable_extractor,
                coefficients=coeffs,
                name=f"cegis_linear_{variable_name}"
            )
        elif template_family == "quadratic":
            return quadratic_barrier(
                variable_name,
                variable_extractor,
                coeff_x2=param_values["coeff_x2"],
                coeff_x=param_values["coeff_x"],
                constant=param_values["constant"],
                name=f"cegis_quadratic_{variable_name}"
            )
        elif template_family in ["cubic", "quartic"]:
            # Use polynomial_barrier with appropriate coefficients
            if template_family == "cubic":
                coeffs = [
                    param_values["constant"],
                    param_values["coeff_x"],
                    param_values["coeff_x2"],
                    param_values["coeff_x3"],
                ]
            else:  # quartic
                coeffs = [
                    param_values["constant"],
                    param_values["coeff_x"],
                    param_values["coeff_x2"],
                    param_values["coeff_x3"],
                    param_values["coeff_x4"],
                ]
            
            return polynomial_barrier(
                variable_name,
                variable_extractor,
                coefficients=coeffs,
                name=f"cegis_{template_family}_{variable_name}"
            )
        else:
            raise ValueError(f"Unknown template family: {template_family}")
    
    def _extract_counterexamples(
        self,
        induct_result: InductivenessResult,
        variable_extractor: Optional[Callable[[SymbolicMachineState], z3.ExprRef]] = None,
        barrier: Optional[BarrierCertificate] = None
    ) -> list[Counterexample]:
        """
        Extract counterexamples from failed inductiveness check with concrete values.
        
        Args:
            induct_result: The inductiveness check result
            variable_extractor: Optional extractor to get variable value from model
            barrier: Optional barrier to evaluate its value at counterexample
        
        Returns:
            List of counterexamples with concrete values extracted
        """
        counterexamples = []
        
        # Check which condition failed
        if not induct_result.init_holds:
            # Init condition failed: ∃s∈S0. B(s) < ε
            # This means initial states violate the barrier
            if hasattr(induct_result, 'init_counterexample') and induct_result.init_counterexample:
                model = induct_result.init_counterexample
                state = getattr(induct_result, 'init_counterexample_state', None)
                state_values = self._extract_state_values_from_model(model)
                var_value = self._extract_variable_value(model, variable_extractor, state) if variable_extractor else None
                barrier_value = self._extract_barrier_value(model, barrier, state) if barrier else None
                
                counterexamples.append(Counterexample(
                    kind='init',
                    model=model,
                    state_values=state_values,
                    variable_value=var_value,
                    barrier_value=barrier_value
                ))
        
        if not induct_result.unsafe_holds:
            # Unsafe condition failed: ∃s∈U. B(s) ≥ -ε
            # Barrier doesn't separate from unsafe region
            if hasattr(induct_result, 'unsafe_counterexample') and induct_result.unsafe_counterexample:
                model = induct_result.unsafe_counterexample
                state = getattr(induct_result, 'unsafe_counterexample_state', None)
                state_values = self._extract_state_values_from_model(model)
                var_value = self._extract_variable_value(model, variable_extractor, state) if variable_extractor else None
                barrier_value = self._extract_barrier_value(model, barrier, state) if barrier else None
                
                counterexamples.append(Counterexample(
                    kind='unsafe',
                    model=model,
                    state_values=state_values,
                    variable_value=var_value,
                    barrier_value=barrier_value
                ))
        
        if not induct_result.step_holds:
            # Step condition failed: ∃s,s'. (B(s) ≥ 0 ∧ s→s') ∧ B(s') < 0
            # Barrier not inductive under transitions
            if hasattr(induct_result, 'step_counterexample') and induct_result.step_counterexample:
                model = induct_result.step_counterexample
                state = getattr(induct_result, 'step_counterexample_state', None)
                state_values = self._extract_state_values_from_model(model)
                var_value = self._extract_variable_value(model, variable_extractor, state) if variable_extractor else None
                barrier_value = self._extract_barrier_value(model, barrier, state) if barrier else None
                
                counterexamples.append(Counterexample(
                    kind='step',
                    model=model,
                    state_values=state_values,
                    variable_value=var_value,
                    barrier_value=barrier_value
                ))
        
        return counterexamples
    
    def _extract_state_values_from_model(self, model: z3.ModelRef) -> dict[str, any]:
        """
        Extract concrete values for all declared constants in the Z3 model.
        
        Args:
            model: Z3 model from counterexample
        
        Returns:
            Dictionary mapping variable names to concrete values
        """
        state_values = {}
        
        # Iterate through all declarations in the model
        for decl in model.decls():
            name = decl.name()
            try:
                val = model[decl]
                # Convert Z3 value to Python value
                concrete_val = self._z3_value_to_python(val)
                state_values[name] = concrete_val
            except Exception:
                # Some values may not be evaluable; skip them
                state_values[name] = f"<unevaluable: {decl}>"
        
        return state_values
    
    def _extract_variable_value(
        self,
        model: z3.ModelRef,
        variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
        state: Optional[SymbolicMachineState] = None
    ) -> Optional[float]:
        """
        Extract concrete value of the tracked program variable from counterexample.
        
        Now improved to use the Z3 variable map if available, or fall back
        to evaluating the variable extractor.
        
        Args:
            model: Z3 model
            variable_extractor: The extractor function to get Z3 expr from state
            state: Optional SymbolicMachineState (for accessing z3_variable_map)
        
        Returns:
            Concrete float value if extractable, None otherwise
        """
        try:
            # Strategy 1: If we have a state with z3_variable_map, use it directly
            if state and hasattr(state, 'z3_variable_map'):
                for var_name, z3_expr in state.z3_variable_map.items():
                    try:
                        val = model.eval(z3_expr, model_completion=True)
                        return self._z3_value_to_python(val)
                    except Exception:
                        continue
            
            # Strategy 2: Try to evaluate the variable extractor if state is available
            # (This requires creating a dummy state, which is not ideal)
            # For now, we skip this and rely on z3_variable_map
            
            # Strategy 3: Fallback - look for common variable name patterns in model
            # Try to find declarations that look like program variables
            for decl in model.decls():
                name = decl.name()
                # Skip internal Z3 names (like k!0, etc.)
                if name.startswith('k!'):
                    continue
                # Look for simple variable names or patterns
                try:
                    val = model[decl]
                    python_val = self._z3_value_to_python(val)
                    if isinstance(python_val, (int, float)):
                        return python_val
                except Exception:
                    continue
            
            return None
        except Exception:
            return None
    
    def _extract_barrier_value(
        self,
        model: z3.ModelRef,
        barrier: BarrierCertificate,
        state: Optional[SymbolicMachineState] = None
    ) -> Optional[float]:
        """
        Extract the value of B(s) at the counterexample state.
        
        Now improved to track and evaluate the barrier expression explicitly.
        
        Args:
            model: Z3 model
            barrier: The barrier certificate
            state: Optional SymbolicMachineState (to evaluate barrier at)
        
        Returns:
            Concrete barrier value if extractable, None otherwise
        """
        try:
            # If we have a state, we can evaluate the barrier function
            if state and barrier.barrier_function:
                # Get the barrier expression for this state
                barrier_expr = barrier.barrier_function(state)
                
                # Evaluate it under the model
                barrier_val = model.eval(barrier_expr, model_completion=True)
                return self._z3_value_to_python(barrier_val)
            
            return None
        except Exception:
            return None
    
    def _z3_value_to_python(self, val: z3.ExprRef) -> any:
        """
        Convert Z3 value to Python primitive.
        
        Args:
            val: Z3 value from model
        
        Returns:
            Python int, float, bool, or str representation
        """
        if z3.is_int_value(val):
            return val.as_long()
        elif z3.is_rational_value(val):
            # Return as float
            frac = val.as_fraction()
            return float(frac)
        elif z3.is_true(val):
            return True
        elif z3.is_false(val):
            return False
        elif z3.is_string_value(val):
            return val.as_string()
        else:
            # Fallback: return string representation
            return str(val)

    
    def _build_exclusion_constraint(
        self,
        params: dict[str, z3.ExprRef],
        param_values: dict[str, float]
    ) -> z3.ExprRef:
        """
        Build constraint to exclude this specific parameter assignment.
        
        We want: NOT (all parameters equal their current values).
        Equivalently: at least one parameter differs.
        """
        # Build: (p1 != v1) OR (p2 != v2) OR ...
        conditions = []
        for param_name, param_var in params.items():
            val = param_values[param_name]
            # Use tolerance for floating point comparison
            conditions.append(z3.Or(
                param_var < val - 0.001,
                param_var > val + 0.001
            ))
        
        return z3.Or(*conditions) if conditions else z3.BoolVal(True)
    
    def _build_counterexample_constraints(
        self,
        params: dict[str, z3.ExprRef],
        counterexamples: list[Counterexample],
        template_family: str,
        variable_name: str
    ) -> list[z3.ExprRef]:
        """
        Build constraints from counterexamples to guide parameter search.
        
        This is the key CEGIS refinement step: use the failure to improve
        the next candidate by leveraging concrete counterexample values.
        
        Strategy:
        - If init failed at x=v: Ensure B(v) ≥ ε by constraining coefficients
        - If unsafe failed at x=u: Ensure B(u) ≤ -ε
        - If step failed at x=v→v': Ensure B(v) ≥ 0 ⇒ B(v') ≥ 0
        
        We extract concrete values from counterexamples to build quantifier-free
        constraints on the parameters.
        """
        constraints = []
        
        for ce in counterexamples:
            # Try to extract variable value from state_values
            # Common patterns: look for variable_name in keys
            var_value = None
            for key, val in ce.state_values.items():
                # Match patterns like "x_0", "n_init", "variable_name_0", etc.
                if variable_name in key and isinstance(val, (int, float)):
                    var_value = val
                    break
            
            if var_value is None:
                # Can't use this CE without concrete value; skip for now
                continue
            
            # Build polynomial evaluation at this point
            # For template B(x) = sum(a_i * x^i), we can constrain
            # sum(a_i * var_value^i) to satisfy the condition
            
            if ce.kind == "init":
                # Init failed: B(var_value) < ε
                # We want B(var_value) ≥ ε, so add constraint:
                # sum(coeff_i * var_value^i) ≥ ε
                poly_at_point = self._evaluate_template_at_point(
                    params, template_family, var_value
                )
                constraints.append(poly_at_point >= self.config.epsilon)
            
            elif ce.kind == "unsafe":
                # Unsafe failed: B(var_value) ≥ -ε (but should be ≤ -ε)
                # We want B(var_value) ≤ -ε
                poly_at_point = self._evaluate_template_at_point(
                    params, template_family, var_value
                )
                constraints.append(poly_at_point <= -self.config.epsilon)
            
            elif ce.kind == "step":
                # Step failed: B(v) ≥ 0, v→v', but B(v') < 0
                # We need to look for both v and v' values
                # This is more complex; for now, try a heuristic
                # If we can identify v and v' from state_values, constrain both
                
                # Look for patterns like "x_0" (pre-state) and "x_1" (post-state)
                pre_value = None
                post_value = None
                
                for key, val in ce.state_values.items():
                    if isinstance(val, (int, float)):
                        if "_0" in key or "_pre" in key or variable_name == key.rstrip("_0"):
                            pre_value = val
                        elif "_1" in key or "_post" in key or "_prime" in key:
                            post_value = val
                
                if pre_value is not None:
                    # Ensure B(pre_value) stays ≥ 0
                    poly_pre = self._evaluate_template_at_point(
                        params, template_family, pre_value
                    )
                    # This is already assumed in the CE; don't over-constrain
                    # constraints.append(poly_pre >= 0)
                    pass
                
                if post_value is not None:
                    # Ensure B(post_value) ≥ 0 (the issue is it went negative)
                    poly_post = self._evaluate_template_at_point(
                        params, template_family, post_value
                    )
                    constraints.append(poly_post >= 0)
        
        return constraints
    
    def _evaluate_template_at_point(
        self,
        params: dict[str, z3.ExprRef],
        template_family: str,
        x: float
    ) -> z3.ExprRef:
        """
        Evaluate the parametric template at a concrete point.
        
        For example, for quadratic B(x) = a·x² + b·x + c,
        returns: params['coeff_x2'] * x² + params['coeff_x'] * x + params['constant']
        
        Args:
            params: Parameter variables
            template_family: Template family name
            x: Concrete value to evaluate at
        
        Returns:
            Z3 expression representing B(x) in terms of parameters
        """
        if template_family == "linear":
            # B(x) = a·x + b
            return (
                params["coeff_x"] * x +
                params["constant"]
            )
        elif template_family == "quadratic":
            # B(x) = a·x² + b·x + c
            return (
                params["coeff_x2"] * (x ** 2) +
                params["coeff_x"] * x +
                params["constant"]
            )
        elif template_family == "cubic":
            # B(x) = a·x³ + b·x² + c·x + d
            return (
                params["coeff_x3"] * (x ** 3) +
                params["coeff_x2"] * (x ** 2) +
                params["coeff_x"] * x +
                params["constant"]
            )
        elif template_family == "quartic":
            # B(x) = a·x⁴ + b·x³ + c·x² + d·x + e
            return (
                params["coeff_x4"] * (x ** 4) +
                params["coeff_x3"] * (x ** 3) +
                params["coeff_x2"] * (x ** 2) +
                params["coeff_x"] * x +
                params["constant"]
            )
        else:
            raise ValueError(f"Unknown template family: {template_family}")


def synthesize_barrier_cegis(
    template_family: str,
    initial_state_builder: Callable[[], SymbolicMachineState],
    unsafe_predicate: Callable[[SymbolicMachineState], z3.ExprRef],
    step_relation: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef],
    variable_name: str,
    variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    config: Optional[CEGISConfig] = None
) -> CEGISResult:
    """
    High-level CEGIS synthesis function.
    
    Args:
        template_family: Template family ('quadratic', 'cubic', 'quartic')
        initial_state_builder: Initial state builder
        unsafe_predicate: Unsafe predicate U(σ)
        step_relation: Step relation (σ → σ')
        variable_name: Program variable name
        variable_extractor: Function to extract variable from state
        config: Optional CEGIS configuration
    
    Returns:
        CEGISResult with synthesized barrier (if found)
    """
    synthesizer = CEGISBarrierSynthesizer(config)
    return synthesizer.synthesize(
        template_family,
        initial_state_builder,
        unsafe_predicate,
        step_relation,
        variable_name,
        variable_extractor
    )


def synthesize_barrier_with_auto_template(
    code: types.CodeType,
    initial_state_builder: Callable[[], SymbolicMachineState],
    unsafe_predicate: Callable[[SymbolicMachineState], z3.ExprRef],
    step_relation: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef],
    variable_name: str,
    variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    config: Optional[CEGISConfig] = None,
) -> tuple[CEGISResult, ProgramStructure]:
    """
    Synthesize barrier with automatic template selection based on program structure.
    
    This function analyzes the program's bytecode to determine loop nesting,
    variable usage, and control flow complexity, then selects an appropriate
    barrier template family automatically.
    
    The template selection strategy:
    - No loops or simple single loop → linear template
    - Multiple sequential loops or nested loops → quadratic template
    - Deeply nested loops (3+ levels) → cubic template
    - Complex branching in loops → try disjunctive templates
    
    Args:
        code: Python code object to analyze
        initial_state_builder: Function that returns a symbolic initial state
        unsafe_predicate: Function that returns U(σ) as Z3 bool
        step_relation: Function that returns (s → s') as Z3 bool
        variable_name: Program variable name
        variable_extractor: Function to extract variable from state
        config: Optional CEGIS configuration
    
    Returns:
        Tuple of (CEGISResult, ProgramStructure analysis)
    """
    # Analyze program structure
    structure = analyze_program_structure(code)
    
    # Select template based on structure
    degree = structure.suggested_template_degree()
    if degree == 1:
        template_family = "linear"
    elif degree == 2:
        template_family = "quadratic"
    else:
        template_family = "cubic"
    
    # Try synthesis with selected template
    synthesizer = CEGISBarrierSynthesizer(config)
    result = synthesizer.synthesize(
        template_family,
        initial_state_builder,
        unsafe_predicate,
        step_relation,
        variable_name,
        variable_extractor
    )
    
    # If failed and degree was low, try escalating
    if not result.success and degree < 3:
        # Try one degree higher
        if degree == 1:
            fallback_template = "quadratic"
        else:  # degree == 2
            fallback_template = "cubic"
        
        fallback_result = synthesizer.synthesize(
            fallback_template,
            initial_state_builder,
            unsafe_predicate,
            step_relation,
            variable_name,
            variable_extractor
        )
        
        # Return whichever succeeded, or the fallback if both failed
        if fallback_result.success:
            return fallback_result, structure
    
    return result, structure
