"""
Barrier certificate templates.

Provides pre-built barrier templates for common safety properties:
- Stack depth bounds
- Variable bounds
- Iteration bounds
- Resource bounds

These templates can be instantiated with specific parameters and checked
for inductiveness.
"""

from typing import Optional, Callable
import z3

from .invariants import BarrierCertificate, linear_combination_barrier, BarrierFunction
from ..semantics.symbolic_vm import SymbolicMachineState


def stack_depth_barrier(
    max_depth: int,
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Stack depth barrier: B(σ) = max_depth - len(frame_stack)
    
    This barrier proves stack overflow is unreachable if:
    - Init: frame_stack starts with depth < max_depth
    - Unsafe: stack overflow when depth ≥ max_depth
    - Step: each call adds at most 1 frame
    
    Args:
        max_depth: Maximum allowed stack depth
        name: Optional custom name
    
    Returns:
        BarrierCertificate for stack depth
    """
    barrier_fn = linear_combination_barrier(
        [("stack_depth", lambda s: z3.IntVal(len(s.frame_stack)))],
        [-1.0],
        float(max_depth)
    )
    
    return BarrierCertificate(
        name=name or f"stack_depth_≤_{max_depth}",
        barrier_fn=barrier_fn,
        epsilon=0.5,  # At least 0.5 away from boundary
        description=f"Stack depth bounded by {max_depth}",
        variables=["frame_stack_length"]
    )


def variable_upper_bound_barrier(
    variable_name: str,
    upper_bound: float,
    variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Variable upper bound: B(σ) = upper_bound - var
    
    Proves that variable `var` never exceeds `upper_bound`.
    
    Args:
        variable_name: Name of the variable (for documentation)
        upper_bound: Upper bound value
        variable_extractor: Function to extract variable value from state
        name: Optional custom name
    
    Returns:
        BarrierCertificate for variable upper bound
    """
    barrier_fn = linear_combination_barrier(
        [(variable_name, variable_extractor)],
        [-1.0],
        upper_bound
    )
    
    return BarrierCertificate(
        name=name or f"{variable_name}_≤_{upper_bound}",
        barrier_fn=barrier_fn,
        epsilon=0.01,
        description=f"Variable {variable_name} bounded above by {upper_bound}",
        variables=[variable_name]
    )


def variable_lower_bound_barrier(
    variable_name: str,
    lower_bound: float,
    variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Variable lower bound: B(σ) = var - lower_bound
    
    Proves that variable `var` never goes below `lower_bound`.
    
    Args:
        variable_name: Name of the variable (for documentation)
        lower_bound: Lower bound value
        variable_extractor: Function to extract variable value from state
        name: Optional custom name
    
    Returns:
        BarrierCertificate for variable lower bound
    """
    barrier_fn = linear_combination_barrier(
        [(variable_name, variable_extractor)],
        [1.0],
        -lower_bound
    )
    
    return BarrierCertificate(
        name=name or f"{variable_name}_≥_{lower_bound}",
        barrier_fn=barrier_fn,
        epsilon=0.01,
        description=f"Variable {variable_name} bounded below by {lower_bound}",
        variables=[variable_name]
    )


def variable_range_barrier(
    variable_name: str,
    lower_bound: float,
    upper_bound: float,
    variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    name: Optional[str] = None
) -> tuple[BarrierCertificate, BarrierCertificate]:
    """
    Variable range: lower_bound ≤ var ≤ upper_bound
    
    Returns a pair of barriers (lower, upper).
    Both must be inductive for the range invariant to hold.
    
    Args:
        variable_name: Name of the variable
        lower_bound: Lower bound value
        upper_bound: Upper bound value
        variable_extractor: Function to extract variable value from state
        name: Optional custom name prefix
    
    Returns:
        Tuple of (lower_barrier, upper_barrier)
    """
    prefix = name or variable_name
    
    lower = variable_lower_bound_barrier(
        variable_name, lower_bound, variable_extractor,
        name=f"{prefix}_lower"
    )
    upper = variable_upper_bound_barrier(
        variable_name, upper_bound, variable_extractor,
        name=f"{prefix}_upper"
    )
    
    return lower, upper


def iteration_count_barrier(
    max_iterations: int,
    counter_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Iteration count barrier: B(σ) = max_iterations - counter
    
    Proves termination by bounding loop iteration count.
    
    Args:
        max_iterations: Maximum number of iterations
        counter_extractor: Function to extract iteration counter from state
        name: Optional custom name
    
    Returns:
        BarrierCertificate for iteration bound
    """
    barrier_fn = linear_combination_barrier(
        [("iteration_count", counter_extractor)],
        [-1.0],
        float(max_iterations)
    )
    
    return BarrierCertificate(
        name=name or f"iterations_≤_{max_iterations}",
        barrier_fn=barrier_fn,
        epsilon=0.5,
        description=f"Loop iterations bounded by {max_iterations}",
        variables=["iteration_count"]
    )


def constant_barrier(
    value: float,
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Constant barrier: B(σ) = value
    
    This is a trivial barrier that always returns the same value.
    Useful for testing and as a baseline.
    
    Args:
        value: Constant value
        name: Optional custom name
    
    Returns:
        BarrierCertificate with constant value
    """
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        return z3.RealVal(value)
    
    return BarrierCertificate(
        name=name or f"constant_{value}",
        barrier_fn=barrier_fn,
        epsilon=0.01,
        description=f"Constant barrier with value {value}",
        variables=[]
    )


def conjunction_barrier(
    barrier1: BarrierCertificate,
    barrier2: BarrierCertificate,
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Conjunction barrier: B(σ) = min(B1(σ), B2(σ))
    
    The conjunction of two barriers is also a valid barrier certificate.
    It is inductive if both component barriers are inductive.
    
    Args:
        barrier1: First barrier
        barrier2: Second barrier
        name: Optional custom name
    
    Returns:
        BarrierCertificate representing conjunction
    """
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        b1 = barrier1.evaluate(state)
        b2 = barrier2.evaluate(state)
        # Use Z3's if-then-else for min
        # Ensure both are real-valued (handle both Int and Real)
        b1_real = b1 if z3.is_real(b1) else (z3.ToReal(b1) if z3.is_int(b1) else b1)
        b2_real = b2 if z3.is_real(b2) else (z3.ToReal(b2) if z3.is_int(b2) else b2)
        cond = b1_real <= b2_real
        return z3.If(cond, b1_real, b2_real)
    
    epsilon = min(barrier1.epsilon, barrier2.epsilon)
    
    return BarrierCertificate(
        name=name or f"conj({barrier1.name},{barrier2.name})",
        barrier_fn=barrier_fn,
        epsilon=epsilon,
        description=f"Conjunction of {barrier1.name} and {barrier2.name}",
        variables=(barrier1.variables or []) + (barrier2.variables or [])
    )


def extract_local_variable(
    var_name: str,
    default_value: int = 0
) -> Callable[[SymbolicMachineState], z3.ExprRef]:
    """
    Helper: extract a local variable from the current frame.
    
    Returns a variable extractor function that gets the value of
    a local variable from the current frame's locals dict.
    
    Args:
        var_name: Name of the local variable
        default_value: Default value if variable not found
    
    Returns:
        Extractor function
    """
    def extractor(state: SymbolicMachineState) -> z3.ExprRef:
        if not state.frame_stack:
            return z3.IntVal(default_value)
        
        frame = state.current_frame
        if var_name in frame.locals:
            sym_val = frame.locals[var_name]
            # Extract the payload (assumes it's an int for now)
            if hasattr(sym_val, 'payload'):
                return sym_val.payload
            return z3.IntVal(default_value)
        
        return z3.IntVal(default_value)
    
    return extractor


def conditional_guard_barrier(
    condition_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    guarded_variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    safe_threshold: float,
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Conditional guard barrier: proves safety when condition implies safety.
    
    B(σ) = if condition(σ) then (var - threshold) else +∞
    
    This models patterns like:
        if x >= 0:
            result = math.sqrt(x)  # Safe because of guard
    
    Args:
        condition_extractor: Extracts the guard condition (Z3 bool)
        guarded_variable_extractor: Extracts the guarded variable
        safe_threshold: The safety threshold (e.g., 0 for sqrt)
        name: Optional custom name
    
    Returns:
        BarrierCertificate for conditional guard
    """
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        cond = condition_extractor(state)
        var = guarded_variable_extractor(state)
        # When condition holds, var must be above threshold
        # When condition doesn't hold, we don't reach the unsafe operation
        # So: B = cond => (var - threshold) ≥ 0
        # Equivalently: B = !cond ∨ (var - threshold)
        # As a real value: If(cond, var - threshold, large_positive)
        return z3.If(
            cond,
            z3.ToReal(var) - safe_threshold,
            z3.RealVal(1000.0)  # Large positive when condition false
        )
    
    return BarrierCertificate(
        name=name or f"guard_threshold_{safe_threshold}",
        barrier_fn=barrier_fn,
        epsilon=0.01,
        description=f"Conditional guard ensures safety above threshold {safe_threshold}",
        variables=["condition", "guarded_var"]
    )


def loop_range_barrier(
    iterator_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    max_iterations: int,
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Loop range barrier: proves termination for bounded loops.
    
    B(σ) = max_iterations - iterator
    
    Common pattern: for i in range(n) where n is known/bounded.
    
    Args:
        iterator_extractor: Extracts the loop iterator value
        max_iterations: Upper bound on iterations
        name: Optional custom name
    
    Returns:
        BarrierCertificate for bounded loop
    """
    barrier_fn = linear_combination_barrier(
        [("iterator", iterator_extractor)],
        [-1.0],
        float(max_iterations)
    )
    
    return BarrierCertificate(
        name=name or f"loop_bounded_by_{max_iterations}",
        barrier_fn=barrier_fn,
        epsilon=0.5,
        description=f"Loop iterator bounded by {max_iterations}",
        variables=["iterator"]
    )


def disjunction_barrier(
    barrier1: BarrierCertificate,
    barrier2: BarrierCertificate,
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Disjunction barrier: B(σ) = max(B1(σ), B2(σ))
    
    The disjunction expresses "at least one of the barriers holds".
    Useful for control-flow dependent safety (different paths have
    different invariants).
    
    Note: Checking inductiveness of disjunctions is more complex
    than conjunctions. The step condition must ensure that if
    max(B1, B2) ≥ 0, then max(B1', B2') ≥ 0.
    
    Args:
        barrier1: First barrier
        barrier2: Second barrier
        name: Optional custom name
    
    Returns:
        BarrierCertificate representing disjunction
    """
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        b1 = barrier1.evaluate(state)
        b2 = barrier2.evaluate(state)
        # max(b1, b2) using Z3 If
        # Ensure both are real-valued (handle both Int and Real)
        b1_real = b1 if z3.is_real(b1) else (z3.ToReal(b1) if z3.is_int(b1) else b1)
        b2_real = b2 if z3.is_real(b2) else (z3.ToReal(b2) if z3.is_int(b2) else b2)
        cond = b1_real >= b2_real
        return z3.If(cond, b1_real, b2_real)
    
    epsilon = min(barrier1.epsilon, barrier2.epsilon)
    
    return BarrierCertificate(
        name=name or f"disj({barrier1.name},{barrier2.name})",
        barrier_fn=barrier_fn,
        epsilon=epsilon,
        description=f"Disjunction of {barrier1.name} and {barrier2.name}",
        variables=(barrier1.variables or []) + (barrier2.variables or [])
    )


def collection_size_barrier(
    collection_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    max_size: int,
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Collection size barrier: bounds the size of a collection (list/dict/set).
    
    B(σ) = max_size - len(collection)
    
    Useful for MEMORY_LEAK detection and proving bounded resource usage.
    
    Args:
        collection_extractor: Extracts collection size
        max_size: Maximum allowed size
        name: Optional custom name
    
    Returns:
        BarrierCertificate for collection size
    """
    barrier_fn = linear_combination_barrier(
        [("collection_size", collection_extractor)],
        [-1.0],
        float(max_size)
    )
    
    return BarrierCertificate(
        name=name or f"collection_size_≤_{max_size}",
        barrier_fn=barrier_fn,
        epsilon=0.5,
        description=f"Collection size bounded by {max_size}",
        variables=["collection_size"]
    )


def progress_measure_barrier(
    progress_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Progress measure barrier: B(σ) = progress(σ)
    
    A progress measure is a quantity that strictly decreases on each
    iteration and is bounded below. Common for NON_TERMINATION proofs.
    
    The progress_extractor should return a value that:
    - Starts positive
    - Decreases by at least epsilon on each step
    - Never goes negative in reachable states
    
    Args:
        progress_extractor: Extracts the progress measure
        name: Optional custom name
    
    Returns:
        BarrierCertificate based on progress measure
    """
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        return z3.ToReal(progress_extractor(state))
    
    return BarrierCertificate(
        name=name or "progress_measure",
        barrier_fn=barrier_fn,
        epsilon=0.1,  # Progress must decrease by at least this much
        description="Progress measure for termination",
        variables=["progress"]
    )


def invariant_region_barrier(
    region_predicate: Callable[[SymbolicMachineState], z3.ExprRef],
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Invariant region barrier: encodes a boolean invariant as a barrier.
    
    B(σ) = if invariant(σ) then +1 else -1
    
    This allows us to use Z3's inductive checking on arbitrary boolean
    predicates by casting them as barriers with margin ±1.
    
    Args:
        region_predicate: Boolean predicate (Z3 BoolSort)
        name: Optional custom name
    
    Returns:
        BarrierCertificate encoding the invariant
    """
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        pred = region_predicate(state)
        # Convert boolean to real: True -> 1.0, False -> -1.0
        return z3.If(pred, z3.RealVal(1.0), z3.RealVal(-1.0))
    
    return BarrierCertificate(
        name=name or "invariant_region",
        barrier_fn=barrier_fn,
        epsilon=0.5,
        description="Boolean invariant encoded as barrier",
        variables=["invariant_predicate"]
    )


def quadratic_barrier(
    variable_name: str,
    variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    coeff_x2: float,
    coeff_x: float,
    constant: float,
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Quadratic barrier: B(σ) = a·x² + b·x + c
    
    Useful for proving properties with non-linear bounds, such as:
    - Parabolic resource usage patterns
    - Quadratic loop invariants
    - Non-linear separation between safe and unsafe regions
    
    Example: B(n) = 100 - n² proves n never exceeds 10 (since B(10) = 0)
    
    Args:
        variable_name: Name of the variable
        variable_extractor: Function to extract variable value from state
        coeff_x2: Coefficient for x² term
        coeff_x: Coefficient for x term
        constant: Constant term
        name: Optional custom name
    
    Returns:
        BarrierCertificate with quadratic form
    """
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        x = variable_extractor(state)
        x_real = z3.ToReal(x) if z3.is_int(x) else x
        # B = a·x² + b·x + c
        return (
            z3.RealVal(coeff_x2) * x_real * x_real +
            z3.RealVal(coeff_x) * x_real +
            z3.RealVal(constant)
        )
    
    return BarrierCertificate(
        name=name or f"quad_{variable_name}",
        barrier_fn=barrier_fn,
        epsilon=0.1,
        description=f"Quadratic barrier: {coeff_x2}·{variable_name}² + {coeff_x}·{variable_name} + {constant}",
        variables=[variable_name]
    )


def polynomial_barrier(
    variable_name: str,
    variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    coefficients: list[float],
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Polynomial barrier: B(σ) = c₀ + c₁·x + c₂·x² + ... + cₙ·xⁿ
    
    General polynomial template for higher-degree invariants.
    coefficients[i] is the coefficient for xⁱ.
    
    Args:
        variable_name: Name of the variable
        variable_extractor: Function to extract variable value from state
        coefficients: List of coefficients [c₀, c₁, c₂, ..., cₙ]
        name: Optional custom name
    
    Returns:
        BarrierCertificate with polynomial form
    """
    degree = len(coefficients) - 1
    
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        x = variable_extractor(state)
        x_real = z3.ToReal(x) if z3.is_int(x) else x
        
        # Horner's method for efficiency: c₀ + x·(c₁ + x·(c₂ + ...))
        result = z3.RealVal(coefficients[-1])
        for i in range(len(coefficients) - 2, -1, -1):
            result = z3.RealVal(coefficients[i]) + x_real * result
        
        return result
    
    coeff_str = " + ".join(f"{c}·{variable_name}^{i}" if i > 0 else str(c) 
                           for i, c in enumerate(coefficients) if c != 0)
    
    return BarrierCertificate(
        name=name or f"poly{degree}_{variable_name}",
        barrier_fn=barrier_fn,
        epsilon=0.1,
        description=f"Polynomial barrier (degree {degree}): {coeff_str}",
        variables=[variable_name]
    )


def bivariate_quadratic_barrier(
    var1_name: str,
    var2_name: str,
    var1_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    var2_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    coeff_x2: float,
    coeff_y2: float,
    coeff_xy: float,
    coeff_x: float,
    coeff_y: float,
    constant: float,
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Bivariate quadratic barrier: B(σ) = a·x² + b·y² + c·xy + d·x + e·y + f
    
    Useful for proving properties involving relationships between two variables:
    - Elliptical/hyperbolic safety regions
    - Resource trade-offs (e.g., time vs space)
    - Coupled loop invariants
    
    Example: B(x,y) = 100 - x² - y² proves x²+y² ≤ 100 (circle of radius 10)
    
    Args:
        var1_name: Name of first variable
        var2_name: Name of second variable
        var1_extractor: Function to extract first variable
        var2_extractor: Function to extract second variable
        coeff_x2: Coefficient for x² term
        coeff_y2: Coefficient for y² term
        coeff_xy: Coefficient for xy term
        coeff_x: Coefficient for x term
        coeff_y: Coefficient for y term
        constant: Constant term
        name: Optional custom name
    
    Returns:
        BarrierCertificate with bivariate quadratic form
    """
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        x = var1_extractor(state)
        y = var2_extractor(state)
        x_real = z3.ToReal(x) if z3.is_int(x) else x
        y_real = z3.ToReal(y) if z3.is_int(y) else y
        
        # B = a·x² + b·y² + c·xy + d·x + e·y + f
        return (
            z3.RealVal(coeff_x2) * x_real * x_real +
            z3.RealVal(coeff_y2) * y_real * y_real +
            z3.RealVal(coeff_xy) * x_real * y_real +
            z3.RealVal(coeff_x) * x_real +
            z3.RealVal(coeff_y) * y_real +
            z3.RealVal(constant)
        )
    
    return BarrierCertificate(
        name=name or f"biquad_{var1_name}_{var2_name}",
        barrier_fn=barrier_fn,
        epsilon=0.1,
        description=f"Bivariate quadratic: {coeff_x2}·{var1_name}² + {coeff_y2}·{var2_name}² + {coeff_xy}·{var1_name}{var2_name} + ...",
        variables=[var1_name, var2_name]
    )


def exponential_barrier(
    variable_name: str,
    variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    base: float,
    scale: float,
    shift: float,
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Exponential barrier (approximated): B(σ) ≈ shift - scale · baseˣ
    
    Note: Z3 does not natively support exponentiation with symbolic exponents.
    This provides a *limited* approximation using case analysis for small integer
    ranges. Use only when x is known to be bounded.
    
    For true exponential reasoning, consider over-approximations or custom theories.
    
    Args:
        variable_name: Name of the variable
        variable_extractor: Function to extract variable value from state
        base: Base of exponential (e.g., 2 for 2ˣ)
        scale: Scale factor
        shift: Vertical shift (upper bound)
        name: Optional custom name
    
    Returns:
        BarrierCertificate with approximate exponential form
    """
    # For simplicity, approximate using bounded case analysis (x in [0, 10])
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        x = variable_extractor(state)
        x_real = z3.ToReal(x) if z3.is_int(x) else x
        
        # Nested If-Then-Else for x = 0, 1, 2, ..., 10
        # This is crude but works for bounded domains
        result = z3.RealVal(shift - scale * (base ** 10))  # x >= 10 case
        for i in range(9, -1, -1):
            value = shift - scale * (base ** i)
            result = z3.If(x_real <= z3.RealVal(i), z3.RealVal(value), result)
        
        return result
    
    return BarrierCertificate(
        name=name or f"exp_{variable_name}",
        barrier_fn=barrier_fn,
        epsilon=0.5,
        description=f"Exponential barrier (approx): {shift} - {scale}·{base}^{variable_name}",
        variables=[variable_name]
    )


def disjunctive_region_barrier(
    barriers: list[BarrierCertificate],
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Enhanced disjunctive barrier for N barriers: B(σ) = max(B₁(σ), ..., Bₙ(σ))
    
    This extends the basic disjunction to N barriers, expressing that at least
    one of the barriers must hold. Useful for:
    - Multi-path safety (different branches have different invariants)
    - Case-split reasoning (e.g., x < 0 ∨ x > 10)
    - Disjoint safety regions
    
    The barrier is inductive if the step relation preserves max(B₁, ..., Bₙ) ≥ 0.
    
    Args:
        barriers: List of barrier certificates to combine
        name: Optional custom name
    
    Returns:
        BarrierCertificate representing disjunction of all barriers
    """
    if len(barriers) == 0:
        raise ValueError("Cannot create disjunctive barrier with empty list")
    
    if len(barriers) == 1:
        return barriers[0]
    
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        # Compute max(B₁(σ), ..., Bₙ(σ))
        values = []
        for b in barriers:
            val = b.evaluate(state)
            # Ensure real-valued
            val_real = val if z3.is_real(val) else (z3.ToReal(val) if z3.is_int(val) else val)
            values.append(val_real)
        
        # Build nested max using If
        result = values[0]
        for val in values[1:]:
            result = z3.If(result >= val, result, val)
        
        return result
    
    epsilon = min(b.epsilon for b in barriers)
    all_vars = []
    for b in barriers:
        all_vars.extend(b.variables or [])
    
    barrier_names = ", ".join(b.name for b in barriers)
    
    return BarrierCertificate(
        name=name or f"disj_N({len(barriers)})",
        barrier_fn=barrier_fn,
        epsilon=epsilon,
        description=f"Disjunction of {len(barriers)} barriers: max({barrier_names})",
        variables=all_vars
    )


def conjunctive_region_barrier(
    barriers: list[BarrierCertificate],
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Enhanced conjunctive barrier for N barriers: B(σ) = min(B₁(σ), ..., Bₙ(σ))
    
    This extends the basic conjunction to N barriers, expressing that all
    barriers must hold simultaneously. Useful for:
    - Multiple independent safety conditions
    - Bounding multiple variables
    - Combining different aspects of safety
    
    The barrier is inductive if all component barriers are inductive.
    
    Args:
        barriers: List of barrier certificates to combine
        name: Optional custom name
    
    Returns:
        BarrierCertificate representing conjunction of all barriers
    """
    if len(barriers) == 0:
        raise ValueError("Cannot create conjunctive barrier with empty list")
    
    if len(barriers) == 1:
        return barriers[0]
    
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        # Compute min(B₁(σ), ..., Bₙ(σ))
        values = []
        for b in barriers:
            val = b.evaluate(state)
            # Ensure real-valued
            val_real = val if z3.is_real(val) else (z3.ToReal(val) if z3.is_int(val) else val)
            values.append(val_real)
        
        # Build nested min using If
        result = values[0]
        for val in values[1:]:
            result = z3.If(result <= val, result, val)
        
        return result
    
    epsilon = min(b.epsilon for b in barriers)
    all_vars = []
    for b in barriers:
        all_vars.extend(b.variables or [])
    
    barrier_names = ", ".join(b.name for b in barriers)
    
    return BarrierCertificate(
        name=name or f"conj_N({len(barriers)})",
        barrier_fn=barrier_fn,
        epsilon=epsilon,
        description=f"Conjunction of {len(barriers)} barriers: min({barrier_names})",
        variables=all_vars
    )


def piecewise_linear_barrier(
    variable_name: str,
    variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    breakpoints: list[tuple[float, float, float]],
    name: Optional[str] = None
) -> BarrierCertificate:
    """
    Piecewise linear barrier: B(σ) = aᵢ·x + bᵢ for x in region i
    
    Defines a barrier that is linear within each region but changes slope
    at breakpoints. Useful for:
    - Phase-dependent invariants (initialization vs main loop vs cleanup)
    - Approximating non-linear barriers with linear pieces
    - Different bounds in different execution phases
    
    breakpoints: List of (threshold, slope, intercept) in ascending threshold order
    For x < breakpoints[0].threshold, use (slope[0], intercept[0])
    For x in [threshold[i-1], threshold[i]), use (slope[i], intercept[i])
    
    Args:
        variable_name: Name of the variable
        variable_extractor: Function to extract variable value
        breakpoints: List of (threshold, slope, intercept) tuples, sorted by threshold
        name: Optional custom name
    
    Returns:
        BarrierCertificate with piecewise linear form
    """
    if len(breakpoints) == 0:
        raise ValueError("Piecewise barrier needs at least one region")
    
    def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
        x = variable_extractor(state)
        x_real = z3.ToReal(x) if z3.is_int(x) else x
        
        # Build nested If for piecewise definition
        # Start from the highest threshold and work backwards
        threshold, slope, intercept = breakpoints[-1]
        result = z3.RealVal(slope) * x_real + z3.RealVal(intercept)
        
        for i in range(len(breakpoints) - 2, -1, -1):
            threshold, slope, intercept = breakpoints[i]
            piece = z3.RealVal(slope) * x_real + z3.RealVal(intercept)
            result = z3.If(x_real < z3.RealVal(threshold), piece, result)
        
        return result
    
    return BarrierCertificate(
        name=name or f"piecewise_{variable_name}",
        barrier_fn=barrier_fn,
        epsilon=0.1,
        description=f"Piecewise linear barrier with {len(breakpoints)} regions",
        variables=[variable_name]
    )
