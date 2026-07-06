"""
Relational summaries for Python stdlib module functions (math, os, sys, etc.).

Each summary follows the "cases + havoc fallback" pattern:
- Multiple guarded cases express known behaviors
- Required havoc fallback ensures soundness when guards don't hold
- All summaries maintain Sem_f ⊆ R_f (sound over-approximation)

Provenance: Python standard library documentation + CPython source.
"""

import z3
from typing import List

from a3_python.contracts.relations import (
    RelationalSummary, RelationalCase, PostCondition, HavocCase,
    register_relational_summary
)
from a3_python.z3model.values import SymbolicValue, ValueTag


def init_stdlib_module_relations():
    """Initialize relational summaries for stdlib module functions."""
    
    # ========================================================================
    # math.sqrt(x) - returns square root, raises ValueError if x < 0
    # ========================================================================
    
    math_sqrt_summary = RelationalSummary(
        function_id="math.sqrt",
        provenance="python_stdlib_docs"
    )
    
    # Case 1: x >= 0 → returns float >= 0
    def sqrt_guard_valid_domain(state, args):
        """Guard: x >= 0 (valid domain)."""
        if not args or len(args) != 1:
            return z3.BoolVal(False)
        
        x = args[0]
        
        # Check if x is numeric (INT or FLOAT)
        if x.tag == ValueTag.INT:
            # For symbolic int, create constraint x >= 0 and simplify
            constraint = x.payload >= 0
            return z3.simplify(constraint)
        elif x.tag == ValueTag.FLOAT:
            # For symbolic float, create constraint x >= 0.0 and simplify
            constraint = x.payload >= 0.0
            return z3.simplify(constraint)
        else:
            # Not a valid numeric type
            return z3.BoolVal(False)
    
    def sqrt_post_valid_domain(state, args, fresh_symbols):
        """Postcondition: returns non-negative float."""
        x = args[0]
        
        # Create fresh symbolic float for result
        ret_sym = z3.Real(f"sqrt_result_{id(fresh_symbols)}")
        
        # Constraints:
        # 1. Result is non-negative
        # 2. Result squared equals input (approximate - for perfect reasoning we'd need reals)
        constraints = [ret_sym >= 0.0]
        
        # If x is symbolic int, add ret_sym^2 == x constraint
        if x.tag == ValueTag.INT:
            # For integer input, we have ret_sym^2 == Real(x)
            # Z3 can handle this with mixed int/real arithmetic
            constraints.append(ret_sym * ret_sym == z3.ToReal(x.payload))
        elif x.tag == ValueTag.FLOAT:
            # For float input, ret_sym^2 == x
            constraints.append(ret_sym * ret_sym == x.payload)
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.FLOAT, ret_sym),
            path_constraints=constraints,
            heap_constraints=[]
        )
    
    math_sqrt_summary.add_case(RelationalCase(
        name="sqrt_valid_domain",
        guard=sqrt_guard_valid_domain,
        post=sqrt_post_valid_domain,
        may_raise=[],  # No exception in valid domain
        provenance="python_stdlib_docs"
    ))
    
    # Case 2: x < 0 → raises ValueError (FP_DOMAIN bug)
    def sqrt_guard_invalid_domain(state, args):
        """Guard: x < 0 (invalid domain → FP_DOMAIN)."""
        if not args or len(args) != 1:
            return z3.BoolVal(False)
        
        x = args[0]
        
        # Check if x is numeric and negative
        if x.tag == ValueTag.INT:
            return z3.simplify(x.payload < 0)
        elif x.tag == ValueTag.FLOAT:
            return z3.simplify(x.payload < 0.0)
        else:
            return z3.BoolVal(False)
    
    def sqrt_post_invalid_domain(state, args, fresh_symbols):
        """Postcondition: raises ValueError (FP_DOMAIN bug)."""
        # This case always raises ValueError
        # We model this by returning None (no normal return) and marking exception
        # The VM will detect this as an uncaught ValueError → PANIC/FP_DOMAIN
        
        # For now, we indicate exception by returning a special marker
        # The actual exception handling is done by the VM
        return PostCondition(
            return_value=None,  # No normal return
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'exception_raised': ('ValueError', 'math domain error')}
        )
    
    math_sqrt_summary.add_case(RelationalCase(
        name="sqrt_domain_error",
        guard=sqrt_guard_invalid_domain,
        post=sqrt_post_invalid_domain,
        may_raise=["ValueError"],  # FP_DOMAIN bug
        provenance="python_stdlib_docs"
    ))
    
    # Case 3: TypeError for non-numeric input
    def sqrt_guard_type_error(state, args):
        """Guard: non-numeric input → TypeError."""
        if not args or len(args) != 1:
            return z3.BoolVal(False)
        
        x = args[0]
        
        # If not INT or FLOAT, it's a type error
        # But OBJ could be a numeric object (complex, Decimal, etc.)
        # For soundness, only reject definitely non-numeric types
        is_numeric = (x.tag == ValueTag.INT) or (x.tag == ValueTag.FLOAT)
        is_definitely_not_numeric = (x.tag == ValueTag.STR) or (x.tag == ValueTag.LIST) or (x.tag == ValueTag.TUPLE) or (x.tag == ValueTag.DICT) or (x.tag == ValueTag.NONE)
        
        return z3.BoolVal(is_definitely_not_numeric)
    
    def sqrt_post_type_error(state, args, fresh_symbols):
        """Postcondition: raises TypeError."""
        return PostCondition(
            return_value=None,
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'exception_raised': ('TypeError', 'must be real number, not str/list/etc')}
        )
    
    math_sqrt_summary.add_case(RelationalCase(
        name="sqrt_type_error",
        guard=sqrt_guard_type_error,
        post=sqrt_post_type_error,
        may_raise=["TypeError"],
        provenance="python_stdlib_docs"
    ))
    
    register_relational_summary(math_sqrt_summary)
    
    
    # ========================================================================
    # math.log(x) - returns natural logarithm, raises ValueError if x <= 0
    # ========================================================================
    
    math_log_summary = RelationalSummary(
        function_id="math.log",
        provenance="python_stdlib_docs"
    )
    
    # Case 1: x > 0 → returns float
    def log_guard_valid_domain(state, args):
        """Guard: x > 0 (valid domain)."""
        if not args or len(args) < 1:
            return z3.BoolVal(False)
        
        x = args[0]
        
        if x.tag == ValueTag.INT:
            return z3.simplify(x.payload > 0)
        elif x.tag == ValueTag.FLOAT:
            return z3.simplify(x.payload > 0.0)
        else:
            return z3.BoolVal(False)
    
    def log_post_valid_domain(state, args, fresh_symbols):
        """Postcondition: returns float (no specific constraint on value for now)."""
        # ln(x) for x > 0 is well-defined
        ret_sym = z3.Real(f"log_result_{id(fresh_symbols)}")
        
        # For x > 0, log(x) can be any real number
        # We could add: if x == 1 then log(x) == 0, etc.
        # But for now, just return a fresh float
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.FLOAT, ret_sym),
            path_constraints=[],
            heap_constraints=[]
        )
    
    math_log_summary.add_case(RelationalCase(
        name="log_valid_domain",
        guard=log_guard_valid_domain,
        post=log_post_valid_domain,
        may_raise=[],
        provenance="python_stdlib_docs"
    ))
    
    # Case 2: x <= 0 → raises ValueError (FP_DOMAIN bug)
    def log_guard_invalid_domain(state, args):
        """Guard: x <= 0 (invalid domain → FP_DOMAIN)."""
        if not args or len(args) < 1:
            return z3.BoolVal(False)
        
        x = args[0]
        
        if x.tag == ValueTag.INT:
            return z3.simplify(x.payload <= 0)
        elif x.tag == ValueTag.FLOAT:
            return z3.simplify(x.payload <= 0.0)
        else:
            return z3.BoolVal(False)
    
    def log_post_invalid_domain(state, args, fresh_symbols):
        """Postcondition: raises ValueError (FP_DOMAIN bug)."""
        return PostCondition(
            return_value=None,
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'exception_raised': ('ValueError', 'math domain error')}
        )
    
    math_log_summary.add_case(RelationalCase(
        name="log_domain_error",
        guard=log_guard_invalid_domain,
        post=log_post_invalid_domain,
        may_raise=["ValueError"],
        provenance="python_stdlib_docs"
    ))
    
    # Case 3: TypeError for non-numeric input
    def log_guard_type_error(state, args):
        """Guard: non-numeric input → TypeError."""
        if not args or len(args) < 1:
            return z3.BoolVal(False)
        
        x = args[0]
        is_definitely_not_numeric = (x.tag == ValueTag.STR) or (x.tag == ValueTag.LIST) or (x.tag == ValueTag.TUPLE) or (x.tag == ValueTag.DICT) or (x.tag == ValueTag.NONE)
        
        return z3.BoolVal(is_definitely_not_numeric)
    
    def log_post_type_error(state, args, fresh_symbols):
        """Postcondition: raises TypeError."""
        return PostCondition(
            return_value=None,
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'exception_raised': ('TypeError', 'must be real number')}
        )
    
    math_log_summary.add_case(RelationalCase(
        name="log_type_error",
        guard=log_guard_type_error,
        post=log_post_type_error,
        may_raise=["TypeError"],
        provenance="python_stdlib_docs"
    ))
    
    register_relational_summary(math_log_summary)
    
    
    # ========================================================================
    # math.asin(x) - returns arcsine, raises ValueError if x not in [-1, 1]
    # ========================================================================
    
    math_asin_summary = RelationalSummary(
        function_id="math.asin",
        provenance="python_stdlib_docs"
    )
    
    # Case 1: -1 <= x <= 1 → returns float in [-π/2, π/2]
    def asin_guard_valid_domain(state, args):
        """Guard: -1 <= x <= 1 (valid domain)."""
        if not args or len(args) != 1:
            return z3.BoolVal(False)
        
        x = args[0]
        
        if x.tag == ValueTag.INT:
            return z3.simplify(z3.And(x.payload >= -1, x.payload <= 1))
        elif x.tag == ValueTag.FLOAT:
            return z3.simplify(z3.And(x.payload >= -1.0, x.payload <= 1.0))
        else:
            return z3.BoolVal(False)
    
    def asin_post_valid_domain(state, args, fresh_symbols):
        """Postcondition: returns float in [-π/2, π/2]."""
        ret_sym = z3.Real(f"asin_result_{id(fresh_symbols)}")
        
        # Result is in [-π/2, π/2] ≈ [-1.5708, 1.5708]
        # For symbolic reasoning, we constrain the range
        constraints = [
            ret_sym >= -1.5708,
            ret_sym <= 1.5708
        ]
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.FLOAT, ret_sym),
            path_constraints=constraints,
            heap_constraints=[]
        )
    
    math_asin_summary.add_case(RelationalCase(
        name="asin_valid_domain",
        guard=asin_guard_valid_domain,
        post=asin_post_valid_domain,
        may_raise=[],
        provenance="python_stdlib_docs"
    ))
    
    # Case 2: x < -1 or x > 1 → raises ValueError (FP_DOMAIN bug)
    def asin_guard_invalid_domain(state, args):
        """Guard: x < -1 or x > 1 (invalid domain → FP_DOMAIN)."""
        if not args or len(args) != 1:
            return z3.BoolVal(False)
        
        x = args[0]
        
        if x.tag == ValueTag.INT:
            return z3.simplify(z3.Or(x.payload < -1, x.payload > 1))
        elif x.tag == ValueTag.FLOAT:
            return z3.simplify(z3.Or(x.payload < -1.0, x.payload > 1.0))
        else:
            return z3.BoolVal(False)
    
    def asin_post_invalid_domain(state, args, fresh_symbols):
        """Postcondition: raises ValueError (FP_DOMAIN bug)."""
        return PostCondition(
            return_value=None,
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'exception_raised': ('ValueError', 'math domain error')}
        )
    
    math_asin_summary.add_case(RelationalCase(
        name="asin_domain_error",
        guard=asin_guard_invalid_domain,
        post=asin_post_invalid_domain,
        may_raise=["ValueError"],
        provenance="python_stdlib_docs"
    ))
    
    # Case 3: TypeError for non-numeric input
    def asin_guard_type_error(state, args):
        """Guard: non-numeric input → TypeError."""
        if not args or len(args) != 1:
            return z3.BoolVal(False)
        
        x = args[0]
        is_definitely_not_numeric = (x.tag == ValueTag.STR) or (x.tag == ValueTag.LIST) or (x.tag == ValueTag.TUPLE) or (x.tag == ValueTag.DICT) or (x.tag == ValueTag.NONE)
        
        return z3.BoolVal(is_definitely_not_numeric)
    
    def asin_post_type_error(state, args, fresh_symbols):
        """Postcondition: raises TypeError."""
        return PostCondition(
            return_value=None,
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'exception_raised': ('TypeError', 'must be real number')}
        )
    
    math_asin_summary.add_case(RelationalCase(
        name="asin_type_error",
        guard=asin_guard_type_error,
        post=asin_post_type_error,
        may_raise=["TypeError"],
        provenance="python_stdlib_docs"
    ))
    
    register_relational_summary(math_asin_summary)
    
    
    # ========================================================================
    # math.acos(x) - returns arccosine, raises ValueError if x not in [-1, 1]
    # ========================================================================
    
    math_acos_summary = RelationalSummary(
        function_id="math.acos",
        provenance="python_stdlib_docs"
    )
    
    # Case 1: -1 <= x <= 1 → returns float in [0, π]
    def acos_guard_valid_domain(state, args):
        """Guard: -1 <= x <= 1 (valid domain)."""
        if not args or len(args) != 1:
            return z3.BoolVal(False)
        
        x = args[0]
        
        if x.tag == ValueTag.INT:
            return z3.simplify(z3.And(x.payload >= -1, x.payload <= 1))
        elif x.tag == ValueTag.FLOAT:
            return z3.simplify(z3.And(x.payload >= -1.0, x.payload <= 1.0))
        else:
            return z3.BoolVal(False)
    
    def acos_post_valid_domain(state, args, fresh_symbols):
        """Postcondition: returns float in [0, π]."""
        ret_sym = z3.Real(f"acos_result_{id(fresh_symbols)}")
        
        # Result is in [0, π] ≈ [0, 3.1416]
        constraints = [
            ret_sym >= 0.0,
            ret_sym <= 3.1416
        ]
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.FLOAT, ret_sym),
            path_constraints=constraints,
            heap_constraints=[]
        )
    
    math_acos_summary.add_case(RelationalCase(
        name="acos_valid_domain",
        guard=acos_guard_valid_domain,
        post=acos_post_valid_domain,
        may_raise=[],
        provenance="python_stdlib_docs"
    ))
    
    # Case 2: x < -1 or x > 1 → raises ValueError (FP_DOMAIN bug)
    def acos_guard_invalid_domain(state, args):
        """Guard: x < -1 or x > 1 (invalid domain → FP_DOMAIN)."""
        if not args or len(args) != 1:
            return z3.BoolVal(False)
        
        x = args[0]
        
        if x.tag == ValueTag.INT:
            return z3.simplify(z3.Or(x.payload < -1, x.payload > 1))
        elif x.tag == ValueTag.FLOAT:
            return z3.simplify(z3.Or(x.payload < -1.0, x.payload > 1.0))
        else:
            return z3.BoolVal(False)
    
    def acos_post_invalid_domain(state, args, fresh_symbols):
        """Postcondition: raises ValueError (FP_DOMAIN bug)."""
        return PostCondition(
            return_value=None,
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'exception_raised': ('ValueError', 'math domain error')}
        )
    
    math_acos_summary.add_case(RelationalCase(
        name="acos_domain_error",
        guard=acos_guard_invalid_domain,
        post=acos_post_invalid_domain,
        may_raise=["ValueError"],
        provenance="python_stdlib_docs"
    ))
    
    # Case 3: TypeError for non-numeric input
    def acos_guard_type_error(state, args):
        """Guard: non-numeric input → TypeError."""
        if not args or len(args) != 1:
            return z3.BoolVal(False)
        
        x = args[0]
        is_definitely_not_numeric = (x.tag == ValueTag.STR) or (x.tag == ValueTag.LIST) or (x.tag == ValueTag.TUPLE) or (x.tag == ValueTag.DICT) or (x.tag == ValueTag.NONE)
        
        return z3.BoolVal(is_definitely_not_numeric)
    
    def acos_post_type_error(state, args, fresh_symbols):
        """Postcondition: raises TypeError."""
        return PostCondition(
            return_value=None,
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'exception_raised': ('TypeError', 'must be real number')}
        )
    
    math_acos_summary.add_case(RelationalCase(
        name="acos_type_error",
        guard=acos_guard_type_error,
        post=acos_post_type_error,
        may_raise=["TypeError"],
        provenance="python_stdlib_docs"
    ))
    
    register_relational_summary(math_acos_summary)


# Initialize on module import
init_stdlib_module_relations()
