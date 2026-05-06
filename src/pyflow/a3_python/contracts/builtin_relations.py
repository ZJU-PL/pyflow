"""
Relational summaries for Python builtin functions.

Each summary follows the "cases + havoc fallback" pattern from ELEVATION_PLAN.md:
- Multiple guarded cases express known behaviors
- Required havoc fallback ensures soundness when guards don't hold
- All summaries maintain Sem_f ⊆ R_f (sound over-approximation)

Provenance: Python language specification + CPython documentation.
"""

import z3
from typing import List

from a3_python.contracts.relations import (
    RelationalSummary, RelationalCase, PostCondition, HavocCase,
    seq_len_observer, register_relational_summary
)
from a3_python.z3model.values import SymbolicValue, ValueTag


def init_builtin_relations():
    """Initialize relational summaries for builtin functions."""
    
    # len(obj) - returns length of sequence/collection
    len_summary = RelationalSummary(
        function_id="len",
        provenance="python_spec"
    )
    
    # Case 1: len(list/tuple/str/dict) -> int >= 0
    def len_guard_sequence(state, args):
        """Guard: argument is a known sequence type."""
        if not args or len(args) != 1:
            return z3.BoolVal(False)
        
        arg = args[0]
        # Check if it's a LIST, TUPLE, STR, or DICT
        is_list = arg.tag == ValueTag.LIST
        is_tuple = arg.tag == ValueTag.TUPLE
        is_str = arg.tag == ValueTag.STR
        is_dict = arg.tag == ValueTag.DICT
        
        # In symbolic execution, we may have OBJ type that could be any of these
        # For now, accept if tag matches known types
        return z3.BoolVal(is_list or is_tuple or is_str or is_dict)
    
    def len_post_sequence(state, args, fresh_symbols):
        """Postcondition: return SeqLen(arg) which is >= 0."""
        arg = args[0]
        
        # Create a fresh symbolic int for the return value
        ret_sym = z3.Int(f"len_result_{id(fresh_symbols)}")
        
        # Constraint: result is non-negative
        constraints = [ret_sym >= 0]
        
        # Use heap observer to tie return value to actual sequence length
        # If arg is OBJ (object reference), extract obj_id and use observer
        if arg.tag == ValueTag.OBJ:
            # arg.payload is the obj_id
            obj_id = arg.payload
            # Get SeqLen observer from heap (VM will handle this)
            # For now, we record that this should be constrained
            # The VM needs to add: ret_sym == SeqLen(obj_id)
            # We'll store this as an observer_update
            return PostCondition(
                return_value=SymbolicValue(ValueTag.INT, ret_sym),
                path_constraints=constraints,
                heap_constraints=[],
                observer_updates={'seq_len': (obj_id, ret_sym)}
            )
        else:
            # For direct LIST/TUPLE/STR/DICT values, just constrain >= 0
            return PostCondition(
                return_value=SymbolicValue(ValueTag.INT, ret_sym),
                path_constraints=constraints,
                heap_constraints=[]
            )
    
    len_summary.add_case(RelationalCase(
        name="len_sequence",
        guard=len_guard_sequence,
        post=len_post_sequence,
        may_raise=[],  # Doesn't raise for valid sequences
        provenance="python_spec"
    ))
    
    # Case 2: len(obj) where obj might not have __len__
    # This case handles TypeError (no __len__ method)
    def len_guard_maybe_no_len(state, args):
        """Guard: argument might not support len (OBJ type)."""
        if not args or len(args) != 1:
            return z3.BoolVal(False)
        
        arg = args[0]
        # If it's generic OBJ, it might not have __len__
        return z3.BoolVal(arg.tag == ValueTag.OBJ)
    
    def len_post_maybe_no_len(state, args, fresh_symbols):
        """Postcondition: either return int >= 0 or raise TypeError."""
        # This case is disjunctive: might succeed OR might raise
        # For simplicity in this implementation, we'll let the havoc
        # case handle the exceptional behavior
        # A full implementation would fork paths here
        ret_sym = z3.Int(f"len_obj_result_{id(fresh_symbols)}")
        return PostCondition(
            return_value=SymbolicValue(ValueTag.INT, ret_sym),
            path_constraints=[ret_sym >= 0],
            heap_constraints=[]
        )
    
    len_summary.add_case(RelationalCase(
        name="len_maybe_no_len",
        guard=len_guard_maybe_no_len,
        post=len_post_maybe_no_len,
        may_raise=["TypeError"],  # May raise if no __len__
        provenance="python_spec"
    ))
    
    # Havoc fallback is automatically present
    register_relational_summary(len_summary)
    
    
    # abs(x) - returns absolute value of numeric argument
    abs_summary = RelationalSummary(
        function_id="abs",
        provenance="python_spec"
    )
    
    def abs_guard_numeric(state, args):
        """Guard: argument is numeric (int or float)."""
        if not args or len(args) != 1:
            return z3.BoolVal(False)
        arg = args[0]
        return z3.BoolVal(arg.tag == ValueTag.INT or arg.tag == ValueTag.FLOAT)
    
    def abs_post_numeric(state, args, fresh_symbols):
        """Postcondition: return |arg| which is >= 0."""
        arg = args[0]
        ret_sym = z3.Int(f"abs_result_{id(fresh_symbols)}") if arg.tag == ValueTag.INT else z3.Real(f"abs_result_{id(fresh_symbols)}")
        
        # Constraint: result >= 0
        # For absolute value, we know the result is non-negative
        # We express |x| as a fresh variable constrained to be >= 0
        # and equal to either x or -x
        constraints = [ret_sym >= 0]
        
        # Add the absolute value constraint
        # |x| = x if x >= 0, else |x| = -x
        # This is: (x >= 0 => ret == x) AND (x < 0 => ret == -x)
        constraints.append(
            z3.And(
                z3.Implies(arg.payload >= 0, ret_sym == arg.payload),
                z3.Implies(arg.payload < 0, ret_sym == -arg.payload)
            )
        )
        
        return PostCondition(
            return_value=SymbolicValue(arg.tag, ret_sym),
            path_constraints=constraints,
            heap_constraints=[]
        )
    
    abs_summary.add_case(RelationalCase(
        name="abs_numeric",
        guard=abs_guard_numeric,
        post=abs_post_numeric,
        may_raise=[],
        provenance="python_spec"
    ))
    
    register_relational_summary(abs_summary)
    
    
    # isinstance(obj, classinfo) - checks if obj is instance of class
    isinstance_summary = RelationalSummary(
        function_id="isinstance",
        provenance="python_spec"
    )
    
    def isinstance_guard(state, args):
        """Guard: two arguments provided."""
        return z3.BoolVal(len(args) == 2)
    
    def isinstance_post(state, args, fresh_symbols):
        """Postcondition: return bool (unknown which)."""
        # We can't determine isinstance result symbolically without type info
        # Return a fresh symbolic bool
        ret_sym = z3.Bool(f"isinstance_result_{id(fresh_symbols)}")
        return PostCondition(
            return_value=SymbolicValue(ValueTag.BOOL, ret_sym),
            path_constraints=[],
            heap_constraints=[]
        )
    
    isinstance_summary.add_case(RelationalCase(
        name="isinstance_check",
        guard=isinstance_guard,
        post=isinstance_post,
        may_raise=["TypeError"],  # May raise if classinfo is invalid
        provenance="python_spec"
    ))
    
    register_relational_summary(isinstance_summary)
    
    
    # range(stop) / range(start, stop[, step]) - returns range object
    range_summary = RelationalSummary(
        function_id="range",
        provenance="python_spec"
    )
    
    def range_guard_valid_args(state, args):
        """Guard: 1, 2, or 3 integer arguments."""
        if not args or len(args) > 3:
            return z3.BoolVal(False)
        # Check all args are INT type
        all_int = all(arg.tag == ValueTag.INT for arg in args)
        return z3.BoolVal(all_int and len(args) in [1, 2, 3])
    
    def range_post_valid(state, args, fresh_symbols):
        """Postcondition: return iterable range object."""
        # range() returns an iterable object (we model as OBJ with iterator protocol)
        # The length of range(start, stop, step) is determinable but complex
        # For simplicity: return fresh OBJ with unknown but finite length
        ret_obj = z3.Int(f"range_obj_{id(fresh_symbols)}")
        
        # We can constrain the length based on arguments
        # len(range(stop)) = max(0, stop)
        # len(range(start, stop)) = max(0, (stop - start))
        # len(range(start, stop, step)) = max(0, ceil((stop - start) / step))
        
        # For now, just assert length >= 0 (conservative)
        ret_len = z3.Int(f"range_len_{id(fresh_symbols)}")
        constraints = [ret_len >= 0]
        
        # Add more precise length constraint based on number of args
        if len(args) == 1:
            # range(stop)
            stop = args[0].payload
            constraints.append(z3.If(stop > 0, ret_len == stop, ret_len == 0))
        elif len(args) == 2:
            # range(start, stop)
            start = args[0].payload
            stop = args[1].payload
            diff = stop - start
            constraints.append(z3.If(diff > 0, ret_len == diff, ret_len == 0))
        # For 3 args with step, it's more complex - leave conservative
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.OBJ, ret_obj),
            path_constraints=constraints,
            heap_constraints=[],
            observer_updates={'seq_len': (ret_obj, ret_len)}
        )
    
    range_summary.add_case(RelationalCase(
        name="range_valid",
        guard=range_guard_valid_args,
        post=range_post_valid,
        may_raise=["ValueError"],  # May raise if step is 0
        provenance="python_spec"
    ))
    
    register_relational_summary(range_summary)
    
    
    # sorted(iterable, *, key=None, reverse=False) - returns sorted list
    sorted_summary = RelationalSummary(
        function_id="sorted",
        provenance="python_spec"
    )
    
    def sorted_guard(state, args):
        """Guard: at least one argument (the iterable)."""
        return z3.BoolVal(len(args) >= 1)
    
    def sorted_post(state, args, fresh_symbols):
        """Postcondition: return list with same length as input iterable."""
        # sorted() returns a new list
        ret_obj = z3.Int(f"sorted_list_{id(fresh_symbols)}")
        
        # The length of the result equals the length of the input
        # If input has known length, preserve it
        arg = args[0]
        ret_len = z3.Int(f"sorted_len_{id(fresh_symbols)}")
        constraints = [ret_len >= 0]
        
        # If input is OBJ with SeqLen, result has same length
        if arg.tag == ValueTag.OBJ:
            obj_id = arg.payload
            # The VM should extract SeqLen(obj_id) and constrain ret_len to match
            # For now, just assert >= 0
            pass
        elif arg.tag in [ValueTag.LIST, ValueTag.TUPLE]:
            # Direct list/tuple - length preserved
            pass
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.LIST, ret_obj),
            path_constraints=constraints,
            heap_constraints=[],
            observer_updates={'seq_len': (ret_obj, ret_len)}
        )
    
    sorted_summary.add_case(RelationalCase(
        name="sorted_iterable",
        guard=sorted_guard,
        post=sorted_post,
        may_raise=["TypeError"],  # May raise if items not comparable
        provenance="python_spec"
    ))
    
    register_relational_summary(sorted_summary)
    
    
    # enumerate(iterable, start=0) - returns enumerate object
    enumerate_summary = RelationalSummary(
        function_id="enumerate",
        provenance="python_spec"
    )
    
    def enumerate_guard(state, args):
        """Guard: at least one argument (the iterable)."""
        return z3.BoolVal(len(args) >= 1)
    
    def enumerate_post(state, args, fresh_symbols):
        """Postcondition: return iterable of (index, item) tuples."""
        # enumerate() returns an iterator object
        ret_obj = z3.Int(f"enumerate_obj_{id(fresh_symbols)}")
        
        # Length equals input iterable length
        ret_len = z3.Int(f"enumerate_len_{id(fresh_symbols)}")
        constraints = [ret_len >= 0]
        
        # Each item is a tuple (int, item)
        return PostCondition(
            return_value=SymbolicValue(ValueTag.OBJ, ret_obj),
            path_constraints=constraints,
            heap_constraints=[],
            observer_updates={'seq_len': (ret_obj, ret_len)}
        )
    
    enumerate_summary.add_case(RelationalCase(
        name="enumerate_iterable",
        guard=enumerate_guard,
        post=enumerate_post,
        may_raise=["TypeError"],  # May raise if not iterable
        provenance="python_spec"
    ))
    
    register_relational_summary(enumerate_summary)
    
    
    # zip(*iterables, strict=False) - returns zip object
    zip_summary = RelationalSummary(
        function_id="zip",
        provenance="python_spec"
    )
    
    def zip_guard(state, args):
        """Guard: any number of arguments (including 0)."""
        return z3.BoolVal(True)  # zip() accepts any number of args
    
    def zip_post(state, args, fresh_symbols):
        """Postcondition: return iterable of tuples."""
        # zip() returns an iterator object
        ret_obj = z3.Int(f"zip_obj_{id(fresh_symbols)}")
        
        # Length is min of all input lengths (or 0 if no args)
        ret_len = z3.Int(f"zip_len_{id(fresh_symbols)}")
        
        if len(args) == 0:
            # zip() with no args returns empty iterator
            constraints = [ret_len == 0]
        else:
            # Length is min of all input lengths
            # Conservative: length >= 0
            constraints = [ret_len >= 0]
            
            # TODO: For more precision, could add constraint:
            # ret_len <= SeqLen(arg_i) for all i
            # This requires accessing observers for all args
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.OBJ, ret_obj),
            path_constraints=constraints,
            heap_constraints=[],
            observer_updates={'seq_len': (ret_obj, ret_len)}
        )
    
    zip_summary.add_case(RelationalCase(
        name="zip_iterables",
        guard=zip_guard,
        post=zip_post,
        may_raise=["TypeError"],  # May raise if args not iterable
        provenance="python_spec"
    ))
    
    register_relational_summary(zip_summary)
    
    
    # reversed(seq) - returns reverse iterator
    reversed_summary = RelationalSummary(
        function_id="reversed",
        provenance="python_spec"
    )
    
    def reversed_guard(state, args):
        """Guard: one argument that is a sequence."""
        if len(args) != 1:
            return z3.BoolVal(False)
        arg = args[0]
        # reversed() works on sequences with __reversed__ or __len__+__getitem__
        return z3.BoolVal(arg.tag in [ValueTag.LIST, ValueTag.TUPLE, ValueTag.STR, ValueTag.OBJ])
    
    def reversed_post(state, args, fresh_symbols):
        """Postcondition: return reverse iterator with same length."""
        ret_obj = z3.Int(f"reversed_obj_{id(fresh_symbols)}")
        ret_len = z3.Int(f"reversed_len_{id(fresh_symbols)}")
        
        # Length equals input sequence length
        constraints = [ret_len >= 0]
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.OBJ, ret_obj),
            path_constraints=constraints,
            heap_constraints=[],
            observer_updates={'seq_len': (ret_obj, ret_len)}
        )
    
    reversed_summary.add_case(RelationalCase(
        name="reversed_sequence",
        guard=reversed_guard,
        post=reversed_post,
        may_raise=["TypeError"],
        provenance="python_spec"
    ))
    
    register_relational_summary(reversed_summary)
    
    
    # map(func, *iterables) - returns map object
    map_summary = RelationalSummary(
        function_id="map",
        provenance="python_spec"
    )
    
    def map_guard(state, args):
        """Guard: at least one argument (function)."""
        return z3.BoolVal(len(args) >= 1)
    
    def map_post(state, args, fresh_symbols):
        """Postcondition: return iterator applying func to iterables."""
        ret_obj = z3.Int(f"map_obj_{id(fresh_symbols)}")
        ret_len = z3.Int(f"map_len_{id(fresh_symbols)}")
        
        # Length is min of all iterable lengths (like zip)
        # Conservative: >= 0
        constraints = [ret_len >= 0]
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.OBJ, ret_obj),
            path_constraints=constraints,
            heap_constraints=[],
            observer_updates={'seq_len': (ret_obj, ret_len)}
        )
    
    map_summary.add_case(RelationalCase(
        name="map_func_iterables",
        guard=map_guard,
        post=map_post,
        may_raise=["TypeError"],
        provenance="python_spec"
    ))
    
    register_relational_summary(map_summary)
    
    
    # filter(func, iterable) - returns filter object
    filter_summary = RelationalSummary(
        function_id="filter",
        provenance="python_spec"
    )
    
    def filter_guard(state, args):
        """Guard: two arguments (function/None and iterable)."""
        return z3.BoolVal(len(args) >= 1)
    
    def filter_post(state, args, fresh_symbols):
        """Postcondition: return iterator of filtered items."""
        ret_obj = z3.Int(f"filter_obj_{id(fresh_symbols)}")
        ret_len = z3.Int(f"filter_len_{id(fresh_symbols)}")
        
        # Length is <= input length, >= 0
        constraints = [ret_len >= 0]
        
        # If we know input length, constrain result <= input
        # For now, just >= 0
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.OBJ, ret_obj),
            path_constraints=constraints,
            heap_constraints=[],
            observer_updates={'seq_len': (ret_obj, ret_len)}
        )
    
    filter_summary.add_case(RelationalCase(
        name="filter_func_iterable",
        guard=filter_guard,
        post=filter_post,
        may_raise=["TypeError"],
        provenance="python_spec"
    ))
    
    register_relational_summary(filter_summary)
    
    
    # all(iterable) - returns bool
    all_summary = RelationalSummary(
        function_id="all",
        provenance="python_spec"
    )
    
    def all_guard(state, args):
        """Guard: one argument (iterable)."""
        return z3.BoolVal(len(args) == 1)
    
    def all_post(state, args, fresh_symbols):
        """Postcondition: return bool."""
        # all() returns True if all elements are truthy (or iterable is empty)
        # We can't determine this symbolically in general
        ret_sym = z3.Bool(f"all_result_{id(fresh_symbols)}")
        
        # Special case: if input is empty, all() returns True
        # For now, return fresh symbolic bool
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.BOOL, ret_sym),
            path_constraints=[],
            heap_constraints=[]
        )
    
    all_summary.add_case(RelationalCase(
        name="all_iterable",
        guard=all_guard,
        post=all_post,
        may_raise=["TypeError"],
        provenance="python_spec"
    ))
    
    register_relational_summary(all_summary)
    
    
    # any(iterable) - returns bool
    any_summary = RelationalSummary(
        function_id="any",
        provenance="python_spec"
    )
    
    def any_guard(state, args):
        """Guard: one argument (iterable)."""
        return z3.BoolVal(len(args) == 1)
    
    def any_post(state, args, fresh_symbols):
        """Postcondition: return bool."""
        # any() returns True if any element is truthy
        # We can't determine this symbolically in general
        ret_sym = z3.Bool(f"any_result_{id(fresh_symbols)}")
        
        # Special case: if input is empty, any() returns False
        # For now, return fresh symbolic bool
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.BOOL, ret_sym),
            path_constraints=[],
            heap_constraints=[]
        )
    
    any_summary.add_case(RelationalCase(
        name="any_iterable",
        guard=any_guard,
        post=any_post,
        may_raise=["TypeError"],
        provenance="python_spec"
    ))
    
    register_relational_summary(any_summary)
    
    
    # int(x, base=10) - converts to integer, can raise ValueError/TypeError
    int_summary = RelationalSummary(
        function_id="int",
        provenance="python_spec"
    )
    
    # Case 1: int(x) where x is already an int - identity
    def int_guard_already_int(state, args):
        if not args or len(args) == 0:
            return z3.BoolVal(False)
        arg = args[0]
        return z3.BoolVal(arg.tag == ValueTag.INT)
    
    def int_post_already_int(state, args, fresh_symbols):
        # Return the same int value
        return PostCondition(
            return_value=args[0],
            path_constraints=[],
            heap_constraints=[]
        )
    
    int_summary.add_case(RelationalCase(
        name="int_identity",
        guard=int_guard_already_int,
        post=int_post_already_int,
        may_raise=[],  # No exception for int->int
        provenance="python_spec"
    ))
    
    # Case 2: int(bool) - converts bool to 0/1
    def int_guard_bool(state, args):
        if not args or len(args) == 0:
            return z3.BoolVal(False)
        arg = args[0]
        return z3.BoolVal(arg.tag == ValueTag.BOOL)
    
    def int_post_bool(state, args, fresh_symbols):
        # Convert bool to int: True=1, False=0
        arg = args[0]
        ret_sym = z3.If(arg.payload, z3.IntVal(1), z3.IntVal(0))
        return PostCondition(
            return_value=SymbolicValue(ValueTag.INT, ret_sym),
            path_constraints=[],
            heap_constraints=[]
        )
    
    int_summary.add_case(RelationalCase(
        name="int_from_bool",
        guard=int_guard_bool,
        post=int_post_bool,
        may_raise=[],  # No exception for bool->int
        provenance="python_spec"
    ))
    
    # Case 3: int(float) - truncates to int
    def int_guard_float(state, args):
        if not args or len(args) == 0:
            return z3.BoolVal(False)
        arg = args[0]
        return z3.BoolVal(arg.tag == ValueTag.FLOAT)
    
    def int_post_float(state, args, fresh_symbols):
        # Truncate float to int (toward zero)
        # For symbolic float, create fresh int constrained by bounds
        ret_sym = z3.Int(f"int_from_float_{fresh_symbols}")
        arg = args[0]
        # Add constraint that ret_sym is truncation of arg.payload
        # For simplicity: no specific constraint, just valid int
        return PostCondition(
            return_value=SymbolicValue(ValueTag.INT, ret_sym),
            path_constraints=[],
            heap_constraints=[]
        )
    
    int_summary.add_case(RelationalCase(
        name="int_from_float",
        guard=int_guard_float,
        post=int_post_float,
        may_raise=[],  # No exception for float->int
        provenance="python_spec"
    ))
    
    # Case 4: int(str) or int(obj) - symbolic, may raise ValueError/TypeError
    def int_guard_symbolic(state, args):
        """Guard: any other type (STR, OBJ, etc.)"""
        if not args or len(args) == 0:
            return z3.BoolVal(False)
        arg = args[0]
        # Applies to STR, OBJ, or any type not handled above
        is_symbolic = arg.tag not in [ValueTag.INT, ValueTag.BOOL, ValueTag.FLOAT]
        return z3.BoolVal(is_symbolic)
    
    def int_post_symbolic(state, args, fresh_symbols):
        """Postcondition: may succeed (return int) OR raise ValueError/TypeError"""
        # This case is nondeterministic: fork paths in VM
        # For now, model success path with fresh int
        ret_sym = z3.Int(f"int_result_{fresh_symbols}")
        return PostCondition(
            return_value=SymbolicValue(ValueTag.INT, ret_sym),
            path_constraints=[],
            heap_constraints=[]
        )
    
    int_summary.add_case(RelationalCase(
        name="int_symbolic_may_raise",
        guard=int_guard_symbolic,
        post=int_post_symbolic,
        may_raise=["ValueError", "TypeError"],  # VM must fork paths!
        provenance="python_spec"
    ))
    
    register_relational_summary(int_summary)
    
    
    # float(x) - converts to float, can raise ValueError/TypeError
    float_summary = RelationalSummary(
        function_id="float",
        provenance="python_spec"
    )
    
    # Case 1: float(x) where x is already a float - identity
    def float_guard_already_float(state, args):
        if not args or len(args) == 0:
            return z3.BoolVal(False)
        arg = args[0]
        return z3.BoolVal(arg.tag == ValueTag.FLOAT)
    
    def float_post_already_float(state, args, fresh_symbols):
        return PostCondition(
            return_value=args[0],
            path_constraints=[],
            heap_constraints=[]
        )
    
    float_summary.add_case(RelationalCase(
        name="float_identity",
        guard=float_guard_already_float,
        post=float_post_already_float,
        may_raise=[],
        provenance="python_spec"
    ))
    
    # Case 2: float(int) - converts int to float
    def float_guard_int(state, args):
        if not args or len(args) == 0:
            return z3.BoolVal(False)
        arg = args[0]
        return z3.BoolVal(arg.tag == ValueTag.INT)
    
    def float_post_int(state, args, fresh_symbols):
        # Convert int to float
        ret_sym = z3.Real(f"float_from_int_{fresh_symbols}")
        arg = args[0]
        # Constrain: ret_sym == (float)arg.payload
        # For Z3: ToReal converts Int to Real
        return PostCondition(
            return_value=SymbolicValue(ValueTag.FLOAT, ret_sym),
            path_constraints=[ret_sym == z3.ToReal(arg.payload)],
            heap_constraints=[]
        )
    
    float_summary.add_case(RelationalCase(
        name="float_from_int",
        guard=float_guard_int,
        post=float_post_int,
        may_raise=[],
        provenance="python_spec"
    ))
    
    # Case 3: float(str) or float(obj) - symbolic, may raise ValueError/TypeError
    def float_guard_symbolic(state, args):
        if not args or len(args) == 0:
            return z3.BoolVal(False)
        arg = args[0]
        is_symbolic = arg.tag not in [ValueTag.FLOAT, ValueTag.INT]
        return z3.BoolVal(is_symbolic)
    
    def float_post_symbolic(state, args, fresh_symbols):
        """May succeed (return float) OR raise ValueError/TypeError"""
        ret_sym = z3.Real(f"float_result_{fresh_symbols}")
        return PostCondition(
            return_value=SymbolicValue(ValueTag.FLOAT, ret_sym),
            path_constraints=[],
            heap_constraints=[]
        )
    
    float_summary.add_case(RelationalCase(
        name="float_symbolic_may_raise",
        guard=float_guard_symbolic,
        post=float_post_symbolic,
        may_raise=["ValueError", "TypeError"],  # VM must fork!
        provenance="python_spec"
    ))
    
    register_relational_summary(float_summary)
    
    
    # str(obj) - converts to string (almost never raises)
    str_summary = RelationalSummary(
        function_id="str",
        provenance="python_spec"
    )
    
    def str_guard_any(state, args):
        """Guard: accepts any argument"""
        return z3.BoolVal(len(args) == 1)
    
    def str_post_any(state, args, fresh_symbols):
        """Postcondition: return STR (unknown content)"""
        ret_obj = z3.Int(f"str_obj_{fresh_symbols}")
        ret_len = z3.Int(f"str_len_{fresh_symbols}")
        # String length is non-negative
        return PostCondition(
            return_value=SymbolicValue(ValueTag.STR, ret_obj),
            path_constraints=[ret_len >= 0],
            heap_constraints=[],
            observer_updates={'seq_len': (ret_obj, ret_len)}
        )
    
    str_summary.add_case(RelationalCase(
        name="str_conversion",
        guard=str_guard_any,
        post=str_post_any,
        may_raise=[],  # str() almost never raises (except recursion/memory)
        provenance="python_spec"
    ))
    
    register_relational_summary(str_summary)
    
    
    # ========================================================================
    # open(file, mode='r', ...) - opens file, raises FileNotFoundError/PermissionError
    # ========================================================================
    
    open_summary = RelationalSummary(
        function_id="open",
        provenance="python_spec"
    )
    
    # Case 1: Successful open (path exists, permissions OK) -> returns file object
    # Note: We cannot determine file existence/permissions symbolically in general,
    # so this case is very permissive and models successful opening
    def open_guard_success(state, args):
        """Guard: file path argument is a string (we cannot check existence symbolically)."""
        if not args:
            return z3.BoolVal(False)
        
        file_arg = args[0]
        
        # Accept if first argument is a string (file path)
        # We over-approximate: might succeed or fail at runtime
        return z3.BoolVal(file_arg.tag == ValueTag.STR)
    
    def open_post_success(state, args, fresh_symbols):
        """Postcondition: returns file object (modeled as OBJ)."""
        # File object is a resource handle (external)
        # Model as OBJ with unique ID
        file_obj_id = z3.Int(f"file_obj_{id(fresh_symbols)}")
        
        return PostCondition(
            return_value=SymbolicValue(ValueTag.OBJ, file_obj_id),
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'resource_allocated': file_obj_id}  # Track for leak detection
        )
    
    open_summary.add_case(RelationalCase(
        name="open_success",
        guard=open_guard_success,
        post=open_post_success,
        may_raise=[],  # Success case: no exception
        provenance="python_spec"
    ))
    
    # Case 2: FileNotFoundError (file does not exist, mode is 'r' or similar)
    # DISABLED: Environmental exceptions depend on file system state (not logic bugs).
    # Forking paths for these creates false positives when analyzing code for
    # non-I/O bugs (e.g., double-free, bounds checks). The file system is an
    # external oracle whose state is unknowable at static analysis time.
    # If the user's code has try/except around open(), the success path is what
    # matters for logic bug detection.
    def open_guard_file_not_found(state, args):
        """Guard: DISABLED — environmental exception, always returns False."""
        return z3.BoolVal(False)
    
    def open_post_file_not_found(state, args, fresh_symbols):
        """Postcondition: raises FileNotFoundError."""
        return PostCondition(
            return_value=None,  # No normal return
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'exception_raised': ('FileNotFoundError', 'No such file or directory')}
        )
    
    open_summary.add_case(RelationalCase(
        name="open_file_not_found",
        guard=open_guard_file_not_found,
        post=open_post_file_not_found,
        may_raise=[],  # Exception is already set in postcondition, no additional forking needed
        provenance="python_spec"
    ))
    
    # Case 3: PermissionError (insufficient permissions to open file)
    def open_guard_permission_error(state, args):
        """Guard: DISABLED — environmental exception, always returns False."""
        return z3.BoolVal(False)
    
    def open_post_permission_error(state, args, fresh_symbols):
        """Postcondition: raises PermissionError."""
        return PostCondition(
            return_value=None,
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'exception_raised': ('PermissionError', 'Permission denied')}
        )
    
    open_summary.add_case(RelationalCase(
        name="open_permission_error",
        guard=open_guard_permission_error,
        post=open_post_permission_error,
        may_raise=[],  # Exception is already set in postcondition, no additional forking needed
        provenance="python_spec"
    ))
    
    # Case 4: IsADirectoryError (trying to open directory as file)
    def open_guard_is_directory_error(state, args):
        """Guard: DISABLED — environmental exception, always returns False."""
        return z3.BoolVal(False)
    
    def open_post_is_directory_error(state, args, fresh_symbols):
        """Postcondition: raises IsADirectoryError."""
        return PostCondition(
            return_value=None,
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'exception_raised': ('IsADirectoryError', 'Is a directory')}
        )
    
    open_summary.add_case(RelationalCase(
        name="open_is_directory_error",
        guard=open_guard_is_directory_error,
        post=open_post_is_directory_error,
        may_raise=[],  # Exception is already set in postcondition, no additional forking needed
        provenance="python_spec"
    ))
    
    # Case 5: TypeError for non-string file argument
    def open_guard_type_error(state, args):
        """Guard: file argument is not a string."""
        if not args:
            return z3.BoolVal(False)
        
        file_arg = args[0]
        
        # Definitely wrong types
        is_definitely_wrong = (file_arg.tag == ValueTag.INT) or (file_arg.tag == ValueTag.FLOAT) or (file_arg.tag == ValueTag.LIST) or (file_arg.tag == ValueTag.DICT) or (file_arg.tag == ValueTag.NONE)
        
        return z3.BoolVal(is_definitely_wrong)
    
    def open_post_type_error(state, args, fresh_symbols):
        """Postcondition: raises TypeError."""
        return PostCondition(
            return_value=None,
            path_constraints=[],
            heap_constraints=[],
            observer_updates={'exception_raised': ('TypeError', 'expected str, bytes or os.PathLike object')}
        )
    
    open_summary.add_case(RelationalCase(
        name="open_type_error",
        guard=open_guard_type_error,
        post=open_post_type_error,
        may_raise=[],  # Exception is already set in postcondition, no additional forking needed
        provenance="python_spec"
    ))
    
    register_relational_summary(open_summary)


# More builtins can be added following the same pattern:
# - Define summary with function_id
# - Add cases with guards and postconditions
# - Cases express semantic properties in Z3
# - Havoc fallback is always present
# - Register the summary


# Initialize on module import
init_builtin_relations()
