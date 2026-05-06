"""
Tagged value representation for symbolic execution with Z3.

Values are tagged unions to make type confusion definable and to distinguish
identity from value. This follows the barrier-certificate requirement that
all unsafe predicates must be definable against the symbolic state.
"""

from enum import IntEnum
from typing import Union
import z3


class ValueTag(IntEnum):
    """Value type tags for Python runtime values."""
    NONE = 0
    BOOL = 1
    INT = 2
    FLOAT = 3
    STR = 4
    OBJ = 5
    LIST = 6
    TUPLE = 7
    DICT = 8
    ELLIPSIS = 9
    SLICE = 10


class SymbolicValue:
    """
    A symbolic value in the Z3 model.
    
    Represents a tagged value: (tag, payload, taint).
    - tag: ValueTag discriminator
    - payload: Z3 expression (IntSort, RealSort, or ObjId)
    - taint: set of taint labels for INFO_LEAK tracking
    """
    
    def __init__(self, tag: Union[ValueTag, z3.ExprRef], payload: z3.ExprRef, taint: set = None):
        if isinstance(tag, ValueTag):
            self.tag = z3.IntVal(tag.value)
        else:
            self.tag = tag
        self.payload = payload
        self.taint = taint if taint is not None else set()
    
    @staticmethod
    def none() -> 'SymbolicValue':
        """Symbolic None value."""
        return SymbolicValue(ValueTag.NONE, z3.IntVal(0))
    
    @staticmethod
    def bool(val: Union[bool, z3.ExprRef]) -> 'SymbolicValue':
        """Symbolic bool value."""
        if isinstance(val, bool):
            return SymbolicValue(ValueTag.BOOL, z3.IntVal(1 if val else 0))
        return SymbolicValue(ValueTag.BOOL, z3.If(val, z3.IntVal(1), z3.IntVal(0)))
    
    @staticmethod
    def int(val: Union[int, z3.ExprRef]) -> 'SymbolicValue':
        """Symbolic int value (unbounded mathematical integer)."""
        if isinstance(val, int):
            return SymbolicValue(ValueTag.INT, z3.IntVal(val))
        return SymbolicValue(ValueTag.INT, val)
    
    @staticmethod
    def float(val: Union[float, z3.ExprRef]) -> 'SymbolicValue':
        """Symbolic float value."""
        if isinstance(val, float):
            return SymbolicValue(ValueTag.FLOAT, z3.RealVal(val))
        return SymbolicValue(ValueTag.FLOAT, val)
    
    @staticmethod
    def str(obj_id: Union[int, z3.ExprRef]) -> 'SymbolicValue':
        """Symbolic string reference (by ObjId)."""
        if isinstance(obj_id, int):
            return SymbolicValue(ValueTag.STR, z3.IntVal(obj_id))
        return SymbolicValue(ValueTag.STR, obj_id)
    
    @staticmethod
    def obj(obj_id: Union[int, z3.ExprRef]) -> 'SymbolicValue':
        """Symbolic object reference (by identity/ObjId)."""
        if isinstance(obj_id, int):
            return SymbolicValue(ValueTag.OBJ, z3.IntVal(obj_id))
        return SymbolicValue(ValueTag.OBJ, obj_id)
    
    @staticmethod
    def list(obj_id: Union[int, z3.ExprRef]) -> 'SymbolicValue':
        """Symbolic list reference (by ObjId)."""
        if isinstance(obj_id, int):
            return SymbolicValue(ValueTag.LIST, z3.IntVal(obj_id))
        return SymbolicValue(ValueTag.LIST, obj_id)
    
    @staticmethod
    def tuple(obj_id: Union[int, z3.ExprRef]) -> 'SymbolicValue':
        """Symbolic tuple reference (by ObjId)."""
        if isinstance(obj_id, int):
            return SymbolicValue(ValueTag.TUPLE, z3.IntVal(obj_id))
        return SymbolicValue(ValueTag.TUPLE, obj_id)
    
    @staticmethod
    def dict(obj_id: Union[int, z3.ExprRef]) -> 'SymbolicValue':
        """Symbolic dict reference (by ObjId)."""
        if isinstance(obj_id, int):
            return SymbolicValue(ValueTag.DICT, z3.IntVal(obj_id))
        return SymbolicValue(ValueTag.DICT, obj_id)
    
    @staticmethod
    def ellipsis() -> 'SymbolicValue':
        """Symbolic ellipsis (... object)."""
        return SymbolicValue(ValueTag.ELLIPSIS, z3.IntVal(0))
    
    @staticmethod
    def slice_obj(obj_id: Union[int, z3.ExprRef]) -> 'SymbolicValue':
        """Symbolic slice object reference (by ObjId)."""
        if isinstance(obj_id, int):
            return SymbolicValue(ValueTag.SLICE, z3.IntVal(obj_id))
        return SymbolicValue(ValueTag.SLICE, obj_id)
    
    @staticmethod
    def fresh_int(name: str, solver: z3.Solver = None) -> 'SymbolicValue':
        """Create a fresh symbolic integer."""
        sym = z3.Int(name)
        if solver:
            solver.add(True)  # No constraints by default (havoc)
        return SymbolicValue.int(sym)
    
    @staticmethod
    def fresh_bool(name: str, solver: z3.Solver = None) -> 'SymbolicValue':
        """Create a fresh symbolic bool."""
        sym = z3.Bool(name)
        if solver:
            solver.add(True)
        return SymbolicValue.bool(sym)
    
    @staticmethod
    def fresh_obj(name: str, solver: z3.Solver = None) -> 'SymbolicValue':
        """Create a fresh symbolic object (generic object reference)."""
        obj_id = z3.Int(name)
        if solver:
            solver.add(True)  # No constraints by default (havoc)
        return SymbolicValue.obj(obj_id)
    
    def is_none(self) -> z3.ExprRef:
        """Check if this value is None."""
        return self.tag == z3.IntVal(ValueTag.NONE.value)
    
    def is_bool(self) -> z3.ExprRef:
        """Check if this value is a bool."""
        return self.tag == z3.IntVal(ValueTag.BOOL.value)
    
    def is_int(self) -> z3.ExprRef:
        """Check if this value is an int."""
        return self.tag == z3.IntVal(ValueTag.INT.value)
    
    def is_float(self) -> z3.ExprRef:
        """Check if this value is a float."""
        return self.tag == z3.IntVal(ValueTag.FLOAT.value)
    
    def is_obj(self) -> z3.ExprRef:
        """Check if this value is an object reference."""
        return self.tag == z3.IntVal(ValueTag.OBJ.value)
    
    def is_list(self) -> z3.ExprRef:
        """Check if this value is a list."""
        return self.tag == z3.IntVal(ValueTag.LIST.value)
    
    def is_tuple(self) -> z3.ExprRef:
        """Check if this value is a tuple."""
        return self.tag == z3.IntVal(ValueTag.TUPLE.value)
    
    def is_dict(self) -> z3.ExprRef:
        """Check if this value is a dict."""
        return self.tag == z3.IntVal(ValueTag.DICT.value)
    
    def is_str(self) -> z3.ExprRef:
        """Check if this value is a string."""
        return self.tag == z3.IntVal(ValueTag.STR.value)
    
    def as_int(self) -> z3.ExprRef:
        """Extract int payload (assumes is_int holds)."""
        return self.payload
    
    def as_bool(self) -> z3.ExprRef:
        """Extract bool payload (assumes is_bool holds)."""
        return self.payload != z3.IntVal(0)
    
    def as_float(self) -> z3.ExprRef:
        """Extract float payload (assumes is_float holds)."""
        return self.payload
    
    def as_obj_id(self) -> z3.ExprRef:
        """Extract object ID (assumes is_obj holds)."""
        return self.payload
    
    def __repr__(self):
        return f"SymbolicValue(tag={self.tag}, payload={self.payload})"


def binary_op_add(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple:
    """
    Symbolic addition.
    
    Handles:
    - int + int -> int
    - int + float -> float
    - float + int -> float
    - float + float -> float
    - str + str -> str (concatenation)
    - list + list -> list (concatenation)
    - OBJ + anything or anything + OBJ -> OBJ (unknown result)
    Other combinations raise TypeError (exception path).
    Returns (result, type_ok, none_misuse).
    """
    # Check for None misuse
    none_misuse = z3.Or(left.is_none(), right.is_none())
    
    # Type check: valid combinations
    both_ints = z3.And(left.is_int(), right.is_int())
    both_floats = z3.And(left.is_float(), right.is_float())
    int_float = z3.And(left.is_int(), right.is_float())
    float_int = z3.And(left.is_float(), right.is_int())
    both_strs = z3.And(left.is_str(), right.is_str())
    both_lists = z3.And(left.is_list(), right.is_list())
    # ITERATION 489: OBJ type represents unknown/tainted values that may be any type
    # Allow OBJ + anything or anything + OBJ (sound over-approximation)
    has_obj = z3.Or(left.is_obj(), right.is_obj())
    
    type_ok = z3.And(
        z3.Or(both_ints, both_floats, int_float, float_int, both_strs, both_lists, has_obj),
        z3.Not(none_misuse)
    )
    
    # Result computation for numeric types
    result_int = left.as_int() + right.as_int()
    # For float operations, convert int to float if needed using Z3 sort checking
    left_val = left.payload
    right_val = right.payload
    
    if z3.is_int(left_val):
        left_as_float = z3.ToReal(left_val)
    else:
        left_as_float = left_val
    
    if z3.is_int(right_val):
        right_as_float = z3.ToReal(right_val)
    else:
        right_as_float = right_val
    
    result_float = left_as_float + right_as_float
    
    # For string and list concatenation, allocate fresh object IDs
    result_str = z3.FreshInt("str_concat")  # Fresh ID for concatenated string
    result_list = z3.FreshInt("list_concat")  # Fresh ID for concatenated list
    result_obj = z3.FreshInt("obj_result")  # Fresh ID for OBJ result
    
    # Choose result based on actual types
    # Priority: OBJ (if either operand is OBJ) > list > str > float > int
    is_numeric_float = z3.Or(both_floats, int_float, float_int)
    result_payload = z3.If(
        has_obj, result_obj,
        z3.If(both_lists, result_list,
              z3.If(both_strs, result_str,
                    z3.If(is_numeric_float, result_float, result_int))))
    
    result_tag = z3.If(
        has_obj, z3.IntVal(ValueTag.OBJ.value),
        z3.If(both_lists, z3.IntVal(ValueTag.LIST.value),
              z3.If(both_strs, z3.IntVal(ValueTag.STR.value),
                    z3.If(is_numeric_float, z3.IntVal(ValueTag.FLOAT.value),
                          z3.IntVal(ValueTag.INT.value)))))
    
    result = SymbolicValue(result_tag, result_payload)
    return result, type_ok, none_misuse


def binary_op_sub(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple:
    """
    Symbolic subtraction.
    
    Handles:
    - int - int -> int
    - int - float -> float
    - float - int -> float
    - float - float -> float
    - OBJ - anything or anything - OBJ -> OBJ (unknown result)
    Returns (result, type_ok, none_misuse).
    """
    none_misuse = z3.Or(left.is_none(), right.is_none())
    
    both_ints = z3.And(left.is_int(), right.is_int())
    both_floats = z3.And(left.is_float(), right.is_float())
    int_float = z3.And(left.is_int(), right.is_float())
    float_int = z3.And(left.is_float(), right.is_int())
    has_obj = z3.Or(left.is_obj(), right.is_obj())
    
    type_ok = z3.And(
        z3.Or(both_ints, both_floats, int_float, float_int, has_obj),
        z3.Not(none_misuse)
    )
    
    result_int = left.as_int() - right.as_int()
    
    # Convert to float using Z3 sort checking
    left_val = left.payload
    right_val = right.payload
    
    if z3.is_int(left_val):
        left_as_float = z3.ToReal(left_val)
    else:
        left_as_float = left_val
    
    if z3.is_int(right_val):
        right_as_float = z3.ToReal(right_val)
    else:
        right_as_float = right_val
    
    result_float = left_as_float - right_as_float
    result_obj = z3.FreshInt("obj_result")
    
    is_numeric_float = z3.Or(both_floats, int_float, float_int)
    result_payload = z3.If(has_obj, result_obj,
                           z3.If(is_numeric_float, result_float, result_int))
    result_tag = z3.If(has_obj, z3.IntVal(ValueTag.OBJ.value),
                       z3.If(is_numeric_float, z3.IntVal(ValueTag.FLOAT.value), z3.IntVal(ValueTag.INT.value)))
    
    result = SymbolicValue(result_tag, result_payload)
    return result, type_ok, none_misuse


def binary_op_mul(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple:
    """
    Symbolic multiplication.
    
    Handles:
    - int * int -> int
    - int * float -> float
    - float * int -> float
    - float * float -> float
    - str * int -> str (repetition)
    - int * str -> str (repetition)
    - list * int -> list (repetition)
    - int * list -> list (repetition)
    - OBJ * anything or anything * OBJ -> OBJ (unknown result)
    Other combinations raise TypeError (exception path).
    Returns (result, type_ok, none_misuse).
    """
    none_misuse = z3.Or(left.is_none(), right.is_none())
    
    # Type check: valid combinations
    both_ints = z3.And(left.is_int(), right.is_int())
    both_floats = z3.And(left.is_float(), right.is_float())
    int_float = z3.And(left.is_int(), right.is_float())
    float_int = z3.And(left.is_float(), right.is_int())
    str_int = z3.And(left.is_str(), right.is_int())
    int_str = z3.And(left.is_int(), right.is_str())
    list_int = z3.And(left.is_list(), right.is_int())
    int_list = z3.And(left.is_int(), right.is_list())
    has_obj = z3.Or(left.is_obj(), right.is_obj())
    
    type_ok = z3.And(
        z3.Or(both_ints, both_floats, int_float, float_int,
              str_int, int_str, list_int, int_list, has_obj),
        z3.Not(none_misuse)
    )
    
    # Result computation
    result_int = left.as_int() * right.as_int()
    
    # For float operations, convert int to float if needed using Z3 sort checking
    left_val = left.payload
    right_val = right.payload
    
    if z3.is_int(left_val):
        left_as_float = z3.ToReal(left_val)
    else:
        left_as_float = left_val
    
    if z3.is_int(right_val):
        right_as_float = z3.ToReal(right_val)
    else:
        right_as_float = right_val
    
    result_float = left_as_float * right_as_float
    
    # For string/list repetition, allocate fresh object IDs
    result_str = z3.FreshInt("str_repeat")  # Fresh ID for repeated string
    result_list = z3.FreshInt("list_repeat")  # Fresh ID for repeated list
    result_obj = z3.FreshInt("obj_result")  # Fresh ID for OBJ result
    
    # Choose result based on actual types
    is_str_repeat = z3.Or(str_int, int_str)
    is_list_repeat = z3.Or(list_int, int_list)
    is_numeric_float = z3.Or(both_floats, int_float, float_int)
    
    result_payload = z3.If(
        has_obj, result_obj,
        z3.If(is_list_repeat, result_list,
              z3.If(is_str_repeat, result_str,
                    z3.If(is_numeric_float, result_float, result_int))))
    
    result_tag = z3.If(
        has_obj, z3.IntVal(ValueTag.OBJ.value),
        z3.If(is_list_repeat, z3.IntVal(ValueTag.LIST.value),
              z3.If(is_str_repeat, z3.IntVal(ValueTag.STR.value),
                    z3.If(is_numeric_float, z3.IntVal(ValueTag.FLOAT.value),
                          z3.IntVal(ValueTag.INT.value)))))
    
    result = SymbolicValue(result_tag, result_payload)
    return result, type_ok, none_misuse


def binary_op_truediv(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef, z3.ExprRef]:
    """
    Symbolic true division.
    
    Handles:
    - int / int -> float
    - int / float -> float
    - float / int -> float
    - float / float -> float
    
    Returns (result, type_ok, div_zero_check, none_misuse).
    Division by zero is an unsafe condition (DIV_ZERO bug class).
    None misuse is an unsafe condition (NULL_PTR bug class).
    """
    none_misuse = z3.Or(left.is_none(), right.is_none())
    
    both_ints = z3.And(left.is_int(), right.is_int())
    both_floats = z3.And(left.is_float(), right.is_float())
    int_float = z3.And(left.is_int(), right.is_float())
    float_int = z3.And(left.is_float(), right.is_int())
    
    type_ok = z3.And(
        z3.Or(both_ints, both_floats, int_float, float_int),
        z3.Not(none_misuse)
    )
    
    # Division by zero check (handle both int and float divisors)
    div_zero = z3.Or(
        z3.And(right.is_int(), right.as_int() == 0),
        z3.And(right.is_float(), right.as_float() == z3.RealVal(0))
    )
    
    # Convert to float and divide
    # Need to handle the case where payload is already RealSort (float) vs IntSort (int)
    # For Z3, we can't call ToReal on a RealSort value
    left_val = left.payload
    right_val = right.payload
    
    # Check Z3 sort and convert only if needed
    if z3.is_int(left_val):
        left_as_float = z3.ToReal(left_val)
    else:
        left_as_float = left_val
    
    if z3.is_int(right_val):
        right_as_float = z3.ToReal(right_val)
    else:
        right_as_float = right_val
    
    result_float = left_as_float / right_as_float
    
    result = SymbolicValue(ValueTag.FLOAT, result_float)
    return result, type_ok, div_zero, none_misuse


def binary_op_floordiv(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef, z3.ExprRef]:
    """
    Symbolic floor division.
    
    Handles:
    - int // int -> int
    - int // float -> float
    - float // int -> float
    - float // float -> float
    
    Returns (result, type_ok, div_zero_check, none_misuse).
    """
    none_misuse = z3.Or(left.is_none(), right.is_none())
    
    both_ints = z3.And(left.is_int(), right.is_int())
    both_floats = z3.And(left.is_float(), right.is_float())
    int_float = z3.And(left.is_int(), right.is_float())
    float_int = z3.And(left.is_float(), right.is_int())
    
    type_ok = z3.And(
        z3.Or(both_ints, both_floats, int_float, float_int),
        z3.Not(none_misuse)
    )
    
    # Division by zero check
    div_zero = z3.Or(
        z3.And(right.is_int(), right.as_int() == 0),
        z3.And(right.is_float(), right.as_float() == z3.RealVal(0))
    )
    
    # For int // int, use Python floor division.
    # Z3's integer `/` is Euclidean division (remainder always non-negative),
    # which differs from Python's floor division when the divisor is negative.
    # Python: 7 // -2 = -4, but Z3: 7 / -2 = -3
    # Fix: adjust when divisor is negative and there's a nonzero remainder.
    # Guard: Z3's `%` requires IntSort, so only build this path for int payloads.
    if z3.is_int(left.payload) and z3.is_int(right.payload):
        euclid_div = left.as_int() / right.as_int()
        euclid_mod = left.as_int() % right.as_int()
        result_int = z3.If(
            z3.And(right.as_int() < 0, euclid_mod != 0),
            euclid_div - 1,
            euclid_div
        )
    else:
        # Float inputs: int path unused; dummy with correct sort for z3.If
        result_int = z3.IntVal(0)
    
    # Convert to float using Z3 sort checking
    left_val = left.payload
    right_val = right.payload
    
    if z3.is_int(left_val):
        left_as_float = z3.ToReal(left_val)
    else:
        left_as_float = left_val
    
    if z3.is_int(right_val):
        right_as_float = z3.ToReal(right_val)
    else:
        right_as_float = right_val
    
    # For float floor division, compute floor of the real quotient.
    # z3.ToInt is floor for reals, then convert back to Real for float result.
    result_float = z3.ToReal(z3.ToInt(left_as_float / right_as_float))
    
    is_numeric_float = z3.Or(both_floats, int_float, float_int)
    result_payload = z3.If(is_numeric_float, result_float, result_int)
    result_tag = z3.If(is_numeric_float, z3.IntVal(ValueTag.FLOAT.value), z3.IntVal(ValueTag.INT.value))
    
    result = SymbolicValue(result_tag, result_payload)
    return result, type_ok, div_zero, none_misuse


def binary_op_mod(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef, z3.ExprRef]:
    """
    Symbolic modulo.
    
    Handles:
    - int % int -> int
    - int % float -> float
    - float % int -> float
    - float % float -> float
    
    Returns (result, type_ok, div_zero_check, none_misuse).
    """
    none_misuse = z3.Or(left.is_none(), right.is_none())
    
    both_ints = z3.And(left.is_int(), right.is_int())
    both_floats = z3.And(left.is_float(), right.is_float())
    int_float = z3.And(left.is_int(), right.is_float())
    float_int = z3.And(left.is_float(), right.is_int())
    
    type_ok = z3.And(
        z3.Or(both_ints, both_floats, int_float, float_int),
        z3.Not(none_misuse)
    )
    
    # Division by zero check
    div_zero = z3.Or(
        z3.And(right.is_int(), right.as_int() == 0),
        z3.And(right.is_float(), right.as_float() == z3.RealVal(0))
    )
    
    # For int % int, use Python floor modulo.
    # Z3's integer `%` is Euclidean mod (always non-negative),
    # which differs from Python's floor mod when the divisor is negative.
    # Python: 7 % -2 = -1, but Z3: 7 % -2 = 1
    # Fix: adjust when divisor is negative and there's a nonzero remainder.
    # Guard: Z3's `%` requires IntSort, so only build this path for int payloads.
    if z3.is_int(left.payload) and z3.is_int(right.payload):
        euclid_mod = left.as_int() % right.as_int()
        result_int = z3.If(
            z3.And(right.as_int() < 0, euclid_mod != 0),
            euclid_mod + right.as_int(),
            euclid_mod
        )
    else:
        # Float inputs: int path unused; dummy with correct sort for z3.If
        result_int = z3.IntVal(0)
    
    # For float modulo, we approximate (Z3 doesn't have built-in real modulo)
    # Convert to float using Z3 sort checking
    left_val = left.payload
    right_val = right.payload
    
    if z3.is_int(left_val):
        left_as_float = z3.ToReal(left_val)
    else:
        left_as_float = left_val
    
    if z3.is_int(right_val):
        right_as_float = z3.ToReal(right_val)
    else:
        right_as_float = right_val
    
    # Approximate: use integer conversion (unsound but better than nothing)
    result_float = left_as_float - right_as_float * z3.ToReal(z3.ToInt(left_as_float / right_as_float))
    
    is_numeric_float = z3.Or(both_floats, int_float, float_int)
    result_payload = z3.If(is_numeric_float, result_float, result_int)
    result_tag = z3.If(is_numeric_float, z3.IntVal(ValueTag.FLOAT.value), z3.IntVal(ValueTag.INT.value))
    
    result = SymbolicValue(result_tag, result_payload)
    return result, type_ok, div_zero, none_misuse


def binary_op_pow(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef, z3.ExprRef]:
    """
    Symbolic power operation (exponentiation).
    
    Handles:
    - int ** int -> int (non-negative exp) or float (negative exp)
    - int ** float -> float
    - float ** int -> float
    - float ** float -> float
    
    Returns (result, type_ok, fp_domain_error, none_misuse).
    
    FP_DOMAIN errors:
    - 0 ** negative_exponent
    - negative_base ** fractional_exponent
    """
    none_misuse = z3.Or(left.is_none(), right.is_none())
    
    both_ints = z3.And(left.is_int(), right.is_int())
    both_floats = z3.And(left.is_float(), right.is_float())
    int_float = z3.And(left.is_int(), right.is_float())
    float_int = z3.And(left.is_float(), right.is_int())
    
    type_ok = z3.And(
        z3.Or(both_ints, both_floats, int_float, float_int),
        z3.Not(none_misuse)
    )
    
    # FP_DOMAIN error checks:
    # 1. 0 ** negative exponent
    left_is_zero = z3.Or(
        z3.And(left.is_int(), left.as_int() == 0),
        z3.And(left.is_float(), left.as_float() == z3.RealVal(0))
    )
    exp_is_negative = z3.Or(
        z3.And(right.is_int(), right.as_int() < 0),
        z3.And(right.is_float(), right.as_float() < z3.RealVal(0))
    )
    zero_to_negative = z3.And(left_is_zero, exp_is_negative)
    
    # 2. Negative base with float exponent (could be fractional)
    base_is_negative = z3.Or(
        z3.And(left.is_int(), left.as_int() < 0),
        z3.And(left.is_float(), left.as_float() < z3.RealVal(0))
    )
    negative_base_float_exp = z3.And(base_is_negative, right.is_float())
    
    fp_domain_error = z3.Or(zero_to_negative, negative_base_float_exp)
    
    # Result computation (approximate - Z3 has limited power support)
    # For int ** int with non-negative exp, result is INT
    # For anything involving float or negative exp, result is FLOAT
    # Z3 doesn't have built-in power for arbitrary expressions, so we use a symbolic approximation
    
    int_to_nonneg_int = z3.And(both_ints, right.as_int() >= 0)
    
    # For symbolic execution, we represent the result symbolically
    # Create a fresh result value (over-approximation)
    # In practice, bounded symbolic execution will concretize simple cases
    result_int_val = z3.Int(f'pow_result_{id(left)}_{id(right)}')
    result_float_val = z3.Real(f'pow_result_{id(left)}_{id(right)}_f')
    
    # Add constraints for bounded cases (small concrete exponents)
    # For now, leave unconstrained (sound over-approximation)
    
    result_payload = z3.If(int_to_nonneg_int, result_int_val, result_float_val)
    result_tag = z3.If(int_to_nonneg_int, z3.IntVal(ValueTag.INT.value), z3.IntVal(ValueTag.FLOAT.value))
    
    result = SymbolicValue(result_tag, result_payload)
    return result, type_ok, fp_domain_error, none_misuse


def binary_op_lshift(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef, z3.ExprRef]:
    """
    Symbolic left shift (<<).
    
    Only valid for int << int. Raises ValueError if shift amount is negative.
    Returns (result, type_ok, domain_error, none_misuse).
    """
    none_misuse = z3.Or(left.is_none(), right.is_none())
    both_ints = z3.And(left.is_int(), right.is_int())
    
    # Python raises ValueError for negative shift count
    # right < 0 is a domain error
    negative_shift = z3.And(
        both_ints,
        right.payload < 0
    )
    
    type_ok = z3.And(both_ints, z3.Not(none_misuse))
    
    # In Python: x << y is equivalent to x * 2**y (when y >= 0)
    # For symbolic execution, represent as fresh symbolic value (sound over-approximation)
    result_val = z3.Int(f'lshift_{id(left)}_{id(right)}')
    result = SymbolicValue(ValueTag.INT, result_val)
    return result, type_ok, negative_shift, none_misuse


def binary_op_rshift(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef, z3.ExprRef]:
    """
    Symbolic right shift (>>).
    
    Only valid for int >> int. Raises ValueError if shift amount is negative.
    Returns (result, type_ok, domain_error, none_misuse).
    """
    none_misuse = z3.Or(left.is_none(), right.is_none())
    both_ints = z3.And(left.is_int(), right.is_int())
    
    # Python raises ValueError for negative shift count
    # right < 0 is a domain error
    negative_shift = z3.And(
        both_ints,
        right.payload < 0
    )
    
    type_ok = z3.And(both_ints, z3.Not(none_misuse))
    
    # In Python: x >> y is equivalent to x // 2**y (when y >= 0)
    # For symbolic execution, represent as fresh symbolic value (sound over-approximation)
    result_val = z3.Int(f'rshift_{id(left)}_{id(right)}')
    result = SymbolicValue(ValueTag.INT, result_val)
    return result, type_ok, negative_shift, none_misuse


def binary_op_and(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef]:
    """
    Symbolic bitwise AND (&).
    
    Only valid for int & int.
    Returns (result, type_ok, none_misuse).
    """
    none_misuse = z3.Or(left.is_none(), right.is_none())
    both_ints = z3.And(left.is_int(), right.is_int())
    type_ok = z3.And(both_ints, z3.Not(none_misuse))
    
    # Z3 has built-in bitwise AND for bitvectors, but we use mathematical integers
    # For bounded cases we could use z3.Int2BV, but for soundness, over-approximate
    result_val = z3.Int(f'and_{id(left)}_{id(right)}')
    result = SymbolicValue(ValueTag.INT, result_val)
    return result, type_ok, none_misuse


def binary_op_or(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef]:
    """
    Symbolic bitwise OR (|).
    
    Only valid for int | int.
    Returns (result, type_ok, none_misuse).
    """
    none_misuse = z3.Or(left.is_none(), right.is_none())
    both_ints = z3.And(left.is_int(), right.is_int())
    type_ok = z3.And(both_ints, z3.Not(none_misuse))
    
    result_val = z3.Int(f'or_{id(left)}_{id(right)}')
    result = SymbolicValue(ValueTag.INT, result_val)
    return result, type_ok, none_misuse


def binary_op_xor(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef]:
    """
    Symbolic bitwise XOR (^).
    
    Only valid for int ^ int.
    Returns (result, type_ok, none_misuse).
    """
    none_misuse = z3.Or(left.is_none(), right.is_none())
    both_ints = z3.And(left.is_int(), right.is_int())
    type_ok = z3.And(both_ints, z3.Not(none_misuse))
    
    result_val = z3.Int(f'xor_{id(left)}_{id(right)}')
    result = SymbolicValue(ValueTag.INT, result_val)
    return result, type_ok, none_misuse


def compare_op_lt(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef]:
    """Symbolic less-than comparison."""
    # Accept OBJ types (conservative overapproximation for soundness)
    # OBJ might be anything, including comparable types
    # Also accept float and mixed int/float comparisons
    type_ok = z3.Or(
        z3.And(left.is_int(), right.is_int()),
        z3.And(left.is_float(), right.is_float()),
        z3.And(left.is_int(), right.is_float()),
        z3.And(left.is_float(), right.is_int()),
        left.is_obj(),
        right.is_obj()
    )
    # When OBJ involved, return nondeterministic result (sound overapproximation)
    # For float comparisons, as_float() returns payload; Z3 auto-coerces Int→Real
    any_float = z3.Or(left.is_float(), right.is_float())
    result_val = z3.If(
        z3.Or(left.is_obj(), right.is_obj()),
        z3.Int(f"cmp_lt_obj_{id(left)}_{id(right)}"),
        z3.If(
            any_float,
            z3.If(left.as_float() < right.as_float(), z3.IntVal(1), z3.IntVal(0)),
            z3.If(left.as_int() < right.as_int(), z3.IntVal(1), z3.IntVal(0))
        )
    )
    return SymbolicValue(ValueTag.BOOL, result_val), type_ok


def compare_op_le(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef]:
    """Symbolic less-than-or-equal comparison."""
    # Accept OBJ types (conservative overapproximation for soundness)
    # Also accept float and mixed int/float comparisons
    type_ok = z3.Or(
        z3.And(left.is_int(), right.is_int()),
        z3.And(left.is_float(), right.is_float()),
        z3.And(left.is_int(), right.is_float()),
        z3.And(left.is_float(), right.is_int()),
        left.is_obj(),
        right.is_obj()
    )
    # When OBJ involved, return nondeterministic result (sound overapproximation)
    any_float = z3.Or(left.is_float(), right.is_float())
    result_val = z3.If(
        z3.Or(left.is_obj(), right.is_obj()),
        z3.Int(f"cmp_le_obj_{id(left)}_{id(right)}"),
        z3.If(
            any_float,
            z3.If(left.as_float() <= right.as_float(), z3.IntVal(1), z3.IntVal(0)),
            z3.If(left.as_int() <= right.as_int(), z3.IntVal(1), z3.IntVal(0))
        )
    )
    return SymbolicValue(ValueTag.BOOL, result_val), type_ok


def compare_op_eq(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef]:
    """Symbolic equality comparison.
    
    For exact values (int, bool, none), comparison is precise.
    For symbolic references (STR, OBJ), comparison is nondeterministic
    because we don't track string contents or object state symbolically.
    This maintains soundness via over-approximation.
    """
    # Check if either operand is OBJ (unknown type)
    left_is_obj = (left.tag == z3.IntVal(ValueTag.OBJ.value))
    right_is_obj = (right.tag == z3.IntVal(ValueTag.OBJ.value))
    either_is_obj = z3.Or(left_is_obj, right_is_obj)
    
    # If either is OBJ, result is nondeterministic (might be any type at runtime)
    # This is sound over-approximation - OBJ could be STR, INT, etc.
    obj_comparison_result = z3.Int(f"obj_eq_{id(left)}_{id(right)}")
    
    # For known types, check if tags match
    tags_equal = (left.tag == right.tag)
    
    # For reference types (STR, LIST, DICT, TUPLE), make nondeterministic if payloads differ
    # For value types (INT, BOOL, NONE), keep deterministic
    is_ref_type = z3.Or(
        left.tag == z3.IntVal(ValueTag.STR.value),
        left.tag == z3.IntVal(ValueTag.LIST.value),
        left.tag == z3.IntVal(ValueTag.DICT.value),
        left.tag == z3.IntVal(ValueTag.TUPLE.value),
    )
    
    # Deterministic case: same payload (identity equality for refs)
    payloads_equal = (left.payload == right.payload)
    
    # Nondeterministic case: different payloads but might have equal content
    nondeterministic_result = z3.Int(f"str_eq_{id(left)}_{id(right)}")
    
    result = z3.If(
        either_is_obj,
        obj_comparison_result,  # OBJ involved → nondeterministic
        z3.If(
            tags_equal,
            z3.If(
                payloads_equal,
                z3.IntVal(1),  # Same identity → definitely equal
                z3.If(
                    is_ref_type,
                    nondeterministic_result,  # Different IDs but might have same content
                    z3.IntVal(0)  # Different values for value types → definitely not equal
                )
            ),
            z3.IntVal(0)  # Different tags (and no OBJ) → definitely not equal
        )
    )
    return SymbolicValue(ValueTag.BOOL, result), z3.BoolVal(True)


def compare_op_ne(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef]:
    """Symbolic not-equal comparison.
    
    For exact values (int, bool, none), comparison is precise.
    For symbolic references (STR, OBJ), comparison is nondeterministic
    because we don't track string contents or object state symbolically.
    """
    # Check if either operand is OBJ (unknown type)
    left_is_obj = (left.tag == z3.IntVal(ValueTag.OBJ.value))
    right_is_obj = (right.tag == z3.IntVal(ValueTag.OBJ.value))
    either_is_obj = z3.Or(left_is_obj, right_is_obj)
    
    # If either is OBJ, result is nondeterministic
    obj_comparison_result = z3.Int(f"obj_ne_{id(left)}_{id(right)}")
    
    # For known types, check if tags match
    tags_equal = (left.tag == right.tag)
    
    # For reference types (STR, LIST, DICT, TUPLE), make nondeterministic if payloads differ
    is_ref_type = z3.Or(
        left.tag == z3.IntVal(ValueTag.STR.value),
        left.tag == z3.IntVal(ValueTag.LIST.value),
        left.tag == z3.IntVal(ValueTag.DICT.value),
        left.tag == z3.IntVal(ValueTag.TUPLE.value),
    )
    
    payloads_equal = (left.payload == right.payload)
    
    # Nondeterministic case for reference types
    nondeterministic_result = z3.Int(f"str_ne_{id(left)}_{id(right)}")
    
    result = z3.If(
        either_is_obj,
        obj_comparison_result,  # OBJ involved → nondeterministic
        z3.If(
            tags_equal,
            z3.If(
                payloads_equal,
                z3.IntVal(0),  # Same identity → definitely equal, so not-equal is False
                z3.If(
                    is_ref_type,
                    nondeterministic_result,  # Different IDs but might have same content
                    z3.IntVal(1)  # Different values for value types → definitely not equal
                )
            ),
            z3.IntVal(1)  # Different tags (and no OBJ) → definitely not equal
        )
    )
    return SymbolicValue(ValueTag.BOOL, result), z3.BoolVal(True)


def compare_op_gt(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef]:
    """Symbolic greater-than comparison."""
    # Accept OBJ types (conservative overapproximation for soundness)
    # Also accept float and mixed int/float comparisons
    type_ok = z3.Or(
        z3.And(left.is_int(), right.is_int()),
        z3.And(left.is_float(), right.is_float()),
        z3.And(left.is_int(), right.is_float()),
        z3.And(left.is_float(), right.is_int()),
        left.is_obj(),
        right.is_obj()
    )
    # When OBJ involved, return nondeterministic result (sound overapproximation)
    any_float = z3.Or(left.is_float(), right.is_float())
    result_val = z3.If(
        z3.Or(left.is_obj(), right.is_obj()),
        z3.Int(f"cmp_gt_obj_{id(left)}_{id(right)}"),
        z3.If(
            any_float,
            z3.If(left.as_float() > right.as_float(), z3.IntVal(1), z3.IntVal(0)),
            z3.If(left.as_int() > right.as_int(), z3.IntVal(1), z3.IntVal(0))
        )
    )
    return SymbolicValue(ValueTag.BOOL, result_val), type_ok


def compare_op_ge(left: SymbolicValue, right: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef]:
    """Symbolic greater-than-or-equal comparison."""
    # Accept OBJ types (conservative overapproximation for soundness)
    # Also accept float and mixed int/float comparisons
    type_ok = z3.Or(
        z3.And(left.is_int(), right.is_int()),
        z3.And(left.is_float(), right.is_float()),
        z3.And(left.is_int(), right.is_float()),
        z3.And(left.is_float(), right.is_int()),
        left.is_obj(),
        right.is_obj()
    )
    # When OBJ involved, return nondeterministic result (sound overapproximation)
    any_float = z3.Or(left.is_float(), right.is_float())
    result_val = z3.If(
        z3.Or(left.is_obj(), right.is_obj()),
        z3.Int(f"cmp_ge_obj_{id(left)}_{id(right)}"),
        z3.If(
            any_float,
            z3.If(left.as_float() >= right.as_float(), z3.IntVal(1), z3.IntVal(0)),
            z3.If(left.as_int() >= right.as_int(), z3.IntVal(1), z3.IntVal(0))
        )
    )
    return SymbolicValue(ValueTag.BOOL, result_val), type_ok


def contains_op(item: SymbolicValue, container: SymbolicValue, heap, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef]:
    """
    Containment test: item in container.
    
    Returns (result, type_ok, none_misuse).
    
    Semantics:
    - Container must be a sequence (list, tuple, str) or dict
    - For sequences: checks if item is equal to any element (overapproximated as nondeterministic)
    - For dicts: checks if item is a key
    - Raises TypeError if container is None or not iterable (NULL_PTR/TYPE_CONFUSION)
    
    Conservative overapproximation: since we can't track all elements symbolically,
    we return a nondeterministic boolean (may be True or False).
    """
    # Check for None misuse
    none_misuse = container.is_none()
    
    # Type check: container must be list, tuple, str, or dict
    is_iterable = z3.Or(
        container.is_list(),
        container.is_tuple(),
        container.is_str(),
        container.is_dict()
    )
    type_ok = z3.And(z3.Not(none_misuse), is_iterable)
    
    # Result: nondeterministic boolean (conservative overapproximation)
    # In a full implementation, we'd check container.elements symbolically
    result_val = z3.Int(f"contains_result_{id(item)}_{id(container)}")
    result = SymbolicValue(ValueTag.BOOL, z3.If(result_val != 0, z3.IntVal(1), z3.IntVal(0)))
    
    return result, type_ok, none_misuse


def is_true(value: SymbolicValue, solver: z3.Solver) -> z3.ExprRef:
    """
    Compute symbolic truthiness condition.
    
    Python truthiness rules:
    - None is False
    - False is False
    - 0 is False
    - Everything else is True (for now; will need refinement for containers)
    
    Returns Z3 boolean expression representing the truthiness.
    """
    # None → False
    is_none = value.tag == z3.IntVal(ValueTag.NONE.value)
    
    # Bool → check payload
    is_false_bool = z3.And(
        value.tag == z3.IntVal(ValueTag.BOOL.value),
        value.payload == z3.IntVal(0)
    )
    
    # Int 0 → False
    is_zero_int = z3.And(
        value.tag == z3.IntVal(ValueTag.INT.value),
        value.payload == z3.IntVal(0)
    )
    
    # Float 0.0 → False
    is_zero_float = z3.And(
        value.tag == z3.IntVal(ValueTag.FLOAT.value),
        value.payload == z3.RealVal(0)
    )
    
    # Value is false if it's None, False, 0, or 0.0
    is_false = z3.Or(is_none, is_false_bool, is_zero_int, is_zero_float)
    
    # Value is true if it's not false
    return z3.Not(is_false)


def binary_op_subscript(container: SymbolicValue, index: SymbolicValue, heap, solver: z3.Solver):
    """
    Subscript operation: container[index].
    
    Returns (result, type_ok, bounds_violated, none_misuse).
    
    Semantics:
    - Lists/tuples: index must be int, 0 <= index < length
    - Dicts: key must exist (for now, concrete keys only)
    - OBJ (type parameterization): Generic types like Mapping[str, str], Callable[[A], B]
      In Python 3.9+, subscripting type objects creates GenericAlias. This operation
      always succeeds and returns an OBJ-tagged value (the parameterized type).
    - Raises TypeError if container is None (NULL_PTR bug class)
    - Raises IndexError if index out of bounds
    - Raises KeyError if key not in dict
    - Raises TypeError if container is not subscriptable or index is wrong type
    
    This is the semantic implementation for BINARY_OP 26 ([]).
    """
    from ..z3model.heap import SequenceObject, DictObject
    
    # Check for None misuse: container must not be None
    none_misuse = container.is_none()
    
    # Type parameterization: OBJ[...] creates GenericAlias (Python 3.9+)
    # Examples: typing.Mapping[str, str], collections.abc.Callable[[Request], Response]
    # This operation always succeeds and returns an OBJ-tagged generic alias
    is_obj = container.is_obj()
    if solver:
        solver.push()
        solver.add(is_obj)
        if solver.check() == z3.sat:
            # Type parameterization: always succeeds, returns OBJ-tagged generic alias
            result = SymbolicValue.fresh_obj("generic_alias", solver)
            type_ok = z3.And(z3.Not(container.is_none()), z3.BoolVal(True))
            bounds_violated = z3.BoolVal(False)  # No bounds check for type parameterization
            solver.pop()
            return result, type_ok, bounds_violated, none_misuse
        solver.pop()
    
    # Type check: container must be list, tuple, dict, or obj (not None)
    is_sequence = z3.Or(container.is_list(), container.is_tuple())
    is_dict = container.is_dict()
    type_ok = z3.And(z3.Not(container.is_none()), z3.Or(is_sequence, is_dict, is_obj))
    
    # Default: bounds not violated (will be refined)
    bounds_violated = z3.BoolVal(False)
    
    # For sequences (list/tuple)
    # Need: index is int AND 0 <= index < length
    if solver:
        solver.push()
        solver.add(is_sequence)
        if solver.check() == z3.sat:
            # Get the sequence from heap
            # For now, use concrete obj_id from model
            # This is a simplification - full symbolic heap needs Z3 Arrays
            model = solver.model()
            try:
                obj_id_val = model.eval(container.payload, model_completion=True)
                if obj_id_val.is_int():
                    obj_id = obj_id_val.as_long()
                    seq_obj = heap.get_sequence(obj_id)
                    if seq_obj:
                        # Check bounds: index must be int and 0 <= index < length
                        index_is_int = index.is_int()
                        index_val = index.as_int()
                        lower_bound = index_val >= 0
                        upper_bound = index_val < seq_obj.length
                        
                        bounds_ok = z3.And(index_is_int, lower_bound, upper_bound)
                        bounds_violated = z3.Not(bounds_ok)
                        
                        # Result: if bounds ok, return element; else undefined
                        # For simplicity, return a fresh symbolic value
                        # In a full implementation, we'd look up seq_obj.elements[index]
                        result = SymbolicValue.fresh_int("subscript_result", solver)
                        solver.pop()
                        return result, type_ok, bounds_violated, none_misuse
            except:
                pass
        solver.pop()
    
    # For dicts: key must exist (concrete check for now)
    if solver:
        solver.push()
        solver.add(is_dict)
        if solver.check() == z3.sat:
            # This is a dict subscript: dict[key]
            # Check if we have a concrete dict with a concrete key
            if isinstance(container.payload, z3.IntNumRef) and isinstance(index.payload, z3.IntNumRef):
                dict_id = container.payload.as_long()
                dict_obj = heap.get_dict(dict_id)
                
                if dict_obj and index.tag == ValueTag.STR:
                    # Concrete dict with concrete string key
                    key_str_id = index.payload.as_long()
                    key_str = heap.get_string(key_str_id)
                    
                    if key_str:
                        if key_str in dict_obj.keys and key_str in dict_obj.values:
                            # Key exists, return value
                            result = dict_obj.values[key_str]
                            bounds_violated = z3.BoolVal(False)  # Key exists, no KeyError
                            solver.pop()
                            return result, type_ok, bounds_violated, none_misuse
                        else:
                            # Key does NOT exist, will raise KeyError
                            result = SymbolicValue.fresh_int("dict_subscript_error", solver)
                            bounds_violated = z3.BoolVal(True)  # KeyError
                            solver.pop()
                            return result, type_ok, bounds_violated, none_misuse
            
            # Symbolic dict or symbolic key: create symbolic bounds check
            # KeyError is possible but not certain (e.g., if key is validated)
            result = SymbolicValue.fresh_int("dict_subscript_symbolic", solver)
            bounds_violated = z3.Bool(f"dict_key_missing_{id(container)}_{id(index)}")
            # Add constraint: allow both paths (key exists / key missing)
            solver.pop()
            return result, type_ok, bounds_violated, none_misuse
        solver.pop()
    
    # Default: return fresh symbolic value, flag bounds violation as possible
    result = SymbolicValue.fresh_int("subscript_default", solver)
    bounds_violated = z3.BoolVal(True)  # Conservative: assume may violate
    
    return result, type_ok, bounds_violated, none_misuse


def unary_op_negative(operand: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef]:
    """
    Unary negation: -x
    
    Semantics:
    - int: -x returns int
    - float: -x returns float
    - bool: -True = -1, -False = 0 (int)
    - None: TypeError
    - other: TypeError
    
    Returns: (result, type_ok, none_misuse)
    """
    solver.push()
    
    tag_none = z3.IntVal(ValueTag.NONE.value)
    tag_bool = z3.IntVal(ValueTag.BOOL.value)
    tag_int = z3.IntVal(ValueTag.INT.value)
    tag_float = z3.IntVal(ValueTag.FLOAT.value)
    
    # None misuse check
    none_misuse = (operand.tag == tag_none)
    
    # Type check: must be numeric (int, float, or bool)
    is_int = (operand.tag == tag_int)
    is_float = (operand.tag == tag_float)
    is_bool = (operand.tag == tag_bool)
    type_ok = z3.Or(is_int, is_float, is_bool)
    
    # Result computation (conditional on types)
    # If bool: convert to int (True=1, False=0), then negate
    # If int: negate int
    # If float: negate float
    
    # For symbolic execution, create result based on type
    # bool → int: -bool = -(1 if bool else 0)
    bool_as_int = z3.If(operand.payload == z3.IntVal(1), z3.IntVal(1), z3.IntVal(0))
    
    result_payload = z3.If(
        is_bool,
        -bool_as_int,
        z3.If(
            is_int,
            -operand.payload,
            -z3.ToReal(operand.payload)  # float case
        )
    )
    
    # Result tag: bool→int, otherwise preserve
    result_tag = z3.If(is_bool, tag_int, operand.tag)
    
    result = SymbolicValue(result_tag, result_payload, operand.taint)
    solver.pop()
    
    return result, type_ok, none_misuse


def unary_op_positive(operand: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef]:
    """
    Unary positive: +x
    
    Semantics:
    - int: +x returns int (identity)
    - float: +x returns float (identity)
    - bool: +True = 1, +False = 0 (int)
    - None: TypeError
    - other: TypeError
    
    Returns: (result, type_ok, none_misuse)
    """
    solver.push()
    
    tag_none = z3.IntVal(ValueTag.NONE.value)
    tag_bool = z3.IntVal(ValueTag.BOOL.value)
    tag_int = z3.IntVal(ValueTag.INT.value)
    tag_float = z3.IntVal(ValueTag.FLOAT.value)
    
    # None misuse check
    none_misuse = (operand.tag == tag_none)
    
    # Type check: must be numeric (int, float, or bool)
    is_int = (operand.tag == tag_int)
    is_float = (operand.tag == tag_float)
    is_bool = (operand.tag == tag_bool)
    type_ok = z3.Or(is_int, is_float, is_bool)
    
    # Result: bool converts to int (True=1, False=0), others are identity
    bool_as_int = z3.If(operand.payload == z3.IntVal(1), z3.IntVal(1), z3.IntVal(0))
    
    result_payload = z3.If(is_bool, bool_as_int, operand.payload)
    result_tag = z3.If(is_bool, tag_int, operand.tag)
    
    result = SymbolicValue(result_tag, result_payload, operand.taint)
    solver.pop()
    
    return result, type_ok, none_misuse


def unary_op_invert(operand: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef, z3.ExprRef]:
    """
    Bitwise inversion: ~x
    
    Semantics:
    - int: ~x returns -(x+1)
    - bool: ~True = -2, ~False = -1 (convert to int first)
    - None: TypeError
    - float: TypeError
    - other: TypeError
    
    Returns: (result, type_ok, none_misuse)
    """
    solver.push()
    
    tag_none = z3.IntVal(ValueTag.NONE.value)
    tag_bool = z3.IntVal(ValueTag.BOOL.value)
    tag_int = z3.IntVal(ValueTag.INT.value)
    
    # None misuse check
    none_misuse = (operand.tag == tag_none)
    
    # Type check: must be int or bool (not float)
    is_int = (operand.tag == tag_int)
    is_bool = (operand.tag == tag_bool)
    type_ok = z3.Or(is_int, is_bool)
    
    # Result: ~x = -(x+1)
    # bool converts to int first (True=1, False=0)
    bool_as_int = z3.If(operand.payload == z3.IntVal(1), z3.IntVal(1), z3.IntVal(0))
    int_value = z3.If(is_bool, bool_as_int, operand.payload)
    
    result_payload = -(int_value + z3.IntVal(1))
    result_tag = tag_int
    
    result = SymbolicValue(result_tag, result_payload, operand.taint)
    solver.pop()
    
    return result, type_ok, none_misuse


def unary_op_not(operand: SymbolicValue, solver: z3.Solver) -> tuple[SymbolicValue, z3.ExprRef]:
    """
    Logical NOT: not x
    
    Semantics:
    - Returns bool (never raises TypeError)
    - None: not None = True
    - bool: not x returns opposite bool
    - int: not 0 = True, not x = False (x != 0)
    - float: not 0.0 = True, not x = False (x != 0.0)
    - empty container: not [] = True
    - non-empty container: not [x] = False
    - OBJ: not obj = False (assume non-empty/truthy)
    
    Returns: (result, none_misuse) - no none_misuse for 'not' (None is valid)
    Note: 'not' never raises TypeError in Python
    """
    solver.push()
    
    # Determine truthiness using is_true function
    truth_value = is_true(operand, solver)
    
    # Result: opposite of truthiness
    result_payload = z3.If(truth_value, z3.IntVal(0), z3.IntVal(1))
    result = SymbolicValue(ValueTag.BOOL, result_payload, set())  # Not operator clears taint
    
    solver.pop()
    
    # 'not' never has none_misuse (None is a valid operand)
    none_misuse = z3.BoolVal(False)
    
    return result, none_misuse
