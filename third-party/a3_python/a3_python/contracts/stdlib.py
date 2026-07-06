"""
Standard library contracts (over-approximating, justified by Python spec).

These contracts are conservative summaries of stdlib functions, justified by:
- Python language reference
- Python library documentation  
- Source code inspection (for CPython implementation details)

All contracts MUST be over-approximations: Sem_f ⊆ R_f.
"""

from a3_python.contracts.schema import (
    Contract, HeapEffect, ExceptionEffect, ValueConstraint, register_contract
)


def init_stdlib_contracts():
    """
    Initialize standard library contracts.
    
    Start with a minimal set of commonly-used pure/simple functions.
    Expand conservatively as needed.
    """
    
    # len(obj) - pure, may raise TypeError
    # Justified by: Python docs - len() is pure, raises TypeError if no __len__
    register_contract(Contract(
        function_name="len",
        arg_constraints=[ValueConstraint(type_constraint="object")],
        return_constraint=ValueConstraint(
            type_constraint="int",
            range_constraint=(0, None)  # Non-negative
        ),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # abs(x) - pure, may raise TypeError
    # Justified by: Python docs - abs() is pure mathematical function
    register_contract(Contract(
        function_name="abs",
        arg_constraints=[ValueConstraint(type_constraint="numeric")],
        return_constraint=ValueConstraint(
            type_constraint="numeric",
            range_constraint=(0, None)  # Non-negative
        ),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # int(x) - pure, may raise TypeError/ValueError
    # Justified by: Python docs - constructor/conversion function
    register_contract(Contract(
        function_name="int",
        arg_constraints=[ValueConstraint()],  # Accepts various types
        return_constraint=ValueConstraint(type_constraint="int"),
        heap_effect=HeapEffect(
            may_read=set(),
            may_write=set(),
            may_allocate=True  # May allocate new int object
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError", "ValueError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # str(x) - mostly pure, may raise
    # Justified by: Python docs - calls __str__ which may have side effects
    # NOTE: Over-approximation needed because __str__ can be arbitrary code
    register_contract(Contract(
        function_name="str",
        arg_constraints=[ValueConstraint()],
        return_constraint=ValueConstraint(type_constraint="str"),
        heap_effect=HeapEffect(
            may_read={'*'},  # __str__ may read heap
            may_write=set(),  # Conservative: assume no writes
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise={'*'},  # __str__ can raise anything
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # max(iterable) or max(a, b, ...) - pure for built-in types, may raise
    # Justified by: Python docs - pure comparison-based operation
    register_contract(Contract(
        function_name="max",
        arg_constraints=[],  # Variable arguments
        return_constraint=ValueConstraint(),  # Type depends on arguments
        heap_effect=HeapEffect(
            may_read={'*'},  # May call __lt__ which reads heap
            may_write=set(),
            may_allocate=False
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError", "ValueError"},  # Empty sequence, incomparable types
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # min(iterable) or min(a, b, ...) - symmetric with max
    register_contract(Contract(
        function_name="min",
        arg_constraints=[],
        return_constraint=ValueConstraint(),
        heap_effect=HeapEffect(
            may_read={'*'},
            may_write=set(),
            may_allocate=False
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError", "ValueError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # sum(iterable) - pure for built-in numeric types
    # Justified by: Python docs - arithmetic operation on iterable
    register_contract(Contract(
        function_name="sum",
        arg_constraints=[ValueConstraint(type_constraint="iterable")],
        return_constraint=ValueConstraint(type_constraint="numeric"),
        heap_effect=HeapEffect(
            may_read={'*'},  # May iterate and read elements
            may_write=set(),
            may_allocate=True  # May create result object
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # isinstance(obj, classinfo) - pure
    # Justified by: Python docs - pure type check
    register_contract(Contract(
        function_name="isinstance",
        arg_constraints=[
            ValueConstraint(),
            ValueConstraint(type_constraint="type")
        ],
        return_constraint=ValueConstraint(type_constraint="bool"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},  # Invalid classinfo
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # issubclass(class, classinfo) - pure
    # Justified by: Python docs - pure type relationship check
    register_contract(Contract(
        function_name="issubclass",
        arg_constraints=[
            ValueConstraint(type_constraint="type"),
            ValueConstraint(type_constraint="type")
        ],
        return_constraint=ValueConstraint(type_constraint="bool"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # range(...) - pure, creates range object
    # Justified by: Python docs - immutable sequence type
    register_contract(Contract(
        function_name="range",
        arg_constraints=[],  # Variable arguments (1-3 ints)
        return_constraint=ValueConstraint(type_constraint="range"),
        heap_effect=HeapEffect(
            may_read=set(),
            may_write=set(),
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # math.sqrt(x) - pure, raises ValueError if x < 0 (domain error)
    # Justified by: Python docs - math.sqrt raises ValueError for negative input
    register_contract(Contract(
        function_name="math.sqrt",
        arg_constraints=[ValueConstraint(type_constraint="numeric")],
        return_constraint=ValueConstraint(type_constraint="float"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"ValueError", "TypeError"},  # ValueError for domain, TypeError for bad type
            always_raises=False,
            domain_precondition="x >= 0"
        ),
        provenance="stdlib_spec"
    ))
    
    # math.log(x) - pure, raises ValueError if x <= 0 (domain error)
    # Justified by: Python docs - math.log raises ValueError for non-positive input
    register_contract(Contract(
        function_name="math.log",
        arg_constraints=[ValueConstraint(type_constraint="numeric")],
        return_constraint=ValueConstraint(type_constraint="float"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"ValueError", "TypeError"},
            always_raises=False,
            domain_precondition="x > 0"
        ),
        provenance="stdlib_spec"
    ))
    
    # math.asin(x) - pure, raises ValueError if x not in [-1, 1] (domain error)
    # Justified by: Python docs - math.asin raises ValueError for out of domain
    register_contract(Contract(
        function_name="math.asin",
        arg_constraints=[ValueConstraint(type_constraint="numeric")],
        return_constraint=ValueConstraint(type_constraint="float"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"ValueError", "TypeError"},
            always_raises=False,
            domain_precondition="-1 <= x <= 1"
        ),
        provenance="stdlib_spec"
    ))
    
    # math.acos(x) - pure, raises ValueError if x not in [-1, 1] (domain error)
    # Justified by: Python docs - math.acos raises ValueError for out of domain
    register_contract(Contract(
        function_name="math.acos",
        arg_constraints=[ValueConstraint(type_constraint="numeric")],
        return_constraint=ValueConstraint(type_constraint="float"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"ValueError", "TypeError"},
            always_raises=False,
            domain_precondition="-1 <= x <= 1"
        ),
        provenance="stdlib_spec"
    ))
    
    # struct.pack(fmt, *values) - converts Python values to C struct bytes
    # Raises struct.error (treated as OverflowError) if value out of range
    # Justified by: Python docs - struct.pack validates range for format types
    # This is the PRIMARY INTEGER_OVERFLOW detector at the Python/native boundary
    register_contract(Contract(
        function_name="struct.pack",
        arg_constraints=[],  # Variable arguments
        return_constraint=ValueConstraint(type_constraint="bytes"),
        heap_effect=HeapEffect(
            may_read=set(),
            may_write=set(),
            may_allocate=True  # Allocates bytes object
        ),
        exception_effect=ExceptionEffect(
            may_raise={"struct.error", "OverflowError", "TypeError"},
            always_raises=False,
            domain_precondition="values must fit in format types"
        ),
        provenance="stdlib_spec"
    ))
    
    # array.array(typecode, initializer) - creates fixed-width typed array
    # May raise OverflowError if values don't fit in the typecode's range
    # Justified by: Python docs - array validates element ranges
    register_contract(Contract(
        function_name="array.array",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="array"),
        heap_effect=HeapEffect(
            may_read=set(),
            may_write=set(),
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise={"OverflowError", "TypeError", "ValueError"},
            always_raises=False,
            domain_precondition="values must fit in typecode range"
        ),
        provenance="stdlib_spec"
    ))
    
    # int.to_bytes(length, byteorder, signed=False) - converts int to bytes
    # Raises OverflowError if int doesn't fit in specified byte length
    # Justified by: Python docs - validates range for fixed byte count
    register_contract(Contract(
        function_name="int.to_bytes",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="bytes"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"OverflowError", "ValueError"},
            always_raises=False,
            domain_precondition="value must fit in specified byte length"
        ),
        provenance="stdlib_spec"
    ))
    
    # list(...) - constructor, pure allocation
    # Justified by: Python docs - list constructor, may iterate argument
    register_contract(Contract(
        function_name="list",
        arg_constraints=[],  # Optional iterable argument
        return_constraint=ValueConstraint(type_constraint="list"),
        heap_effect=HeapEffect(
            may_read={'*'},  # May iterate and read elements
            may_write=set(),
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # tuple(...) - constructor, pure allocation
    # Justified by: Python docs - tuple constructor, may iterate argument
    register_contract(Contract(
        function_name="tuple",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="tuple"),
        heap_effect=HeapEffect(
            may_read={'*'},
            may_write=set(),
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # set(...) - constructor, pure allocation
    # Justified by: Python docs - set constructor, may iterate argument
    register_contract(Contract(
        function_name="set",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="set"),
        heap_effect=HeapEffect(
            may_read={'*'},
            may_write=set(),
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},  # Unhashable elements
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # dict(...) - constructor, pure allocation
    # Justified by: Python docs - dict constructor
    register_contract(Contract(
        function_name="dict",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="dict"),
        heap_effect=HeapEffect(
            may_read={'*'},
            may_write=set(),
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError", "ValueError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # float(...) - conversion, pure
    # Justified by: Python docs - float constructor/conversion
    register_contract(Contract(
        function_name="float",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="float"),
        heap_effect=HeapEffect(
            may_read=set(),
            may_write=set(),
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise={"ValueError", "TypeError", "OverflowError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # bool(...) - conversion, pure
    # Justified by: Python docs - bool constructor, calls __bool__ or __len__
    register_contract(Contract(
        function_name="bool",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="bool"),
        heap_effect=HeapEffect(
            may_read={'*'},  # __bool__/__len__ may read
            may_write=set(),
            may_allocate=False
        ),
        exception_effect=ExceptionEffect(
            may_raise={'*'},  # __bool__ can raise anything
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # any(iterable) - pure logical operation
    # Justified by: Python docs - returns True if any element is truthy
    register_contract(Contract(
        function_name="any",
        arg_constraints=[ValueConstraint(type_constraint="iterable")],
        return_constraint=ValueConstraint(type_constraint="bool"),
        heap_effect=HeapEffect(
            may_read={'*'},  # Iterates and checks truthiness
            may_write=set(),
            may_allocate=False
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # all(iterable) - pure logical operation
    # Justified by: Python docs - returns True if all elements are truthy
    register_contract(Contract(
        function_name="all",
        arg_constraints=[ValueConstraint(type_constraint="iterable")],
        return_constraint=ValueConstraint(type_constraint="bool"),
        heap_effect=HeapEffect(
            may_read={'*'},
            may_write=set(),
            may_allocate=False
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # sorted(iterable, key=None, reverse=False) - pure sort
    # Justified by: Python docs - returns new sorted list
    register_contract(Contract(
        function_name="sorted",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="list"),
        heap_effect=HeapEffect(
            may_read={'*'},  # Iterates and compares elements
            may_write=set(),
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},  # Incomparable types
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # enumerate(iterable, start=0) - creates enumerate object
    # Justified by: Python docs - returns enumerate iterator
    register_contract(Contract(
        function_name="enumerate",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="enumerate"),
        heap_effect=HeapEffect(
            may_read=set(),
            may_write=set(),
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # zip(*iterables) - creates zip object
    # Justified by: Python docs - returns zip iterator
    register_contract(Contract(
        function_name="zip",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="zip"),
        heap_effect=HeapEffect(
            may_read=set(),
            may_write=set(),
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise=set(),
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # reversed(sequence) - creates reverse iterator
    # Justified by: Python docs - returns reverse iterator
    register_contract(Contract(
        function_name="reversed",
        arg_constraints=[ValueConstraint(type_constraint="sequence")],
        return_constraint=ValueConstraint(type_constraint="reversed"),
        heap_effect=HeapEffect(
            may_read=set(),
            may_write=set(),
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},  # Not a sequence or no __reversed__
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # chr(i) - pure conversion
    # Justified by: Python docs - converts int to unicode character
    register_contract(Contract(
        function_name="chr",
        arg_constraints=[ValueConstraint(type_constraint="int")],
        return_constraint=ValueConstraint(type_constraint="str"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"ValueError", "TypeError"},  # Out of valid Unicode range
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # ord(c) - pure conversion
    # Justified by: Python docs - converts character to int
    register_contract(Contract(
        function_name="ord",
        arg_constraints=[ValueConstraint(type_constraint="str")],
        return_constraint=ValueConstraint(
            type_constraint="int",
            range_constraint=(0, 0x10FFFF)  # Valid Unicode range
        ),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},  # Not a string or wrong length
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # chr(i) - pure conversion
    # Justified by: Python docs - converts int to Unicode character
    register_contract(Contract(
        function_name="chr",
        arg_constraints=[ValueConstraint(type_constraint="int")],
        return_constraint=ValueConstraint(type_constraint="str"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"ValueError", "TypeError"},  # Out of range or not an int
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # round(number, ndigits=None) - pure rounding
    # Justified by: Python docs - rounds to nearest integer or n digits
    register_contract(Contract(
        function_name="round",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="numeric"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # pow(base, exp, mod=None) - pure exponentiation
    # Justified by: Python docs - power operation
    register_contract(Contract(
        function_name="pow",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="numeric"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"ValueError", "TypeError", "ZeroDivisionError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # divmod(a, b) - pure division with remainder
    # Justified by: Python docs - returns (a // b, a % b)
    register_contract(Contract(
        function_name="divmod",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="tuple"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"ZeroDivisionError", "TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # hash(obj) - pure hash function
    # Justified by: Python docs - returns hash value
    register_contract(Contract(
        function_name="hash",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="int"),
        heap_effect=HeapEffect(
            may_read={'*'},  # __hash__ may read heap
            may_write=set(),
            may_allocate=False
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},  # Unhashable type
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # id(obj) - pure identity function
    # Justified by: Python docs - returns identity (memory address)
    register_contract(Contract(
        function_name="id",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="int"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise=set(),
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # type(obj) - pure type query (single argument form)
    # Justified by: Python docs - returns type of object
    register_contract(Contract(
        function_name="type",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="type"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise=set(),
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # hasattr(obj, name) - checks attribute existence
    # Justified by: Python docs - uses getattr and catches exceptions
    register_contract(Contract(
        function_name="hasattr",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="bool"),
        heap_effect=HeapEffect(
            may_read={'*'},  # __getattribute__ may read
            may_write=set(),
            may_allocate=False
        ),
        exception_effect=ExceptionEffect(
            may_raise=set(),  # Suppresses exceptions from getattr
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # setattr(obj, name, value) - sets attribute on object
    # Justified by: Python docs - modifies object attributes
    # NOTE: Over-approximation - may invoke __setattr__ with arbitrary side effects
    register_contract(Contract(
        function_name="setattr",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="none"),
        heap_effect=HeapEffect(
            may_read={'*'},  # __setattr__ may read heap
            may_write={'*'},  # Modifies object attributes
            may_allocate=True  # May allocate for new attributes
        ),
        exception_effect=ExceptionEffect(
            may_raise={'*'},  # __setattr__ can raise anything
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # callable(obj) - pure check if object is callable
    # Justified by: Python docs - checks for __call__ method
    register_contract(Contract(
        function_name="callable",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="bool"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise=set(),
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # repr(obj) - string representation
    # Justified by: Python docs - calls __repr__ which may have side effects
    register_contract(Contract(
        function_name="repr",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="str"),
        heap_effect=HeapEffect(
            may_read={'*'},  # __repr__ may read heap
            may_write=set(),
            may_allocate=True
        ),
        exception_effect=ExceptionEffect(
            may_raise={'*'},  # __repr__ can raise anything
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # hex(x) - pure conversion to hex string
    # Justified by: Python docs - converts integer to hex string
    register_contract(Contract(
        function_name="hex",
        arg_constraints=[ValueConstraint(type_constraint="int")],
        return_constraint=ValueConstraint(type_constraint="str"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # oct(x) - pure conversion to octal string
    # Justified by: Python docs - converts integer to octal string
    register_contract(Contract(
        function_name="oct",
        arg_constraints=[ValueConstraint(type_constraint="int")],
        return_constraint=ValueConstraint(type_constraint="str"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # bin(x) - pure conversion to binary string
    # Justified by: Python docs - converts integer to binary string
    register_contract(Contract(
        function_name="bin",
        arg_constraints=[ValueConstraint(type_constraint="int")],
        return_constraint=ValueConstraint(type_constraint="str"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # globals() - returns current frame's global namespace as dict
    # Justified by: Python docs - returns the current global namespace
    # NOTE: This is a special builtin that needs frame-aware handling in symbolic_vm.py
    # The contract here documents the specification; actual implementation is special-cased
    register_contract(Contract(
        function_name="globals",
        arg_constraints=[],  # Takes no arguments
        return_constraint=ValueConstraint(type_constraint="dict"),
        heap_effect=HeapEffect.pure(),  # Reading namespace, not mutating
        exception_effect=ExceptionEffect.no_raise(),  # Never raises
        provenance="stdlib_spec"
    ))
    
    # locals() - returns current frame's local namespace as dict
    # Justified by: Python docs - returns the current local namespace
    # NOTE: This is a special builtin that needs frame-aware handling in symbolic_vm.py
    # The contract here documents the specification; actual implementation is special-cased
    # locals() returns a dictionary of the current local symbol table
    register_contract(Contract(
        function_name="locals",
        arg_constraints=[],  # Takes no arguments
        return_constraint=ValueConstraint(type_constraint="dict"),
        heap_effect=HeapEffect.pure(),  # Reading namespace, not mutating
        exception_effect=ExceptionEffect.no_raise(),  # Never raises
        provenance="stdlib_spec"
    ))
    
    # dataclass(cls) - class decorator that generates special methods
    # Justified by: Python docs - dataclasses.dataclass is a class decorator
    # Returns a modified version of the class with generated __init__, __repr__, etc.
    # For symbolic execution: treat as identity on class objects (sound over-approximation)
    # Actual behavior: generates __init__ with parameters matching field definitions
    # NOTE: Special-cased in symbolic_vm.py for decorator tracking
    register_contract(Contract(
        function_name="dataclasses.dataclass",
        arg_constraints=[ValueConstraint()],  # Takes a class object as first arg
        return_constraint=ValueConstraint(type_constraint="class"),  # Returns a class
        heap_effect=HeapEffect(
            may_read={'*'},  # May inspect class definition
            may_write={'*'},  # Modifies class by adding methods
            may_allocate=True  # Creates new method objects
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TypeError"},  # May raise if invalid class structure
            always_raises=False
        ),
        provenance="stdlib_spec"
    ))
    
    # ===== METHOD CONTRACTS (Iteration 280) =====
    # These contracts model return types for stdlib methods that are commonly used
    # in security-critical contexts. Return type precision is critical for eliminating
    # spurious PANIC/TYPE_CONFUSION bugs that block security analysis.
    
    # subprocess.Popen.communicate() - returns (stdout, stderr) tuple
    # Justified by: Python docs - subprocess.Popen.communicate() returns (stdout, stderr)
    # Returns: tuple of bytes or str, depending on encoding/text mode
    # NOTE: Pattern matching handles "*.communicate" where * is any Popen-like object
    register_contract(Contract(
        function_name="*.communicate",  # Matches any obj.communicate() call
        arg_constraints=[],  # communicate() takes optional timeout/input
        return_constraint=ValueConstraint(type_constraint="tuple"),
        heap_effect=HeapEffect(
            may_read={'*'},  # Reads from subprocess stdout/stderr
            may_write={'*'},  # Writes to subprocess stdin
            may_allocate=True  # Allocates tuple and bytes/str objects
        ),
        exception_effect=ExceptionEffect(
            may_raise={"TimeoutExpired", "SubprocessError"},
            always_raises=False
        ),
        provenance="stdlib_spec_iteration_280"
    ))
    
    # bytes.decode() - returns str
    # Justified by: Python docs - bytes.decode() returns str
    # NOTE: Pattern matching handles "*.decode" where * is any bytes-like object
    register_contract(Contract(
        function_name="*.decode",  # Matches any obj.decode() call (bytes/bytearray)
        arg_constraints=[],  # decode() takes optional encoding/errors
        return_constraint=ValueConstraint(type_constraint="str"),
        heap_effect=HeapEffect(
            may_read={'*'},  # Reads codec state
            may_write=set(),  # Pure (doesn't mutate)
            may_allocate=True  # Allocates str object
        ),
        exception_effect=ExceptionEffect(
            may_raise={"UnicodeDecodeError", "LookupError"},
            always_raises=False
        ),
        provenance="stdlib_spec_iteration_280"
    ))
    
    # re.findall() - returns list of matches
    # Justified by: Python docs - re.findall() returns list of strings (or tuples if groups)
    # NOTE: Matches both re.findall() and compiled_pattern.findall()
    register_contract(Contract(
        function_name="re.findall",
        arg_constraints=[],  # findall(pattern, string, flags=0)
        return_constraint=ValueConstraint(type_constraint="list"),
        heap_effect=HeapEffect(
            may_read={'*'},  # Reads regex engine state/cache
            may_write=set(),  # Pure (doesn't mutate)
            may_allocate=True  # Allocates list and str objects
        ),
        exception_effect=ExceptionEffect(
            may_raise={"re.error", "TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec_iteration_280"
    ))
    
    # Compiled regex pattern .findall() method
    register_contract(Contract(
        function_name="*.findall",  # Matches any compiled_pattern.findall() call
        arg_constraints=[],  # findall(string, pos=0, endpos=...)
        return_constraint=ValueConstraint(type_constraint="list"),
        heap_effect=HeapEffect(
            may_read={'*'},  # Reads regex engine state
            may_write=set(),  # Pure
            may_allocate=True  # Allocates list and str objects
        ),
        exception_effect=ExceptionEffect(
            may_raise={"re.error", "TypeError"},
            always_raises=False
        ),
        provenance="stdlib_spec_iteration_280"
    ))


# Initialize contracts on module import
init_stdlib_contracts()
