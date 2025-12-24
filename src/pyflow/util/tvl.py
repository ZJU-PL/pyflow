"""
Three-valued logic (TVL) for modeling uncertainty in static analysis.

This module implements a three-valued logic system where values can be:
- TVLTrue: Definitely true (certain)
- TVLFalse: Definitely false (certain)
- TVLMaybe: Possibly true or false (uncertain)

Three-valued logic is essential for static analysis because the analyzer
often cannot determine with certainty whether a condition is true or false.
For example, when analyzing a variable that may or may not be initialized,
the analysis must represent this uncertainty.

The TVL system supports logical operations (AND, OR, NOT, XOR) that preserve
uncertainty correctly. For example:
- True AND Maybe = Maybe (if one is uncertain, result is uncertain)
- False AND Maybe = False (False dominates)
- True OR Maybe = True (True dominates)

This is used throughout pyflow for:
- Call feasibility analysis (will a function call succeed?)
- Parameter binding analysis (is a parameter bound?)
- Control flow analysis (can a path be taken?)
- Type inference (is a value of a certain type?)
"""

__all__ = ("TVLType", "TVLTrue", "TVLFalse", "TVLMaybe", "tvl")

# Three-valued logic: True/Maybe/False


class TVLType(object):
    """
    Abstract base class for three-valued logic types.
    
    This class defines the interface for TVL values. It prevents direct
    conversion to boolean (which would lose uncertainty information) and
    provides methods to query the certainty and truth value of a TVL.
    
    Subclasses must implement:
    - maybeTrue(): Can this value be true?
    - maybeFalse(): Can this value be false?
    - mustBeTrue(): Must this value be true?
    - mustBeFalse(): Must this value be false?
    """
    __slots__ = ()

    def __nonzero__(self):
        """
        Prevent direct boolean conversion.
        
        TVL values cannot be directly converted to boolean because this would
        lose uncertainty information. Use maybeTrue()/mustBeTrue() instead.
        
        Raises:
            TypeError: Always, to prevent accidental boolean conversion
        """
        # return self.maybeTrue()
        raise TypeError("%r cannot be directly converted a boolean value." % self)

    # Python 3 compatibility
    __bool__ = __nonzero__

    def certain(self):
        """
        Check if this value is certain (not Maybe).
        
        Returns:
            bool: True if value is TVLTrue or TVLFalse, False if TVLMaybe
        """
        return True

    def uncertain(self):
        """
        Check if this value is uncertain (Maybe).
        
        Returns:
            bool: True if value is TVLMaybe, False otherwise
        """
        return False


class TVLTrueType(TVLType):
    """
    TVL value representing definitely true (certain).
    
    This represents a value that is known with certainty to be true.
    In logical operations, True dominates (True OR X = True, True AND X = X).
    """
    def maybeTrue(self):
        """Return True (this value can be true)."""
        return True

    def maybeFalse(self):
        """Return False (this value cannot be false)."""
        return False

    def mustBeTrue(self):
        """Return True (this value must be true)."""
        return True

    def mustBeFalse(self):
        """Return False (this value cannot be false)."""
        return False

    def __repr__(self):
        return "TVLTrue"

    def __invert__(self):
        """Logical NOT: True -> False"""
        return TVLFalse

    def __and__(self, other):
        """Logical AND: True AND X = X (True is identity for AND)"""
        return other

    def __rand__(self, other):
        """Right-hand logical AND: X AND True = X"""
        return other

    def __or__(self, other):
        """Logical OR: True OR X = True (True dominates)"""
        return self

    def __ror__(self, other):
        """Right-hand logical OR: X OR True = True"""
        return self

    def __xor__(self, other):
        """Logical XOR: True XOR X = NOT X"""
        return ~other

    def __rxor__(self, other):
        """Right-hand logical XOR: X XOR True = NOT X"""
        return ~other


class TVLFalseType(TVLType):
    """
    TVL value representing definitely false (certain).
    
    This represents a value that is known with certainty to be false.
    In logical operations, False dominates AND (False AND X = False) but
    is identity for OR (False OR X = X).
    """
    __slots__ = ()

    def maybeTrue(self):
        """Return False (this value cannot be true)."""
        return False

    def maybeFalse(self):
        """Return True (this value can be false)."""
        return True

    def mustBeTrue(self):
        """Return False (this value cannot be true)."""
        return False

    def mustBeFalse(self):
        """Return True (this value must be false)."""
        return True

    def __repr__(self):
        return "TVLFalse"

    def __invert__(self):
        """Logical NOT: False -> True"""
        return TVLTrue

    def __and__(self, other):
        """Logical AND: False AND X = False (False dominates)"""
        return self

    def __rand__(self, other):
        """Right-hand logical AND: X AND False = False"""
        return self

    def __or__(self, other):
        """Logical OR: False OR X = X (False is identity for OR)"""
        return other

    def __ror__(self, other):
        """Right-hand logical OR: X OR False = X"""
        return other

    def __xor__(self, other):
        """Logical XOR: False XOR X = X"""
        return other

    def __rxor__(self, other):
        """Right-hand logical XOR: X XOR False = X"""
        return other


class TVLMaybeType(TVLType):
    """
    TVL value representing uncertainty (maybe true, maybe false).
    
    This represents a value where the analysis cannot determine with certainty
    whether it is true or false. In logical operations, Maybe propagates
    uncertainty unless the other operand forces a certain result.
    
    Examples:
    - Maybe AND False = False (False dominates)
    - Maybe AND True = Maybe (uncertainty preserved)
    - Maybe OR True = True (True dominates)
    - Maybe OR False = Maybe (uncertainty preserved)
    - NOT Maybe = Maybe (uncertainty preserved)
    """
    __slots__ = ()

    def maybeTrue(self):
        """Return True (this value might be true)."""
        return True

    def maybeFalse(self):
        """Return True (this value might be false)."""
        return True

    def mustBeTrue(self):
        """Return False (this value is not definitely true)."""
        return False

    def mustBeFalse(self):
        """Return False (this value is not definitely false)."""
        return False

    def certain(self):
        """Return False (this value is uncertain)."""
        return False

    def uncertain(self):
        """Return True (this value is uncertain)."""
        return True

    def __repr__(self):
        return "TVLMaybe"

    def __invert__(self):
        """Logical NOT: Maybe -> Maybe (uncertainty preserved)"""
        return self

    def __and__(self, other):
        """Logical AND: Maybe AND X = Maybe (unless X is False)"""
        if isinstance(other, TVLFalseType):
            return other  # False dominates
        else:
            return self  # Uncertainty preserved

    def __rand__(self, other):
        """Right-hand logical AND: X AND Maybe = Maybe (unless X is False)"""
        if isinstance(other, TVLFalseType):
            return other  # False dominates
        else:
            return self  # Uncertainty preserved

    def __or__(self, other):
        """Logical OR: Maybe OR X = Maybe (unless X is True)"""
        if isinstance(other, TVLTrueType):
            return other  # True dominates
        else:
            return self  # Uncertainty preserved

    def __ror__(self, other):
        """Right-hand logical OR: X OR Maybe = Maybe (unless X is True)"""
        if isinstance(other, TVLTrueType):
            return other  # True dominates
        else:
            return self  # Uncertainty preserved

    def __xor__(self, other):
        """Logical XOR: Maybe XOR X = Maybe (uncertainty always preserved)"""
        return self

    def __rxor__(self, other):
        """Right-hand logical XOR: X XOR Maybe = Maybe"""
        return self


# Singleton instances for the three TVL values
TVLTrue = TVLTrueType()
TVLFalse = TVLFalseType()
TVLMaybe = TVLMaybeType()


def tvl(obj):
    """
    Convert a Python value to a TVL value.
    
    Converts regular Python boolean/truthy values to TVL:
    - Truthy values -> TVLTrue
    - Falsy values -> TVLFalse
    - TVL values -> returned as-is
    
    Args:
        obj: Python value to convert (any type)
        
    Returns:
        TVLType: TVLTrue, TVLFalse, or the original TVL value
        
    Example:
        >>> tvl(True)
        TVLTrue
        >>> tvl(False)
        TVLFalse
        >>> tvl(42)
        TVLTrue
        >>> tvl(0)
        TVLFalse
        >>> tvl(TVLMaybe)
        TVLMaybe
    """
    if isinstance(obj, TVLType):
        return obj
    else:
        return TVLTrue if obj else TVLFalse
