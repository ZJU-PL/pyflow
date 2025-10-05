"""CPA signature definitions for constraint-based analysis.

This module provides signature classes for constraint-based analysis,
including parameter types and signature comparison functionality.
"""

from pyflow.util import canonical

Any = canonical.Sentinel("<Any>")


class DoNotCareType(object):
    """Represents a "do not care" type in CPA analysis.
    
    This type is used when a parameter value doesn't matter for analysis purposes.
    """
    
    def isDoNotCare(self):
        """Check if this is a do not care type.
        
        Returns:
            bool: Always True for DoNotCareType.
        """
        return True

    def __repr__(self):
        """String representation of the do not care type.
        
        Returns:
            str: String representation.
        """
        return "<DoNotCare>"


DoNotCare = DoNotCareType()


class CPASignature(canonical.CanonicalObject):
    """Canonical signature for constraint-based analysis.
    
    This class represents a canonical signature for a function with its
    parameter types, used for constraint-based analysis and optimization.
    
    Attributes:
        code: Function code object.
        selfparam: Self parameter type (for methods).
        params: Tuple of parameter types.
    """
    __slots__ = "code", "selfparam", "params"

    def __init__(self, code, selfparam, params):
        """Initialize a CPA signature.
        
        Args:
            code: Function code object.
            selfparam: Self parameter type (None for regular functions).
            params: List of parameter types.
        """
        params = tuple(params)

        # HACK - Sanity check.  Used for catching infinite loops in the analysis
        assert len(params) < 30, (code, params)

        self.code = code
        self.selfparam = selfparam
        self.params = params

        self.setCanonical(code, selfparam, params)

    def classification(self):
        """Get the classification of this signature.
        
        Returns:
            Tuple of (code, number of parameters).
        """
        return (self.code, self.numParams())

    def subsumes(self, other):
        """Check if this signature subsumes another signature.
        
        A signature subsumes another if it's more general (e.g., has Any types
        where the other has specific types).
        
        Args:
            other: Other signature to compare against.
            
        Returns:
            bool: True if this signature subsumes the other.
        """
        if self.classification() == other.classification():
            subsume = False
            for sparam, oparam in zip(self.params, other.params):
                if sparam is Any and oparam is not Any:
                    subsume = True
                elif sparam != oparam:
                    return False
            return subsume
        else:
            return False

    def numParams(self):
        return len(self.params)

    def __repr__(self):
        return "%s(code=%s, self=%r, params=%r)" % (
            type(self).__name__,
            self.code.codeName(),
            self.selfparam,
            self.params,
        )
