"""CPA (Constraint Propagation Analysis) signature management.

This module provides signature representation for context-sensitive analysis.
Signatures combine code with parameter types to create distinct analysis
contexts for different calling patterns.
"""

import itertools
from pyflow.util import canonical
from pyflow.analysis.storegraph import extendedtypes


def cpaArgOK(arg):
    """Check if an argument type is valid for CPA.
    
    Valid types are None, anyType, or ExtendedType.
    
    Args:
        arg: Argument type to check
        
    Returns:
        bool: True if valid CPA argument type
    """
    return arg is None or arg is anyType or isinstance(arg, extendedtypes.ExtendedType)


class CPAContextSignature(canonical.CanonicalObject):
    """Represents a function signature for context-sensitive analysis.
    
    Signatures combine code with parameter types to create distinct
    analysis contexts. Different calling patterns (different parameter
    types) get different signatures and contexts.
    
    Attributes:
        code: Function code object
        selfparam: Self parameter type (or None, or nullIter)
        params: List of positional parameter types
        vparams: List of variable parameter types (*args)
    """
    def __init__(self, code, selfparam, params, vparams):
        """Initialize a CPA context signature.
        
        Args:
            code: Function code object
            selfparam: Self parameter type (None, nullIter, or ExtendedType)
            params: List of positional parameter types
            vparams: List of variable parameter types
            
        Raises:
            AssertionError: If invalid argument types or too many vparams
        """
        assert cpaArgOK(selfparam), selfparam
        for param in params:
            assert cpaArgOK(param), param
        for param in vparams:
            assert cpaArgOK(param), param

        self.code = code
        self.selfparam = selfparam
        self.params = params
        self.vparams = vparams

        # Sanity check, probably a runaway loop in the analysis logic.
        assert len(vparams) < 30, code

        self.setCanonical(code, selfparam, params, vparams)

    def __repr__(self):
        return "cpa(%r, %r, %r, %r/%d)" % (
            self.code,
            self.selfparam,
            self.params,
            self.vparams,
            id(self),
        )


anyType = object()
nullIter = (None,)


class CPATypeSigBuilder(object):
    """Builds CPA signatures from call sites.
    
    This class extracts parameter types from call sites and builds
    CPA signatures for context-sensitive analysis. It handles:
    - Self parameters
    - Positional parameters
    - Variable parameters (*args)
    - Default parameters
    
    Attributes:
        analysis: IPAnalysis instance
        call: Call constraint being processed
        code: Function code being called
        selfparam: Self parameter type
        params: List of positional parameter types
        vparams: List of variable parameter types
    """
    def __init__(self, analysis, call, info):
        """Initialize signature builder.
        
        Args:
            analysis: IPAnalysis instance
            call: Call constraint (FlatCallConstraint)
            info: TransferInfo for parameter mapping
        """
        self.analysis = analysis
        self.call = call

        self.code = self.call.code
        self.selfparam = None
        self.params = [None for i in range(info.numParams())]
        self.vparams = [None for i in range(info.numVParams())]

        assert not info.numKParams()

    def unusedSelfParam(self):
        self.selfparam = nullIter

    def setSelfParam(self, value):
        if value is None:
            self.selfparam = nullIter
        else:
            self.selfparam = value

    def unusedParam(self, index):
        self.params[index] = nullIter

    def setParam(self, index, value):
        if value is None:
            self.params[index] = nullIter
        else:
            self.params[index] = value

    def unusedVParam(self, index):
        self.vparams[index] = nullIter

    def setVParam(self, index, value):
        if value is None:
            self.vparams[index] = nullIter
        else:
            self.vparams[index] = value

    def getSelfArg(self):
        if self.call.selfarg is None:
            return None
        return self.call.selfarg.typeSplit.types()

    def getArg(self, index):
        if index >= len(self.call.args) or self.call.args[index] is None:
            return None
        return self.call.args[index].typeSplit.types()

    def getVArg(self, index):
        if index >= len(self.call.vargSlots) or self.call.vargSlots[index] is None:
            return None
        return self.call.vargSlots[index].typeSplit.types()

    def getDefault(self, index):
        if index >= len(self.call.defaultSlots) or self.call.defaultSlots[index] is None:
            return None
        return self.call.defaultSlots[index].typeSplit.types()

    def setReturnArg(self, i, value):
        pass

    def getReturnParam(self, i):
        pass

    def flatten(self):
        flat = [self.selfparam]
        flat.extend(self.params)
        flat.extend(self.vparams)
        return flat

    def split(self, flat):
        psplit = len(self.params) + 1
        return flat[0], flat[1:psplit], flat[psplit:]

    def signatures(self):
        results = []
        for concrete in itertools.product(*self.flatten()):
            selfparam, params, vparams = self.split(concrete)

            sig = CPAContextSignature(self.code, selfparam, params, vparams)
            results.append(sig)

        return results


externalContext = CPAContextSignature(None, None, (), ())
