"""
Function call argument and parameter matching utilities.

This module provides classes and functions for statically analyzing Python function
calls, matching call-site arguments to function parameters. It handles:
- Positional arguments
- Keyword arguments
- *args (variable positional arguments)
- **kwargs (variable keyword arguments)
- Default parameter values
- Method calls (self parameter)

The module uses three-valued logic (TVL) to represent uncertainty in static analysis,
where a call may succeed (TVLTrue), fail (TVLFalse), or be uncertain (TVLMaybe).

This is a core component of pyflow's interprocedural analysis, used to determine
which function calls are feasible and how arguments flow into parameters.
"""

__all__ = ["CallerArgs", "CalleeParams", "CallInfo", "Maybe", "callStackToParamsInfo"]

from pyflow.util.tvl import *


class CallerArgs(object):
    """
    Represents the arguments at a function call site.
    
    This class encapsulates all information about how a function is being called,
    including positional arguments, keyword arguments, and variable arguments.
    Used to model the caller's side of a function call during static analysis.
    
    Attributes:
        selfarg: The 'self' argument for method calls (None for regular functions)
        args: List/tuple of positional arguments
        kwds: List/tuple of keyword argument names (currently unused, kept for compatibility)
        vargs: Variable positional arguments (*args), or None if not present
        kargs: Variable keyword arguments (**kwargs), or None if not present
        returnargs: List/tuple of return value targets, or None
    """
    __slots__ = "selfarg", "args", "kwds", "vargs", "kargs", "returnargs"

    def __init__(self, selfarg, args, kwds, vargs, kargs, returnargs):
        """
        Initialize a CallerArgs object.
        
        Args:
            selfarg: The 'self' argument (object or None)
            args: List or tuple of positional arguments
            kwds: List or tuple of keyword argument names (deprecated)
            vargs: Variable positional arguments (*args) or None
            kargs: Variable keyword arguments (**kwargs) or None
            returnargs: List or tuple of return value targets, or None
        """
        assert isinstance(args, (list, tuple)), args
        assert isinstance(returnargs, (list, tuple)) or returnargs is None, returnargs

        self.selfarg = selfarg
        self.args = args
        self.kwds = kwds
        self.vargs = vargs
        self.kargs = kargs
        self.returnargs = returnargs

    def __repr__(self):
        return "args(self=%r, args=%r, kwds=%r, vargs=%r, kargs=%r)" % (
            self.selfarg,
            self.args,
            self.kwds,
            self.vargs,
            self.kargs,
        )

    def map(self, callback):
        """
        Apply a transformation function to all arguments.
        
        Creates a new CallerArgs object with all arguments transformed by the
        callback function. This is used during analysis to map abstract values
        or apply transformations to the call arguments.
        
        Args:
            callback: Function to apply to each argument
            
        Returns:
            CallerArgs: New CallerArgs object with transformed arguments
            
        Note:
            returnargs are not transformed as they represent return value targets,
            which have different semantics than input arguments.
        """
        selfarg = callback(self.selfarg)
        args = [callback(arg) for arg in self.args]
        assert not self.kwds
        kwds = []
        vargs = callback(self.vargs)
        kargs = callback(self.kargs)

        # HACK returnargs are by nature different?
        returnargs = self.returnargs

        return CallerArgs(selfarg, args, kwds, vargs, kargs, returnargs)


class CalleeParams(object):
    """
    Represents the parameter signature of a function definition.
    
    This class encapsulates all information about a function's parameters,
    including their names, default values, and whether the function accepts
    variable arguments. Used to model the callee's side of a function call
    during static analysis.
    
    Attributes:
        selfparam: The 'self' parameter for methods (object or None)
        params: List/tuple of parameter objects/values
        paramnames: List/tuple of parameter names (strings)
        defaults: List/tuple of default values for parameters with defaults
        vparam: Variable positional parameter (*args), or None if not present
        kparam: Variable keyword parameter (**kwargs), or None if not present
        returnparams: List/tuple of return parameter objects
    """
    __slots__ = (
        "selfparam",
        "params",
        "paramnames",
        "defaults",
        "vparam",
        "kparam",
        "returnparams",
    )

    def __init__(
        self, selfparam, params, paramnames, defaults, vparam, kparam, returnparams
    ):
        """
        Initialize a CalleeParams object.
        
        Args:
            selfparam: The 'self' parameter (object or None)
            params: List or tuple of parameter objects
            paramnames: List or tuple of parameter name strings
            defaults: List or tuple of default values
            vparam: Variable positional parameter (*args) or None
            kparam: Variable keyword parameter (**kwargs) or None
            returnparams: List or tuple of return parameter objects
        """
        assert isinstance(params, (list, tuple))
        assert isinstance(paramnames, (list, tuple))
        assert isinstance(returnparams, (list, tuple))

        self.selfparam = selfparam
        self.params = params
        self.paramnames = paramnames
        self.defaults = defaults
        self.vparam = vparam
        self.kparam = kparam
        self.returnparams = returnparams

    def __repr__(self):
        return "params(self=%r, params=%r, names=%r, vparam=%r, kparam=%r)" % (
            self.selfparam,
            self.params,
            self.paramnames,
            self.vparam,
            self.kparam,
        )


# Argument to parameter mapping rules:
# arg  -> param / vparam  (positional arg maps to param or *args)
# varg -> param / vparam  (variable arg maps to param or *args)
# kwd  -> param / kparam  (keyword arg maps to param or **kwargs)
# karg -> param / kparam  (variable keyword arg maps to param or **kwargs)


class PositionalTransfer(object):
    """
    Tracks the mapping of positional arguments to parameters.
    
    This class represents a transfer of arguments from a source range to a
    destination range. Used to track how positional arguments at the call site
    map to function parameters.
    
    Attributes:
        active: Whether this transfer is active (has arguments to transfer)
        sourceBegin: Starting index in the source (caller arguments)
        sourceEnd: Ending index in the source (exclusive)
        destinationBegin: Starting index in the destination (callee parameters)
        destinationEnd: Ending index in the destination (exclusive)
        count: Number of arguments being transferred
    """
    def __init__(self):
        """Initialize an inactive PositionalTransfer."""
        self.reset()

    def reset(self):
        """Reset the transfer to inactive state with zero count."""
        self.active = False
        self.sourceBegin = 0
        self.sourceEnd = 0
        self.destinationBegin = 0
        self.destinationEnd = 0
        self.count = 0

    def transfer(self, src, dst, count):
        """
        Set up a transfer from source to destination.
        
        Args:
            src: Starting index in source arguments
            dst: Starting index in destination parameters
            count: Number of arguments to transfer (must be > 0)
        """
        assert count > 0, count

        self.active = True
        self.sourceBegin = src
        self.sourceEnd = src + count

        self.destinationBegin = dst
        self.destinationEnd = dst + count

        self.count = count

    def __iter__(self):
        """
        Iterate over (source_index, destination_index) pairs.
        
        Yields:
            tuple: (source_index, destination_index) for each transferred argument
        """
        assert self.active or self.count == 0
        for i in range(self.count):
            yield self.sourceBegin + i, self.destinationBegin + i

    def __len__(self):
        """Return the number of arguments being transferred."""
        return self.count


class CallInfo(object):
    """
    Information about whether a function call will succeed and how arguments bind.
    
    This class tracks the result of matching call-site arguments to function
    parameters. It uses three-valued logic (TVL) to represent certainty:
    - TVLTrue: The call will definitely succeed
    - TVLFalse: The call will definitely fail
    - TVLMaybe: The call may or may not succeed (uncertain)
    
    Attributes:
        willSucceed: TVL value indicating if the call will succeed
        selfTransfer: Whether 'self' argument is being passed (for methods)
        argParam: PositionalTransfer for regular positional arguments -> parameters
        argVParam: PositionalTransfer for extra arguments -> *args parameter
        exceptions: Set of exception types that may be raised (e.g., TypeError)
        uncertainParam: Whether there are uncertain arguments that may fill parameters
        uncertainParamStart: Starting parameter index for uncertain arguments
        uncertainVParam: Whether uncertain arguments may go into *args
        uncertainVParamStart: Starting *args index for uncertain arguments
        certainKeywords: Set of parameter indices bound by keyword arguments
        defaults: Set of parameter indices that will use default values
    """
    def __init__(self):
        """Initialize CallInfo with default (uncertain) values."""
        self.willSucceed = TVLMaybe

        self.selfTransfer = False

        self.argParam = PositionalTransfer()
        self.argVParam = PositionalTransfer()

        self.exceptions = set()

        self.uncertainParam = False
        self.uncertainParamStart = 0

        self.uncertainVParam = False
        self.uncertainVParamStart = 0

        self.certainKeywords = set()
        self.defaults = set()

    def isBound(self, param):
        """
        Check if a parameter is bound (will receive a value).
        
        A parameter is bound if:
        - It receives a positional argument (TVLTrue)
        - It receives a keyword argument (TVLTrue)
        - It has a default value and no argument (TVLTrue)
        - It may receive an uncertain argument (TVLMaybe)
        - Otherwise, it's not bound (TVLFalse)
        
        Args:
            param: Parameter index to check
            
        Returns:
            TVL value: TVLTrue if definitely bound, TVLFalse if definitely not,
                     TVLMaybe if uncertain
        """
        if param < self.argParam.count:
            return TVLTrue
        elif param in self.certainKeywords:
            return TVLTrue
        elif param in self.defaults:
            return TVLTrue
        elif self.uncertainParam:
            return TVLMaybe
        else:
            return TVLFalse

    def _mustFail(self):
        """
        Mark this call as definitely failing.
        
        Resets all transfer information and marks willSucceed as TVLFalse.
        Used when analysis determines the call cannot succeed (e.g., too many
        arguments, missing required parameters).
        
        Returns:
            self: For method chaining
        """
        self.willSucceed = TVLFalse

        self.selfTransfer = False

        self.argParam.reset()
        self.argVParam.reset()

        self.uncertainParam = False
        self.uncertainVParam = False

        self.certainKeywords.clear()
        self.defaults.clear()

        return self


def bindDefaults(callee, info):
    """
    Mark parameters with default values that may be used.
    
    Parameters with default values are only used if they're not bound by
    arguments. This function checks each parameter with a default and adds
    it to info.defaults if it's not definitely bound.
    
    Args:
        callee: CalleeParams object describing the function signature
        info: CallInfo object to update with default bindings
    """
    ### Handle default values ###
    numDefaults = len(callee.defaults)
    numParams = len(callee.params)
    defaultOffset = numParams - numDefaults
    for i in range(defaultOffset, numParams):
        bound = info.isBound(i)
        # If it isn't bound for sure, it may default.
        if bound.maybeFalse():
            info.defaults.add(i)


def isDoNotCare(node):
    """
    Check if a node represents a "do not care" value in the analysis.
    
    Some analysis nodes may be marked as "do not care", meaning their value
    is irrelevant for the current analysis. This is used to skip certain
    checks or optimizations.
    
    Args:
        node: Analysis node to check
        
    Returns:
        bool: True if the node is marked as "do not care"
        
    Note:
        This is a hack to check for a specific method on nodes. Nodes that
        don't care about their value implement isDoNotCare() returning True.
    """
    return hasattr(node, "isDoNotCare") and node.isDoNotCare()  # HACK oh my, yes.


def callStackToParamsInfo(
    callee, selfarg, numArgs, uncertainVArgs, certainKwds, isUncertainKwds
):
    """
    Match call-site arguments to function parameters and determine call feasibility.
    
    This is the core function for static call analysis. It takes information about
    a function call and determines:
    1. Whether the call will succeed, fail, or is uncertain (using TVL)
    2. How arguments map to parameters (positional, keyword, *args, **kwargs)
    3. Which parameters will use default values
    4. What exceptions might be raised (e.g., TypeError for mismatched arguments)
    
    The function handles:
    - Method calls (self parameter)
    - Positional arguments
    - Keyword arguments
    - Variable positional arguments (*args)
    - Default parameter values
    - Uncertain arguments (when analysis cannot determine exact count)
    
    Args:
        callee: CalleeParams object describing the function's parameter signature
        selfarg: Whether a 'self' argument is being passed (True/False)
        numArgs: Number of positional arguments being passed
        uncertainVArgs: Whether there may be additional uncertain positional arguments
        certainKwds: Set of keyword argument names that are definitely being passed
        isUncertainKwds: Whether there may be additional uncertain keyword arguments
                         (currently must be False - not fully supported)
    
    Returns:
        CallInfo: Object containing information about argument binding and call success
        
    Raises:
        AssertionError: If callee is not a CalleeParams or if isUncertainKwds is True
        
    Example:
        >>> # Function: def foo(a, b, c=10): ...
        >>> callee = CalleeParams(None, [0, 1, 2], ["a", "b", "c"], [10], None, None, [])
        >>> info = callStackToParamsInfo(callee, False, 2, False, set(), False)
        >>> info.willSucceed
        TVLTrue  # Call succeeds: a and b provided, c uses default
        >>> info.defaults
        {2}  # Parameter c (index 2) uses default value
    """
    assert isinstance(callee, CalleeParams), callee
    assert isinstance(numArgs, int) and numArgs >= 0, numArgs

    assert not isUncertainKwds, isUncertainKwds

    info = CallInfo()

    # Handle 'self' parameter for method calls
    if isDoNotCare(callee.selfparam):
        info.selfTransfer = False
    elif callee.selfparam and selfarg:
        info.selfTransfer = True
    elif callee.selfparam is None and not selfarg:
        info.selfTransfer = False
    else:
        # Mismatch: method called without self, or function called with self
        info.exceptions.add(TypeError)
        return info._mustFail()

    # Exactly known parameters [0, exact)
    numParams = len(callee.params)

    arg = 0
    param = 0
    vparam = 0

    cleanTransfer = TVLTrue

    # arg -> param: Map positional arguments to regular parameters
    count = min(numArgs, numParams)
    if count > 0:
        info.argParam.transfer(arg, param, count)
        arg += count
        param += count

    # arg -> vparam: Extra arguments go into *args if available
    count = numArgs - arg
    if count > 0:
        if callee.vparam is not None:
            assert param == numParams
            info.argVParam.transfer(arg, vparam, count)
            arg += count
            vparam += count
        else:
            # Can't put extra args into vparam.
            info.exceptions.add(TypeError)
            return info._mustFail()

    # Parameters to fill with uncertain values [uncertain, inf)
    if param < numParams and uncertainVArgs:
        info.uncertainParam = True
        info.uncertainParamStart = param

    # Uncertain args will spill into vargs.
    if uncertainVArgs:
        if callee.vparam is not None:
            info.uncertainVParam = True
            info.uncertainVParamStart = vparam
        else:
            # Without a vparam, the uncertain arguments may overflow.
            info.exceptions.add(TypeError)
            cleanTransfer &= TVLMaybe

    ### Handle keywords that we are certain will be passed ###
    if certainKwds:
        paramMap = {}
        for i, name in enumerate(callee.paramnames):
            paramMap[name] = i

        for kwd in certainKwds:
            if kwd in paramMap:
                param = paramMap[kwd]
                bound = info.isBound(param)
                if bound.mustBeFalse():
                    info.certainKeywords.add(param)
                elif bound.mustBeTrue():
                    # got multiple values for keyword argument '%s'
                    info.exceptions.add(TypeError)
                    return info._mustFail()
                else:
                    # POSSIBLE: got multiple values for keyword argument '%s'
                    info.certainKeywords.add(param)
                    cleanTransfer &= TVLMaybe
                    # TODO may no fail
            elif callee.kparam is None:
                # got an unexpected keyword argument '%s'
                info.exceptions.add(TypeError)
                return info._mustFail()
            else:
                assert False, "Temporary limitation: cannot handle kparams"

    bindDefaults(callee, info)

    # Validate binding: all parameters must be bound for call to succeed
    completelyBound = TVLTrue
    for i in range(numParams):
        completelyBound &= info.isBound(i)

    info.willSucceed = completelyBound & cleanTransfer

    if info.willSucceed.maybeFalse():
        info.exceptions.add(TypeError)

    if info.willSucceed.mustBeFalse():
        info._mustFail()

    return info
