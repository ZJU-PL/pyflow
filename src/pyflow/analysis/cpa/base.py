"""Base module for CPA (Constraint-based Analysis) context management.

This module provides the core AnalysisContext class and utility functions for managing
analysis contexts in the constraint-based analysis system. Analysis contexts represent
different calling situations and enable context-sensitive inter-procedural analysis.

Key concepts:
- AnalysisContext: Represents a specific calling context with signature, operation path, and store graph group
- Context-sensitive analysis: Different contexts allow precise analysis by distinguishing calling situations
- Parameter binding: Connects caller arguments to callee parameters across function boundaries
"""

from pyflow.language.python import program, ast
import pyflow.util as util
# from pyflow.util.python import calling
import pyflow.util.canonical as canonical
import pyflow.analysis as analysis  # for analysis.cpasignature references
import pyflow.analysis.cpasignature as cpasignature


CanonicalObject = canonical.CanonicalObject

from pyflow.analysis.storegraph import extendedtypes
from pyflow.analysis.storegraph import storegraph

###########################
### Evaluation Contexts ###
###########################


def localSlot(sys, code, lcl, context):
    """Convert an AST local variable to a store graph slot node.
    
    This function maps a local variable from the AST representation to its corresponding
    slot in the store graph for a given analysis context. The slot represents the
    abstract storage location for the variable in the constraint system.
    
    Args:
        sys: The CPA system instance (InterproceduralDataflow)
        code: The code object containing the local variable
        lcl: The local variable AST node (ast.Local, ast.DoNotCare, or None)
        context: The analysis context in which the local appears
        
    Returns:
        A SlotNode representing the variable's storage location, or:
        - cpasignature.DoNotCare if the local is DoNotCare (megamorphic)
        - None if the local is None (not present)
        
    Raises:
        AssertionError: If lcl is an unexpected type
    """
    if isinstance(lcl, ast.Local):
        assert isinstance(lcl, ast.Local), type(lcl)
        name = sys.canonical.localName(code, lcl, context)
        return context.group.root(name)
    elif isinstance(lcl, ast.DoNotCare):
        return cpasignature.DoNotCare
    elif lcl is None:
        return None
    else:
        assert False, type(lcl)


def calleeSlotsFromContext(sys, context):
    """Extract callee parameter slots from an analysis context.
    
    This function extracts all parameter slots (self, positional, defaults, varargs,
    keyword args, and return parameters) from a function's code parameters and maps
    them to store graph slots in the given context.
    
    Args:
        sys: The CPA system instance
        context: The analysis context containing the function signature
        
    Returns:
        CalleeParams object containing:
        - selfparam: Slot for 'self' parameter (or None)
        - parameters: Tuple of slots for positional parameters
        - paramnames: Parameter names (from callee)
        - defaults: Default values (currently stored as objects, not slots)
        - vparam: Slot for *args parameter (or None)
        - kparam: Slot for **kwargs parameter (or None)
        - returnparams: List of slots for return values
    """
    code = context.signature.code

    callee = code.codeParameters()

    selfparam = localSlot(sys, code, callee.selfparam, context)
    parameters = tuple([localSlot(sys, code, p, context) for p in callee.params])
    if callee.defaults:
        defaults = callee.defaults  # HACK: defaults are stored as objects, not converted to slots
        # defualts = tuple([localSlot(sys, code, d, context) for d in callee.defaults])
    else:
        defaults = ()
    vparam = localSlot(sys, code, callee.vparam, context)
    kparam = localSlot(sys, code, callee.kparam, context)
    returnparams = [
        localSlot(sys, code, param, context) for param in callee.returnparams
    ]

    return util.python.calling.CalleeParams(
        selfparam, parameters, callee.paramnames, defaults, vparam, kparam, returnparams
    )


class AnalysisContext(CanonicalObject):
    """Represents a context-sensitive analysis context for inter-procedural analysis.
    
    An AnalysisContext combines:
    - signature: The CPA signature (function code + parameter types) for this context
    - opPath: The operation path (call stack) leading to this context
    - group: The store graph region group for this context
    
    Context sensitivity allows the analysis to distinguish between different calling
    situations. For example, a function called from different call sites may have
    different parameter types and behaviors, which are tracked separately.
    
    The context is canonicalized (via CanonicalObject) to ensure that equivalent
    contexts are represented by the same object, enabling efficient caching.
    
    Attributes:
        signature: CPASignature representing the function and its parameter types
        opPath: Tuple of operations representing the call path (or None for flow-insensitive)
        group: StoreGraph region group for this context's storage locations
    """
    __slots__ = "signature", "opPath", "group"

    def __init__(self, signature, opPath, group):
        """Initialize a new analysis context.
        
        Args:
            signature: CPASignature for this context
            opPath: Operation path (call stack) for context sensitivity
            group: StoreGraph region group for this context
        """
        self.signature = signature
        self.opPath = opPath
        self.group = group

        self.setCanonical(self.signature, self.opPath)

    def _bindObjToSlot(self, sys, obj, slot):
        """Bind an extended type object to a store graph slot.
        
        This establishes the connection between an abstract type representation and
        its storage location in the store graph. Both obj and slot must be None or
        both must be non-None (exclusive-or constraint).
        
        Args:
            sys: The CPA system instance
            obj: ExtendedType to bind (or None)
            slot: SlotNode to bind to (or None)
            
        Raises:
            AssertionError: If obj and slot are not both None or both non-None
        """
        assert not ((obj is None) ^ (slot is None)), (obj, slot)
        if obj is not None and slot is not None:
            assert isinstance(obj, extendedtypes.ExtendedType), type(obj)
            assert isinstance(slot, storegraph.SlotNode)

            slot.initializeType(obj)

    def vparamType(self, sys):
        """Get the extended type for variable arguments (*args) in this context.
        
        Variable arguments are represented as tuples, so this returns a context-specific
        tuple type that distinguishes varargs from different calling contexts.
        
        Args:
            sys: The CPA system instance
            
        Returns:
            ExtendedType representing the tuple type for *args in this context
        """
        return self._extendedParamType(sys, sys.tupleClass.typeinfo.abstractInstance)

    def _extendedParamType(self, sys, inst):
        """Create an extended parameter type named by this context.
        
        Extended parameter objects (varargs, kwargs) are named by the context they
        appear in, enabling context-sensitive analysis of these parameters.
        
        Args:
            sys: The CPA system instance
            inst: The abstract instance to wrap in an extended type
            
        Returns:
            ExtendedType named by this context
        """
        # Extended param objects are named by the context they appear in.
        return sys.canonical.contextType(self, inst, None)

    def _vparamSlot(self, sys, vparamObj, index):
        """Get the slot for a specific index in the variable arguments tuple.
        
        Variable arguments are stored as a tuple, and this method accesses individual
        elements by index. The slot name is derived from the index value.
        
        Args:
            sys: The CPA system instance
            vparamObj: The object node representing the varargs tuple
            index: The index into the varargs tuple
            
        Returns:
            SlotNode for the vararg element at the given index
        """
        slotName = sys.canonical.fieldName("Array", sys.extractor.getObject(index))
        field = vparamObj.field(slotName, self.group.regionHint)
        return field

    def invocationMaySucceed(self, sys):
        """Check if a function invocation with this context's signature may succeed.
        
        This performs a static check to determine if the function call is feasible
        based on the number and types of arguments. It helps avoid analyzing contexts
        that can never actually occur at runtime.
        
        Args:
            sys: The CPA system instance
            
        Returns:
            bool: True if the invocation may succeed (should be analyzed),
                  False if it will always fail (can be skipped)
        """
        sig = self.signature
        callee = calleeSlotsFromContext(sys, self)

        # info is not actually intrinsic to the context?
        info = util.python.calling.callStackToParamsInfo(
            callee, sig.selfparam is not None, sig.numParams(), False, 0, False
        )

        if info.willSucceed.maybeFalse():
            if info.willSucceed.mustBeFalse():
                print("Call to %r will always fail." % self.signature)
            else:
                print("Call to %r may fail." % self.signature)

        return info.willSucceed.maybeTrue()

    def initializeVParam(self, sys, cop, vparamSlot, length):
        """Initialize the variable arguments (*args) tuple for this context.
        
        This creates and initializes the tuple object that holds variable arguments,
        sets its length, and logs the allocation and modification operations.
        
        Args:
            sys: The CPA system instance
            cop: Operation context for logging
            vparamSlot: The slot node for the varargs parameter
            length: The number of variable arguments
            
        Returns:
            ObjectNode representing the initialized varargs tuple
        """
        vparamType = self.vparamType(sys)

        # Set the varg pointer
        # Ensures the object node is created.
        self._bindObjToSlot(sys, vparamType, vparamSlot)

        vparamObj = vparamSlot.initializeType(vparamType)
        sys.logAllocation(cop, vparamObj)  # Implicitly allocated

        # Set the length of the vparam tuple.
        lengthObjxtype = sys.canonical.existingType(sys.extractor.getObject(length))
        lengthSlot = vparamObj.field(
            sys.storeGraph.lengthSlotName, self.group.regionHint
        )
        self._bindObjToSlot(sys, lengthObjxtype, lengthSlot)
        sys.logModify(cop, lengthSlot)

        return vparamObj

    def initalizeParameter(self, sys, param, cpaType, arg):
        """Initialize a function parameter slot with its type or bind it to an argument.
        
        This method handles different cases:
        - None parameters: No parameter exists
        - DoNotCare: Parameter is megamorphic, no initialization needed
        - None type: Parameter type is None (e.g., from null iteration), skip
        - Any type: Create assignment constraint from argument to parameter
        - Concrete type: Initialize parameter slot with the type
        
        Args:
            sys: The CPA system instance
            param: The parameter slot node (or None/DoNotCare)
            cpaType: The extended type for this parameter (or None/Any)
            arg: The caller's argument slot (or None)
            
        Note:
            TODO: Skip initialization if context already bound for a different caller
        """
        if param is None:
            assert cpaType is None
            assert arg is None
        elif param is cpasignature.DoNotCare:
            pass
        elif cpaType is None:
            # Parameter type is None (from nullIter), skip initialization
            pass
        elif cpaType is cpasignature.Any:
            assert isinstance(param, storegraph.SlotNode)
            assert isinstance(arg, storegraph.SlotNode)
            sys.createAssign(arg, param)
        else:
            # TODO skip this if this context has already been bound
            # but for a different caller
            param.initializeType(cpaType)

    def bindParameters(self, sys, caller):
        """Bind caller arguments to callee parameters for this context.
        
        This is the core inter-procedural binding operation that connects a function
        call site (caller) to a function definition (callee) in this analysis context.
        It handles:
        - Self parameter binding (for methods)
        - Positional parameter binding
        - Default parameter values (when fewer args than params)
        - Variable arguments (*args) binding
        - Return value binding
        
        The binding creates constraints and initializes types in the store graph,
        enabling the constraint solver to propagate information across function boundaries.
        
        Args:
            sys: The CPA system instance
            caller: CallerArgs object containing the call site's arguments and return slots
        """
        sig = self.signature

        callee = calleeSlotsFromContext(sys, self)

        # Bind self parameter
        self.initalizeParameter(sys, callee.selfparam, sig.selfparam, caller.selfarg)

        # Bind the positional parameters
        numArgs = len(sig.params)
        numParam = len(callee.params)

        for arg, cpaType, param in zip(
            caller.args[:numParam], sig.params[:numParam], callee.params
        ):
            self.initalizeParameter(sys, param, cpaType, arg)

        # assert numArgs >= numParam
        # HACK bind defaults
        if numArgs < numParam:
            # Handle default parameter values when caller provides fewer arguments
            defaultOffset = len(callee.params) - len(callee.defaults)
            for i in range(numArgs, numParam):
                obj = callee.defaults[i - defaultOffset].object

                # Create and initialize an existing object slot for the default value
                name = sys.canonical.existingName(sig.code, obj, self)
                slot = self.group.root(name)
                slot.initializeType(sys.canonical.existingType(obj))

                # Transfer the default value to the parameter slot
                sys.createAssign(slot, callee.params[i])

        # An op context for implicit allocation (e.g., varargs tuple)
        cop = sys.canonical.opContext(sig.code, None, self)

        # Bind the vparams (variable arguments *args)
        if (
            callee.vparam is not None
            and callee.vparam is not analysis.cpasignature.DoNotCare
        ):
            # Initialize the varargs tuple with the correct length
            vparamObj = self.initializeVParam(
                sys, cop, callee.vparam, numArgs - numParam
            )

            # Bind each vararg element to its corresponding tuple slot
            for i in range(numParam, numArgs):
                arg = caller.args[i]
                cpaType = sig.params[i]
                param = self._vparamSlot(sys, vparamObj, i - numParam)
                self.initalizeParameter(sys, param, cpaType, arg)
                sys.logModify(cop, param)

        else:
            pass  # assert callee.vparam is not None or numArgs == numParam

        # Bind the kparams (keyword arguments **kwargs)
        # Note: Currently not supported (assertion ensures kparam is None)
        assert callee.kparam is None

        # Copy the return value(s) from callee return params to caller return args
        if caller.returnargs is not None:
            # Handle mismatched return parameters gracefully
            if len(callee.returnparams) != len(caller.returnargs):
                # This can happen with dynamically analyzed code
                # Use the minimum length to avoid index errors
                min_len = min(len(callee.returnparams), len(caller.returnargs))
                for param, arg in zip(
                    callee.returnparams[:min_len], caller.returnargs[:min_len]
                ):
                    sys.createAssign(param, arg)
            else:
                for param, arg in zip(callee.returnparams, caller.returnargs):
                    sys.createAssign(param, arg)

    def isAnalysisContext(self):
        """Check if this object is an analysis context.
        
        This is a type check method used by the analysis system to distinguish
        AnalysisContext objects from other types.
        
        Returns:
            bool: Always returns True for AnalysisContext instances
        """
        return True
