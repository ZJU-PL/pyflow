"""Constraint system for CPA (Constraint-based Analysis).

This module implements the constraint-based analysis system using a worklist algorithm.
Constraints represent relationships between abstract values (slots) in the store graph
and are solved iteratively until a fixed point is reached.

The constraint system operates on:
- Store graph slots: Abstract storage locations for variables and objects
- Extended types: Abstract representations of Python types and objects
- Operation contexts: Context-sensitive operation information

Key constraint types:
- AssignmentConstraint: Models variable assignments (x = y)
- IsConstraint: Models identity checks (x is y)
- LoadConstraint/StoreConstraint: Model object field access
- AllocateConstraint: Models object creation
- CallConstraint: Models function calls with context sensitivity
- Switch constraints: Model conditional branching
"""

import itertools
from pyflow.analysis.storegraph import storegraph
from pyflow.analysis.storegraph import canonicalobjects
from pyflow.analysis.storegraph import extendedtypes
from pyflow.analysis import cpasignature
from pyflow import analysis  # ensure 'analysis.cpasignature' references resolve

from pyflow.util.python import calling
from pyflow.util import tvl
from pyflow.util.monkeypatch import xtypes

# HACK to testing if a object is a bool True/False...
from pyflow.language.python import ast, program


def slotRefs(slot):
    """Get the set of type references from a slot node.
    
    This utility function extracts the extended types that a slot may hold.
    It handles special cases:
    - None slots: Return singleton tuple with None
    - DoNotCare slots: Return Any type (megamorphic)
    - Normal slots: Return the slot's refs set
    
    Args:
        slot: SlotNode, None, or DoNotCare
        
    Returns:
        Tuple of ExtendedType objects (or None/Any special values)
    """
    if slot is None:
        # Not collected.
        return (None,)
    elif slot is analysis.cpasignature.DoNotCare:
        # Automatically megamorphic.
        return (analysis.cpasignature.Any,)
    else:
        return slot.refs


class Constraint(object):
    """Base class for all constraints in the CPA system.
    
    Constraints represent relationships between abstract values that must be maintained
    during analysis. The constraint solver uses a worklist algorithm:
    1. Constraints are marked as "dirty" when their inputs change
    2. Dirty constraints are processed from the worklist
    3. Processing may mark other constraints as dirty
    4. Process continues until fixed point (no dirty constraints)
    
    Each constraint:
    - Observes input slots (reads())
    - Updates output slots (writes())
    - Can be marked dirty and processed
    
    Attributes:
        sys: The CPA system instance (InterproceduralDataflow)
        dirty: Boolean flag indicating if constraint needs re-evaluation
    """
    __slots__ = "sys", "dirty"

    def __init__(self, sys):
        """Initialize a constraint.
        
        Args:
            sys: The CPA system instance
        """
        self.dirty = False
        self.sys = sys
        self.attach()

    def process(self):
        """Process this constraint (called by worklist algorithm).
        
        Asserts that the constraint is dirty, then clears the dirty flag and
        calls update() to perform the actual constraint processing.
        
        Raises:
            AssertionError: If constraint is not dirty when processed
        """
        assert self.dirty
        self.dirty = False
        self.update()

    def update(self):
        """Update the constraint based on current slot values.
        
        Subclasses must implement this method to define the constraint's behavior.
        This method is called when the constraint is processed from the worklist.
        
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError

    def mark(self):
        """Mark this constraint as dirty and add it to the worklist.
        
        Called when input slots change, indicating this constraint needs
        re-evaluation. Only adds to worklist if not already dirty.
        """
        if not self.dirty:
            self.dirty = True
            self.sys.dirty.append(self)

    def getBad(self):
        """Get slots that this constraint reads but have no type information.
        
        Returns:
            List of SlotNodes that are read but have no refs (unresolved)
        """
        return [
            slot for slot in self.reads() if slot is not None and not slotRefs(slot)
        ]

    def check(self, console):
        """Check for unresolved dependencies and report them.
        
        Reports slots that this constraint reads but have no type information,
        which indicates incomplete analysis or missing type information.
        
        Args:
            console: Console object for output
        """
        bad = self.getBad()

        if bad:
            console.verbose_output("Unresolved %r:" % self.name())
            for slot in bad:
                console.verbose_output("\t%r" % slot)
                if hasattr(slot.slotName, "context"):
                    console.verbose_output("\t%r" % slot.slotName.context)
            console.verbose_output("")


class CachedConstraint(Constraint):
    """Base class for constraints that cache combinations of input types.
    
    Many constraints need to consider all combinations of types from multiple
    input slots. This class provides caching to avoid redundant work:
    - Tracks which type combinations have been processed
    - Only calls concreteUpdate() for new combinations
    - Uses Cartesian product of input slot types
    
    This is used by constraints like IsConstraint, LoadConstraint, CallConstraint
    that need to consider multiple type combinations.
    
    Attributes:
        observing: Tuple of slots this constraint observes (reads)
        cache: Set of (type1, type2, ...) tuples that have been processed
    """
    __slots__ = "observing", "cache"

    def __init__(self, sys, *args):
        """Initialize a cached constraint.
        
        Args:
            sys: The CPA system instance
            *args: Variable number of slots to observe
        """
        self.observing = args
        self.cache = set()

        Constraint.__init__(self, sys)

    def update(self):
        """Update constraint by processing all type combinations.
        
        Generates Cartesian product of all input slot types and calls
        concreteUpdate() for each new combination. Uses cache to avoid
        redundant processing.
        """
        values = [slotRefs(slot) for slot in self.observing]

        for args in itertools.product(*values):
            if not args in self.cache:
                self.cache.add(args)
            self.concreteUpdate(*args)

    def attach(self):
        """Attach this constraint to the system and register dependencies.
        
        Registers the constraint with the system and sets up read dependencies
        on observed slots. If no valid slots are observed, marks constraint
        immediately (for constraints that don't depend on slots).
        """
        self.sys.constraint(self)

        depends = False
        for slot in self.observing:
            if slot is not None and slot is not analysis.cpasignature.DoNotCare:
                slot.dependsRead(self)
                depends = True

        if not depends:
            # Nothing will trigger this constraint...
            self.mark()

    def name(self):
        """Get name of this constraint for debugging.
        
        Returns:
            String representation of the operation
        """
        return self.op.op

    def reads(self):
        """Get slots that this constraint reads.
        
        Returns:
            Tuple of SlotNodes that this constraint observes
        """
        return self.observing

    def writes(self):
        """Get slots that this constraint writes.
        
        Returns:
            Tuple containing the target slot (subclasses override)
        """
        return (self.target,)


class AssignmentConstraint(Constraint):
    """Constraint for variable assignments (x = y).
    
    Models data flow from source slot to destination slot. When the source slot's
    types change, this constraint propagates them to the destination slot.
    
    This is the most fundamental constraint type, representing direct data flow
    between variables. Used for:
    - Direct assignments: x = y
    - Parameter passing: func(x) where x flows to parameter
    - Return value propagation: return x where x flows to caller
    
    Attributes:
        sourceslot: SlotNode representing the source of the assignment
        destslot: SlotNode representing the destination of the assignment
    """
    __slots__ = "sourceslot", "destslot"

    def __init__(self, sys, sourceslot, destslot):
        """Initialize an assignment constraint.
        
        Args:
            sys: The CPA system instance
            sourceslot: Source slot (must be SlotNode)
            destslot: Destination slot (SlotNode or DoNotCare)
            
        Note:
            If destslot is DoNotCare, the constraint is not created (early return)
        """
        assert isinstance(sourceslot, storegraph.SlotNode), sourceslot
        # Handle DoNotCare case - if destslot is DoNotCare, we don't need to create this constraint
        if destslot is analysis.cpasignature.DoNotCare:
            return
        
        assert isinstance(destslot, storegraph.SlotNode), destslot

        self.sourceslot = sourceslot
        self.destslot = destslot

        Constraint.__init__(self, sys)

    def update(self):
        """Update destination slot with types from source slot.
        
        Propagates all types from sourceslot to destslot using the slot's
        update() method, which handles type merging and constraint propagation.
        """
        self.destslot = self.destslot.update(self.sourceslot)

    def attach(self):
        """Attach constraint and register dependencies.
        
        Registers read dependency on sourceslot and write dependency on destslot,
        so the constraint is triggered when source changes and updates destination.
        """
        self.sys.constraint(self)
        self.sourceslot.dependsRead(self)
        self.destslot.dependsWrite(self)

    def name(self):
        """Get string representation for debugging.
        
        Returns:
            String showing source -> destination
        """
        return "%r -> %r" % (self.sourceslot, self.destslot)

    def reads(self):
        """Get slots read by this constraint.
        
        Returns:
            Tuple containing sourceslot
        """
        return (self.sourceslot,)

    def writes(self):
        """Get slots written by this constraint.
        
        Returns:
            Tuple containing destslot
        """
        return (self.destslot,)


class IsConstraint(CachedConstraint):
    """Constraint for identity checks (x is y).
    
    Models Python's 'is' operator, which checks object identity (not equality).
    This constraint determines when two objects may be the same object and propagates
    boolean results to the target slot.
    
    The constraint considers all combinations of types from left and right slots,
    and determines if they can be the same object based on:
    - Type compatibility (must be same Python type)
    - Object identity (existing objects must match exactly)
    - Constant pooling (constants may be ambiguous)
    
    Attributes:
        op: Operation context for this constraint
        left: Left operand slot
        right: Right operand slot
        target: Target slot for boolean result
        t: Whether True result has been emitted
        f: Whether False result has been emitted
    """
    __slots__ = "op", "left", "right", "target", "t", "f"

    def __init__(self, sys, op, left, right, target):
        """Initialize an identity check constraint.
        
        Args:
            sys: The CPA system instance
            op: Operation context
            left: Left operand slot (must be SlotNode)
            right: Right operand slot (must be SlotNode)
            target: Target slot for result (must not be None)
        """
        assert target is not None
        assert isinstance(left, storegraph.SlotNode), type(left)
        assert isinstance(right, storegraph.SlotNode), type(right)

        self.op = op
        self.left = left
        self.right = right
        self.target = target

        self.t = False
        self.f = False

        CachedConstraint.__init__(self, sys, left, right)

    def emitTrue(self):
        if not self.t:
            self.t = True
            self.emitConstant(True)

    def emitFalse(self):
        if not self.f:
            self.f = True
            self.emitConstant(False)

    def emitConstant(self, pyobj):
        obj = self.sys.extractor.getObject(pyobj)
        xtype = self.sys.canonical.existingType(obj)
        self.target.initializeType(xtype)
        # self.sys.createAssign(field, self.target)

    def concreteUpdate(self, leftType, rightType):
        if self.t and self.f:
            return

        lpt = leftType.obj.pythonType()
        rpt = rightType.obj.pythonType()

        if lpt is not rpt:
            # print("type mismatch")
            self.emitFalse()
        elif leftType.isExisting() and rightType.isExisting():
            if leftType.obj is rightType.obj:
                # print("existing match")
                self.emitTrue()
            else:
                # print("existing mismatch")
                self.emitFalse()
        elif isinstance(lpt, xtypes.ConstantTypes):
            # May be pooled later, which creates ambiguity
            # print("ambiguous constant")
            self.emitTrue()
            self.emitFalse()
        elif leftType is rightType:
            # More that one of this object may be created...
            # print("ambiguous xtype match")
            self.emitTrue()
            self.emitFalse()
        else:
            # Not the same object, will not be pooled.
            # print("xtype mistpatch")
            self.emitFalse()


class LoadConstraint(CachedConstraint):
    """Constraint for loading values from object fields (x = obj.field).
    
    Models reading a field from an object, where:
    - expr is the object being accessed
    - key is the field name/index being accessed
    - target is where the loaded value goes
    
    The constraint considers all combinations of object types and key types,
    and creates field accesses in the store graph. If target is None, the
    load is being discarded (e.g., in a descriptive stub).
    
    Attributes:
        op: Operation context for logging
        expr: SlotNode for the object being accessed
        slottype: String indicating slot type ("Attribute", "Array", etc.)
        key: SlotNode for the field name/index
        target: SlotNode for the loaded value (or None if discarded)
    """
    __slots__ = "op", "expr", "slottype", "key", "target"

    def __init__(self, sys, op, expr, slottype, key, target):
        """Initialize a load constraint.
        
        Args:
            sys: The CPA system instance
            op: Operation context
            expr: Object slot (must be SlotNode)
            slottype: Type of slot ("Attribute", "Array", etc.)
            key: Field name/index slot (must be SlotNode)
            target: Target slot for loaded value (may be None)
        """
        assert isinstance(expr, storegraph.SlotNode), type(expr)
        assert isinstance(key, storegraph.SlotNode), type(key)

        self.op = op
        self.expr = expr
        self.slottype = slottype
        self.key = key
        self.target = target

        CachedConstraint.__init__(self, sys, expr, key)

    def concreteUpdate(self, exprType, keyType):
        assert keyType.isExisting() or keyType.isExternal(), keyType

        obj = self.expr.region.object(exprType)
        name = self.sys.canonical.fieldName(self.slottype, keyType.obj)

        if self.target:
            field = obj.field(name, self.target.region)
            self.sys.createAssign(field, self.target)
        else:
            # The load is being discarded.  This is probally in a
            # descriptive stub.  As such, we want to log the read.
            field = obj.field(name, self.expr.region.group.regionHint)

        self.sys.logRead(self.op, field)


class StoreConstraint(CachedConstraint):
    """Constraint for storing values to object fields (obj.field = x).
    
    Models writing a value to an object field, where:
    - expr is the object being modified
    - key is the field name/index
    - value is the value being stored
    
    The constraint creates field writes in the store graph and logs the
    modification for tracking purposes.
    
    Attributes:
        op: Operation context for logging
        expr: SlotNode for the object being modified
        slottype: String indicating slot type ("Attribute", "Array", etc.)
        key: SlotNode for the field name/index
        value: SlotNode for the value being stored
    """
    __slots__ = "op", "expr", "slottype", "key", "value"

    def __init__(self, sys, op, expr, slottype, key, value):
        """Initialize a store constraint.
        
        Args:
            sys: The CPA system instance
            op: Operation context
            expr: Object slot
            slottype: Type of slot ("Attribute", "Array", etc.)
            key: Field name/index slot
            value: Value slot to store
        """
        self.op = op
        self.expr = expr
        self.slottype = slottype
        self.key = key
        self.value = value

        CachedConstraint.__init__(self, sys, expr, key)

    def concreteUpdate(self, exprType, keyType):
        assert keyType.isExisting() or keyType.isExternal(), keyType

        obj = self.expr.region.object(exprType)
        name = self.sys.canonical.fieldName(self.slottype, keyType.obj)
        field = obj.field(name, self.value.region)

        self.sys.createAssign(self.value, field)
        self.sys.logModify(self.op, field)

    def writes(self):
        return ()


class AllocateConstraint(CachedConstraint):
    """Constraint for object allocation (obj = MyClass()).
    
    Models object creation/instantiation. When the type slot contains a type,
    this constraint creates an extended instance type and initializes the target
    slot with it. The allocation is logged for tracking purposes.
    
    Attributes:
        op: Operation context for logging
        type_: SlotNode containing the type to instantiate
        target: SlotNode where the new instance is stored
    """
    __slots__ = "op", "type_", "target"

    def __init__(self, sys, op, type_, target):
        """Initialize an allocation constraint.
        
        Args:
            sys: The CPA system instance
            op: Operation context
            type_: Type slot (must contain a type)
            target: Target slot for the new instance
        """
        self.op = op
        self.type_ = type_
        self.target = target

        CachedConstraint.__init__(self, sys, type_)

    def concreteUpdate(self, type_):
        if type_.obj.isType():
            xtype = self.sys.extendedInstanceType(
                self.op.context, type_, id(self.op.op)
            )
            obj = self.target.initializeType(xtype)
            self.sys.logAllocation(self.op, obj)

    def attach(self):
        CachedConstraint.attach(self)
        self.target.dependsWrite(self)


class CheckConstraint(CachedConstraint):
    __slots__ = "op", "expr", "slottype", "key", "target"

    def __init__(self, sys, op, expr, slottype, key, target):
        assert isinstance(expr, storegraph.SlotNode), type(expr)
        assert isinstance(key, storegraph.SlotNode), type(key)
        assert target

        self.op = op
        self.expr = expr
        self.slottype = slottype
        self.key = key
        self.target = target

        CachedConstraint.__init__(self, sys, expr, key)

    def concreteUpdate(self, exprType, keyType):
        assert keyType.isExisting() or keyType.isExternal(), keyType

        self.expr = self.expr.getForward()

        obj = self.expr.region.object(exprType)
        name = self.sys.canonical.fieldName(self.slottype, keyType.obj)

        slot = obj.field(name, obj.region.group.regionHint)

        con = SimpleCheckConstraint(self.sys, self.op, slot, self.target)

        # Constraints are usually not marked based on an existing null...
        if slot.null:
            con.mark()


class SimpleCheckConstraint(Constraint):
    __slots__ = "op", "slot", "target", "refs", "null"

    def __init__(self, sys, op, slot, target):
        self.op = op
        self.slot = slot
        self.target = target

        self.refs = False
        self.null = False

        Constraint.__init__(self, sys)

    def emit(self, pyobj):
        obj = self.sys.extractor.getObject(pyobj)
        xtype = self.sys.canonical.existingType(obj)

        # HACK initalize type implies then reference is never null...
        # Make sound?
        cobj = self.target.initializeType(xtype)
        assert cobj is not None
        self.sys.logAllocation(self.op, cobj)

    def update(self):
        if not self.refs and self.slot.refs:
            self.sys.logRead(self.op, self.slot)
            self.emit(True)
            self.refs = True

        if not self.null and self.slot.null:
            self.sys.logRead(self.op, self.slot)
            self.emit(False)
            self.null = True

    def attach(self):
        self.sys.constraint(self)
        self.slot.dependsRead(self)
        self.target.dependsWrite(self)

    def name(self):
        return self.op.op

    def reads(self):
        # Reads no locals.
        return ()

    def write(self):
        return (self.target,)


# Resolves the type of the expression, varg, and karg
class AbstractCallConstraint(CachedConstraint):
    """Base class for function call constraints.
    
    Models function calls with context sensitivity. This constraint resolves:
    - The callee function (from selfarg/expr)
    - Variable arguments (*args) length
    - Keyword arguments (**kwargs)
    
    For each combination of callee type and argument types, it creates a
    SimpleCallConstraint to handle the actual call binding.
    
    This is an abstract base class - subclasses must implement getCode() to
    determine which function is being called.
    
    Attributes:
        op: Operation context for the call
        selfarg: SlotNode for 'self' argument (or None)
        args: List of SlotNodes for positional arguments
        kwds: List of keyword arguments (currently unused)
        vargs: SlotNode for *args tuple (or None)
        kargs: SlotNode for **kwargs dict (or None)
        targets: List of SlotNodes for return values (or None)
    """
    __slots__ = "op", "selfarg", "args", "kwds", "vargs", "kargs", "targets"

    def __init__(self, sys, op, selfarg, args, kwds, vargs, kargs, targets):
        """Initialize an abstract call constraint.
        
        Args:
            sys: The CPA system instance
            op: Operation context (must be OpContext)
            selfarg: Self argument slot (or None)
            args: List/tuple of argument slots
            kwds: Keyword arguments (must be empty currently)
            vargs: Variable arguments slot (or None)
            kargs: Keyword arguments slot (or None)
            targets: Return value slots (or None)
        """
        assert isinstance(op, canonicalobjects.OpContext), type(op)
        assert isinstance(args, (list, tuple)), args
        assert not kwds, kwds
        assert targets is None or isinstance(targets, (list, tuple)), type(targets)

        self.op = op
        self.selfarg = selfarg
        self.args = args
        self.kwds = kwds
        self.vargs = vargs
        self.kargs = kargs

        self.targets = targets

        CachedConstraint.__init__(self, sys, selfarg, vargs, kargs)

    def getVArgLengths(self, vargsType):
        if vargsType is not None:
            try:
                assert isinstance(vargsType, extendedtypes.ExtendedType), type(
                    vargsType
                )
                vargsObj = self.vargs.region.object(vargsType)
                slotName = self.sys.storeGraph.lengthSlotName
                field = vargsObj.field(slotName, None)
                self.sys.logRead(self.op, field)

                lengths = []
                for lengthType in field.refs:
                    assert lengthType.isExisting()
                    lengths.append(lengthType.obj.pyobj)

                return lengths
            except Exception as e:
                return (0,)
        else:
            return (0,)

    def concreteUpdate(self, expr, vargs, kargs):
        for vlength in self.getVArgLengths(vargs):
            key = (expr, vargs, kargs, vlength)
            if not key in self.cache:
                self.cache.add(key)
                self.finalCombination(expr, vargs, kargs, vlength)

    def finalCombination(self, expr, vargs, kargs, vlength):
        code = self.getCode(expr)

        assert code, (
            "Attempted to call uncallable object:\n%r\n\nat op:\n%r\n\nwith args:\n%r\n\n"
            % (expr.obj, self.op, vargs)
        )

        callee = code.codeParameters()
        numArgs = len(self.args) + vlength
        # fix: 'util' was not imported here; use the already-imported 'calling'
        # For regular function calls, selfarg should be False since we don't have a self parameter
        has_self = self.selfarg is not None
        info = calling.callStackToParamsInfo(
            callee, has_self, numArgs, False, None, False
        )

        if info.willSucceed.maybeTrue():
            allslots = list(self.args)

            if vargs:
                vargsObj = self.vargs.region.object(vargs)
                for index in range(vlength):
                    slotName = self.sys.canonical.fieldName(
                        "Array", self.sys.extractor.getObject(index)
                    )
                    field = vargsObj.field(slotName, None)
                    allslots.append(field)
                    self.sys.logRead(self.op, field)

            # HACK this is actually somewhere between caller and callee...
            caller = calling.CallerArgs(
                self.selfarg, allslots, [], None, None, self.targets
            )

            SimpleCallConstraint(self.sys, self.op, code, expr, allslots, caller)

    def writes(self):
        if self.targets:
            return self.targets
        else:
            return ()


class CallConstraint(AbstractCallConstraint):
    __slots__ = ()

    def getCode(self, selfType):
        # Add null check for selfType
        if selfType is None or selfType.obj is None:
            return self.sys.extractor.stubs.exports["interpreter_call"]
        code = self.sys.getCall(selfType.obj)
        if code is None:
            return self.sys.extractor.stubs.exports["interpreter_call"]
        else:
            return code


# TODO If there's no selfv, vargs, or kargs, turn into a simple call?
class DirectCallConstraint(AbstractCallConstraint):
    __slots__ = ("code",)

    def __init__(self, sys, op, code, selfarg, args, kwds, vargs, kargs, target):
        assert code.isCode(), type(code)
        self.code = code

        AbstractCallConstraint.__init__(
            self, sys, op, selfarg, args, kwds, vargs, kargs, target
        )

    def getCode(self, selfType):
        return self.code


# Resolves argument types, given and exact function, self type,
# and list of argument slots.
# TODO make contextual?
class SimpleCallConstraint(CachedConstraint):
    __slots__ = "op", "code", "selftype", "slots", "caller", "megamorphic"

    def __init__(self, sys, op, code, selftype, slots, caller):
        assert isinstance(op, canonicalobjects.OpContext), type(op)
        assert code.isCode(), type(code)
        assert (
            selftype is None
            or selftype is analysis.cpasignature.Any
            or isinstance(selftype, extendedtypes.ExtendedType)
        ), selftype

        self.op = op
        self.code = code
        self.selftype = selftype
        self.slots = slots
        self.caller = caller

        self.megamorphic = [False for s in slots]

        CachedConstraint.__init__(self, sys, *slots)

    def concreteUpdate(self, *argsTypes):
        targetcontext = self.sys.canonicalContext(
            self.op, self.code, self.selftype, argsTypes
        )
        self.sys.bindCall(self.op, self.caller, targetcontext)

    def clearInvocations(self):
        # TODO eliminate constraints if target invocation is unused?
        self.cache.clear()
        self.sys.opInvokes[self.op].clear()

    def processMegamorphic(self, values):
        numValues = len(values)
        limit = 4 if len(values) < 3 else 3

        # Look for new megamorphic arguments
        changed = False
        for i, value in enumerate(values):
            if not self.megamorphic[i]:
                if len(value) > limit:
                    self.megamorphic[i] = True
                    changed = True

            if self.megamorphic[i]:
                values[i] = (analysis.cpasignature.Any,)
        return changed

    def update(self):
        values = [slotRefs(slot) for slot in self.observing]

        changed = self.processMegamorphic(values)

        if changed:
            self.clearInvocations()

        for args in itertools.product(*values):
            if not args in self.cache:
                self.cache.add(args)
            self.concreteUpdate(*args)

    def writes(self):
        if self.caller.returnargs:
            return self.caller.returnargs
        else:
            return ()


class DeferedSwitchConstraint(Constraint):
    def __init__(self, sys, extractor, cond, t, f):
        self.extractor = extractor
        self.cond = cond
        self.t = t
        self.f = f

        self.tDefered = True
        self.fDefered = True

        Constraint.__init__(self, sys)

    def getBranch(self, cobj):
        obj = cobj.obj
        if isinstance(obj, program.Object) and isinstance(
            obj.pyobj, (bool, int, float, str)
        ):
            return tvl.tvl(obj.pyobj)
        else:
            return tvl.TVLMaybe

    def updateBranching(self, branch):
        # Process defered branches, if they will be taken.
        if branch.maybeTrue() and self.tDefered:
            self.tDefered = False
            self.extractor(self.t)

        if branch.maybeFalse() and self.fDefered:
            self.fDefered = False
            self.extractor(self.f)

    def update(self):
        if self.tDefered or self.fDefered:
            for condType in self.cond.refs:
                self.updateBranching(self.getBranch(condType))

    def attach(self):
        self.sys.constraint(self)
        self.cond.dependsRead(self)

    def name(self):
        return "if %r" % self.cond

    def reads(self):
        return (self.cond,)

    def writes(self):
        return ()


class DeferedTypeSwitchConstraint(Constraint):
    def __init__(self, sys, op, extractor, cond, cases):
        self.op = op
        self.extractor = extractor
        self.cond = cond

        self.cases = cases
        self.switchSlots = [extractor.localSlot(case.expr) for case in cases]

        self.caseLUT = {}
        self.deferedLUT = {}
        for case in cases:
            for t in case.types:
                self.caseLUT[t.object] = case
            self.deferedLUT[case] = True

        self.cache = set()

        Constraint.__init__(self, sys)

    def update(self):
        for ref in self.cond.refs:
            # Only process a given xtype once.
            if ref in self.cache:
                continue
            self.cache.add(ref)

            # Log that the type field has been read.
            region = self.sys.storeGraph.regionHint
            refObj = region.object(ref)
            slotName = self.sys.storeGraph.typeSlotName
            field = refObj.field(slotName, region)
            self.sys.logRead(self.op, field)

            # Setup
            t = ref.obj.type
            case = self.caseLUT[t]
            slot = self.extractor.localSlot(case.expr)

            # Transfer the (filtered) reference
            # HACK this may poison regions?
            slot.initializeType(ref)

            # If the case has not be extracted yet, do it.
            if self.deferedLUT[case]:
                self.deferedLUT[case] = False
                self.extractor(case.body)

    def attach(self):
        self.sys.constraint(self)
        self.cond.dependsRead(self)
        for slot in self.switchSlots:
            slot.dependsWrite(self)

    def name(self):
        return "type switch %r" % self.cond

    def reads(self):
        return (self.cond,)

    def writes(self):
        return self.switchSlots
