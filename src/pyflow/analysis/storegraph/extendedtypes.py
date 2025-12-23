"""Extended type system for store graph.

Extended types provide rich type information for objects in the store graph.
They represent objects that cannot be merged during analysis, enabling
precise tracking of object identity and relationships.

Extended types include:
- ExternalObjectType: Objects passed as arguments
- ExistingObjectType: Objects found in memory (constants, globals)
- PathObjectType: Objects allocated along specific paths
- MethodObjectType: Bound method objects
- ContextObjectType: Context-sensitive objects
- IndexedObjectType: Wrapper for splitting objects
"""

from pyflow.util import canonical

# Extended types are names for objects that cannot be merged by the analysis.


# Abstract base class
class ExtendedType(canonical.CanonicalObject):
    """Base class for extended types.
    
    Extended types represent objects that maintain separate identities
    during analysis (cannot be merged). They provide rich type information
    beyond simple Python types.
    """
    __slots__ = ()

    def isExisting(self):
        """Check if this is an existing object type.
        
        Returns:
            bool: True if ExistingObjectType
        """
        return False

    def isExternal(self):
        """Check if this is an external object type.
        
        Returns:
            bool: True if ExternalObjectType
        """
        return False

    def isUnique(self):
        """Check if this object is unique (not aliased).
        
        Returns:
            bool: True if object is unique
        """
        return False

    def group(self):
        """Get the grouping key for this type.
        
        Used for region-based analysis to group related objects.
        
        Returns:
            object: Grouping key (typically self or obj)
        """
        return self

    def cpaType(self):
        """Get the CPA type for this extended type.
        
        CPA types are used for type-based splitting in inter-procedural
        analysis.
        
        Returns:
            ExtendedType: CPA type (may be self)
        """
        return self


# All extended types may as well have an "obj" slot,
# as the type of an object won't change.
class ExtendedObjectType(ExtendedType):
    """Base class for extended types with object references.
    
    ExtendedObjectType provides the common structure for extended types
    that reference program objects. Most extended types inherit from this.
    
    Attributes:
        obj: program.AbstractObject being typed
        op: Operation that created/accessed this object (or None)
    """
    __slots__ = "obj", "op"

    def __init__(self, obj, op):
        """Initialize an extended object type.
        
        Args:
            obj: AbstractObject being typed
            op: Operation context (or None)
        """
        self.obj = obj
        self.op = op
        self.setCanonical(obj, op)

    def group(self):
        """Get grouping key (the object itself).
        
        Returns:
            AbstractObject: The object for grouping
        """
        return self.obj


# Passed in as an argument
class ExternalObjectType(ExtendedObjectType):
    """Extended type for objects passed as arguments.
    
    ExternalObjectType represents objects that are passed into a function
    as arguments. These objects come from outside the function's scope.
    """
    __slots__ = ()

    def isExternal(self):
        """Type check: this is an external object.
        
        Returns:
            bool: Always True for ExternalObjectType
        """
        return True

    def __repr__(self):
        return "<external %r>" % self.obj


# Found in memory by the decompiler
class ExistingObjectType(ExtendedObjectType):
    """Extended type for existing objects (constants, globals).
    
    ExistingObjectType represents objects that exist in memory before
    function execution (constants, globals, etc.). These are discovered
    by the decompiler.
    """
    __slots__ = ()

    def isUnique(self):
        """Check if this existing object is unique.
        
        Returns:
            bool: True if object.isUnique()
        """
        return self.obj.isUnique()

    def isExisting(self):
        """Type check: this is an existing object.
        
        Returns:
            bool: Always True for ExistingObjectType
        """
        return True

    def __repr__(self):
        return "<existing %r>" % self.obj


# The basic extended type, even when the analysis is not path sensitive
# (the path will simply be None)
class PathObjectType(ExtendedObjectType):
    """Extended type for objects allocated along specific paths.
    
    PathObjectType represents objects allocated at specific program points.
    The path identifies the allocation site. If path is None, the analysis
    is not path-sensitive.
    
    Attributes:
        path: Path identifier (or None for path-insensitive)
    """
    __slots__ = ("path",)

    def __init__(self, path, obj, op):
        """Initialize a path object type.
        
        Args:
            path: Path identifier (or None)
            obj: AbstractObject being typed
            op: Operation context
        """
        self.path = path
        self.obj = obj
        self.op = op
        self.setCanonical(path, obj, op)

    def __repr__(self):
        if self.path is None:
            return "<path * %r>" % self.obj
        else:
            return "<path %d %r>" % (id(self.path), self.obj)


# Methods are typed according to the function and instance they are bound to
# TODO prevent type loops
class MethodObjectType(ExtendedObjectType):
    """Extended type for bound method objects.
    
    MethodObjectType represents bound methods (obj.method). Methods are
    typed by their function and instance to enable precise method call
    resolution.
    
    Attributes:
        func: ExtendedType for the function
        inst: ExtendedType for the instance
    """
    __slots__ = "func", "inst"

    def __init__(self, func, inst, obj, op):
        """Initialize a method object type.
        
        Args:
            func: ExtendedType for the function
            inst: ExtendedType for the instance
            obj: AbstractObject for the method
            op: Operation context
        """
        # assert isinstance(func, ExtendedType)
        # assert isinstance(inst, ExtendedType)
        self.func = func
        self.inst = inst
        self.obj = obj
        self.op = op
        self.setCanonical(func, inst, obj, op)

    def __repr__(self):
        return "<method %s %d %r>" % (id(self.func), id(self.inst), self.obj)


# Extended parameter objects need to be kept precise per context
# TODO make this based on the full context?
# TODO prevent type loops
class ContextObjectType(ExtendedObjectType):
    """Extended type for context-sensitive objects.
    
    ContextObjectType represents objects that are context-sensitive
    (e.g., parameters in different calling contexts). These objects
    maintain separate identities per context for precise inter-procedural
    analysis.
    
    Attributes:
        context: Context identifier (CPAContextSignature)
    """
    __slots__ = "context"

    def __init__(self, context, obj, op):
        """Initialize a context object type.
        
        Args:
            context: Context identifier
            obj: AbstractObject being typed
            op: Operation context
        """
        self.context = context
        self.obj = obj
        self.op = op
        self.setCanonical(context, obj, op)

    def __repr__(self):
        return "<context %d %r>" % (id(self.context), self.obj)


# Wraps another extended type
# Used for splitting objects
class IndexedObjectType(ExtendedObjectType):
    """Extended type wrapper for object splitting.
    
    IndexedObjectType wraps another ExtendedType with an index, enabling
    splitting of objects into multiple instances. Used when objects need
    to be distinguished (e.g., for type-based splitting).
    
    Attributes:
        xtype: Wrapped ExtendedType
        index: Index for distinguishing instances
    """
    __slots__ = "xtype", "index", "obj"

    def __init__(self, xtype, index):
        """Initialize an indexed object type.
        
        Args:
            xtype: ExtendedType to wrap
            index: Index for splitting
        """
        assert isinstance(xtype, ExtendedObjectType), xtype
        self.xtype = xtype
        self.index = index
        self.obj = xtype.obj
        self.setCanonical(xtype, index)

    def isUnique(self):
        return self.xtype.isUnique()

    def isExisting(self):
        return self.xtype.isExisting()

    def isExternal(self):
        return self.xtype.isExternal()

    def __repr__(self):
        return "<index %r %r>" % (self.index, self.xtype)
