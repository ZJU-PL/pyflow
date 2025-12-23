"""Canonical naming for store graph objects.

This module provides canonical naming for objects, types, and slot names
in the store graph. Canonical naming ensures that equivalent objects
share the same name, enabling efficient comparison and merging.

Key components:
- SlotName classes: Names for storage locations (locals, existing, fields)
- Context classes: Names for operation and code contexts
- CanonicalObjects: Factory for creating canonical names
"""

from pyflow.util import canonical
from pyflow.language.python import program
from pyflow.util.monkeypatch import xcollections
from . import extendedtypes


class BaseSlotName(canonical.CanonicalObject):
    """Base class for slot names.
    
    Slot names identify storage locations in the store graph. They are
    canonicalized to ensure equivalent slots share the same name.
    """
    __slots__ = ()

    def isRoot(self):
        """Check if this is a root slot name (local or existing).
        
        Returns:
            bool: True if root slot
        """
        return False

    def isLocal(self):
        """Check if this is a local variable slot name.
        
        Returns:
            bool: True if LocalSlotName
        """
        return False

    def isExisting(self):
        """Check if this is an existing object slot name.
        
        Returns:
            bool: True if ExistingSlotName
        """
        return False

    def isField(self):
        """Check if this is a field slot name.
        
        Returns:
            bool: True if FieldSlotName
        """
        return False


class LocalSlotName(BaseSlotName):
    """Canonical name for local variable slots.
    
    LocalSlotName identifies a local variable in a specific code and
    context. Local variables are root slots in the store graph.
    
    Attributes:
        code: Code object containing the local
        local: AST Local node for the variable
        context: Analysis context (for context-sensitive analysis)
    """
    __slots__ = "code", "local", "context"

    def __init__(self, code, lcl, context):
        """Initialize a local slot name.
        
        Args:
            code: Code object
            lcl: AST Local node
            context: Analysis context
        """
        assert code.isCode(), type(code)
        # 		assert context.isAnalysisContext(), type(context)

        self.code = code
        self.local = lcl
        self.context = context
        self.setCanonical(code, lcl, context)

    def isRoot(self):
        return True

    def isLocal(self):
        return True

    def __repr__(self):
        return "local(%s, %r, %d)" % (
            self.code.codeName(),
            self.local,
            id(self.context),
        )


class ExistingSlotName(BaseSlotName):
    """Canonical name for existing object reference slots.
    
    ExistingSlotName identifies a reference to an existing object (constant,
    global, etc.) in a specific code and context. Existing objects are root
    slots in the store graph.
    
    Attributes:
        code: Code object containing the reference
        object: AbstractObject being referenced
        context: Analysis context
    """
    __slots__ = "code", "object", "context"

    def __init__(self, code, object, context):
        """Initialize an existing slot name.
        
        Args:
            code: Code object
            object: AbstractObject being referenced
            context: Analysis context
        """
        assert code.isCode(), type(code)
        # 		assert isinstance(obj, program.AbstractObject), type(obj)
        # 		assert context.isAnalysisContext(), type(context)

        self.code = code
        self.object = object
        self.context = context
        self.setCanonical(code, object, context)

    def isRoot(self):
        return True

    def isExisting(self):
        return True

    def __repr__(self):
        return "existing(%s, %r, %d)" % (
            self.code.codeName(),
            self.object,
            id(self.context),
        )


class FieldSlotName(BaseSlotName):
    """Canonical name for object field slots.
    
    FieldSlotName identifies a field of an object. Fields can be:
    - Attribute: Object attributes (obj.attr)
    - Array: Array elements (arr[i])
    - LowLevel: Low-level fields (type pointer, length)
    - Dictionary: Dictionary entries
    
    Attributes:
        type: Field type string ("Attribute", "Array", "LowLevel", "Dictionary")
        name: AbstractObject identifying the field (attribute name, index, etc.)
    """
    __slots__ = "type", "name"

    def __init__(self, ftype, name):
        """Initialize a field slot name.
        
        Args:
            ftype: Field type string
            name: AbstractObject identifying the field
        """
        assert isinstance(ftype, str), type(ftype)
        assert isinstance(name, program.AbstractObject), type(name)

        self.type = ftype
        self.name = name
        self.setCanonical(ftype, name)

    def isField(self):
        return True

    def __repr__(self):
        return "field(%s, %r)" % (self.type, self.name)


class OpContext(canonical.CanonicalObject):
    """Canonical name for operation context.
    
    OpContext identifies an operation (AST node) within a specific code
    and analysis context. Used for context-sensitive analysis.
    
    Attributes:
        code: Code object containing the operation
        op: AST operation node
        context: Analysis context
    """
    __slots__ = (
        "code",
        "op",
        "context",
    )

    def __init__(self, code, op, context):
        """Initialize operation context.
        
        Args:
            code: Code object
            op: AST operation node
            context: Analysis context
        """
        assert code.isCode(), type(code)
        assert context.isAnalysisContext(), type(context)

        self.setCanonical(code, op, context)

        self.code = code
        self.op = op
        self.context = context


class CodeContext(canonical.CanonicalObject):
    """Canonical name for code context.
    
    CodeContext identifies a code object within a specific analysis
    context. Used for context-sensitive analysis.
    
    Attributes:
        code: Code object
        context: Analysis context
    """
    __slots__ = (
        "code",
        "context",
    )

    def __init__(self, code, context):
        """Initialize code context.
        
        Args:
            code: Code object
            context: Analysis context
        """
        assert code.isCode(), type(code)
        assert context.isAnalysisContext(), type(context)

        self.setCanonical(code, context)

        self.code = code
        self.context = context

    def decontextualize(self):
        """Remove context, returning just the code.
        
        Returns:
            Code: Code object without context
        """
        return self.code


class CanonicalObjects(object):
    """Factory for creating canonical names and types.
    
    CanonicalObjects provides methods to create canonical names for:
    - Slot names: LocalSlotName, ExistingSlotName, FieldSlotName
    - Extended types: Various ExtendedType subclasses
    - Contexts: OpContext, CodeContext
    
    All names are cached to ensure canonicalization.
    
    Attributes:
        opContext: CanonicalCache for OpContext
        codeContext: CanonicalCache for CodeContext
        cache: Weak cache for slot names and types
        index: Counter for IndexedObjectType creation
    """
    def __init__(self):
        """Initialize canonical objects factory."""
        self.opContext = canonical.CanonicalCache(OpContext)
        self.codeContext = canonical.CanonicalCache(CodeContext)
        self.cache = xcollections.weakcache()

        self.index = 0

    def localName(self, code, lcl, context):
        return self.cache[LocalSlotName(code, lcl, context)]

    def existingName(self, code, obj, context):
        return self.cache[ExistingSlotName(code, obj, context)]

    def fieldName(self, type, fname):
        return self.cache[FieldSlotName(type, fname)]

    def externalType(self, obj):
        return self.cache[extendedtypes.ExternalObjectType(obj, None)]

    def existingType(self, obj):
        return self.cache[extendedtypes.ExistingObjectType(obj, None)]

    def pathType(self, path, obj, op):
        # HACK reduces the ops by 50%
        if obj.pythonType() in (float, int, bool, str):
            op = None
            path = None

        return self.cache[extendedtypes.PathObjectType(path, obj, op)]

    def methodType(self, func, inst, obj, op):
        return self.cache[extendedtypes.MethodObjectType(func, inst, obj, op)]

    def contextType(self, sig, obj, op):
        return self.cache[extendedtypes.ContextObjectType(sig, obj, op)]

    def indexedType(self, xtype):
        # Remove indexed object wrappers
        while isinstance(xtype, extendedtypes.IndexedObjectType):
            xtype = xtype.xtype

        if xtype.obj.pythonType() in (float, int, bool, str):
            return xtype

        index = self.index
        self.index += 1

        return self.cache[extendedtypes.IndexedObjectType(xtype, index)]
