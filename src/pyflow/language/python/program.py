# Describes the program "image" in memory.

import collections
import inspect
import types

# HACK types are considered constant
# This allows issubclass(type, type) to be folded
# Types are almost constant, however, by fiat.
constantTypes = set((float, int, str, bool, type(None), type, types.CodeType))
lexicalConstantTypes = set((float, int, str, bool, type(None)))
poolableTypes = set((float, int, str, bool))


class ProgramDecl(object):
    """Base class for program declarations.
    
    ProgramDecl marks classes that represent program-level declarations
    (objects, types, etc.) in the program representation.
    """
    __slots__ = ()


class TypeInfo(object):
    """Type information for objects.
    
    TypeInfo associates type information with objects, including abstract
    instance information for type objects.
    
    Attributes:
        abstractInstance: Abstract instance for this type (if applicable)
    """
    __slots__ = "abstractInstance"

    def __init__(self):
        """Initialize type info."""
        self.abstractInstance = None


class AbstractObject(ProgramDecl):
    """Base class for all program objects.
    
    AbstractObject represents objects in the program, either concrete
    (wrapping Python values) or abstract (for analysis). It provides
    methods for querying object properties.
    
    Attributes:
        type: Type object for this object
    """
    __slots__ = "type", "__weakref__"

    def isType(self):
        """Check if this object is a type.
        
        Returns:
            bool: True if object is a type
        """
        return False

    def isAbstract(self):
        """Check if this object is abstract (not concrete).
        
        Returns:
            bool: True if object is abstract
        """
        return (self.type is not None and 
                hasattr(self.type, 'typeinfo') and 
                self.type.typeinfo is not None and 
                self.type.typeinfo.abstractInstance == self)

    def isConcrete(self):
        """Check if this object is concrete (not abstract).
        
        Returns:
            bool: True if object is concrete
        """
        return not self.isAbstract()

    def isConstant(self):
        """Check if this object is constant.
        
        Returns:
            bool: True if object is constant
        """
        return False

    def isLexicalConstant(self):
        """Check if this object is a lexical constant.
        
        Lexical constants are compile-time constants (literals).
        
        Returns:
            bool: True if object is lexical constant
        """
        return False

    def isUnique(self):
        """Check if this object is unique (not poolable).
        
        Unique objects cannot be pooled (shared) because they have identity.
        
        Returns:
            bool: True if object is unique
        """
        return self.isPreexisting() and self.pythonType() not in poolableTypes


def isConstant(pyobj):
    if isinstance(pyobj, (tuple, frozenset)):
        for item in pyobj:
            if not isConstant(item):
                return False
        return True
    else:
        return type(pyobj) in constantTypes


def isLexicalConstant(pyobj):
    if isinstance(pyobj, (tuple, frozenset)):
        for item in pyobj:
            if not isLexicalConstant(item):
                return False
        return True
    else:
        return type(pyobj) in lexicalConstantTypes


class Object(AbstractObject):
    """Concrete object wrapping a Python value.
    
    Object wraps a Python value (pyobj) and provides access to its
    attributes, array elements, dictionary items, and low-level fields.
    Objects are lazily initialized - data structures are allocated on demand.
    
    Attributes:
        pyobj: Python object being wrapped
        type: Type object for this object
        typeinfo: TypeInfo for this object
        slot: Dictionary mapping attribute names to objects
        array: Dictionary mapping array indices to objects
        dictionary: Dictionary mapping dictionary keys to objects
        lowlevel: Dictionary mapping low-level field names to objects
    """
    __slots__ = "pyobj", "type", "typeinfo", "slot", "array", "dictionary", "lowlevel"

    def __init__(self, pyobj):
        """Initialize object wrapper.
        
        Args:
            pyobj: Python object to wrap
            
        Raises:
            AssertionError: If pyobj is already a ProgramDecl
        """
        assert not isinstance(pyobj, ProgramDecl), "Tried to wrap a wrapper."
        self.pyobj = pyobj
        self.type = None  # Initialize type attribute
        self.typeinfo = None  # Initialize typeinfo attribute

    def allocateDatastructures(self, type_):
        """Allocate data structures for this object.
        
        Initializes slot, array, dictionary, and lowlevel dictionaries.
        Called lazily when data structures are first accessed.
        
        Args:
            type_: Type object for this object
        """
        # Even the simple ones are set lazily,
        # so early accesses become hard errors.
        self.type = type_
        self.typeinfo = None
        self.slot = {}
        self.array = {}
        self.dictionary = {}
        self.lowlevel = {}

    def isPreexisting(self):
        return True

    def isConstant(self):
        return isConstant(self.pyobj)

    def isLexicalConstant(self):
        return isLexicalConstant(self.pyobj)

    def isType(self):
        return isinstance(self.pyobj, type)

    def abstractInstance(self):
        assert self.isType()
        return self.typeinfo.abstractInstance

    def addSlot(self, name, obj):
        assert isinstance(name, Object), name
        assert isinstance(name.pyobj, str), name
        assert isinstance(obj, AbstractObject), obj
        self.slot[name] = obj

    def addDictionaryItem(self, key, value):
        assert isinstance(key, Object), key
        assert isinstance(value, AbstractObject), value
        self.dictionary[key] = value

    def addArrayItem(self, index, value):
        assert isinstance(index, Object), index
        assert isinstance(index.pyobj, int), index
        assert isinstance(value, AbstractObject), value
        self.array[index] = value

    def addLowLevel(self, name, obj):
        assert isinstance(name, Object), name
        assert isinstance(name.pyobj, str), name
        assert isinstance(obj, AbstractObject), obj
        self.lowlevel[name] = obj

    def getDict(self, fieldtype):
        if fieldtype == "LowLevel":
            d = self.lowlevel
        elif fieldtype == "Attribute":
            d = self.slot
        elif fieldtype == "Array":
            d = self.array
        elif fieldtype == "Dictionary":
            d = self.dictionary
        else:
            assert False, fieldtype
        return d

    def __repr__(self):
        if isinstance(self.pyobj, dict):
            # Simplifies large, global dictionaries.
            r = "dict" + repr(tuple(self.pyobj.keys()))
        else:
            r = repr(self.pyobj)

        if len(r) > 40:
            return "%s(%s...)" % (type(self).__name__, r[:37])
        else:
            return "%s(%s)" % (type(self).__name__, r)

    def pythonType(self):
        # self.type may be uninitialized, so go directly to the pyobj.
        return type(self.pyobj)


class ImaginaryObject(AbstractObject):
    """Abstract object for analysis (not a concrete Python value).
    
    ImaginaryObject represents abstract objects used during analysis.
    These objects don't correspond to concrete Python values but represent
    abstract concepts (e.g., "any list", "any function").
    
    Attributes:
        name: Name of the imaginary object
        preexisting: Whether object is preexisting (exists before analysis)
        type: Type object for this imaginary object
    """
    __slots__ = "name", "preexisting"

    def __init__(self, name, t, preexisting):
        """Initialize imaginary object.
        
        Args:
            name: Name of the imaginary object
            t: Type object (must be a type)
            preexisting: Whether object is preexisting
            
        Raises:
            AssertionError: If t is not a type
        """
        assert t.isType()
        self.name = name
        self.type = t
        self.preexisting = preexisting

    def __repr__(self):
        """String representation of imaginary object.
        
        Returns:
            str: String representation
        """
        return "%s(%s)" % (type(self).__name__, self.name)

    def isPreexisting(self):
        """Check if object is preexisting.
        
        Preexisting objects exist before analysis (e.g., hidden function stubs).
        
        Returns:
            bool: True if object is preexisting
        """
        # HACK imaginary objects may be prexisting
        # For example: hidden function stubs.
        return self.preexisting

    def pythonType(self):
        """Get Python type of this object.
        
        Returns:
            type: Python type object
        """
        return self.type.pyobj


# TODO create unique ID for hashable objects.
# Collect IDs from given type into abstract object.  (Should be a continguous range?)

# Namespaces (dicts)
# Objects
# Function
# Types - objects w/object model info?


def getPrev(t):
    mro = inspect.getmro(t)

    if len(mro) > 1:
        return mro[1]
    else:
        return t


class ProgramDescription(object):
    def __init__(self):
        self.objects = []
        self.functions = []
        self.callLUT = {}
        self.origin = {}

    def clusterObjects(self):
        children = collections.defaultdict(set)
        instances = collections.defaultdict(list)

        for obj in self.objects:
            assert obj.type != None, obj
            t = obj.type.pyobj

            instances[t].append(obj)

            prev = getPrev(t)

            while not t in children[prev] and t != prev:
                children[prev].add(t)
                t = prev
                prev = getPrev(t)

        count = len(self.objects)
        self.objects = []
        self.addChildren(children, instances, object)
        assert len(self.objects) == count

    def addChildren(self, c, i, t, tabs=""):
        # print(tabs, t, len(i[t]))
        self.objects.extend(i[t])
        for child in c[t]:
            self.addChildren(c, i, child, tabs + "\t")

    def bindCall(self, obj, func):
        assert isinstance(obj, AbstractObject), obj
        assert not isinstance(func, AbstractObject), func
        assert obj not in self.callLUT, obj
        self.callLUT[obj] = func
        self.origin[obj] = func.annotation.origin
