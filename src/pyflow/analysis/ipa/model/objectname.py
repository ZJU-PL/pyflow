"""Object name representation for IPA.

ObjectName represents an abstract object in inter-procedural analysis.
It combines an ExtendedType (from store graph) with a qualifier that
indicates the object's scope and lifetime.
"""

from pyflow.analysis.storegraph import extendedtypes


class ObjectName(object):
    """Represents an abstract object in IPA.
    
    ObjectName combines type information (ExtendedType) with a qualifier
    that indicates scope and lifetime. Objects are canonicalized by
    (xtype, qualifier) pair in IPAnalysis.objs.
    
    Attributes:
        xtype: ExtendedType from store graph (type and object info)
        qualifier: Qualifier string (HZ, DN, UP, GLBL)
    """
    __slots__ = "xtype", "qualifier"

    def __init__(self, xtype, qualifier):
        """Initialize an object name.
        
        Args:
            xtype: ExtendedType from store graph
            qualifier: Qualifier string (HZ, DN, UP, GLBL)
        """
        assert isinstance(xtype, extendedtypes.ExtendedType), xtype
        self.xtype = xtype
        self.qualifier = qualifier

    def __repr__(self):
        """String representation for debugging.
        
        Returns:
            str: Representation showing type and qualifier
        """
        return "ao(%r, %s/%d)" % (self.xtype, self.qualifier, id(self))

    def cpaType(self):
        """Get CPA type for this object.
        
        Returns the type used in CPA (Constraint Propagation Analysis)
        for type-based splitting.
        
        Returns:
            ExtendedType: CPA type
        """
        return self.xtype.cpaType()

    def obj(self):
        """Get the underlying program object.
        
        Returns:
            program.AbstractObject: Program object
        """
        return self.xtype.obj

    def pyObj(self):
        """Get the Python object.
        
        Returns:
            object: Python object (if available)
        """
        return self.xtype.obj.pyobj

    def isObjectName(self):
        """Type check: this is an ObjectName.
        
        Returns:
            bool: Always True for ObjectName instances
        """
        return True
