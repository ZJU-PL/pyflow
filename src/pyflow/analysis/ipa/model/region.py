"""Region management for IPA contexts.

Regions group objects within a context. Each context has a region that
manages object representations and their fields. Regions enable efficient
lookup and management of objects within a context.
"""

from .object import Object


class Region(object):
    """Manages objects within a context.
    
    A region groups objects and their fields within a single context.
    Objects are canonicalized within a region (same ObjectName returns
    same Object instance).
    
    Attributes:
        context: Context this region belongs to
        objects: Dictionary mapping ObjectName to Object instances
    """
    __slots__ = "context", "objects"

    def __init__(self, context):
        """Initialize a region.
        
        Args:
            context: Context this region belongs to
        """
        self.context = context
        self.objects = {}

    def object(self, obj):
        """Get or create an Object for an ObjectName.
        
        Objects are canonicalized within a region.
        
        Args:
            obj: ObjectName to get Object for
            
        Returns:
            Object: Object instance for the ObjectName
        """
        if obj not in self.objects:
            result = Object(self.context, obj)
            self.objects[obj] = result
        else:
            result = self.objects[obj]

        return result
