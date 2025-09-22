"""
Object Manager for handling Python objects in static analysis.

This module manages object creation, caching, and type information
for Python objects used in static analysis.
"""

from typing import Any, Dict, Optional

from pyflow.language.python.program import Object, ImaginaryObject, AbstractObject, TypeInfo


class ObjectManager:
    """Manages Python objects and their PyFlow representations."""

    def __init__(self, verbose: bool = True, function_extractor=None):
        self.verbose = verbose
        self._object_cache: Dict[Any, Object] = {}
        self.function_extractor = function_extractor

    def get_object(self, obj: Any) -> Object:
        """Get or create an object representation for static analysis."""
        if obj in self._object_cache:
            return self._object_cache[obj]

        # Create an Object wrapper for the Python object
        try:
            pyflow_obj = Object(obj)
            self._object_cache[obj] = pyflow_obj
            return pyflow_obj
        except Exception as e:
            if self.verbose:
                print(f"Error creating Object for {obj}: {e}")
            # Return a fallback object
            return obj

    def get_object_call(self, func: Any) -> tuple:
        """Get object call information for a function."""
        if hasattr(func, "__name__"):
            # Use the function extractor if available
            if self.function_extractor:
                code_obj = self.function_extractor.convert_function(func)
                return func, code_obj
            return func, None
        return func, None

    def make_imaginary(
        self, name: str, t: AbstractObject, preexisting: bool
    ) -> ImaginaryObject:
        """Create an imaginary object for static analysis."""
        return ImaginaryObject(name, t, preexisting)

    def ensure_loaded(self, obj: AbstractObject) -> None:
        """Ensure an abstract object is loaded. Initialize typeinfo for type objects."""
        # Handle None objects
        if obj is None:
            return None
            
        # If this object doesn't have a type set, we need to initialize it
        if not hasattr(obj, "type") or obj.type is None:
            if hasattr(obj, "pyobj"):
                # Set the type to be the type of the Python object
                obj.type = self.get_object(type(obj.pyobj))

        # If this is a type object and doesn't have typeinfo, create it
        if obj.isType() and (not hasattr(obj, "typeinfo") or obj.typeinfo is None):
            obj.typeinfo = TypeInfo()

            # Create an abstract instance for this type
            # The abstract instance represents instances of this type
            abstract_instance = ImaginaryObject(
                f"abstract_instance_of_{obj.pyobj.__name__}", obj, False
            )
            obj.typeinfo.abstractInstance = abstract_instance

        return None

    def get_call(self, obj: Any) -> Optional[Any]:
        """Get call information for an object."""
        if hasattr(obj, "pyobj") and callable(obj.pyobj):
            # For callable objects, return the second element from getObjectCall
            func_obj, code_obj = self.get_object_call(obj.pyobj)
            return code_obj
        return None
