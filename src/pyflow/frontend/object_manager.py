"""
Object Manager for handling Python objects in static analysis.

This module manages object creation, caching, and type information
for Python objects used in static analysis.
"""

from typing import Any, Dict, Optional

from pyflow.language.python.program import Object, ImaginaryObject, AbstractObject, TypeInfo


class ObjectManager:
    """Manages Python objects and their PyFlow representations."""

    def __init__(
        self, verbose: bool = True, function_extractor=None, stub_manager=None
    ):
        self.verbose = verbose
        self._object_cache: Dict[Any, Object] = {}
        self.function_extractor = function_extractor
        self.stub_manager = stub_manager

    def get_object(self, obj: Any) -> Object:
        """Get or create an object representation for static analysis."""
        if obj in self._object_cache:
            return self._object_cache[obj]

        # Create an Object wrapper for the Python object
        try:
            pyflow_obj = Object(obj)
            # Ensure the object is properly loaded with its type
            self.ensure_loaded(pyflow_obj)

            # Initialize data structures for the object (required for IPA analysis)
            if hasattr(pyflow_obj, 'type') and pyflow_obj.type is not None:
                pyflow_obj.allocateDatastructures(pyflow_obj.type)

            self._object_cache[obj] = pyflow_obj
            return pyflow_obj
        except Exception as e:
            if self.verbose:
                print(f"Error creating Object for {obj}: {e}")
            # Return a fallback object
            return obj

    def get_object_call(self, func: Any, source_code: Any = None) -> tuple:
        """Get object call information for a function."""
        if hasattr(func, "__name__"):
            # Use the function extractor if available
            if self.function_extractor:
                # Get source code for this function if available
                func_source = None
                if source_code:
                    if self.verbose:
                        print(f"DEBUG: Source code provided, type: {type(source_code)}")
                        if isinstance(source_code, dict):
                            print(f"DEBUG: Source code keys: {list(source_code.keys())}")

                    if hasattr(func, '__code__') and func.__code__.co_filename:
                        filename = func.__code__.co_filename
                        if isinstance(source_code, dict):
                            # Try exact match first
                            if filename in source_code:
                                func_source = source_code[filename]
                                if self.verbose:
                                    print(f"DEBUG: Found exact source match for '{filename}'")
                            # Special case: if filename is '<string>' and we have source code, use it
                            elif filename == '<string>':
                                # For functions created by exec(), use the corresponding source file
                                # We need to find which source file this function came from
                                # For now, use the first available .py file
                                for src_filename, src_content in source_code.items():
                                    if src_filename.endswith('.py'):
                                        func_source = src_content
                                        if self.verbose:
                                            print(f"DEBUG: Using source for '<string>' filename from '{src_filename}'")
                                        break
                            else:
                                if self.verbose:
                                    print(f"DEBUG: No source found for filename '{filename}'")
                        elif isinstance(source_code, str):
                            func_source = source_code
                else:
                    if self.verbose:
                        print(f"DEBUG: No source code provided for {func.__name__}")

                if self.verbose:
                    print(f"DEBUG: Calling convert_function for {func.__name__} with source_code type: {type(func_source)}")
                    if func_source:
                        print(f"DEBUG: Source code length: {len(func_source)}")
                        print(f"DEBUG: Source code preview: {repr(func_source[:100])}")
                    else:
                        print(f"DEBUG: No source code for {func.__name__}")

                code_obj = self.function_extractor.convert_function(func, func_source)
                # Allow small functions to fold concretely using their Python implementation.
                try:
                    code_obj.annotation.dynamicFold = func
                except Exception:
                    pass
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
                # Prevent recursion for type objects - type(type) is type itself
                if obj.pyobj is type:
                    # For the type class itself, we can't set a type without recursion
                    # Leave it as None or handle specially
                    pass  # Don't set type for the type class itself
                else:
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

        # Ensure container datastructures exist for existing objects
        try:
            from pyflow.language.python.program import Object as ProgramObject
        except Exception:
            ProgramObject = None

        if ProgramObject is not None and isinstance(obj, ProgramObject):
            # Allocate internal dicts if missing
            has_slot = hasattr(obj, "slot")
            # obj.type may be None for special cases; guard before allocation
            if (not has_slot) and getattr(obj, "type", None) is not None:
                obj.allocateDatastructures(obj.type)

        return None

    def get_call(self, obj: Any, source_code: Any = None) -> Optional[Any]:
        """Get call information for an object."""
        if hasattr(obj, "pyobj"):
            pyobj = obj.pyobj

            # Resolve stubbed interpreter/helper functions by name.
            if isinstance(pyobj, str) and self.stub_manager:
                exports = getattr(self.stub_manager.stubs, "exports", {})
                if pyobj in exports:
                    return exports[pyobj]

            if callable(pyobj):
                # For callable objects, return the second element from getObjectCall
                func_obj, code_obj = self.get_object_call(pyobj, source_code)
                return code_obj
        return None
