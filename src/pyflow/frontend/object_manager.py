"""
Object Manager for handling Python objects in static analysis.

This module manages object creation, caching, and type information
for Python objects used in static analysis.
"""

from typing import Any, Dict, Optional

from pyflow.language.python.program import (
    Object,
    ImaginaryObject,
    AbstractObject,
    TypeInfo,
)

from .source_locator import best_source_for_callable


class ObjectManager:
    """Manages Python objects and their PyFlow representations."""

    def __init__(
        self, verbose: bool = True, function_extractor=None, stub_manager=None
    ):
        self.verbose = verbose
        # Cache for hashable objects (value-based key).
        self._object_cache: Dict[Any, Object] = {}
        # Fallback cache for unhashable objects (identity-based key).
        self._object_cache_by_id: Dict[int, Object] = {}
        self.function_extractor = function_extractor
        self.stub_manager = stub_manager

    def _hashable_cache_key(self, obj: Any) -> Any:
        """Use type-aware cache keys so equal-but-distinct values do not collide."""
        return (type(obj), obj)

    def get_object(self, obj: Any) -> Object:
        """Get or create an object representation for static analysis."""
        try:
            key = self._hashable_cache_key(obj)
            if key in self._object_cache:
                return self._object_cache[key]
        except TypeError:
            # Unhashable objects (e.g., list/dict): cache by identity.
            oid = id(obj)
            cached = self._object_cache_by_id.get(oid)
            if cached is not None:
                return cached

        # Create an Object wrapper for the Python object
        try:
            pyflow_obj = Object(obj)
            # Ensure the object is properly loaded with its type
            self.ensure_loaded(pyflow_obj)

            # Initialize data structures for the object (required for IPA analysis)
            if hasattr(pyflow_obj, "type") and pyflow_obj.type is not None:
                pyflow_obj.allocateDatastructures(pyflow_obj.type)

            try:
                self._object_cache[self._hashable_cache_key(obj)] = pyflow_obj
            except TypeError:
                self._object_cache_by_id[id(obj)] = pyflow_obj
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
                            print(
                                f"DEBUG: Source code keys: {list(source_code.keys())}"
                            )

                    if hasattr(func, "__code__") and func.__code__.co_filename:
                        filename = func.__code__.co_filename
                        if isinstance(source_code, dict):
                            func_source = best_source_for_callable(func, source_code)
                            if self.verbose:
                                if func_source is not None:
                                    print(
                                        f"DEBUG: Located source for {func.__qualname__} (len={len(func_source)})"
                                    )
                                else:
                                    print(
                                        f"DEBUG: Could not locate source for {func.__qualname__}"
                                    )
                        elif isinstance(source_code, str):
                            func_source = source_code
                else:
                    if self.verbose:
                        print(f"DEBUG: No source code provided for {func.__name__}")

                if self.verbose:
                    print(
                        f"DEBUG: Calling convert_function for {func.__name__} with source_code type: {type(func_source)}"
                    )
                    if func_source:
                        print(f"DEBUG: Source code length: {len(func_source)}")
                        print(f"DEBUG: Source code preview: {repr(func_source[:100])}")
                    else:
                        print(f"DEBUG: No source code for {func.__name__}")

                code_obj = self.function_extractor.convert_function(func, func_source)
                # NOTE: Do not enable dynamic folding for extracted target code.
                #
                # CPA's dynamic folding executes the Python function when all arguments
                # are constant. For analyzed programs this can cause real side effects
                # (e.g., `os.system("safe_value")` in benchmarks), which is unsafe and
                # can skew analysis results.
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

    def get_instance(self, typeobj: type) -> AbstractObject:
        """Get an abstract instance object for a given type.

        Args:
            typeobj: A Python type object (e.g., int, str, MyClass) or string name (e.g., 'float', 'int')

        Returns:
            AbstractObject: The abstract instance representing instances of the type
        """
        # Handle string type names by converting to actual type objects
        if isinstance(typeobj, str):
            import builtins

            if hasattr(builtins, typeobj):
                typeobj = getattr(builtins, typeobj)
            else:
                raise ValueError(f"Unknown builtin type: {typeobj}")

        # Get the type object representation
        type_obj = self.get_object(typeobj)
        # Ensure it's loaded (this will create the abstractInstance if needed)
        self.ensure_loaded(type_obj)
        # Return the abstract instance
        if type_obj.isType() and hasattr(type_obj, "typeinfo") and type_obj.typeinfo:
            return type_obj.typeinfo.abstractInstance
        else:
            # Fallback: create a minimal abstract instance if typeinfo wasn't created
            type_name = (
                typeobj.__name__ if hasattr(typeobj, "__name__") else str(typeobj)
            )
            return self.make_imaginary(f"instance_of_{type_name}", type_obj, False)
