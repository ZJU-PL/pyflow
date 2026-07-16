from abc import ABC, abstractmethod
from collections import defaultdict
from enum import Enum, auto
from typing import Dict, Set, List, Optional, Union, Tuple, Any, FrozenSet, TypeVar, Generic
import ast
import sys
import math
from dataclasses import dataclass, field

from pyflow.analysis.alias.kcfa._pythonstan.utils.common import Singleton
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRFunc, IRClass, IRModule


class ObjectType(Enum):
    """Enum for different types of objects in the abstract domain"""
    CONSTANT = auto()
    BUILTIN = auto()
    FUNCTION = auto()
    CLASS = auto()
    INSTANCE = auto()
    EXTERNAL_FUNCTION = auto()
    EXTERNAL_CLASS = auto()
    EXTERNAL_INSTANCE = auto()
    UNKNOWN = auto()


class Object(ABC):
    """Base class for all objects in the abstract domain"""
    
    def __init__(self, obj_type: ObjectType):
        self.obj_type = obj_type
        self.attributes: Dict[str, 'Value'] = {}
    
    @abstractmethod
    def __str__(self) -> str:
        pass
        
    def __repr__(self) -> str:
        return self.__str__()
        
    def has_attr(self, name: str) -> bool:
        """Check if object has a specific attribute"""
        return name in self.attributes
    
    def get_attr(self, name: str) -> Optional['Value']:
        """Get attribute by name"""
        return self.attributes.get(name)
    
    def set_attr(self, name: str, value: 'Value'):
        """Set attribute by name"""
        self.attributes[name] = value
    
    @abstractmethod
    def merge(self, other: 'Object') -> 'Object':
        """Merge this object with another object of the same type"""
        pass
    
    @staticmethod
    def can_merge(obj1: 'Object', obj2: 'Object') -> bool:
        """Check if two objects can be merged"""
        # First, check if they're the same general object type
        if obj1.obj_type != obj2.obj_type:
            return False
        
        # For constant objects, also check const_type
        if obj1.obj_type == ObjectType.CONSTANT and obj2.obj_type == ObjectType.CONSTANT:
            if isinstance(obj1, ConstantObject) and isinstance(obj2, ConstantObject):
                return obj1.const_type == obj2.const_type
        
        # For builtin objects, check builtin_type
        if obj1.obj_type == ObjectType.BUILTIN and obj2.obj_type == ObjectType.BUILTIN:
            if isinstance(obj1, BuiltinObject) and isinstance(obj2, BuiltinObject):
                return obj1.builtin_type == obj2.builtin_type
        
        # For function, class, and instance objects, check qualname
        if obj1.obj_type in (ObjectType.FUNCTION, ObjectType.CLASS, ObjectType.INSTANCE) and \
           obj2.obj_type in (ObjectType.FUNCTION, ObjectType.CLASS, ObjectType.INSTANCE):
            if hasattr(obj1, 'qualname') and hasattr(obj2, 'qualname'):
                return obj1.qualname == obj2.qualname
        
        # Default to just checking if they're the same general object type
        return obj1.obj_type == obj2.obj_type


class Value:
    """Represents a set of possible objects a variable could have at runtime"""
    
    def __init__(self, objects: Optional[Set[Object]] = None):
        self.objects: Set[Object] = objects or set()
    
    def __bool__(self) -> bool:
        """Check if this value contains any objects"""
        return bool(self.objects)
    
    def __str__(self) -> str:
        if not self.objects:
            return "EmptyValue"
        return f"Value({', '.join(str(obj) for obj in self.objects)})"
    
    def add(self, obj: Object):
        """Add an object to this value"""
        self.objects.add(obj)
    
    def merge(self, other: 'Value') -> 'Value':
        """Merge this value with another value"""
        if not other.objects:
            return self
        if not self.objects:
            return other
        
        # Create a new value to hold the merged result
        result = Value()
        
        # Track which objects from both self and other have been merged together
        merged_self_objects = set()
        merged_other_objects = set()
        
        # Try to merge objects of the same type
        for obj1 in self.objects:
            for obj2 in other.objects:
                if Object.can_merge(obj1, obj2):
                    # Merge compatible objects
                    merged_obj = obj1.merge(obj2)
                    result.add(merged_obj)
                    merged_self_objects.add(obj1)
                    merged_other_objects.add(obj2)
        
        # Add any objects from self that weren't merged
        for obj1 in self.objects:
            if obj1 not in merged_self_objects:
                result.add(obj1)
        
        # Add any objects from other that weren't merged
        for obj2 in other.objects:
            if obj2 not in merged_other_objects:
                result.add(obj2)
        
        return result
    
    def get_objects_of_type(self, obj_type: ObjectType) -> Set[Object]:
        """Get all objects of a specific type"""
        return {obj for obj in self.objects if obj.obj_type == obj_type}
    
    def is_definitely_constant(self) -> bool:
        """Check if this value is definitely a constant"""
        return all(obj.obj_type == ObjectType.CONSTANT for obj in self.objects)
    
    def is_possibly_constant(self) -> bool:
        """Check if this value might be a constant"""
        return any(obj.obj_type == ObjectType.CONSTANT for obj in self.objects)
    
    def get_attribute(self, name: str) -> 'Value':
        """Get an attribute from all objects in this value"""
        result = Value()
        for obj in self.objects:
            if obj.has_attr(name):
                attr_value = obj.get_attr(name)
                if attr_value:
                    result = result.merge(attr_value)
        return result


class NumericProperty:
    """Tracks properties of numeric values (integers and floats)"""
    
    def __init__(self, 
                 exact_values: Optional[Set[Union[int, float]]] = None,
                 lower_bound: Optional[Union[int, float]] = None,
                 upper_bound: Optional[Union[int, float]] = None,
                 may_be_zero: bool = True,
                 may_be_negative: bool = True,
                 may_be_positive: bool = True):
        self.exact_values = exact_values or set()
        self.lower_bound = lower_bound if lower_bound is not None else -math.inf
        self.upper_bound = upper_bound if upper_bound is not None else math.inf
        self.may_be_zero = may_be_zero
        self.may_be_negative = may_be_negative
        self.may_be_positive = may_be_positive
        
        # Keep the property consistent
        self._normalize()
    
    def _normalize(self):
        """Ensure the property is consistent"""
        if self.exact_values:
            min_val = min(self.exact_values)
            max_val = max(self.exact_values)
            self.lower_bound = max(self.lower_bound, min_val)
            self.upper_bound = min(self.upper_bound, max_val)
            self.may_be_zero = 0 in self.exact_values or any(abs(v) < 1e-10 for v in self.exact_values)
            self.may_be_negative = any(v < 0 for v in self.exact_values)
            self.may_be_positive = any(v > 0 for v in self.exact_values)
        
        # Update based on bounds
        if self.upper_bound <= 0:
            self.may_be_positive = False
        if self.lower_bound >= 0:
            self.may_be_negative = False
        if self.lower_bound > 0 or self.upper_bound < 0:
            self.may_be_zero = False
            
    def merge(self, other: 'NumericProperty') -> 'NumericProperty':
        """Merge this property with another numeric property"""
        exact_values = self.exact_values.union(other.exact_values) if self.exact_values and other.exact_values else None
        lower_bound = min(self.lower_bound, other.lower_bound)
        upper_bound = max(self.upper_bound, other.upper_bound)
        may_be_zero = self.may_be_zero or other.may_be_zero
        may_be_negative = self.may_be_negative or other.may_be_negative
        may_be_positive = self.may_be_positive or other.may_be_positive
        
        return NumericProperty(
            exact_values=exact_values,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
            may_be_zero=may_be_zero,
            may_be_negative=may_be_negative,
            may_be_positive=may_be_positive
        )


class StringProperty:
    """Tracks properties of string values"""
    
    def __init__(self,
                 exact_values: Optional[Set[str]] = None,
                 prefixes: Optional[Set[str]] = None,
                 suffixes: Optional[Set[str]] = None,
                 min_length: int = 0,
                 max_length: Optional[int] = None):
        self.exact_values = exact_values or set()
        self.prefixes = prefixes or set()
        self.suffixes = suffixes or set()
        self.min_length = min_length
        self.max_length = max_length
        
        # Keep the property consistent
        self._normalize()
    
    def _normalize(self):
        """Ensure the property is consistent"""
        if self.exact_values:
            min_len = min(len(s) for s in self.exact_values)
            max_len = max(len(s) for s in self.exact_values)
            self.min_length = max(self.min_length, min_len)
            if self.max_length is not None:
                self.max_length = min(self.max_length, max_len)
            else:
                self.max_length = max_len
                
            # Update prefixes and suffixes
            if not self.prefixes:
                self.prefixes = {s[:min(len(s), 1)] for s in self.exact_values}
            if not self.suffixes:
                self.suffixes = {s[-min(len(s), 1):] for s in self.exact_values}
    
    def merge(self, other: 'StringProperty') -> 'StringProperty':
        """Merge this property with another string property"""
        exact_values = self.exact_values.union(other.exact_values) if self.exact_values and other.exact_values else None
        prefixes = self.prefixes.union(other.prefixes) if self.prefixes and other.prefixes else None
        suffixes = self.suffixes.union(other.suffixes) if self.suffixes and other.suffixes else None
        
        min_length = min(self.min_length, other.min_length)
        max_length = None
        if self.max_length is not None and other.max_length is not None:
            max_length = max(self.max_length, other.max_length)
        
        return StringProperty(
            exact_values=exact_values,
            prefixes=prefixes,
            suffixes=suffixes,
            min_length=min_length,
            max_length=max_length
        )


class ContainerProperty:
    """Tracks properties of container values (list, set, tuple, dict)"""
    
    def __init__(self,
                 element_types: Optional[Set[ObjectType]] = None,
                 element_values: Optional['Value'] = None,
                 key_types: Optional[Set[ObjectType]] = None,
                 key_values: Optional['Value'] = None,
                 min_size: int = 0,
                 max_size: Optional[int] = 0):
        self.element_types = element_types or set()
        self.element_values = element_values or create_unknown_value()
        self.key_types = key_types or set()
        self.key_values = key_values or create_unknown_value()
        self.min_size = min_size
        self.max_size = max_size
    
    def merge(self, other: 'ContainerProperty') -> 'ContainerProperty':
        """Merge this property with another container property"""
        element_types = self.element_types.union(other.element_types)
        element_values = self.element_values.merge(other.element_values)
        key_types = self.key_types.union(other.key_types)
        key_values = self.key_values.merge(other.key_values)
        
        min_size = min(self.min_size, other.min_size)
        max_size = None
        if self.max_size is not None and other.max_size is not None:
            max_size = max(self.max_size, other.max_size)
        
        return ContainerProperty(
            element_types=element_types,
            element_values=element_values,
            key_types=key_types,
            key_values=key_values,
            min_size=min_size,
            max_size=max_size
        )


class ConstantObject(Object):
    """Represents a constant value (int, float, str, bool, None)"""
    
    def __init__(self, const_type: type, value: Optional[Any] = None):
        super().__init__(ObjectType.CONSTANT)
        self.const_type = const_type
        
        # Properties for specific constant types
        if const_type in (int, float):
            self.numeric_property = NumericProperty(
                exact_values={value} if value is not None else None
            )
        elif const_type == str:
            self.string_property = StringProperty(
                exact_values={value} if value is not None else None
            )
        elif const_type == bool:
            self.bool_value = value
        elif const_type == type(None):  # NoneType
            pass
        else:
            raise ValueError(f"Unsupported constant type: {const_type}")
    
    def __str__(self) -> str:
        if self.const_type == int:
            if self.numeric_property.exact_values:
                return f"Int({sorted(self.numeric_property.exact_values)})"
            return f"Int[{self.numeric_property.lower_bound}..{self.numeric_property.upper_bound}]"
        elif self.const_type == float:
            if self.numeric_property.exact_values:
                return f"Float({sorted(self.numeric_property.exact_values)})"
            return f"Float[{self.numeric_property.lower_bound}..{self.numeric_property.upper_bound}]"
        elif self.const_type == str:
            if self.string_property.exact_values:
                return f"Str({sorted(self.string_property.exact_values)})"
            return f"Str[len={self.string_property.min_length}..{self.string_property.max_length}]"
        elif self.const_type == bool:
            if hasattr(self, 'bool_value') and self.bool_value is not None:
                return f"Bool({self.bool_value})"
            return "Bool"
        elif self.const_type == type(None):
            return "None"
        return f"Const({self.const_type.__name__})"
    
    def merge(self, other: Object) -> Object:
        """Merge this constant with another object"""
        if not isinstance(other, ConstantObject) or self.const_type != other.const_type:
            # Return self instead of creating an UnknownObject
            # This allows preserving both types when merged at the Value level
            return self
        
        result = ConstantObject(self.const_type)
        
        # Merge based on type
        if self.const_type in (int, float):
            result.numeric_property = self.numeric_property.merge(other.numeric_property)
        elif self.const_type == str:
            result.string_property = self.string_property.merge(other.string_property)
        elif self.const_type == bool:
            # If one is True and the other is False, result is unknown boolean
            if hasattr(self, 'bool_value') and hasattr(other, 'bool_value'):
                if self.bool_value != other.bool_value:
                    # Unknown boolean (could be True or False)
                    pass
                else:
                    result.bool_value = self.bool_value
                    
        return result


class BuiltinObject(Object):
    """Represents a built-in container (list, dict, set, tuple)"""
    
    def __init__(self, builtin_type: type):
        super().__init__(ObjectType.BUILTIN)
        self.builtin_type = builtin_type
        self.container_property = ContainerProperty()
        
    def __str__(self) -> str:
        elem_types_str = ", ".join(t.name for t in self.container_property.element_types) or "empty"
        
        if self.builtin_type == dict:
            key_types_str = ", ".join(t.name for t in self.container_property.key_types) or "empty"
            return f"Dict<{key_types_str}, {elem_types_str}>"
        
        size_str = ""
        if self.container_property.min_size == self.container_property.max_size and self.container_property.min_size is not None:
            size_str = f"[{self.container_property.min_size}]"
        elif self.container_property.min_size > 0 or self.container_property.max_size is not None:
            size_str = f"[{self.container_property.min_size}..{self.container_property.max_size or 'inf'}]"
            
        if self.builtin_type == list:
            return f"List<{elem_types_str}>{size_str}"
        elif self.builtin_type == set:
            return f"Set<{elem_types_str}>{size_str}"
        elif self.builtin_type == tuple:
            return f"Tuple<{elem_types_str}>{size_str}"
        
        return f"Builtin({self.builtin_type.__name__})"
    
    def merge(self, other: Object) -> Object:
        """Merge this builtin with another object"""
        if not isinstance(other, BuiltinObject) or self.builtin_type != other.builtin_type:
            # Return self instead of creating an UnknownObject
            # This allows preserving both types when merged at the Value level
            return self
            
        result = BuiltinObject(self.builtin_type)
        result.container_property = self.container_property.merge(other.container_property)
        
        # Merge attributes
        for name, value in self.attributes.items():
            if name in other.attributes:
                result.attributes[name] = value.merge(other.attributes[name])
            else:
                result.attributes[name] = value
                
        for name, value in other.attributes.items():
            if name not in result.attributes:
                result.attributes[name] = value
                
        return result


class FunctionObject(Object):
    """Represents a user-defined function"""
    
    def __init__(self, ir_func: IRFunc):
        super().__init__(ObjectType.FUNCTION)
        self.ir_func = ir_func
        self.name = ir_func.name
        self.qualname = ir_func.get_qualname()
        self.is_async = ir_func.is_async
        self.is_static_method = ir_func.is_static_method
        self.is_class_method = ir_func.is_class_method
        self.is_getter = ir_func.is_getter
        self.is_setter = ir_func.is_setter
        self.is_instance_method = ir_func.is_instance_method
    
    def __str__(self) -> str:
        method_type = ""
        if self.is_static_method:
            method_type = "static "
        elif self.is_class_method:
            method_type = "class "
        elif self.is_instance_method:
            method_type = "instance "
            
        async_prefix = "async " if self.is_async else ""
        return f"{async_prefix}{method_type}function {self.qualname}"
    
    def merge(self, other: Object) -> Object:
        """Merge this function with another object"""
        if not isinstance(other, FunctionObject) or self.qualname != other.qualname:
            # Return self instead of creating an UnknownObject
            return self
        
        # Functions with the same qualname are considered the same object
        return self


class ClassObject(Object):
    """Represents a user-defined class"""
    
    def __init__(self, ir_class: IRClass):
        super().__init__(ObjectType.CLASS)
        self.ir_class = ir_class
        self.name = ir_class.name
        self.qualname = ir_class.get_qualname()
        self.bases = ir_class.get_bases()
        # Dict of method_name -> FunctionObject
        self.methods: Dict[str, FunctionObject] = {}
    
    def __str__(self) -> str:
        bases_str = ", ".join(self.bases) if self.bases else ""
        return f"class {self.qualname}({bases_str})"
    
    def add_method(self, method_name: str, method_obj: FunctionObject):
        """Add a method to this class"""
        self.methods[method_name] = method_obj
    
    def get_method(self, method_name: str) -> Optional[FunctionObject]:
        """Get a method by name"""
        return self.methods.get(method_name)
    
    def merge(self, other: Object) -> Object:
        """Merge this class with another object"""
        if not isinstance(other, ClassObject) or self.qualname != other.qualname:
            # Return self instead of creating an UnknownObject
            return self
        
        # Classes with the same qualname are considered the same object
        # But we should merge their methods and attributes
        result = ClassObject(self.ir_class)
        
        # Merge methods
        for name, method in self.methods.items():
            if name in other.methods:
                result.methods[name] = method.merge(other.methods[name])
            else:
                result.methods[name] = method
                
        for name, method in other.methods.items():
            if name not in result.methods:
                result.methods[name] = method
                
        # Merge attributes
        for name, value in self.attributes.items():
            if name in other.attributes:
                result.attributes[name] = value.merge(other.attributes[name])
            else:
                result.attributes[name] = value
                
        for name, value in other.attributes.items():
            if name not in result.attributes:
                result.attributes[name] = value
                
        return result


class InstanceObject(Object):
    """Represents an instance of a class"""
    
    def __init__(self, class_obj: ClassObject):
        super().__init__(ObjectType.INSTANCE)
        self.class_obj = class_obj
    
    def __str__(self) -> str:
        return f"instance of {self.class_obj.qualname}"
    
    def merge(self, other: Object) -> Object:
        """Merge this instance with another object"""
        if not isinstance(other, InstanceObject):
            # Return self instead of creating an UnknownObject
            return self
        
        # For now, we require instances to be of the same class
        if self.class_obj.qualname != other.class_obj.qualname:
            # Return self instead of creating an UnknownObject
            return self
        
        result = InstanceObject(self.class_obj)
        
        # Merge attributes
        for name, value in self.attributes.items():
            if name in other.attributes:
                result.attributes[name] = value.merge(other.attributes[name])
            else:
                result.attributes[name] = value
                
        for name, value in other.attributes.items():
            if name not in result.attributes:
                result.attributes[name] = value
                
        return result


class ExternalFunctionObject(Object):
    """Represents an imported/external function"""
    
    def __init__(self, name: str, module_name: str, qualname: Optional[str] = None):
        super().__init__(ObjectType.EXTERNAL_FUNCTION)
        self.name = name
        self.module_name = module_name
        self.qualname = qualname or f"{module_name}.{name}"
    
    def __str__(self) -> str:
        return f"external function {self.qualname}"
    
    def merge(self, other: Object) -> Object:
        """Merge this external function with another object"""
        if not isinstance(other, ExternalFunctionObject) or self.qualname != other.qualname:
            # Return self instead of creating an UnknownObject
            return self
        
        # External functions with the same qualname are considered the same object
        return self


class ExternalClassObject(Object):
    """Represents an imported/external class"""
    
    def __init__(self, name: str, module_name: str, qualname: Optional[str] = None):
        super().__init__(ObjectType.EXTERNAL_CLASS)
        self.name = name
        self.module_name = module_name
        self.qualname = qualname or f"{module_name}.{name}"
        # Dict of method_name -> ExternalFunctionObject
        self.methods: Dict[str, ExternalFunctionObject] = {}
    
    def __str__(self) -> str:
        return f"external class {self.qualname}"
    
    def add_method(self, method_name: str, method_obj: ExternalFunctionObject):
        """Add a method to this external class"""
        self.methods[method_name] = method_obj
    
    def get_method(self, method_name: str) -> Optional[ExternalFunctionObject]:
        """Get a method by name"""
        return self.methods.get(method_name)
    
    def merge(self, other: Object) -> Object:
        """Merge this external class with another object"""
        if not isinstance(other, ExternalClassObject) or self.qualname != other.qualname:
            # Return self instead of creating an UnknownObject
            return self
        
        # External classes with the same qualname are considered the same object
        # But we should merge their methods and attributes
        result = ExternalClassObject(self.name, self.module_name, self.qualname)
        
        # Merge methods
        for name, method in self.methods.items():
            if name in other.methods:
                result.methods[name] = method.merge(other.methods[name])
            else:
                result.methods[name] = method
                
        for name, method in other.methods.items():
            if name not in result.methods:
                result.methods[name] = method
                
        # Merge attributes
        for name, value in self.attributes.items():
            if name in other.attributes:
                result.attributes[name] = value.merge(other.attributes[name])
            else:
                result.attributes[name] = value
                
        for name, value in other.attributes.items():
            if name not in result.attributes:
                result.attributes[name] = value
                
        return result


class ExternalInstanceObject(Object):
    """Represents an instance of an external class"""
    
    def __init__(self, class_obj: ExternalClassObject):
        super().__init__(ObjectType.EXTERNAL_INSTANCE)
        self.class_obj = class_obj
    
    def __str__(self) -> str:
        return f"external instance of {self.class_obj.qualname}"
    
    def merge(self, other: Object) -> Object:
        """Merge this external instance with another object"""
        if not isinstance(other, ExternalInstanceObject):
            # Return self instead of creating an UnknownObject
            return self
        
        # For now, we require instances to be of the same class
        if self.class_obj.qualname != other.class_obj.qualname:
            # Return self instead of creating an UnknownObject
            return self
        
        result = ExternalInstanceObject(self.class_obj)
        
        # Merge attributes
        for name, value in self.attributes.items():
            if name in other.attributes:
                result.attributes[name] = value.merge(other.attributes[name])
            else:
                result.attributes[name] = value
                
        for name, value in other.attributes.items():
            if name not in result.attributes:
                result.attributes[name] = value
                
        return result


class UnknownObject(Object):
    """Represents an unknown object (used when merging incompatible types)"""
    
    def __init__(self):
        super().__init__(ObjectType.UNKNOWN)
    
    def __str__(self) -> str:
        return "Unknown"
    
    def merge(self, other: Object) -> Object:
        """Merge this unknown object with another object"""
        if other.obj_type != ObjectType.UNKNOWN:
            # Preserve non-unknown types when merging
            return other
            
        # Unknown merged with unknown is still unknown
        result = UnknownObject()
        
        # Merge attributes if any
        for name, value in self.attributes.items():
            if name in other.attributes:
                result.attributes[name] = value.merge(other.attributes[name])
            else:
                result.attributes[name] = value
                
        for name, value in other.attributes.items():
            if name not in result.attributes:
                result.attributes[name] = value
                
        return result


# Type-specific value factories
def create_int_value(value: Optional[int] = None) -> Value:
    """Create a Value containing an int object"""
    obj = ConstantObject(int, value)
    return Value({obj})

def create_float_value(value: Optional[float] = None) -> Value:
    """Create a Value containing a float object"""
    obj = ConstantObject(float, value)
    return Value({obj})

def create_str_value(value: Optional[str] = None) -> Value:
    """Create a Value containing a string constant"""
    obj = ConstantObject(str, value)
    if value is not None:
        # Set string properties
        obj.string_property = StringProperty(exact_values={value}, min_length=len(value), max_length=len(value))
    result = Value()
    result.add(obj)
    return result

def create_bool_value(value: Optional[bool] = None) -> Value:
    """Create a Value containing a bool object"""
    obj = ConstantObject(bool, value)
    return Value({obj})

def create_none_value() -> Value:
    """Create a Value containing None"""
    obj = ConstantObject(type(None))
    return Value({obj})

def create_list_value() -> Value:
    """Create a Value containing an empty list"""
    obj = BuiltinObject(list)
    return Value({obj})

def create_dict_value() -> Value:
    """Create a Value containing an empty dict"""
    obj = BuiltinObject(dict)
    return Value({obj})

def create_set_value() -> Value:
    """Create a Value containing an empty set"""
    obj = BuiltinObject(set)
    return Value({obj})

def create_tuple_value() -> Value:
    """Create a Value containing an empty tuple"""
    obj = BuiltinObject(tuple)
    return Value({obj})

def create_function_value(ir_func: IRFunc) -> Value:
    """Create a Value containing a function object"""
    obj = FunctionObject(ir_func)
    return Value({obj})

def create_class_value(ir_class: IRClass) -> Value:
    """Create a Value containing a class object"""
    obj = ClassObject(ir_class)
    return Value({obj})

def create_instance_value(class_obj: ClassObject) -> Value:
    """Create a Value containing an instance object"""
    obj = InstanceObject(class_obj)
    return Value({obj})

def create_external_function_value(name: str, module_name: str) -> Value:
    """Create a Value containing an external function object"""
    obj = ExternalFunctionObject(name, module_name)
    return Value({obj})

def create_external_class_value(name: str, module_name: str) -> Value:
    """Create a Value containing an external class object"""
    obj = ExternalClassObject(name, module_name)
    return Value({obj})

def create_external_instance_value(class_obj: ExternalClassObject) -> Value:
    """Create a Value containing an external instance object"""
    obj = ExternalInstanceObject(class_obj)
    return Value({obj})

def create_unknown_value() -> Value:
    """Create a Value containing an unknown object"""
    obj = UnknownObject()
    return Value({obj}) 