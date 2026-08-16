"""Builtin function and method handling for pointer analysis.

This module provides handlers for Python builtin functions and methods that
model their pointer effects using PFG edges and lazy constraints.

Design:
- Builtin classes/functions/methods are represented as specialized objects
- Operations use PFG edges for direct dataflows
- Lazy constraints are added when new objects might be created later
"""

from typing import List, Optional, Dict, Set, Tuple, TYPE_CHECKING
import logging

from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.constraints import (
    AllocConstraint,
    CallConstraint,
    CopyConstraint,
    AttrReadConstraint,
    AttrWriteConstraint,
    AttrDeleteConstraint,
    LoadConstraint,
    LoadSubscrConstraint,
    StoreConstraint,
    StoreSubscrConstraint,
    SuperResolveConstraint,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.heap_model import FieldKind, attr, elem, key, unknown
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import (
    AllocKind,
    AllocSite,
    BuiltinClassObject,
    BuiltinFunctionObject,
    BuiltinInstanceObject,
    BuiltinMethodObject,
    ClassObject,
    ConstantObject,
    InstanceObject,
    ListObject,
    DictObject,
    SetObject,
    TupleObject,
    ObjectFactory,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.pointer_flow_graph import NormalNode
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.points_to_set import PointsToSet
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.variable import Variable, VariableKind

if TYPE_CHECKING:
    from .constraints import Constraint, CallConstraint, LoadConstraint, StoreConstraint
    from .variable import Variable, FieldAccess
    from .context import AbstractContext, Ctx, Scope
    from .config import Config
    from .state import PointerAnalysisState
    from .object import (
        AbstractObject, BuiltinInstanceObject, BuiltinMethodObject,
        BuiltinClassObject, BuiltinFunctionObject
    )

logger = logging.getLogger(__name__)

__all__ = ["BuiltinAPIHandler", "BuiltinSummaryManager"]


class BuiltinAPIHandler:
    """Handler for builtin function and method operations.
    
    Uses PFG edges for direct dataflows and constraints for lazy processing.
    """
    
    # Builtin container types
    CONTAINER_TYPES = {"list", "dict", "tuple", "set", "frozenset"}
    
    # List methods that modify elements
    LIST_MUTATOR_METHODS = {"append", "extend", "insert", "__setitem__"}
    LIST_ACCESSOR_METHODS = {"__getitem__", "__iter__", "pop", "index"}
    
    # Dict methods
    DICT_MUTATOR_METHODS = {"__setitem__", "update", "setdefault"}
    DICT_ACCESSOR_METHODS = {"__getitem__", "get", "pop", "keys", "values", "items", "__iter__"}
    
    # Set methods
    SET_MUTATOR_METHODS = {"add", "update", "discard", "remove"}
    SET_ACCESSOR_METHODS = {"__iter__", "pop"}
    
    # Iterator/functional builtins
    ITERATOR_BUILTINS = {"iter", "next", "enumerate", "zip", "map", "filter", "reversed", "range"}
    
    # Scalar/type builtins
    TYPE_BUILTINS = {"len", "isinstance", "issubclass", "type", "object", "bool", "int", "float", "str", "bytes"}
    
    def __init__(self, state: 'PointerAnalysisState', config: 'Config'):
        """Initialize builtin handler.
        
        Args:
            state: Pointer analysis state
            config: Analysis configuration
        """
        self.state = state
        self.config = config
        self._method_handlers: Dict[str, callable] = self._init_method_handlers()
        self._function_handlers: Dict[str, callable] = self._init_function_handlers()

    def _make_temp_var(self, prefix: str, call: 'CallConstraint') -> 'Variable':
        """Create a temporary variable unique to the call site."""
        return Variable(
            name=f"${prefix}@{call.call_site.short_id()}",
            kind=VariableKind.TEMPORARY,
        )

    @staticmethod
    def _infer_container_type(receiver: 'AbstractObject') -> Optional[str]:
        """Infer builtin container type name from receiver object."""
        if isinstance(receiver, BuiltinInstanceObject):
            return receiver.builtin_type
        if isinstance(receiver, ListObject):
            return "list"
        if isinstance(receiver, DictObject):
            return "dict"
        if isinstance(receiver, TupleObject):
            return "tuple"
        if isinstance(receiver, SetObject):
            return "set"
        return None

    def _resolve_attr_names(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        name_var: 'Variable',
    ) -> Tuple[Set[str], bool]:
        """Resolve constant attribute names from name_var points-to set."""
        ctx_name = self.state.get_variable(scope, context, name_var)
        name_pts = self.state.get_points_to(ctx_name)
        const_names: Set[str] = set()
        has_non_const = False
        for obj in name_pts:
            if isinstance(obj, ConstantObject) and isinstance(obj.value, str):
                const_names.add(obj.value)
            else:
                has_non_const = True
        if len(name_pts) == 0:
            has_non_const = True
        return const_names, has_non_const

    def _collect_known_attr_names(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        base_var: 'Variable',
    ) -> Set[str]:
        """Collect known attribute names for objects in base_var points-to set."""
        ctx_base = self.state.get_variable(scope, context, base_var)
        base_pts = self.state.get_points_to(ctx_base)
        names: Set[str] = set()
        if not base_pts:
            return names
        for (obj, field) in self.state._field_accesses.keys():
            if obj in base_pts and field.kind == FieldKind.ATTRIBUTE and field.name:
                names.add(field.name)
        return names
    
    def _init_method_handlers(self) -> Dict[str, callable]:
        """Initialize method handler dispatch table."""
        return {
            # List methods
            "append": self._handle_list_append,
            "extend": self._handle_list_extend,
            "insert": self._handle_list_insert,
            "__getitem__": self._handle_container_getitem,
            "__setitem__": self._handle_container_setitem,
            "__iter__": self._handle_container_iter,
            "pop": self._handle_container_pop,
            
            # Dict methods
            "get": self._handle_dict_get,
            "setdefault": self._handle_dict_setdefault,
            "update": self._handle_container_update,
            "keys": self._handle_dict_keys,
            "values": self._handle_dict_values,
            "items": self._handle_dict_items,
            
            # Set methods
            "add": self._handle_set_add,
            "discard": self._handle_set_discard,
            "remove": self._handle_set_remove,
            "update": self._handle_container_update,
        }
    
    def _init_function_handlers(self) -> Dict[str, callable]:
        """Initialize function handler dispatch table."""
        return {
            # Container constructors
            "list": self._handle_list_constructor,
            "dict": self._handle_dict_constructor,
            "tuple": self._handle_tuple_constructor,
            "set": self._handle_set_constructor,
            
            # Iterator functions
            "iter": self._handle_iter,
            "next": self._handle_next,
            "enumerate": self._handle_enumerate,
            "zip": self._handle_zip,
            "map": self._handle_map,
            "filter": self._handle_filter,
            "reversed": self._handle_reversed,
            "sorted": self._handle_sorted,
            "range": self._handle_range,
            
            # Type/scalar functions
            "len": self._handle_len,
            "isinstance": self._handle_isinstance,
            "issubclass": self._handle_issubclass,
            "type": self._handle_type,
            "object": self._handle_object,
            "bool": self._handle_bool,
            "int": self._handle_int,
            "float": self._handle_float,
            "str": self._handle_str,
            "callable": self._handle_callable,
            
            # Introspection/dynamic attribute functions
            "getattr": self._handle_getattr,
            "setattr": self._handle_setattr,
            "hasattr": self._handle_hasattr,
            "delattr": self._handle_delattr,
            "vars": self._handle_vars,
            
            # Object-oriented functions
            "super": self._handle_super,
        }
    
    def handle_builtin_call(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        builtin_obj: 'AbstractObject'
    ) -> List['Constraint']:
        """Handle a call to a builtin function or method.
        
        Returns constraints to be added to the solver for lazy processing.
        
        Args:
            scope: Current scope
            context: Current context
            call: Call constraint
            builtin_obj: Builtin object being called
        
        Returns:
            List of constraints to process
        """
        constraints = []
        
        # Dispatch based on builtin object type
        if isinstance(builtin_obj, BuiltinClassObject):
            # Calling a builtin class as constructor
            handler = self._function_handlers.get(builtin_obj.builtin_name)
            if handler:
                constraints = handler(scope, context, call)
            else:
                # Generic constructor
                constraints = self._handle_generic_constructor(scope, context, call, builtin_obj.builtin_name)
        
        elif isinstance(builtin_obj, BuiltinFunctionObject):
            # Calling a builtin function
            handler = self._function_handlers.get(builtin_obj.function_name)
            if handler:
                constraints = handler(scope, context, call)
            else:
                # Generic builtin function
                constraints = self._handle_generic_builtin(scope, context, call, builtin_obj.function_name)
        
        elif isinstance(builtin_obj, BuiltinMethodObject):
            # Calling a builtin method
            handler = self._method_handlers.get(builtin_obj.method_name)
            if handler:
                # Pass both the receiver object and the method object (which has receiver_var)
                constraints = handler(scope, context, call, builtin_obj)
            else:
                # Generic method
                constraints = self._handle_generic_method(scope, context, call, builtin_obj)
        
        return constraints
    
    # ===== Container Constructors =====
    
    def _handle_list_constructor(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle list() constructor call.
        
        Creates a new list instance. If an iterable is provided, adds
        constraints to copy elements from the iterable to the list.
        """
        constraints = []
        
        if not call.target:
            return constraints
        
        # Create allocation constraint for new list
        alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.LIST)
        constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        # If iterable argument provided, copy elements
        if len(call.args) > 0:
            iterable_var = call.args[0]
            elem_var = self._make_temp_var("list_ctor_elem", call)
            constraints.append(LoadConstraint(
                base=iterable_var,
                field=elem(),
                target=elem_var,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=elem_var,
            ))
        
        return constraints
    
    def _handle_dict_constructor(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle dict() constructor call."""
        constraints = []
        
        if not call.target:
            return constraints
        
        alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.DICT)
        constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))

        if len(call.args) > 0:
            iterable_var = call.args[0]
            elem_var = self._make_temp_var("dict_ctor_elem", call)
            constraints.append(LoadConstraint(
                base=iterable_var,
                field=elem(),
                target=elem_var,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=elem_var,
            ))

        for kw_name, kw_var in call.kwargs:
            if kw_name is None:
                expanded_elem_var = self._make_temp_var("dict_ctor_kwargs_elem", call)
                constraints.append(LoadConstraint(
                    base=kw_var,
                    field=elem(),
                    target=expanded_elem_var,
                ))
                constraints.append(StoreConstraint(
                    base=call.target,
                    field=elem(),
                    source=expanded_elem_var,
                ))
                continue

            constraints.append(StoreConstraint(
                base=call.target,
                field=key(kw_name),
                source=kw_var,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=kw_var,
            ))
        
        return constraints
    
    def _handle_tuple_constructor(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle tuple() constructor call."""
        constraints = []
        
        if not call.target:
            return constraints
        
        alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.TUPLE)
        constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        # If iterable provided, copy elements
        if len(call.args) > 0:
            iterable_var = call.args[0]
            elem_var = self._make_temp_var("tuple_ctor_elem", call)
            constraints.append(LoadConstraint(
                base=iterable_var,
                field=elem(),
                target=elem_var,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=elem_var,
            ))
        
        return constraints
    
    def _handle_set_constructor(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle set() constructor call."""
        constraints = []
        
        if not call.target:
            return constraints
        
        alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.SET)
        constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        # If iterable provided, copy elements
        if len(call.args) > 0:
            iterable_var = call.args[0]
            elem_var = self._make_temp_var("set_ctor_elem", call)
            constraints.append(LoadConstraint(
                base=iterable_var,
                field=elem(),
                target=elem_var,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=elem_var,
            ))
        
        return constraints
    
    # ===== List Methods =====
    
    def _handle_list_append(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle list.append(x).
        
        Stores x to list.elem() by directly setting up PFG edge and also adding
        a StoreConstraint as a fallback for cases where the receiver's points-to
        set is populated after this call.
        """
        constraints = []
        
        if len(call.args) > 0 and method_obj.receiver_var:
            # Get the first argument (the item to append)
            item_var = call.args[0]
            
            # Get contextualized variables
            base_ctx_var = self.state.get_variable(scope, context, method_obj.receiver_var)
            item_ctx_var = self.state.get_variable(scope, context, item_var)
            
            # Directly set up the PFG edge from item to receiver.elem()
            # This handles cases where the receiver already has objects
            base_pts = self.state.get_points_to(base_ctx_var)
            for base_obj in base_pts:
                field_access = self.state.get_field(scope, context, base_obj, elem())
                self.state._add_var_points_flow(item_ctx_var, field_access)
            
            # ALSO add a StoreConstraint as fallback for lazy resolution
            # This ensures the store is captured even if the list object is created later
            constraints.append(StoreConstraint(
                base=method_obj.receiver_var,
                field=elem(),
                source=item_var
            ))
        
        return constraints
    
    def _handle_list_extend(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle list.extend(iterable).
        
        Loads from iterable.elem() and stores to list.elem().
        """
        constraints = []
        
        # Similar to append, but loads from iterable
        if len(call.args) > 0 and method_obj.receiver_var:
            iterable_var = call.args[0]
            elem_var = self._make_temp_var("list_extend_elem", call)
            constraints.append(LoadConstraint(
                base=iterable_var,
                field=elem(),
                target=elem_var,
            ))
            constraints.append(StoreConstraint(
                base=method_obj.receiver_var,
                field=elem(),
                source=elem_var,
            ))
        
        return constraints
    
    def _handle_list_insert(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle list.insert(index, x).
        
        Stores x to list.elem().
        """
        constraints = []
        
        if len(call.args) > 1 and method_obj.receiver_var:
            item_var = call.args[1]  # Second arg is the item
            # Add constraint to store item to receiver.elem()
            constraints.append(StoreConstraint(
                base=method_obj.receiver_var,
                field=elem(),
                source=item_var,
            ))
        
        return constraints
    
    def _handle_list_pop(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle list.pop([index]).
        
        Loads from list.elem() to return value.
        """
        constraints = []
        
        if call.target and method_obj.receiver_var:
            if len(call.args) > 0:
                index_var = call.args[0]
                constraints.append(LoadSubscrConstraint(
                    target=call.target,
                    base=method_obj.receiver_var,
                    index=index_var,
                ))
            else:
                constraints.append(LoadConstraint(
                    base=method_obj.receiver_var,
                    field=elem(),
                    target=call.target,
                ))
        
        return constraints
    
    # ===== Container Methods =====
    
    def _handle_container_getitem(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle container.__getitem__(key).
        
        For lists/tuples: loads from elem()
        For dicts: loads from key(k) if constant, else elem()
        """
        constraints = []
        
        if call.target and len(call.args) > 0 and method_obj.receiver_var:
            index_var = call.args[0]
            # Add LoadSubscrConstraint which will be resolved based on index type
            # This will be handled in solver's _apply_load_subscr
            constraints.append(LoadSubscrConstraint(
                target=call.target,
                base=method_obj.receiver_var,
                index=index_var,
            ))
        
        return constraints
    
    def _handle_container_setitem(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle container.__setitem__(key, value).
        
        Stores value to appropriate field based on key type.
        """
        constraints = []
        
        if len(call.args) > 1 and method_obj.receiver_var:
            key_var = call.args[0]
            value_var = call.args[1]
            # Add StoreSubscrConstraint
            constraints.append(StoreSubscrConstraint(
                base=method_obj.receiver_var,
                index=key_var,
                source=value_var,
            ))
        
        return constraints
    
    def _handle_container_iter(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle container.__iter__().
        
        Creates iterator object that yields container elements.
        """
        constraints = []
        
        if call.target and method_obj.receiver_var:
            # Create iterator object
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
            
            # Link iterator to container elements
            # The iterator's elem() field should point to container's elem()
            container_type = self._infer_container_type(method_obj.receiver)
            if container_type == "dict":
                unknown_var = self._make_temp_var("dict_iter_key", call)
                constraints.append(AllocConstraint(
                    target=unknown_var,
                    alloc_site=AllocSite(stmt=call.stmt, kind=AllocKind.UNKNOWN),
                ))
                constraints.append(StoreConstraint(
                    base=call.target,
                    field=elem(),
                    source=unknown_var,
                ))
            else:
                elem_var = self._make_temp_var("iter_elem", call)
                constraints.append(LoadConstraint(
                    base=method_obj.receiver_var,
                    field=elem(),
                    target=elem_var,
                ))
                constraints.append(StoreConstraint(
                    base=call.target,
                    field=elem(),
                    source=elem_var,
                ))
        
        return constraints

    def _handle_container_pop(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle container.pop(...) for list/dict/set."""
        constraints = []
        if not call.target or not method_obj.receiver_var:
            return constraints
        
        container_type = self._infer_container_type(method_obj.receiver)
        if container_type == "dict":
            if len(call.args) > 0:
                key_var = call.args[0]
                constraints.append(LoadSubscrConstraint(
                    target=call.target,
                    base=method_obj.receiver_var,
                    index=key_var,
                ))
                if len(call.args) > 1:
                    default_var = call.args[1]
                    constraints.append(CopyConstraint(
                        source=default_var,
                        target=call.target,
                    ))
        elif container_type in {"list", "tuple", "set"}:
            if len(call.args) > 0 and container_type == "list":
                index_var = call.args[0]
                constraints.append(LoadSubscrConstraint(
                    target=call.target,
                    base=method_obj.receiver_var,
                    index=index_var,
                ))
            else:
                constraints.append(LoadConstraint(
                    base=method_obj.receiver_var,
                    field=elem(),
                    target=call.target,
                ))
        return constraints

    def _handle_container_update(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle update() for dict/set by receiver type."""
        container_type = self._infer_container_type(method_obj.receiver)
        if container_type == "dict":
            return self._handle_dict_update(scope, context, call, method_obj)
        if container_type == "set":
            return self._handle_set_update(scope, context, call, method_obj)
        return []
    
    # ===== Dict Methods =====
    
    def _handle_dict_get(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle dict.get(key, default=None).
        
        Loads from dict.key(k) if constant, else dict.elem().
        """
        constraints = []
        
        if call.target and len(call.args) > 0 and method_obj.receiver_var:
            key_var = call.args[0]
            # Add LoadSubscrConstraint
            constraints.append(LoadSubscrConstraint(
                target=call.target,
                base=method_obj.receiver_var,
                index=key_var,
            ))
            if len(call.args) > 1:
                default_var = call.args[1]
                constraints.append(CopyConstraint(
                    source=default_var,
                    target=call.target,
                ))
        
        return constraints
    
    def _handle_dict_update(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle dict.update(other)."""
        constraints = []
        
        if len(call.args) > 0 and method_obj.receiver_var:
            other_var = call.args[0]
            # Copy other's values to receiver
            elem_var = self._make_temp_var("dict_update_elem", call)
            constraints.append(LoadConstraint(
                base=other_var,
                field=elem(),
                target=elem_var,
            ))
            constraints.append(StoreConstraint(
                base=method_obj.receiver_var,
                field=elem(),
                source=elem_var,
            ))
        
        return constraints
    
    def _handle_dict_setdefault(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle dict.setdefault(key, default)."""
        constraints = []
        
        if len(call.args) > 0 and method_obj.receiver_var:
            key_var = call.args[0]
            if len(call.args) > 1:
                default_var = call.args[1]
                constraints.append(StoreSubscrConstraint(
                    base=method_obj.receiver_var,
                    index=key_var,
                    source=default_var,
                ))
                if call.target:
                    constraints.append(CopyConstraint(
                        source=default_var,
                        target=call.target,
                    ))
            if call.target:
                constraints.append(LoadSubscrConstraint(
                    target=call.target,
                    base=method_obj.receiver_var,
                    index=key_var,
                ))
        
        return constraints
    
    def _handle_dict_keys(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle dict.keys()."""
        constraints = []
        
        if call.target:
            # Create dict_keys object
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
            unknown_var = self._make_temp_var("dict_keys_elem", call)
            constraints.append(AllocConstraint(
                target=unknown_var,
                alloc_site=AllocSite(stmt=call.stmt, kind=AllocKind.UNKNOWN),
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=unknown_var,
            ))
        
        return constraints
    
    def _handle_dict_values(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle dict.values()."""
        constraints = []
        
        if call.target and method_obj.receiver_var:
            # Create dict_values object that yields dict values
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
            elem_var = self._make_temp_var("dict_values_elem", call)
            constraints.append(LoadConstraint(
                base=method_obj.receiver_var,
                field=elem(),
                target=elem_var,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=elem_var,
            ))
        
        return constraints
    
    def _handle_dict_items(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle dict.items()."""
        constraints = []
        
        if call.target and method_obj.receiver_var:
            # Create dict_items object
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
            tuple_var = self._make_temp_var("dict_items_tuple", call)
            constraints.append(AllocConstraint(
                target=tuple_var,
                alloc_site=AllocSite(stmt=call.stmt, kind=AllocKind.TUPLE),
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=tuple_var,
            ))

            value_var = self._make_temp_var("dict_items_value", call)
            constraints.append(LoadConstraint(
                base=method_obj.receiver_var,
                field=elem(),
                target=value_var,
            ))
            constraints.append(StoreConstraint(
                base=tuple_var,
                field=key(1),
                source=value_var,
            ))
            constraints.append(StoreConstraint(
                base=tuple_var,
                field=elem(),
                source=value_var,
            ))

            key_var = self._make_temp_var("dict_items_key", call)
            constraints.append(AllocConstraint(
                target=key_var,
                alloc_site=AllocSite(stmt=call.stmt, kind=AllocKind.UNKNOWN),
            ))
            constraints.append(StoreConstraint(
                base=tuple_var,
                field=key(0),
                source=key_var,
            ))
            constraints.append(StoreConstraint(
                base=tuple_var,
                field=elem(),
                source=key_var,
            ))
        
        return constraints
    
    # ===== Set Methods =====
    
    def _handle_set_add(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle set.add(x).
        
        Stores x to set.elem().
        """
        constraints = []
        
        if len(call.args) > 0 and method_obj.receiver_var:
            item_var = call.args[0]
            # Store item to receiver.elem()
            constraints.append(StoreConstraint(
                base=method_obj.receiver_var,
                field=elem(),
                source=item_var,
            ))
        
        return constraints

    def _handle_set_update(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle set.update(iterable)."""
        constraints = []
        
        if len(call.args) > 0 and method_obj.receiver_var:
            iterable_var = call.args[0]
            elem_var = self._make_temp_var("set_update_elem", call)
            constraints.append(LoadConstraint(
                base=iterable_var,
                field=elem(),
                target=elem_var,
            ))
            constraints.append(StoreConstraint(
                base=method_obj.receiver_var,
                field=elem(),
                source=elem_var,
            ))
        
        return constraints
    
    def _handle_set_discard(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle set.discard(x)."""
        # No-op for pointer analysis
        return []
    
    def _handle_set_remove(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle set.remove(x)."""
        # No-op for pointer analysis
        return []
    
    # ===== Iterator Functions =====
    
    def _handle_iter(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle iter(iterable).
        
        Creates an iterator whose elem() flows from iterable.elem().
        """
        constraints = []
        
        if call.target and len(call.args) > 0:
            iterable_var = call.args[0]
            
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))

            elem_var = self._make_temp_var("iter_elem", call)
            constraints.append(LoadConstraint(
                base=iterable_var,
                field=elem(),
                target=elem_var,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=elem_var,
            ))
        
        return constraints
    
    def _handle_next(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle next(iterator).
        
        Loads from iterator.elem().
        """
        constraints = []
        
        if call.target and len(call.args) > 0:
            iterator_var = call.args[0]
            
            # Load from iterator.elem()
            constraints.append(LoadConstraint(
                base=iterator_var,
                field=elem(),
                target=call.target
            ))
        
        return constraints
    
    def _handle_enumerate(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle enumerate(iterable).
        
        Creates enumerate iterator that yields (index, item) tuples.
        """
        constraints = []
        
        if call.target and len(call.args) > 0:
            # Create enumerate iterator
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
            tuple_var = self._make_temp_var("enumerate_tuple", call)
            constraints.append(AllocConstraint(
                target=tuple_var,
                alloc_site=AllocSite(stmt=call.stmt, kind=AllocKind.TUPLE),
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=tuple_var,
            ))

            item_var = self._make_temp_var("enumerate_item", call)
            constraints.append(LoadConstraint(
                base=call.args[0],
                field=elem(),
                target=item_var,
            ))
            constraints.append(StoreConstraint(
                base=tuple_var,
                field=key(1),
                source=item_var,
            ))
            constraints.append(StoreConstraint(
                base=tuple_var,
                field=elem(),
                source=item_var,
            ))

            index_var = self._make_temp_var("enumerate_index", call)
            constraints.append(AllocConstraint(
                target=index_var,
                alloc_site=AllocSite(stmt=call.stmt, kind=AllocKind.INTEGER),
            ))
            constraints.append(StoreConstraint(
                base=tuple_var,
                field=key(0),
                source=index_var,
            ))
            constraints.append(StoreConstraint(
                base=tuple_var,
                field=elem(),
                source=index_var,
            ))
        
        return constraints
    
    def _handle_zip(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle zip(*iterables)."""
        constraints = []
        
        if call.target:
            # Create zip iterator
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
            tuple_var = self._make_temp_var("zip_tuple", call)
            constraints.append(AllocConstraint(
                target=tuple_var,
                alloc_site=AllocSite(stmt=call.stmt, kind=AllocKind.TUPLE),
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=tuple_var,
            ))
            for idx, iterable_var in enumerate(call.args):
                elem_var = self._make_temp_var(f"zip_elem_{idx}", call)
                constraints.append(LoadConstraint(
                    base=iterable_var,
                    field=elem(),
                    target=elem_var,
                ))
                constraints.append(StoreConstraint(
                    base=tuple_var,
                    field=key(idx),
                    source=elem_var,
                ))
                constraints.append(StoreConstraint(
                    base=tuple_var,
                    field=elem(),
                    source=elem_var,
                ))
        
        return constraints
    
    def _handle_map(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle map(func, *iterables)."""
        constraints = []
        
        if call.target and len(call.args) > 1:
            # Create map iterator
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
            func_var = call.args[0]
            elem_vars = []
            for idx, iterable_var in enumerate(call.args[1:]):
                elem_var = self._make_temp_var(f"map_elem_{idx}", call)
                constraints.append(LoadConstraint(
                    base=iterable_var,
                    field=elem(),
                    target=elem_var,
                ))
                elem_vars.append(elem_var)
            result_var = self._make_temp_var("map_result", call)
            constraints.append(CallConstraint(
                callee=func_var,
                args=tuple(elem_vars),
                kwargs=call.kwargs,
                target=result_var,
                call_site=call.call_site,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=result_var,
            ))
        
        return constraints
    
    def _handle_filter(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle filter(func, iterable).
        
        Creates filter iterator linked to iterable elements.
        """
        constraints = []
        
        if call.target and len(call.args) > 1:
            func_var = call.args[0]
            iterable_var = call.args[1]
            
            # Create filter iterator
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
            
            # Link to iterable elements
            elem_var = self._make_temp_var("filter_elem", call)
            constraints.append(LoadConstraint(
                base=iterable_var,
                field=elem(),
                target=elem_var,
            ))
            pred_var = self._make_temp_var("filter_pred", call)
            constraints.append(CallConstraint(
                callee=func_var,
                args=(elem_var,),
                kwargs=(),
                target=pred_var,
                call_site=call.call_site,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=elem_var,
            ))
        
        return constraints
    
    def _handle_reversed(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle reversed(sequence).
        
        Creates reverse iterator linked to sequence elements.
        """
        constraints = []
        
        if call.target and len(call.args) > 0:
            sequence_var = call.args[0]
            
            # Create reverse iterator
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
            
            # Link to sequence elements
            elem_var = self._make_temp_var("reversed_elem", call)
            constraints.append(LoadConstraint(
                base=sequence_var,
                field=elem(),
                target=elem_var,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=elem_var,
            ))
        
        return constraints
    
    def _handle_sorted(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle sorted(iterable).
        
        Creates new list with elements from iterable.
        """
        constraints = []
        
        if call.target and len(call.args) > 0:
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.LIST)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
            elem_var = self._make_temp_var("sorted_elem", call)
            constraints.append(LoadConstraint(
                base=call.args[0],
                field=elem(),
                target=elem_var,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=elem_var,
            ))
        
        return constraints
    
    def _handle_range(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle range(...)."""
        constraints = []
        
        if call.target:
            # Create range object
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
            elem_var = self._make_temp_var("range_elem", call)
            constraints.append(AllocConstraint(
                target=elem_var,
                alloc_site=AllocSite(stmt=call.stmt, kind=AllocKind.INTEGER),
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=elem_var,
            ))
        
        return constraints
    
    # ===== Type/Scalar Functions =====
    
    def _handle_len(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle len(obj)."""
        constraints = []
        
        if call.target:
            # Create int object
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.INTEGER)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        return constraints
    
    def _handle_isinstance(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle isinstance(obj, type)."""
        constraints = []
        
        if call.target:
            # Create bool object
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.BOOLEAN)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        return constraints

    def _handle_issubclass(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle issubclass(cls, classinfo)."""
        constraints = []
        
        if call.target:
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.BOOLEAN)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        return constraints
    
    def _handle_type(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle type(obj)."""
        constraints = []
        
        if call.target and len(call.args) > 0:
            arg_var = call.args[0]
            arg_ctx = self.state.get_variable(scope, context, arg_var)
            target_ctx = self.state.get_variable(scope, context, call.target)
            arg_pts = self.state.get_points_to(arg_ctx)
            added = False
            for obj in arg_pts:
                if isinstance(obj, InstanceObject):
                    self.state._worklist.add((scope, NormalNode(target_ctx), PointsToSet.singleton(obj.class_obj)))
                    added = True
                elif isinstance(obj, ClassObject):
                    self.state._worklist.add((scope, NormalNode(target_ctx), PointsToSet.singleton(obj)))
                    added = True
                elif isinstance(obj, BuiltinInstanceObject):
                    builtin_cls = ObjectFactory.create_builtin_class(obj.builtin_type, context)
                    self.state._worklist.add((scope, NormalNode(target_ctx), PointsToSet.singleton(builtin_cls)))
                    added = True
                elif isinstance(obj, BuiltinClassObject):
                    self.state._worklist.add((scope, NormalNode(target_ctx), PointsToSet.singleton(obj)))
                    added = True
            if not added:
                alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
                constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        return constraints

    def _handle_object(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle object()."""
        constraints = []

        if call.target:
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))

        return constraints
    
    def _handle_bool(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle bool(obj)."""
        constraints = []
        
        if call.target:
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.BOOLEAN)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        return constraints
    
    def _handle_int(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle int(obj)."""
        constraints = []
        
        if call.target:
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.INTEGER)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        return constraints
    
    def _handle_float(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle float(obj)."""
        constraints = []
        
        if call.target:
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.FLOAT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        return constraints
    
    def _handle_str(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle str(obj)."""
        constraints = []
        
        if call.target:
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.STRING)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        return constraints

    def _handle_callable(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle callable(obj)."""
        constraints = []
        
        if call.target:
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.BOOLEAN)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        return constraints

    def _handle_getattr(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle getattr(obj, name, default=None)."""
        constraints = []
        
        if not call.target or len(call.args) < 2:
            return constraints
        
        base_var = call.args[0]
        name_var = call.args[1]
        const_names, has_non_const = self._resolve_attr_names(scope, context, name_var)
        
        for name in const_names:
            constraints.append(AttrReadConstraint(
                base=base_var,
                attr=name,
                target=call.target,
                call_site=call.call_site,
            ))
        
        if has_non_const or not const_names:
            constraints.append(AttrReadConstraint(
                base=base_var,
                attr=unknown(),
                target=call.target,
                call_site=call.call_site,
            ))
        
        if len(call.args) > 2:
            default_var = call.args[2]
            constraints.append(CopyConstraint(
                source=default_var,
                target=call.target,
            ))
        
        return constraints

    def _handle_setattr(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle setattr(obj, name, value)."""
        constraints = []
        
        if len(call.args) < 3:
            return constraints
        
        base_var = call.args[0]
        name_var = call.args[1]
        value_var = call.args[2]
        const_names, has_non_const = self._resolve_attr_names(scope, context, name_var)
        
        for name in const_names:
            constraints.append(AttrWriteConstraint(
                base=base_var,
                attr=name,
                source=value_var,
                call_site=call.call_site,
            ))
        
        if has_non_const or not const_names:
            constraints.append(AttrWriteConstraint(
                base=base_var,
                attr=unknown(),
                source=value_var,
                call_site=call.call_site,
            ))
        
        return constraints

    def _handle_hasattr(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle hasattr(obj, name)."""
        constraints = []
        
        if call.target:
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.BOOLEAN)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))

        if len(call.args) < 2:
            return constraints

        base_var = call.args[0]
        name_var = call.args[1]
        const_names, has_non_const = self._resolve_attr_names(scope, context, name_var)
        temp_var = self._make_temp_var("hasattr_value", call)

        for name in const_names:
            constraints.append(AttrReadConstraint(
                base=base_var,
                attr=name,
                target=temp_var,
                call_site=call.call_site,
            ))

        if has_non_const or not const_names:
            constraints.append(AttrReadConstraint(
                base=base_var,
                attr=unknown(),
                target=temp_var,
                call_site=call.call_site,
            ))
        
        return constraints

    def _handle_delattr(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle delattr(obj, name)."""
        constraints = []
        
        if len(call.args) < 2:
            return constraints
        
        base_var = call.args[0]
        name_var = call.args[1]
        const_names, has_non_const = self._resolve_attr_names(scope, context, name_var)
        
        for name in const_names:
            constraints.append(AttrDeleteConstraint(
                base=base_var,
                attr=name,
                call_site=call.call_site,
            ))
        
        if has_non_const or not const_names:
            constraints.append(AttrDeleteConstraint(
                base=base_var,
                attr=unknown(),
                call_site=call.call_site,
            ))
        
        return constraints

    def _handle_vars(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle vars(obj)."""
        constraints = []
        
        if not call.target or len(call.args) < 1:
            return constraints
        
        base_var = call.args[0]
        alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.DICT)
        constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        attr_names = self._collect_known_attr_names(scope, context, base_var)
        for idx, name in enumerate(sorted(attr_names)):
            val_var = self._make_temp_var(f"vars_attr_{idx}", call)
            constraints.append(AttrReadConstraint(
                base=base_var,
                attr=name,
                target=val_var,
                call_site=call.call_site,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=key(name),
                source=val_var,
            ))
            constraints.append(StoreConstraint(
                base=call.target,
                field=elem(),
                source=val_var,
            ))
        
        unknown_var = self._make_temp_var("vars_unknown", call)
        constraints.append(AttrReadConstraint(
            base=base_var,
            attr=unknown(),
            target=unknown_var,
            call_site=call.call_site,
        ))
        constraints.append(StoreConstraint(
            base=call.target,
            field=elem(),
            source=unknown_var,
        ))
        
        return constraints
    
    # ===== Object-Oriented Functions =====
    
    def _handle_super(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint'
    ) -> List['Constraint']:
        """Handle super() builtin for MRO-based method resolution.
        
        Creates a SuperObject that enables parent class field access:
        
        Supported forms:
        - super() - no args, uses __class__ cell var and first param
        - super(Class, instance) - explicit class and instance
        
        The SuperObject is created via AllocConstraint. A SuperResolveConstraint
        then populates it with current_class and instance_obj. When fields are
        accessed on the SuperObject, state.get_field() uses InheritanceConstraint
        to resolve through parent classes via PFG edges.
        
        Design:
        1. AllocConstraint creates SuperObject allocation
        2. SuperResolveConstraint resolves class/instance from args
        3. Field access on SuperObject triggers InheritanceConstraint
        4. Parent class fields flow to super field via PFG edges
        5. Methods are bound to instance_obj when called
        """
        constraints = []
        
        if not call.target:
            return constraints
        
        # Create SuperObject allocation
        alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
        constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        # Add SuperResolveConstraint to populate current_class and instance_obj
        # This constraint applies when the target's points-to set contains SuperObject
        if len(call.args) >= 2:
            # super(Class, instance) - explicit form
            class_var = call.args[0]
            instance_var = call.args[1]
            constraints.append(SuperResolveConstraint(
                target=call.target,
                class_var=class_var,
                instance_var=instance_var,
                implicit=False
            ))
        else:
            # super() - implicit form, needs to look up __class__ and first param
            # The constraint examines the enclosing scope when applied
            constraints.append(SuperResolveConstraint(
                target=call.target,
                class_var=None,
                instance_var=None,
                implicit=True
            ))
        
        return constraints
    
    # ===== Generic Handlers =====
    
    def _handle_generic_constructor(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        builtin_name: str
    ) -> List['Constraint']:
        """Handle generic builtin constructor."""
        constraints = []
        
        if call.target:
            logger.debug(f"Generic constructor: {builtin_name}")
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        return constraints
    
    def _handle_generic_builtin(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        function_name: str
    ) -> List['Constraint']:
        """Handle generic builtin function."""
        constraints = []
        
        if call.target:
            logger.debug(f"Generic builtin function: {function_name}")
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        return constraints
    
    def _handle_generic_method(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        method_obj: 'BuiltinMethodObject'
    ) -> List['Constraint']:
        """Handle generic builtin method."""
        constraints = []
        
        if call.target:
            logger.debug(f"Generic builtin method: {method_obj.method_name}")
            alloc_site = AllocSite(stmt=call.stmt, kind=AllocKind.OBJECT)
            constraints.append(AllocConstraint(target=call.target, alloc_site=alloc_site))
        
        return constraints


# Maintain backward compatibility with old BuiltinSummaryManager
class BuiltinSummaryManager:
    """Backward-compatible wrapper around BuiltinAPIHandler.
    
    This maintains the old interface while delegating to the new handler.
    """
    
    def __init__(self, config: 'Config'):
        """Initialize builtin summary manager.
        
        Args:
            config: Analysis configuration
        """
        self.config = config
        self._handler: Optional[BuiltinAPIHandler] = None
    
    def set_state(self, state: 'PointerAnalysisState'):
        """Set the analysis state (called by solver)."""
        self._handler = BuiltinAPIHandler(state, self.config)
    
    def get_handler(self) -> Optional[BuiltinAPIHandler]:
        """Get the builtin API handler."""
        return self._handler
    
    def has_summary(self, function_name: str) -> bool:
        """Check if function has a summary."""
        if not self._handler:
            return False
        return (
            function_name in self._handler._function_handlers or
            function_name in BuiltinAPIHandler.CONTAINER_TYPES or
            function_name in BuiltinAPIHandler.ITERATOR_BUILTINS or
            function_name in BuiltinAPIHandler.TYPE_BUILTINS
        )
