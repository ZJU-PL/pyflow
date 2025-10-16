
"""
Definition management and points-to analysis for PyFlow.

This module provides the core data structures for tracking variable definitions,
function definitions, and performing points-to analysis. It implements the
fundamental analysis that tracks what each variable can point to during program
execution.
"""

from pyflow.machinery.utils import join_ns, RETURN_NAME, NAME_DEF, FUN_DEF, MOD_DEF, CLS_DEF, EXT_DEF
from pyflow.machinery.pointers import LiteralPointer, NamePointer


class DefinitionManager(object):
    """
    Manages all variable and function definitions in the program.
    
    This class is the central registry for all definitions encountered during
    analysis. It performs points-to analysis to determine what each variable
    can point to, enabling sophisticated data flow analysis.
    """
    
    def __init__(self):
        """Initialize the definition manager with an empty registry."""
        self.defs = {}  # Maps namespace to Definition objects

    def create(self, ns, def_type):
        """
        Create a new definition in the registry.
        
        Args:
            ns (str): The namespace/name for the definition.
            def_type (str): The type of definition (FUN_DEF, NAME_DEF, etc.).
            
        Returns:
            Definition: The newly created definition.
            
        Raises:
            DefinitionError: If namespace is invalid, type is invalid, or
                           definition already exists.
        """
        if not ns or not isinstance(ns, str):
            raise DefinitionError("Invalid namespace argument")
        if def_type not in Definition.types:
            raise DefinitionError("Invalid def type argument")
        if self.get(ns):
            raise DefinitionError("Definition already exists")

        self.defs[ns] = Definition(ns, def_type)
        return self.defs[ns]

    def assign(self, ns, defi):
        """
        Assign a definition to a namespace, merging with existing information.
        
        Args:
            ns (str): The target namespace.
            defi (Definition): The definition to assign.
            
        Returns:
            Definition: The updated definition in the registry.
        """
        self.defs[ns] = Definition(ns, defi.get_type())
        self.defs[ns].merge(defi)

        # If it is a function def, we need to create a return pointer
        if defi.is_function_def():
            return_ns = join_ns(ns,  RETURN_NAME)
            self.defs[return_ns] = Definition(return_ns, NAME_DEF)
            self.defs[return_ns].get_name_pointer().add(
                join_ns(defi.get_ns(), RETURN_NAME)
            )

        return self.defs[ns]

    def get(self, ns):
        """
        Retrieve a definition by namespace.
        
        Args:
            ns (str): The namespace to look up.
            
        Returns:
            Definition or None: The definition if found, None otherwise.
        """
        if ns in self.defs:
            return self.defs[ns]

    def get_defs(self):
        """
        Get all definitions in the registry.
        
        Returns:
            dict: Dictionary mapping namespaces to Definition objects.
        """
        return self.defs

    def handle_function_def(self, parent_ns, fn_name):
        """
        Handle function definition creation and setup.
        
        Args:
            parent_ns (str): The parent namespace.
            fn_name (str): The function name.
            
        Returns:
            Definition: The function definition with return pointer set up.
        """
        full_ns = join_ns(parent_ns, fn_name)
        defi = self.get(full_ns)
        if not defi:
            defi = self.create(full_ns, FUN_DEF)
            defi.decorator_names = set()

        return_ns = join_ns(full_ns, RETURN_NAME)
        if not self.get(return_ns):
            self.create(return_ns, NAME_DEF)

        return defi

    def handle_class_def(self, parent_ns, cls_name):
        """
        Handle class definition creation.
        
        Args:
            parent_ns (str): The parent namespace.
            cls_name (str): The class name.
            
        Returns:
            Definition: The class definition.
        """
        full_ns = join_ns(parent_ns, cls_name)
        defi = self.get(full_ns)
        if not defi:
            defi = self.create(full_ns, CLS_DEF)

        return defi

    def transitive_closure(self):
        """
        Compute the transitive closure of all definitions.
        
        This method performs a depth-first search to find all definitions that
        each definition can transitively reach through pointer relationships.
        This is essential for understanding the complete data flow graph.
        
        Returns:
            dict: Mapping from namespace to set of all transitively reachable namespaces.
        """
        closured = {}

        def dfs(defi):
            """Depth-first search to compute transitive closure."""
            name_pointer = defi.get_name_pointer()
            new_set = set()
            
            # Base case: already computed
            if closured.get(defi.get_ns(), None) is not None:
                return closured[defi.get_ns()]

            # If no direct pointers, just add self
            if not name_pointer.get():
                new_set.add(defi.get_ns())

            closured[defi.get_ns()] = new_set

            # Recursively process all pointed-to definitions
            for name in name_pointer.get():
                if not self.defs.get(name, None):
                    continue
                items = dfs(self.defs[name])
                if not items:
                    items = set([name])
                new_set = new_set.union(items)

            closured[defi.get_ns()] = new_set
            return closured[defi.get_ns()]

        # Process all definitions
        for ns, current_def in self.defs.items():
            if closured.get(current_def, None) is None:
                dfs(current_def)

        return closured

    def complete_definitions(self):
        """
        Complete the points-to analysis by propagating information through the graph.
        
        This is the most computationally expensive part of the analysis process.
        It performs iterative data flow analysis to determine what each variable
        can point to, propagating information through assignments and function calls.
        
        The algorithm iterates until no more information can be propagated,
        implementing a worklist-based approach for efficiency.
        """
        def update_pointsto_args(pointsto_args, arg, name):
            """
            Update the points-to arguments by propagating information from arg to pointsto_args.
            
            This helper function handles the propagation of points-to information
            between arguments, detecting cycles and avoiding infinite loops.
            
            Args:
                pointsto_args: The target arguments to update.
                arg: The source arguments to propagate from.
                name: The name of the current definition (for cycle detection).
                
            Returns:
                bool: True if any changes were made, False otherwise.
            """
            changed_something = False
            if arg == pointsto_args:
                return False
                
            for pointsto_arg in pointsto_args:
                if not self.defs.get(pointsto_arg, None):
                    continue
                if pointsto_arg == name:
                    continue
                pointsto_arg_def = self.defs[pointsto_arg].get_name_pointer()
                if pointsto_arg_def == pointsto_args:
                    continue

                # Sometimes we may end up with a cycle - remove it
                if pointsto_arg in arg:
                    arg.remove(pointsto_arg)

                for item in arg:
                    if item not in pointsto_arg_def.get():
                        if self.defs.get(item, None) is not None:
                            changed_something = True
                    # HACK: this check shouldn't be needed
                    # if we remove this the following breaks:
                    # x = lambda x: x + 1
                    # x(1)
                    # since on line 184 we don't discriminate between
                    # literal values and name values
                    if not self.defs.get(item, None):
                        continue
                    pointsto_arg_def.add(item)
            return changed_something

        # Main analysis loop - iterate until no more changes occur
        for i in range(len(self.defs)):
            changed_something = False
            
            # Process each definition in the registry
            for ns, current_def in self.defs.items():
                # Get the name pointer of the definition we're currently iterating
                current_name_pointer = current_def.get_name_pointer()
                
                # Iterate through all names that the current definition points to
                # Use .copy() to avoid modification during iteration
                for name in current_name_pointer.get().copy():
                    # Get the name pointer of the pointed-to name
                    if not self.defs.get(name, None):
                        continue
                    if name == ns:  # Skip self-references
                        continue

                    pointsto_name_pointer = self.defs[name].get_name_pointer()
                    
                    # Iterate through the arguments of the current definition
                    for arg_name, arg in current_name_pointer.get_args().items():
                        pos = current_name_pointer.get_pos_of_name(arg_name)
                        if pos is not None:
                            # Handle positional arguments
                            pointsto_args = pointsto_name_pointer.get_pos_arg(pos)
                            if not pointsto_args:
                                pointsto_name_pointer.add_pos_arg(pos, None, arg)
                                continue
                        else:
                            # Handle named arguments
                            pointsto_args = pointsto_name_pointer.get_arg(arg_name)
                            if not pointsto_args:
                                pointsto_name_pointer.add_arg(arg_name, arg)
                                continue
                                
                        # Propagate information and track if changes occurred
                        changed_something = changed_something or update_pointsto_args(
                            pointsto_args, arg, current_def.get_ns()
                        )

            # If no changes occurred in this iteration, we've reached a fixpoint
            if not changed_something:
                break


class Definition(object):
    """
    Represents a single definition in the program.
    
    A definition can be a variable, function, class, module, or external symbol.
    Each definition tracks what it can point to through literal and name pointers,
    enabling sophisticated points-to analysis.
    """
    
    types = [
        FUN_DEF,    # Function definition
        MOD_DEF,    # Module definition  
        NAME_DEF,   # Variable/name definition
        CLS_DEF,    # Class definition
        EXT_DEF,    # External definition (builtin, etc.)
    ]

    def __init__(self, fullns, def_type):
        """
        Initialize a definition.
        
        Args:
            fullns (str): The full namespace/name of the definition.
            def_type (str): The type of definition (one of the types above).
        """
        self.fullns = fullns  # Full namespace/name
        self.points_to = {"lit": LiteralPointer(), "name": NamePointer()}  # Points-to information
        self.def_type = def_type  # Definition type

    def get_type(self):
        """
        Get the definition type.
        
        Returns:
            str: The type of this definition.
        """
        return self.def_type

    def is_function_def(self):
        """
        Check if this is a function definition.
        
        Returns:
            bool: True if this is a function definition.
        """
        return self.def_type == FUN_DEF

    def is_ext_def(self):
        """
        Check if this is an external definition.
        
        Returns:
            bool: True if this is an external definition.
        """
        return self.def_type == EXT_DEF

    def is_callable(self):
        """
        Check if this definition is callable (function or external).
        
        Returns:
            bool: True if this definition can be called.
        """
        return self.is_function_def() or self.is_ext_def()

    def get_lit_pointer(self):
        """
        Get the literal pointer for this definition.
        
        Returns:
            LiteralPointer: The literal pointer object.
        """
        return self.points_to["lit"]

    def get_name_pointer(self):
        """
        Get the name pointer for this definition.
        
        Returns:
            NamePointer: The name pointer object.
        """
        return self.points_to["name"]

    def get_name(self):
        """
        Get the simple name (last part of namespace) of this definition.
        
        Returns:
            str: The simple name of the definition.
        """
        return self.fullns.split(".")[-1]

    def get_ns(self):
        """
        Get the full namespace of this definition.
        
        Returns:
            str: The full namespace.
        """
        return self.fullns

    def merge(self, to_merge):
        """
        Merge another definition's points-to information into this one.
        
        Args:
            to_merge (Definition): The definition to merge from.
        """
        for name, pointer in to_merge.points_to.items():
            self.points_to[name].merge(pointer)


class DefinitionError(Exception):
    """Exception raised for definition-related errors."""
    pass