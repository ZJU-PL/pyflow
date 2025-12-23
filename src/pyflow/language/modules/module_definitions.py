"""Module definitions for tracking Python module imports and definitions.

This module provides classes for tracking module definitions, imports, and
their relationships. It maintains a global registry of project definitions
and provides utilities for managing module-level definitions.

Key concepts:
- ModuleDefinition: Represents a single module definition
- LocalModuleDefinition: Represents a local (project) module definition
- ModuleDefinitions: Collection of module definitions for a module
- project_definitions: Global registry of all project definitions
"""

import ast


# Contains all project definitions for a program run
# Only used in framework_adaptor.py, but modified here
project_definitions = dict()


class ModuleDefinition():
    """Represents a module definition (class, function, etc.).
    
    ModuleDefinition tracks definitions within modules, including their
    names, parent modules, and associated AST nodes. It handles both
    top-level and nested module definitions.
    
    Attributes:
        module_definitions: Local module definitions collection
        name: Full qualified name of the definition
        node: AST node for this definition (if available)
        path: File path where definition is located
        parent_module_name: Parent module name (for nested definitions)
    """
    module_definitions = None
    name = None
    node = None
    path = None

    def __init__(
        self,
        local_module_definitions,
        name,
        parent_module_name,
        path
    ):
        """Initialize module definition.
        
        Args:
            local_module_definitions: ModuleDefinitions collection
            name: Name of the definition
            parent_module_name: Parent module name (or None for top-level)
            path: File path where definition is located
        """
        self.module_definitions = local_module_definitions
        self.parent_module_name = parent_module_name
        self.path = path

        if parent_module_name:
            if isinstance(parent_module_name, ast.alias):
                self.name = parent_module_name.name + '.' + name
            else:
                self.name = parent_module_name + '.' + name
        else:
            self.name = name

    def __str__(self):
        name = 'NoName'
        node = 'NoNode'
        if self.name:
            name = self.name
        if self.node:
            node = str(self.node)
        return "Path:" + self.path + " " + self.__class__.__name__ + ': ' + ';'.join((name, node))


class LocalModuleDefinition(ModuleDefinition):
    """Represents a local (project) module definition.
    
    LocalModuleDefinition marks definitions that are defined in the
    current project (not imported from external modules).
    """
    pass


class ModuleDefinitions():
    """Collection of module definitions for a module.
    
    ModuleDefinitions manages definitions within a module, tracking:
    - Imported definitions: Definitions imported from other modules
    - Local definitions: Definitions defined in this module
    - Class definitions: Class definitions in this module
    - Import aliases: Mapping of import aliases to actual names
    
    It filters definitions based on import statements and maintains
    a global registry of project definitions.
    
    Attributes:
        import_names: List of names imported (or ["*"] for wildcard)
        module_name: Name of the module (ast.alias or string)
        is_init: Whether this is an __init__.py module
        filename: Filename of the module
        definitions: List of ModuleDefinition instances
        classes: List of class definitions
        import_alias_mapping: Dictionary mapping aliases to actual names
    """

    def __init__(
        self,
        import_names=None,
        module_name=None,
        is_init=False,
        filename=None
    ):
        """Initialize module definitions collection.
        
        Args:
            import_names: List of imported names (or ["*"] for wildcard)
            module_name: Module name (ast.alias or string, for normal imports)
            is_init: Whether this is __init__.py module
            filename: Filename of the module
        """
        self.import_names = import_names
        # module_name is sometimes ast.alias or a string
        self.module_name = module_name
        self.is_init = is_init
        self.filename = filename
        self.definitions = list()
        self.classes = list()
        self.import_alias_mapping = dict()

    def append_if_local_or_in_imports(self, definition):
        """Add definition if it's local or matches import names.
        
        Adds definition to collection if:
        - It's a LocalModuleDefinition (local definition)
        - Import is wildcard ("*")
        - Definition name is in import_names
        - Definition name matches an import alias
        
        Also adds to global project_definitions registry.
        
        Args:
            definition: ModuleDefinition to add
        """
        if isinstance(definition, LocalModuleDefinition):
            self.definitions.append(definition)
        elif self.import_names == ["*"]:
            self.definitions.append(definition)
        elif self.import_names and definition.name in self.import_names:
            self.definitions.append(definition)
        elif (self.import_alias_mapping and definition.name in
              self.import_alias_mapping.values()):
            self.definitions.append(definition)

        if definition.parent_module_name:
            self.definitions.append(definition)

        if definition.node not in project_definitions:
            project_definitions[definition.node] = definition

    def get_definition(self, name):
        """Get definition by name.
        
        Args:
            name: Name of definition to find
            
        Returns:
            ModuleDefinition: Definition with matching name, or None
        """
        for definition in self.definitions:
            if definition.name == name:
                return definition

    def set_definition_node(self, node, name):
        """Set the AST node for a definition by name.
        
        Args:
            node: AST node to set
            name: Name of definition to update
        """
        definition = self.get_definition(name)
        if definition:
            definition.node = node

    def __str__(self):
        module = 'NoModuleName'
        if self.module_name:
            module = self.module_name

        if self.definitions:
            if isinstance(module, ast.alias):
                return (
                    'Definitions: "' + '", "'
                    .join([str(definition) for definition in self.definitions]) +
                    '" and module_name: ' + module.name +
                    ' and filename: ' + str(self.filename) +
                    ' and is_init: ' + str(self.is_init) + '\n')
            return (
                'Definitions: "' + '", "'
                .join([str(definition) for definition in self.definitions]) +
                '" and module_name: ' + module +
                ' and filename: ' + str(self.filename) +
                ' and is_init: ' + str(self.is_init) + '\n')
        else:
            if isinstance(module, ast.alias):
                return (
                    'import_names is ' + str(self.import_names) +
                    ' No Definitions, module_name: ' + str(module.name) +
                    ' and filename: ' + str(self.filename) +
                    ' and is_init: ' + str(self.is_init) + '\n')
            return (
                'import_names is ' + str(self.import_names) +
                ' No Definitions, module_name: ' + str(module) +
                ' and filename: ' + str(self.filename) +
                ' and is_init: ' + str(self.is_init) + '\n')