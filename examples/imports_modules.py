#!/usr/bin/env python3
"""
Imports and Module System Example for PyFlow

This example demonstrates Python import system, module loading, and dynamic
imports that can be analyzed by PyFlow's static analysis tools.

Usage:
    pyflow optimize imports_modules.py --analysis ipa
    pyflow callgraph imports_modules.py
"""

import sys
import importlib
import importlib.util
from typing import Any, Dict, List, Optional, Union, Callable
from pathlib import Path

# Standard library imports
import os
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from functools import partial, wraps

# Conditional imports
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    pd = None

# Relative imports (simulated)
# from .local_module import LocalClass
# from ..parent_module import ParentFunction

# Dynamic imports
def dynamic_import_example():
    """Demonstrate dynamic module importing."""
    
    # Import by string name
    try:
        math_module = importlib.import_module('math')
        sqrt_func = getattr(math_module, 'sqrt')
        result = sqrt_func(16)
        print(f"Dynamic sqrt(16) = {result}")
    except ImportError as e:
        print(f"Failed to import math: {e}")
    
    # Import with error handling
    modules_to_try = ['json', 'xml', 'yaml', 'toml']
    loaded_modules = {}
    
    for module_name in modules_to_try:
        try:
            module = importlib.import_module(module_name)
            loaded_modules[module_name] = module
            print(f"Successfully imported {module_name}")
        except ImportError:
            print(f"Failed to import {module_name}")
    
    return loaded_modules

# Module introspection
def module_introspection():
    """Demonstrate module introspection capabilities."""
    
    def analyze_module(module_name: str) -> Dict[str, Any]:
        """Analyze a module and return information about it."""
        try:
            module = importlib.import_module(module_name)
            
            analysis = {
                'name': module_name,
                'file': getattr(module, '__file__', None),
                'package': getattr(module, '__package__', None),
                'doc': getattr(module, '__doc__', None),
                'version': getattr(module, '__version__', None),
                'functions': [],
                'classes': [],
                'variables': []
            }
            
            # Analyze module contents
            for name in dir(module):
                if not name.startswith('_'):
                    obj = getattr(module, name)
                    obj_type = type(obj).__name__
                    
                    if callable(obj):
                        if isinstance(obj, type):
                            analysis['classes'].append({
                                'name': name,
                                'type': obj_type,
                                'doc': getattr(obj, '__doc__', None)
                            })
                        else:
                            analysis['functions'].append({
                                'name': name,
                                'type': obj_type,
                                'doc': getattr(obj, '__doc__', None)
                            })
                    else:
                        analysis['variables'].append({
                            'name': name,
                            'type': obj_type,
                            'value': str(obj)[:100]  # Truncate long values
                        })
            
            return analysis
            
        except ImportError as e:
            return {'error': str(e)}
    
    # Analyze some common modules
    modules_to_analyze = ['math', 'json', 'os', 'sys']
    analyses = {}
    
    for module_name in modules_to_analyze:
        analyses[module_name] = analyze_module(module_name)
    
    return analyses

# Plugin system using imports
class PluginManager:
    """Plugin manager using dynamic imports."""
    
    def __init__(self):
        self.plugins: Dict[str, Any] = {}
        self.plugin_paths: List[str] = []
    
    def add_plugin_path(self, path: str):
        """Add a path to search for plugins."""
        self.plugin_paths.append(path)
    
    def load_plugin(self, plugin_name: str, module_path: str = None) -> bool:
        """Load a plugin dynamically."""
        try:
            if module_path:
                # Load from specific path
                spec = importlib.util.spec_from_file_location(plugin_name, module_path)
                if spec is None:
                    return False
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            else:
                # Load from installed modules
                module = importlib.import_module(plugin_name)
            
            # Look for plugin class or function
            if hasattr(module, 'Plugin'):
                plugin_class = getattr(module, 'Plugin')
                plugin_instance = plugin_class()
                self.plugins[plugin_name] = plugin_instance
                return True
            elif hasattr(module, 'main'):
                plugin_func = getattr(module, 'main')
                self.plugins[plugin_name] = plugin_func
                return True
            
            return False
            
        except Exception as e:
            print(f"Failed to load plugin {plugin_name}: {e}")
            return False
    
    def execute_plugin(self, plugin_name: str, *args, **kwargs):
        """Execute a loaded plugin."""
        if plugin_name not in self.plugins:
            raise ValueError(f"Plugin {plugin_name} not loaded")
        
        plugin = self.plugins[plugin_name]
        if callable(plugin):
            return plugin(*args, **kwargs)
        else:
            return plugin

# Module reloading
def module_reloading_example():
    """Demonstrate module reloading capabilities."""
    
    def create_test_module():
        """Create a test module file."""
        module_content = '''
def get_value():
    return "original_value"

def get_message():
    return "Hello from test module"
'''
        with open('test_module.py', 'w') as f:
            f.write(module_content)
    
    def reload_and_test():
        """Reload module and test changes."""
        # Create initial module
        create_test_module()
        
        # Import module
        import test_module
        print(f"Initial value: {test_module.get_value()}")
        
        # Modify module
        modified_content = '''
def get_value():
    return "modified_value"

def get_message():
    return "Hello from modified test module"

def new_function():
    return "This is a new function"
'''
        with open('test_module.py', 'w') as f:
            f.write(modified_content)
        
        # Reload module
        importlib.reload(test_module)
        print(f"After reload: {test_module.get_value()}")
        print(f"New function: {test_module.new_function()}")
        
        # Clean up
        os.remove('test_module.py')
    
    return reload_and_test

# Import hooks
class CustomImportHook:
    """Custom import hook for module loading."""
    
    def __init__(self):
        self.loaded_modules = []
    
    def find_spec(self, fullname, path, target=None):
        """Find module spec."""
        if fullname.startswith('custom_'):
            # Create a mock module
            spec = importlib.util.spec_from_loader(
                fullname,
                CustomLoader(),
                origin='custom'
            )
            return spec
        return None

class CustomLoader:
    """Custom module loader."""
    
    def create_module(self, spec):
        """Create module object."""
        return None  # Use default module creation
    
    def exec_module(self, module):
        """Execute module code."""
        # Add custom attributes to the module
        module.custom_attribute = "This is a custom module"
        module.custom_function = lambda x: f"Custom: {x}"
        module.__version__ = "1.0.0"

# Module caching and lazy loading
class LazyModule:
    """Lazy loading module wrapper."""
    
    def __init__(self, module_name: str):
        self.module_name = module_name
        self._module = None
        self._loading = False
    
    def __getattr__(self, name):
        """Lazy load module when attribute is accessed."""
        if self._module is None and not self._loading:
            self._loading = True
            try:
                self._module = importlib.import_module(self.module_name)
            except ImportError as e:
                raise AttributeError(f"Module {self.module_name} not found: {e}")
            finally:
                self._loading = False
        
        if self._module is None:
            raise AttributeError(f"Module {self.module_name} not available")
        
        return getattr(self._module, name)

# Module dependency analysis
def analyze_dependencies(module_name: str) -> Dict[str, List[str]]:
    """Analyze module dependencies."""
    
    def get_module_imports(module):
        """Get all imports from a module."""
        imports = []
        if hasattr(module, '__file__') and module.__file__:
            try:
                with open(module.__file__, 'r') as f:
                    content = f.read()
                
                # Simple regex-based import detection
                import re
                import_patterns = [
                    r'^import\s+(\w+)',
                    r'^from\s+(\w+)\s+import',
                    r'^from\s+(\w+\.\w+)\s+import'
                ]
                
                for line in content.split('\n'):
                    for pattern in import_patterns:
                        match = re.match(pattern, line.strip())
                        if match:
                            imports.append(match.group(1))
            except Exception as e:
                print(f"Error reading module file: {e}")
        
        return imports
    
    try:
        module = importlib.import_module(module_name)
        direct_imports = get_module_imports(module)
        
        # Analyze transitive dependencies
        all_dependencies = set(direct_imports)
        to_analyze = direct_imports.copy()
        
        while to_analyze:
            current_import = to_analyze.pop(0)
            try:
                dep_module = importlib.import_module(current_import)
                dep_imports = get_module_imports(dep_module)
                for dep in dep_imports:
                    if dep not in all_dependencies:
                        all_dependencies.add(dep)
                        to_analyze.append(dep)
            except ImportError:
                continue  # Skip modules that can't be imported
        
        return {
            'direct': direct_imports,
            'all': list(all_dependencies),
            'transitive': list(all_dependencies - set(direct_imports))
        }
        
    except ImportError as e:
        return {'error': str(e)}

# Module factory pattern
class ModuleFactory:
    """Factory for creating modules dynamically."""
    
    @staticmethod
    def create_module(name: str, code: str, **kwargs) -> Any:
        """Create a module from code string."""
        spec = importlib.util.spec_from_loader(
            name,
            ModuleFactory.CodeLoader(code),
            origin='<string>'
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Add any additional attributes
        for key, value in kwargs.items():
            setattr(module, key, value)
        
        return module
    
    class CodeLoader:
        """Loader for code-based modules."""
        
        def __init__(self, code: str):
            self.code = code
        
        def create_module(self, spec):
            return None
        
        def exec_module(self, module):
            exec(self.code, module.__dict__)

# Module testing utilities
def test_module_functionality(module_name: str) -> Dict[str, Any]:
    """Test basic functionality of a module."""
    
    try:
        module = importlib.import_module(module_name)
        
        tests = {
            'import_successful': True,
            'has_docstring': bool(getattr(module, '__doc__', None)),
            'has_version': bool(getattr(module, '__version__', None)),
            'functions': [],
            'classes': [],
            'test_results': {}
        }
        
        # Test functions
        for name in dir(module):
            if not name.startswith('_') and callable(getattr(module, name)):
                obj = getattr(module, name)
                if not isinstance(obj, type):
                    tests['functions'].append(name)
                    
                    # Try to test the function
                    try:
                        if name in ['sqrt', 'sin', 'cos']:  # Math functions
                            result = obj(1.0)
                            tests['test_results'][name] = {'success': True, 'result': result}
                        elif name in ['loads', 'dumps']:  # JSON functions
                            if name == 'loads':
                                result = obj('{"test": "value"}')
                            else:
                                result = obj({'test': 'value'})
                            tests['test_results'][name] = {'success': True, 'result': result}
                    except Exception as e:
                        tests['test_results'][name] = {'success': False, 'error': str(e)}
        
        return tests
        
    except ImportError as e:
        return {'import_successful': False, 'error': str(e)}

if __name__ == "__main__":
    # Example usage
    print("=== Dynamic Imports ===")
    loaded_modules = dynamic_import_example()
    print(f"Loaded modules: {list(loaded_modules.keys())}")
    
    print("\n=== Module Introspection ===")
    analyses = module_introspection()
    for module_name, analysis in analyses.items():
        if 'error' not in analysis:
            print(f"\n{module_name}:")
            print(f"  Functions: {len(analysis['functions'])}")
            print(f"  Classes: {len(analysis['classes'])}")
            print(f"  Variables: {len(analysis['variables'])}")
    
    print("\n=== Plugin Manager ===")
    plugin_manager = PluginManager()
    # Note: This would work with actual plugin modules
    print("Plugin manager created (would load actual plugins in real usage)")
    
    print("\n=== Module Reloading ===")
    reload_func = module_reloading_example()
    reload_func()
    
    print("\n=== Lazy Loading ===")
    lazy_math = LazyModule('math')
    print(f"Lazy sqrt(16): {lazy_math.sqrt(16)}")
    
    print("\n=== Dependency Analysis ===")
    deps = analyze_dependencies('json')
    if 'error' not in deps:
        print(f"JSON dependencies - Direct: {len(deps['direct'])}, All: {len(deps['all'])}")
    
    print("\n=== Module Factory ===")
    code = '''
def hello(name):
    return f"Hello, {name}!"

def add(a, b):
    return a + b
'''
    dynamic_module = ModuleFactory.create_module('dynamic_test', code, author='PyFlow')
    print(f"Dynamic module: {dynamic_module.hello('World')}")
    print(f"Author: {dynamic_module.author}")
    
    print("\n=== Module Testing ===")
    math_tests = test_module_functionality('math')
    print(f"Math module tests: {math_tests['test_results']}")
    
    print("\n=== Conditional Imports ===")
    print(f"NumPy available: {HAS_NUMPY}")
    print(f"Pandas available: {HAS_PANDAS}")
    
    if HAS_NUMPY:
        print(f"NumPy version: {np.__version__}")
    
    print("\n=== Import Hooks ===")
    # Install custom import hook
    hook = CustomImportHook()
    sys.meta_path.insert(0, hook)
    
    try:
        import custom_test
        print(f"Custom module: {custom_test.custom_function('test')}")
    except ImportError:
        print("Custom module not found (expected in this context)")
    
    # Remove hook
    sys.meta_path.remove(hook)
