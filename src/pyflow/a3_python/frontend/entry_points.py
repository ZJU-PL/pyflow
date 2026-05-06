"""
Entry Point Detection for Interprocedural Analysis.

Implements entry point identification as defined in python-barrier-certificate-theory.md §9.5.7:

Definition (Entry Points): Entry points are the roots of reachability:
1. Module-level code: Statements at the top level of each module
2. `if __name__ == "__main__":` blocks
3. Framework entry points: Flask routes, Django views, pytest tests
4. Callbacks: Functions passed to libraries

Analysis must:
1. Identify all entry points
2. Compute call graph reachability from entry points
3. Analyze all reachable functions (not just module-level code)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path
import ast
import re


# Patterns for identifying sensitive parameter names
# Used to apply σ-taint (sensitivity) for CLEARTEXT_LOGGING, CLEARTEXT_STORAGE, etc.
SENSITIVE_PARAM_PATTERNS = [
    'pass', 'password', 'passwd', 'pwd',
    'secret', 'token', 'key', 'api_key', 'apikey',
    'credential', 'auth', 'ssn', 'credit_card',
    'pin', 'private'
]


def mark_sensitive_params(tainted_params: List[str]) -> List[str]:
    """
    Identify which tainted parameters contain sensitive data.
    
    Used to apply σ-taint (sensitivity) in addition to τ-taint (untrusted).
    This enables detection of CLEARTEXT_LOGGING, CLEARTEXT_STORAGE, WEAK_SENSITIVE_DATA_HASHING.
    
    Args:
        tainted_params: List of parameter names that receive user input
    
    Returns:
        List of parameters matching sensitive patterns
    """
    sensitive = []
    for param in tainted_params:
        param_lower = param.lower()
        if any(pattern in param_lower for pattern in SENSITIVE_PARAM_PATTERNS):
            sensitive.append(param)
    return sensitive


@dataclass
class EntryPoint:
    """An identified entry point in the program."""
    name: str
    qualified_name: str
    file_path: str
    line_number: int
    entry_type: str  # 'main_block', 'module', 'flask_route', 'django_view', 'pytest', 'callback'
    
    # For framework entry points, additional metadata
    route_path: Optional[str] = None  # For Flask/Django routes
    http_methods: List[str] = field(default_factory=list)  # GET, POST, etc.
    
    # Parameters that receive external input
    tainted_params: List[str] = field(default_factory=list)
    
    # Parameters containing sensitive data (passwords, keys, tokens)
    # Used for σ-taint (sensitivity) in addition to τ-taint (untrusted)
    sensitive_params: List[str] = field(default_factory=list)


class EntryPointDetector(ast.NodeVisitor):
    """
    AST visitor that detects entry points in Python code.
    
    Detects:
    - if __name__ == "__main__": blocks
    - Flask route decorators (@app.route, @blueprint.route)
    - Django view functions/classes
    - pytest test functions
    - Click/argparse CLI handlers
    - asyncio entry points
    """
    
    def __init__(self, file_path: str, module_name: str):
        self.file_path = file_path
        self.module_name = module_name
        self.entry_points: List[EntryPoint] = []
        
        # Context
        self.current_class: Optional[str] = None
        self.decorators_stack: List[List[ast.expr]] = []
        
        # Track imports for framework detection
        self.flask_app_names: Set[str] = set()
        self.has_flask = False
        self.has_django = False
        self.has_pytest = False
        self.has_click = False
        self.has_fastapi = False
    
    def visit_Import(self, node: ast.Import) -> None:
        """Detect framework imports."""
        for alias in node.names:
            if alias.name == 'flask' or alias.name.startswith('flask.'):
                self.has_flask = True
            if alias.name == 'django' or alias.name.startswith('django.'):
                self.has_django = True
            if alias.name == 'pytest':
                self.has_pytest = True
            if alias.name == 'click':
                self.has_click = True
            if alias.name == 'fastapi' or alias.name.startswith('fastapi.'):
                self.has_fastapi = True
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Detect framework imports."""
        module = node.module or ''
        if module.startswith('flask'):
            self.has_flask = True
            for alias in node.names:
                if alias.name == 'Flask':
                    name = alias.asname or alias.name
                    self.flask_app_names.add(name)
        if module.startswith('django'):
            self.has_django = True
        if module == 'pytest':
            self.has_pytest = True
        if module == 'click':
            self.has_click = True
        if module.startswith('fastapi'):
            self.has_fastapi = True
        self.generic_visit(node)
    
    def visit_If(self, node: ast.If) -> None:
        """Detect if __name__ == "__main__": blocks."""
        if self._is_main_block(node.test):
            entry = EntryPoint(
                name='__main__',
                qualified_name=f'{self.module_name}.__main__',
                file_path=self.file_path,
                line_number=node.lineno,
                entry_type='main_block',
            )
            self.entry_points.append(entry)
            
            # Also look for function calls in the main block
            for stmt in node.body:
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    # Direct function call in main
                    pass
        
        self.generic_visit(node)
    
    def _is_main_block(self, test: ast.expr) -> bool:
        """Check if test is `__name__ == "__main__"`."""
        if isinstance(test, ast.Compare):
            if len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
                left = test.left
                right = test.comparators[0] if test.comparators else None
                
                if isinstance(left, ast.Name) and left.id == '__name__':
                    if isinstance(right, ast.Constant):
                        return right.value == '__main__'
                
                if isinstance(right, ast.Name) and right.id == '__name__':
                    if isinstance(left, ast.Constant):
                        return val == '__main__'
        return False
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Detect decorated entry point functions."""
        self._check_function_entry(node)
        self.generic_visit(node)
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Detect async entry point functions."""
        self._check_function_entry(node)
        self.generic_visit(node)
    
    def _check_function_entry(self, node) -> None:
        """Check if a function is an entry point based on decorators and naming."""
        qualified = f'{self.module_name}.{node.name}'
        if self.current_class:
            qualified = f'{self.module_name}.{self.current_class}.{node.name}'
        
        # Check decorators
        for decorator in node.decorator_list:
            entry = self._check_decorator_entry(node, decorator, qualified)
            if entry:
                self.entry_points.append(entry)
                return
        
        # Check pytest naming convention
        if self.has_pytest or 'test_' in self.file_path:
            if node.name.startswith('test_') or node.name.startswith('Test'):
                # Check for taintable parameters (e.g., 'request' fixture)
                tainted_params = []
                for arg in node.args.args:
                    if arg.arg in ['request', 'user_input', 'data']:
                        tainted_params.append(arg.arg)
                
                entry = EntryPoint(
                    name=node.name,
                    qualified_name=qualified,
                    file_path=self.file_path,
                    line_number=node.lineno,
                    entry_type='pytest',
                    tainted_params=tainted_params,
                    sensitive_params=mark_sensitive_params(tainted_params),
                )
                self.entry_points.append(entry)
                return
        
        # Check for Django view patterns
        if self.has_django:
            # Check for HttpRequest parameter
            for arg in node.args.args:
                if arg.arg == 'request':
                    tainted = ['request']
                    entry = EntryPoint(
                        name=node.name,
                        qualified_name=qualified,
                        file_path=self.file_path,
                        line_number=node.lineno,
                        entry_type='django_view',
                        tainted_params=tainted,
                        sensitive_params=mark_sensitive_params(tainted),
                    )
                    self.entry_points.append(entry)
                    return
    
    def _check_decorator_entry(
        self, func: ast.FunctionDef, decorator: ast.expr, qualified: str
    ) -> Optional[EntryPoint]:
        """Check if a decorator marks an entry point."""
        
        # Flask/FastAPI route: @app.route('/path')
        if isinstance(decorator, ast.Call):
            func_expr = decorator.func
            
            if isinstance(func_expr, ast.Attribute):
                if func_expr.attr in ('route', 'get', 'post', 'put', 'delete', 'patch'):
                    route_path = None
                    methods = []
                    
                    if decorator.args:
                        arg = decorator.args[0]
                        if isinstance(arg, ast.Constant):
                            route_path = arg.value
                    
                    for kw in decorator.keywords:
                        if kw.arg == 'methods' and isinstance(kw.value, ast.List):
                            for elt in kw.value.elts:
                                if isinstance(elt, ast.Constant):
                                    methods.append(elt.value)
                    
                    tainted = ['request'] if 'request' in [a.arg for a in func.args.args] else []
                    return EntryPoint(
                        name=func.name,
                        qualified_name=qualified,
                        file_path=self.file_path,
                        line_number=func.lineno,
                        entry_type='flask_route' if self.has_flask else 'fastapi_route',
                        route_path=route_path,
                        http_methods=methods or ['GET'],
                        tainted_params=tainted,
                        sensitive_params=mark_sensitive_params(tainted),
                    )
        
        # Click command: @click.command()
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
            if decorator.func.attr in ('command', 'group'):
                return EntryPoint(
                    name=func.name,
                    qualified_name=qualified,
                    file_path=self.file_path,
                    line_number=func.lineno,
                    entry_type='cli_command',
                )
        
        # Simple decorator: @app.route without call
        if isinstance(decorator, ast.Attribute):
            if decorator.attr in ('route', 'get', 'post'):
                return EntryPoint(
                    name=func.name,
                    qualified_name=qualified,
                    file_path=self.file_path,
                    line_number=func.lineno,
                    entry_type='flask_route',
                )
        
        return None
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Handle class definitions for Django CBVs."""
        old_class = self.current_class
        self.current_class = node.name
        
        # Check for Django class-based views
        if self.has_django:
            for base in node.bases:
                base_name = self._get_name(base)
                if base_name and 'View' in base_name:
                    entry = EntryPoint(
                        name=node.name,
                        qualified_name=f'{self.module_name}.{node.name}',
                        file_path=self.file_path,
                        line_number=node.lineno,
                        entry_type='django_view',
                    )
                    self.entry_points.append(entry)
                    break
        
        self.generic_visit(node)
        self.current_class = old_class
    
    def _get_name(self, node: ast.expr) -> Optional[str]:
        """Extract name from an expression."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None


def detect_entry_points_in_file(file_path: Path, module_name: str = None) -> List[EntryPoint]:
    """Detect all entry points in a single file."""
    if module_name is None:
        module_name = file_path.stem
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, IOError):
        return []
    
    detector = EntryPointDetector(str(file_path), module_name)
    detector.visit(tree)
    
    # Add module itself as entry point (for module-level code)
    if detector.entry_points or _has_module_level_code(tree):
        detector.entry_points.insert(0, EntryPoint(
            name=module_name,
            qualified_name=module_name,
            file_path=str(file_path),
            line_number=1,
            entry_type='module',
        ))
    
    return detector.entry_points


def _has_module_level_code(tree: ast.Module) -> bool:
    """Check if module has executable code at top level."""
    for node in tree.body:
        # Skip imports, function/class defs
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, 
                            ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        # Skip docstrings
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue
        # Skip __all__ assignment
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == '__all__':
                    continue
        # Any other statement is executable
        return True
    return False


def detect_entry_points_in_project(
    root_path: Path,
    exclude_patterns: List[str] = None
) -> List[EntryPoint]:
    """Detect all entry points in a project directory."""
    exclude_patterns = exclude_patterns or ['__pycache__', '.git', 'venv', '.venv', 'node_modules', 'test_']
    
    all_entries = []
    
    for py_file in root_path.rglob('*.py'):
        # Check exclusions
        if any(p in str(py_file) for p in exclude_patterns):
            continue
        
        # Compute module name
        try:
            rel_path = py_file.relative_to(root_path)
            parts = list(rel_path.parts[:-1]) + [py_file.stem]
            if parts[-1] == '__init__':
                parts = parts[:-1]
            module_name = '.'.join(parts) if parts else py_file.stem
        except ValueError:
            module_name = py_file.stem
        
        entries = detect_entry_points_in_file(py_file, module_name)
        all_entries.extend(entries)
    
    return all_entries


def get_entry_point_functions(entry_points: List[EntryPoint]) -> Set[str]:
    """Get the set of function names from entry points."""
    return {ep.qualified_name for ep in entry_points}


__all__ = [
    'EntryPoint',
    'EntryPointDetector',
    'detect_entry_points_in_file',
    'detect_entry_points_in_project',
    'get_entry_point_functions',
]
