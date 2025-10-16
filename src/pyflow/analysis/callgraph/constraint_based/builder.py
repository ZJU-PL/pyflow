
"""
Lightweight constraint-based call graph constructor.

Design
------
- Parse Python source into the stdlib `ast` and walk it.
- Track a minimal environment mapping variables to possible function names.
- Represent functions as qualified names `main.<func>` and also store bare
  names for matching expected tests that sometimes use qualified names.
- Propagate via simple constraints:
    var := function        -> pts[var] includes that function
    var := other_var       -> pts[var] supersets pts[other_var]
    call(var)(...)         -> for f in pts[var], add edge caller -> f
    call(name)(...)        -> add edge caller -> resolved name if defined
  We ignore heap/field-sensitivity and treat attributes conservatively when
  they obviously refer to local function defs in the same module.

This intentionally does not attempt to solve all tests; it should, however,
cover many simple cases better than the current AST approach.
"""

from __future__ import annotations

import ast
from typing import Dict, Set, List, Tuple, Optional

from ....machinery.callgraph import CallGraph


class ConstraintEnv:
    """A minimal points-to environment for variables -> possible functions."""

    def __init__(self):
        self.var_to_funcs: Dict[str, Set[str]] = {}
        self.var_to_classes: Dict[str, Set[str]] = {}

    def add_points_to(self, var: str, func_name: str) -> None:
        self.var_to_funcs.setdefault(var, set()).add(func_name)

    def union_from(self, target: str, source: str) -> None:
        if source in self.var_to_funcs:
            self.var_to_funcs.setdefault(target, set()).update(self.var_to_funcs[source])
        if source in self.var_to_classes:
            self.var_to_classes.setdefault(target, set()).update(self.var_to_classes[source])

    def possible_functions(self, var: str) -> Set[str]:
        return self.var_to_funcs.get(var, set())

    def add_points_to_class(self, var: str, class_name: str) -> None:
        self.var_to_classes.setdefault(var, set()).add(class_name)

    def possible_classes(self, var: str) -> Set[str]:
        return self.var_to_classes.get(var, set())


def _collect_declarations(tree: ast.AST, main_name: str) -> Tuple[Set[str], Set[str], Dict[str, Set[str]]]:
    """Collect functions, classes, and class->methods qualified names."""
    function_names: Set[str] = set([main_name])
    class_names: Set[str] = set()
    class_methods: Dict[str, Set[str]] = {}

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef):
            function_names.add(node.name)
            function_names.add(f"{main_name}.{node.name}")
        elif isinstance(node, ast.ClassDef):
            clsq = f"{main_name}.{node.name}"
            class_names.add(clsq)
            for b in node.body:
                if isinstance(b, ast.FunctionDef):
                    methq = f"{clsq}.{b.name}"
                    class_methods.setdefault(clsq, set()).add(methq)
                    function_names.add(methq)
                    # also track __init__ if present
    return function_names, class_names, class_methods


def _resolve_name_to_function(name: str, function_names: Set[str]) -> Optional[str]:
    # Prefer qualified names when both exist
    qual = f"main.{name}"
    if qual in function_names:
        return qual
    if name in function_names:
        return name
    return None


def _resolve_name_to_class(name: str, class_names: Set[str]) -> Optional[str]:
    if name in class_names:
        return name
    qual = f"main.{name}"
    if qual in class_names:
        return qual
    return None


def _attribute_full_name(expr: ast.AST) -> Optional[str]:
    parts: List[str] = []
    node = expr
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        parts.reverse()
        return ".".join(parts)
    return None


class FunctionBodyAnalyzer(ast.NodeVisitor):
    """Analyze a single function body using constraints and add edges."""

    def __init__(self, caller_qualname: str, function_names: Set[str], graph: CallGraph,
                 class_names: Optional[Set[str]] = None,
                 class_methods: Optional[Dict[str, Set[str]]] = None,
                 import_modules: Optional[Dict[str, str]] = None,
                 from_imports: Optional[Dict[str, str]] = None,
                 scope: str = "function",
                 param_names: Optional[Set[str]] = None):
        self.caller = caller_qualname
        self.function_names = function_names
        self.graph = graph
        self.env = ConstraintEnv()
        self.class_names = class_names or set()
        self.class_methods = class_methods or {}
        self.import_modules = import_modules or {}
        self.from_imports = from_imports or {}
        self.scope = scope
        self.lambda_counter = 0
        self.param_names = param_names or set()

        # If analyzing a class method, bind self to that class
        if "." in self.caller and self.caller.count(".") >= 2:
            cls = ".".join(self.caller.split(".")[:2])
            if cls in self.class_names:
                self.env.add_points_to_class("self", cls)

    def visit_Assign(self, node: ast.Assign):
        # Handle: x = func, x = y, tuple unpacking, x = Class(), etc.
        value = node.value
        # Support tuple unpacking like a, b = func1, func2
        if isinstance(value, (ast.Tuple, ast.List)):
            rhs = list(value.elts)
            lhs_targets = []
            for t in node.targets:
                if isinstance(t, (ast.Tuple, ast.List)):
                    lhs_targets.extend([e for e in t.elts if isinstance(e, ast.Name)])
                elif isinstance(t, ast.Name):
                    lhs_targets.append(t)
            for i, t in enumerate(lhs_targets):
                if i < len(rhs):
                    r = rhs[i]
                    if isinstance(r, ast.Name):
                        resolved = _resolve_name_to_function(r.id, self.function_names)
                        if resolved:
                            self.env.add_points_to(t.id, resolved)
                        else:
                            self.env.union_from(t.id, r.id)
                    elif isinstance(r, ast.Call):
                        # best-effort: treat as class instantiation case
                        if isinstance(r.func, ast.Name):
                            cls = _resolve_name_to_class(r.func.id, self.class_names)
                            if cls:
                                self.env.add_points_to_class(t.id, cls)
                                init_name = f"{cls}.__init__"
                                if init_name in self.function_names:
                                    self.graph.add_edge(self.caller, init_name)
            return

        targets = [t for t in node.targets if isinstance(t, ast.Name)]
        if not targets:
            return
        if isinstance(value, ast.Name):
            resolved = _resolve_name_to_function(value.id, self.function_names)
            for t in targets:
                if resolved:
                    self.env.add_points_to(t.id, resolved)
                else:
                    # x = y
                    self.env.union_from(t.id, value.id)
        elif isinstance(value, ast.Lambda):
            # Treat lambda as a distinct callable symbol
            self.lambda_counter += 1
            lambda_name = f"{self.caller}.<lambda{self.lambda_counter}>"
            self.graph.add_node(lambda_name)
            for t in targets:
                self.env.add_points_to(t.id, lambda_name)
        elif isinstance(value, ast.Call):
            # x = Class() or x = module.Class()
            class_name = None
            if isinstance(value.func, ast.Name):
                class_name = _resolve_name_to_class(value.func.id, self.class_names)
            elif isinstance(value.func, ast.Attribute):
                full = _attribute_full_name(value.func)
                # module.Class
                if full and "." in full:
                    base = full.split(".")[0]
                    if base in self.import_modules:
                        class_name = f"{self.import_modules[base]}.{full.split('.', 1)[1]}"
            if class_name:
                # Record object type and add __init__ edge if defined
                for t in targets:
                    self.env.add_points_to_class(t.id, class_name)
                init_name = f"{class_name}.__init__"
                if init_name in self.function_names:
                    self.graph.add_edge(self.caller, init_name)
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr):
        # capture calls at expression statements
        if isinstance(node.value, ast.Call):
            self._handle_call(node.value)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        # If returning a simple name that is function or var-to-function, add edges as "possible returns"
        value = node.value
        if isinstance(value, ast.Name):
            resolved = _resolve_name_to_function(value.id, self.function_names)
            if resolved:
                self.graph.add_edge(self.caller, resolved)
            else:
                for f in self.env.possible_functions(value.id):
                    self.graph.add_edge(self.caller, f)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # When visiting at module scope, do not traverse into functions/classes
        if self.scope == "module":
            return
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        if self.scope == "module":
            return
        self.generic_visit(node)

    def _handle_call(self, call: ast.Call):
        func_expr = call.func
        # Direct name call
        if isinstance(func_expr, ast.Name):
            name = func_expr.id
            # Builtins
            if name in {"len", "range", "map", "eval", "super"}:
                self.graph.add_node(f"<builtin>.{name}")
                self.graph.add_edge(self.caller, f"<builtin>.{name}")
                return
            # from-import mapping
            if name in self.from_imports:
                self.graph.add_edge(self.caller, self.from_imports[name])
                return
            # param call heuristic: if calling a parameter and a function of same name exists
            if name in self.param_names:
                resolved = _resolve_name_to_function(name, self.function_names)
                if resolved:
                    self.graph.add_edge(self.caller, resolved)
                    return
            # direct function
            resolved = _resolve_name_to_function(name, self.function_names)
            if resolved:
                self.graph.add_edge(self.caller, resolved)
                # Module-level arg-to-callee linkage: func(param_func)
                if self.scope == "module":
                    for arg in call.args:
                        if isinstance(arg, ast.Name):
                            targ = _resolve_name_to_function(arg.id, self.function_names)
                            if targ:
                                self.graph.add_edge(resolved, targ)
                return
            # class constructor
            cls = _resolve_name_to_class(name, self.class_names)
            if cls:
                init_name = f"{cls}.__init__"
                if init_name in self.function_names:
                    self.graph.add_edge(self.caller, init_name)
                return
            # variable function value
            for f in self.env.possible_functions(name):
                self.graph.add_edge(self.caller, f)
        # Attribute call obj.method() -> try resolve method name
        elif isinstance(func_expr, ast.Attribute):
            attr_name = func_expr.attr
            # Case: Class.static()
            if isinstance(func_expr.value, ast.Name):
                base = func_expr.value.id
                # module.func or module.sub.func
                if base in self.import_modules:
                    full = _attribute_full_name(func_expr)
                    if full:
                        module_full = full.replace(base, self.import_modules[base], 1)
                        self.graph.add_edge(self.caller, module_full)
                        return
                # direct class method
                cls = _resolve_name_to_class(base, self.class_names)
                if cls:
                    self.graph.add_edge(self.caller, f"{cls}.{attr_name}")
                    return
                # variable bound to an instance
                for cls2 in self.env.possible_classes(base):
                    self.graph.add_edge(self.caller, f"{cls2}.{attr_name}")
                    return
            # Case: obj.method() where obj is attribute chain from module
            full = _attribute_full_name(func_expr)
            if full and "." in full:
                base = full.split(".")[0]
                if base in self.import_modules:
                    module_full = full.replace(base, self.import_modules[base], 1)
                    self.graph.add_edge(self.caller, module_full)
                    return
            # Fallback: if method name matches a local free function
            cand = _resolve_name_to_function(attr_name, self.function_names)
            if cand:
                self.graph.add_edge(self.caller, cand)


def extract_call_graph_constraint(source_code: str) -> CallGraph:
    graph = CallGraph()
    main_name = "main"
    graph.add_node(main_name)

    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return graph

    function_names, class_names, class_methods = _collect_declarations(tree, main_name)

    # Collect import mappings at module level
    import_modules: Dict[str, str] = {}
    from_imports: Dict[str, str] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                alias_name = alias.asname or alias.name.split(".")[0]
                import_modules[alias_name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue
                alias_name = alias.asname or alias.name
                from_imports[alias_name] = f"{mod}.{alias.name}" if mod else alias.name

    # Analyze module-level (treat as main) without recursing into defs
    mod_analyzer = FunctionBodyAnalyzer(
        main_name, function_names, graph,
        class_names=class_names,
        class_methods=class_methods,
        import_modules=import_modules,
        from_imports=from_imports,
        scope="module",
    )
    mod_analyzer.visit(tree)

    # Add nodes for imported modules (for visibility in output)
    for alias, mod in import_modules.items():
        graph.add_node(alias)

    # Analyze free functions and class methods
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef):
            caller_qual = f"{main_name}.{node.name}"
            graph.add_node(caller_qual)
            params: Set[str] = set(a.arg for a in getattr(node.args, "args", []) if hasattr(a, "arg"))
            analyzer = FunctionBodyAnalyzer(
                caller_qual, function_names, graph,
                class_names=class_names,
                class_methods=class_methods,
                import_modules=import_modules,
                from_imports=from_imports,
                scope="function",
                param_names=params,
            )
            analyzer.visit(node)
        elif isinstance(node, ast.ClassDef):
            clsq = f"{main_name}.{node.name}"
            for b in node.body:
                if isinstance(b, ast.FunctionDef):
                    caller_qual = f"{clsq}.{b.name}"
                    graph.add_node(caller_qual)
                    analyzer = FunctionBodyAnalyzer(
                        caller_qual, function_names, graph,
                        class_names=class_names,
                        class_methods=class_methods,
                        import_modules=import_modules,
                        from_imports=from_imports,
                        scope="function",
                    )
                    analyzer.visit(b)


def analyze_file_constraint(filepath: str) -> str:
    try:
        with open(filepath, "r") as f:
            source = f.read()
        graph = extract_call_graph_constraint(source)
        from ..formats import generate_text_output
        return generate_text_output(graph, None)
    except Exception as e:
        return f"Error analyzing {filepath}: {e}"


