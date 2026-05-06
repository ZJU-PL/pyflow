"""
Call Graph Construction for Interprocedural Analysis.

Implements static call graph construction as defined in python-barrier-certificate-theory.md §9.5.2:

Definition (Static Call Graph): G_call = (V, E) where:
- V is the set of all functions (code objects) in the program
- E ⊆ V × V where (f, g) ∈ E iff f contains a call site that may invoke g

For Python, this is approximate due to:
1. First-class functions
2. Dynamic dispatch
3. Reflection
4. Imports
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path
import ast
import sys
import types
import dis


@dataclass
class CallSite:
    """
    A call site π_c in a function.
    
    Contains:
    - The callee expression (the function being called)
    - Arguments (positional and keyword)
    - A return continuation (where control resumes after the call)
    """
    # Location
    file_path: str
    line_number: int
    col_offset: int
    
    # Caller info
    caller_name: str  # Fully qualified name
    bytecode_offset: Optional[int] = None
    
    # Callee info (what we can statically determine)
    callee_name: Optional[str] = None  # May be unknown for dynamic calls
    callee_attribute: Optional[str] = None  # For method calls: obj.method
    is_method_call: bool = False
    
    # Arguments (for context-sensitive analysis)
    num_args: int = 0
    has_starargs: bool = False
    has_kwargs: bool = False


@dataclass
class FunctionInfo:
    """Information about a function definition."""
    name: str  # Simple name
    qualified_name: str  # module.class.function format
    file_path: str
    line_number: int
    
    # Parameters for summary computation
    parameters: List[str] = field(default_factory=list)
    has_varargs: bool = False
    has_kwargs: bool = False
    vararg_name: Optional[str] = None  # Name of *args parameter
    kwarg_name: Optional[str] = None   # Name of **kwargs parameter
    
    # ITERATION 610: Parameter nullability from type annotations
    # Maps param_index -> True if Optional/nullable, False if non-nullable typed
    # None means no type annotation
    param_nullable: Dict[int, Optional[bool]] = field(default_factory=dict)
    
    # Call sites within this function
    call_sites: List[CallSite] = field(default_factory=list)
    
    # Return statements (for dataflow)
    return_count: int = 0
    
    # Code object reference (if available)
    code_object: Optional[types.CodeType] = None


@dataclass
class CallGraph:
    """
    Static call graph G_call = (V, E).
    
    Provides sound over-approximation: every actual call is represented.
    """
    # V: set of all functions
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)
    
    # E: edges (caller_qname -> set of callee_qnames)
    edges: Dict[str, Set[str]] = field(default_factory=dict)
    
    # Reverse edges for bottom-up traversal
    reverse_edges: Dict[str, Set[str]] = field(default_factory=dict)
    
    # Call sites indexed by caller
    call_sites_by_caller: Dict[str, List[CallSite]] = field(default_factory=dict)
    
    # External/library calls (callee not in V)
    external_calls: Dict[str, Set[str]] = field(default_factory=dict)
    
    def add_function(self, func: FunctionInfo) -> None:
        """Add a function to the graph."""
        self.functions[func.qualified_name] = func
        if func.qualified_name not in self.edges:
            self.edges[func.qualified_name] = set()
        if func.qualified_name not in self.reverse_edges:
            self.reverse_edges[func.qualified_name] = set()
    
    def add_edge(self, caller: str, callee: str) -> None:
        """Add a call edge."""
        if caller not in self.edges:
            self.edges[caller] = set()
        self.edges[caller].add(callee)
        
        if callee not in self.reverse_edges:
            self.reverse_edges[callee] = set()
        self.reverse_edges[callee].add(caller)
    
    def add_external_call(self, caller: str, callee: str) -> None:
        """Record a call to external/library function."""
        if caller not in self.external_calls:
            self.external_calls[caller] = set()
        self.external_calls[caller].add(callee)
    
    def get_function(self, name: str) -> Optional[FunctionInfo]:
        """Get function info by qualified name."""
        return self.functions.get(name)
    
    def get_callees(self, func: str) -> Set[str]:
        """Get all functions called by func."""
        return self.edges.get(func, set())
    
    def get_callers(self, func: str) -> Set[str]:
        """Get all functions that call func."""
        return self.reverse_edges.get(func, set())
    
    def compute_sccs(self) -> List[Set[str]]:
        """
        Compute strongly connected components using Tarjan's algorithm.
        
        Returns SCCs in reverse topological order (leaves first).
        """
        index_counter = [0]
        stack = []
        lowlink = {}
        index = {}
        on_stack = {}
        sccs = []
        
        def strongconnect(v):
            index[v] = index_counter[0]
            lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack[v] = True
            
            for w in self.edges.get(v, set()):
                if w not in self.functions:
                    continue  # External call
                if w not in index:
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif on_stack.get(w, False):
                    lowlink[v] = min(lowlink[v], index[w])
            
            if lowlink[v] == index[v]:
                scc = set()
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.add(w)
                    if w == v:
                        break
                sccs.append(scc)
        
        for v in self.functions:
            if v not in index:
                strongconnect(v)
        
        return sccs  # Already in reverse topological order
    
    def is_recursive(self, func: str) -> bool:
        """Check if a function is (mutually) recursive."""
        for scc in self.compute_sccs():
            if func in scc and len(scc) > 1:
                return True
            if func in scc and func in self.edges.get(func, set()):
                return True  # Self-recursive
        return False
    
    def get_reachable_from(self, entry_points: Set[str]) -> Set[str]:
        """Get all functions reachable from entry points."""
        reachable = set()
        worklist = list(entry_points)
        
        while worklist:
            func = worklist.pop()
            if func in reachable:
                continue
            if func not in self.functions:
                continue
            reachable.add(func)
            worklist.extend(self.edges.get(func, set()))
        
        return reachable
    
    def resolve_cross_module_calls(self) -> int:
        """
        Resolve external calls that should be internal edges.
        
        After building the call graph from multiple files, some calls
        tracked as "external" are actually to functions in the graph.
        This method resolves those and converts them to internal edges.
        
        Returns:
            Number of external calls resolved to internal edges.
        """
        resolved_count = 0
        
        # Build a lookup map: function simple name -> set of qualified names
        name_to_qnames: Dict[str, Set[str]] = {}
        for qname in self.functions:
            # Extract simple name (last component)
            simple_name = qname.split('.')[-1]
            if simple_name not in name_to_qnames:
                name_to_qnames[simple_name] = set()
            name_to_qnames[simple_name].add(qname)
        
        # Also build exact qualified name lookup
        qname_to_func = {qname: qname for qname in self.functions}
        
        # For each caller, check external calls
        for caller, external_callees in list(self.external_calls.items()):
            resolved_callees = set()
            
            for external_name in external_callees:
                resolved_qname = None
                
                # Try exact match first
                if external_name in qname_to_func:
                    resolved_qname = external_name
                else:
                    # Try to match by simple name
                    simple_name = external_name.split('.')[-1]
                    if simple_name in name_to_qnames:
                        candidates = name_to_qnames[simple_name]
                        
                        # If external_name is qualified (has dots), try prefix matching
                        if '.' in external_name:
                            # e.g., external_name = "module_a.source_func"
                            # Try to find qname that ends with this
                            for qname in candidates:
                                if qname.endswith(external_name) or external_name == qname:
                                    resolved_qname = qname
                                    break
                            
                            # If no suffix match, check if any candidate's module matches
                            if not resolved_qname:
                                for qname in candidates:
                                    # e.g., qname = "module_a.source_func", external_name = "module_a.source_func"
                                    if qname == external_name:
                                        resolved_qname = qname
                                        break
                        else:
                            # Simple name only - could be ambiguous, but take first match
                            # (In a real system, we'd use import tracking to resolve)
                            if len(candidates) == 1:
                                resolved_qname = list(candidates)[0]
                
                if resolved_qname and resolved_qname in self.functions:
                    # Convert to internal edge
                    self.add_edge(caller, resolved_qname)
                    resolved_callees.add(external_name)
                    resolved_count += 1
            
            # Remove resolved callees from external_calls
            for resolved in resolved_callees:
                self.external_calls[caller].discard(resolved)
            
            # Clean up empty sets
            if not self.external_calls[caller]:
                del self.external_calls[caller]
        
        # ITERATION 610: Resolve self.method calls to qualified class method names
        resolved_count += self._resolve_self_method_calls()
        
        return resolved_count
    
    def _resolve_self_method_calls(self) -> int:
        """
        Resolve self.method calls to their qualified method names.
        
        When a method calls self.other_method(), we need to resolve this to
        the qualified name like module.ClassName.other_method.
        
        Returns:
            Number of self-method calls resolved.
        """
        resolved_count = 0
        
        for caller in list(self.external_calls.keys()):
            # Get the caller's class (if any)
            # Caller format: module.ClassName.method_name
            parts = caller.rsplit('.', 2)
            if len(parts) < 2:
                continue
            
            # Check if this is a method (has a class component)
            # Try to find the class by looking for other methods with same prefix
            caller_prefix = '.'.join(parts[:-1])  # e.g., "module.ClassName"
            
            resolved_callees = set()
            for external_name in self.external_calls[caller]:
                # Check for self.method pattern
                if external_name.startswith('self.'):
                    method_name = external_name[5:]  # Remove "self."
                    # Try to resolve to caller's class
                    resolved_qname = f"{caller_prefix}.{method_name}"
                    
                    if resolved_qname in self.functions:
                        self.add_edge(caller, resolved_qname)
                        resolved_callees.add(external_name)
                        resolved_count += 1
            
            # Remove resolved callees
            for resolved in resolved_callees:
                self.external_calls[caller].discard(resolved)
            
            if not self.external_calls[caller]:
                del self.external_calls[caller]
        
        return resolved_count


class CallGraphBuilder(ast.NodeVisitor):
    """
    AST visitor that builds a call graph from Python source.
    
    Handles:
    - Function/method definitions
    - Call expressions
    - Import tracking for cross-file resolution
    """
    
    def __init__(self, file_path: str, module_name: str):
        self.file_path = file_path
        self.module_name = module_name
        self.graph = CallGraph()
        
        # Current context
        self.current_class: Optional[str] = None
        self.current_function: Optional[str] = None
        self.function_stack: List[str] = []
        
        # Name bindings for callee resolution
        self.imports: Dict[str, str] = {}  # local name -> qualified name
        self.local_defs: Dict[str, str] = {}  # local name -> qualified name
    
    def qualified_name(self, name: str) -> str:
        """Build fully qualified name from current context."""
        parts = [self.module_name]
        if self.current_class:
            parts.append(self.current_class)
        parts.append(name)
        return '.'.join(parts)
    
    def current_qualified_name(self) -> str:
        """Get the fully qualified name of the current function."""
        if self.function_stack:
            return self.function_stack[-1]
        return self.module_name
    
    def visit_Import(self, node: ast.Import) -> None:
        """Handle 'import x' statements."""
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Handle 'from x import y' statements."""
        module = node.module or ''
        for alias in node.names:
            name = alias.asname or alias.name
            if alias.name == '*':
                # Star import - can't track precisely
                pass
            else:
                qualified = f"{module}.{alias.name}" if module else alias.name
                self.imports[name] = qualified
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Handle class definitions."""
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class
    
    def _extract_param_nullability(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Dict[int, Optional[bool]]:
        """
        Extract parameter nullability from type annotations.
        
        ITERATION 610: Reduce false positive NULL_PTR for typed parameters.
        Returns dict mapping param_index -> nullable (True if Optional, False if typed non-nullable, None if no annotation).
        """
        result: Dict[int, Optional[bool]] = {}
        idx = 0
        
        # Process all argument types in order
        all_args = list(node.args.args) + list(node.args.posonlyargs) + list(node.args.kwonlyargs)
        
        for arg in all_args:
            if arg.annotation:
                result[idx] = self._annotation_is_optional(arg.annotation)
            else:
                result[idx] = None  # No annotation
            idx += 1
        
        return result
    
    def _annotation_is_optional(self, annotation: ast.AST) -> bool:
        """
        Check if a type annotation indicates Optional/nullable.
        
        Handles:
        - Optional[X] -> True
        - Union[X, None] -> True
        - X | None -> True (Python 3.10+)
        - None -> True
        - Everything else -> False (typed non-nullable)
        """
        # None literal
        if isinstance(annotation, ast.Constant) and annotation.value is None:
            return True
        
        # ast.Name("None")
        if isinstance(annotation, ast.Name) and annotation.id == 'None':
            return True
        
        # Subscript: Optional[X] or Union[X, None]
        if isinstance(annotation, ast.Subscript):
            if isinstance(annotation.value, ast.Attribute):
                attr_name = annotation.value.attr
            elif isinstance(annotation.value, ast.Name):
                attr_name = annotation.value.id
            else:
                return False
            
            if attr_name == 'Optional':
                return True
            if attr_name == 'Union':
                # Check if None is in the union
                if isinstance(annotation.slice, ast.Tuple):
                    for elt in annotation.slice.elts:
                        if self._annotation_is_optional(elt):
                            return True
                elif self._annotation_is_optional(annotation.slice):
                    return True
        
        # BinOp: X | None (Python 3.10+)
        if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
            if self._annotation_is_optional(annotation.left) or self._annotation_is_optional(annotation.right):
                return True
        
        return False
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Handle function definitions."""
        self._visit_function(node)
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Handle async function definitions."""
        self._visit_function(node)
    
    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Common handler for function definitions."""
        qname = self.qualified_name(node.name)
        
        # Extract parameters
        params = []
        for arg in node.args.args:
            params.append(arg.arg)
        for arg in node.args.posonlyargs:
            params.append(arg.arg)
        for arg in node.args.kwonlyargs:
            params.append(arg.arg)
        
        # ITERATION 610: Extract parameter nullability from type annotations
        param_nullable = self._extract_param_nullability(node)
        
        # Extract vararg and kwarg names
        vararg_name = node.args.vararg.arg if node.args.vararg else None
        kwarg_name = node.args.kwarg.arg if node.args.kwarg else None
        
        # Compile the function to get code object
        code_obj = None
        try:
            # Wrap function in a module and compile
            module = ast.Module(body=[node], type_ignores=[])
            ast.fix_missing_locations(module)
            compiled = compile(module, filename=self.file_path, mode='exec')
            # Extract the function code object
            for const in compiled.co_consts:
                if isinstance(const, types.CodeType) and const.co_name == node.name:
                    code_obj = const
                    break
        except Exception:
            # Compilation failed - code object remains None
            pass
        
        func_info = FunctionInfo(
            name=node.name,
            qualified_name=qname,
            file_path=self.file_path,
            line_number=node.lineno,
            parameters=params,
            has_varargs=node.args.vararg is not None,
            has_kwargs=node.args.kwarg is not None,
            vararg_name=vararg_name,
            kwarg_name=kwarg_name,
            param_nullable=param_nullable,
            code_object=code_obj,
        )
        
        self.graph.add_function(func_info)
        self.local_defs[node.name] = qname
        
        # Visit body with this function as context
        old_function = self.current_function
        self.current_function = node.name
        self.function_stack.append(qname)
        
        # Count returns
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Return):
                func_info.return_count += 1
        
        self.generic_visit(node)
        
        self.function_stack.pop()
        self.current_function = old_function
    
    def visit_Call(self, node: ast.Call) -> None:
        """Handle call expressions."""
        if not self.function_stack:
            # Top-level call (module initialization)
            caller = self.module_name
        else:
            caller = self.current_qualified_name()
        
        call_site = CallSite(
            file_path=self.file_path,
            line_number=node.lineno,
            col_offset=node.col_offset,
            caller_name=caller,
            num_args=len(node.args),
            has_starargs=any(isinstance(a, ast.Starred) for a in node.args),
            has_kwargs=len(node.keywords) > 0,
        )
        
        # Resolve callee
        callee_name = self._resolve_callee(node.func)
        call_site.callee_name = callee_name
        
        if isinstance(node.func, ast.Attribute):
            call_site.is_method_call = True
            call_site.callee_attribute = node.func.attr
        
        # Store call site
        if caller not in self.graph.call_sites_by_caller:
            self.graph.call_sites_by_caller[caller] = []
        self.graph.call_sites_by_caller[caller].append(call_site)
        
        # Add edge if we can resolve callee
        if callee_name:
            if callee_name in self.local_defs:
                self.graph.add_edge(caller, self.local_defs[callee_name])
            elif callee_name in self.imports:
                # External or cross-module call
                self.graph.add_external_call(caller, self.imports[callee_name])
            elif '.' not in callee_name and callee_name in self.graph.functions:
                self.graph.add_edge(caller, callee_name)
            else:
                # Unresolved - could be builtin or dynamic
                self.graph.add_external_call(caller, callee_name)
        
        self.generic_visit(node)
    
    def _resolve_callee(self, node: ast.expr) -> Optional[str]:
        """Try to resolve the callee name from an expression."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # obj.method - try to resolve obj
            base = self._resolve_callee(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        elif isinstance(node, ast.Call):
            # f()(args) - can't statically resolve
            return None
        elif isinstance(node, ast.Subscript):
            # f[x](args) - can't statically resolve
            return None
        return None


def build_call_graph_from_file(file_path: Path, module_name: str = None) -> CallGraph:
    """Build call graph from a single Python file."""
    if module_name is None:
        module_name = file_path.stem
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()
    except (OSError, IOError):
        return CallGraph()
    
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        # Try to handle partial/indented code snippets (e.g., from diff extraction)
        tree = _try_parse_partial(source, str(file_path))
        if tree is None:
            return CallGraph()
    
    builder = CallGraphBuilder(str(file_path), module_name)
    
    # Temporarily increase recursion limit for deeply nested ASTs,
    # and catch RecursionError so one problematic file doesn't crash
    # the entire scan.
    old_limit = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(max(old_limit, 8000))
        builder.visit(tree)
    except RecursionError:
        # File has excessively deep nesting — return whatever we collected
        pass
    finally:
        sys.setrecursionlimit(old_limit)
    
    # Populate FunctionInfo.call_sites from call_sites_by_caller
    for caller_qname, call_sites in builder.graph.call_sites_by_caller.items():
        func_info = builder.graph.functions.get(caller_qname)
        if func_info:
            func_info.call_sites.extend(call_sites)
    
    return builder.graph


def _try_parse_partial(source: str, filename: str):
    """Try to parse partial/indented code by dedenting or wrapping in a function.
    
    Handles code snippets extracted from diffs that may be indented or incomplete.
    """
    import textwrap
    import re
    dedented = textwrap.dedent(source)
    
    # Try 1: Parse dedented source directly
    for src in (dedented, source):
        try:
            return ast.parse(src, filename=filename)
        except SyntaxError:
            pass
    
    # Try 2: Complete trailing incomplete blocks (e.g., 'if x:' with no body)
    # by appending 'pass' at the right indentation
    completed = _complete_trailing_blocks(dedented)
    if completed != dedented:
        try:
            return ast.parse(completed, filename=filename)
        except SyntaxError:
            pass
    
    # Try 3: Wrap in a function
    for src in (completed, dedented):
        try:
            wrapped = "def _a3_snippet_wrapper_():\n" + textwrap.indent(src, "    ") + "\n"
            return ast.parse(wrapped, filename=filename)
        except SyntaxError:
            pass
    
    # Try 4: Split multi-hunk diff fragments and wrap each hunk separately
    result = _try_parse_multi_hunk(source, filename)
    if result is not None:
        return result
    
    return None


def _try_parse_multi_hunk(source: str, filename: str):
    """Parse multi-hunk diff fragments by splitting and wrapping each hunk.
    
    Diff-extracted code often has multiple '# @@ hunk @@' markers separating
    fragments at different indent levels, plus non-Python metadata lines.
    We split at hunk markers, dedent each hunk individually, wrap in functions,
    and combine into a single module.
    """
    import textwrap
    import re
    
    # Check if this looks like a multi-hunk fragment
    if '# @@ hunk @@' not in source:
        return None
    
    # Strip non-Python metadata lines (e.g., "index 635eba2..8318674 100644")
    cleaned_lines = []
    for line in source.splitlines(keepends=True):
        stripped = line.strip()
        # Skip git diff metadata lines
        if re.match(r'^index\s+[0-9a-f]+\.\.[0-9a-f]+', stripped):
            continue
        if re.match(r'^(old|new) mode \d+', stripped):
            continue
        cleaned_lines.append(line)
    cleaned = ''.join(cleaned_lines)
    
    # Split at hunk markers
    hunks = re.split(r'^# @@ hunk @@\s*$', cleaned, flags=re.MULTILINE)
    # Strip only leading/trailing blank lines, preserving internal indentation
    hunks = [h.strip('\n\r') for h in hunks if h.strip()]
    
    if not hunks:
        return None
    
    # Try to wrap each hunk in a function and combine
    func_defs = []
    for i, hunk in enumerate(hunks):
        wrapped = _wrap_hunk_as_function(hunk, i)
        if wrapped:
            func_defs.append(wrapped)
    
    if func_defs:
        combined = '\n\n'.join(func_defs) + '\n'
        try:
            return ast.parse(combined, filename=filename)
        except SyntaxError:
            pass
    
    # Fallback: merge all hunks into a single block, strip orphaned
    # partial expressions and unterminated docstrings, then wrap.
    merged = re.sub(r'^# @@ hunk @@\s*$', '', cleaned, flags=re.MULTILINE)
    merged = re.sub(r'\n{3,}', '\n\n', merged)
    result = _try_parse_merged_hunks(merged, filename)
    if result is not None:
        return result
    
    return None


def _try_parse_merged_hunks(source: str, filename: str):
    """Parse merged diff hunks by progressively stripping unparseable lines.
    
    Combines all hunks into a single block, removes unterminated docstrings
    and orphaned partial expressions (e.g., string continuation lines from
    across hunk boundaries), then wraps the result in a function.
    """
    import textwrap
    import re

    lines = source.splitlines(keepends=True)
    if not lines:
        return None

    # Strip unterminated triple-quoted strings at the start
    stripped_source = _strip_orphaned_triple_quotes(source)
    # Clean up interior issues from hunk boundaries
    stripped_source = _cleanup_hunk_boundary_artifacts(stripped_source)
    lines = stripped_source.splitlines(keepends=True)

    # Progressively strip leading lines that look like orphaned expression
    # fragments: string literals, unmatched parens, docstring content, etc.
    max_strip = min(len(lines), 30)
    for start in range(max_strip):
        candidate = ''.join(lines[start:])
        if not candidate.strip():
            continue
        dedented = textwrap.dedent(candidate)
        if not dedented.strip():
            continue
        # Also strip orphaned quotes from this candidate
        dedented = _strip_orphaned_triple_quotes(dedented)
        # Strip orphaned partial expression lines at the beginning
        dedented = _strip_leading_partial_lines(dedented)
        if not dedented.strip():
            continue
        # Handle elif/else/except/finally without matching if/try
        dedented = _fixup_orphaned_clauses(dedented)
        # Close unclosed parentheses from incomplete expressions
        dedented = _close_unclosed_expressions(dedented)
        completed = _complete_trailing_blocks(dedented)
        body = textwrap.indent(completed, "    ")
        wrapped = f"def _a3_merged_snippet_():\n{body}\n"
        try:
            tree = ast.parse(wrapped, filename=filename)
            return tree
        except SyntaxError:
            continue

    return None


def _cleanup_hunk_boundary_artifacts(source: str) -> str:
    """Clean up artifacts that appear at hunk boundaries inside merged code.
    
    1. Remove blank lines that interrupt multi-line expressions (line ending
       with +, -, *, /, etc. followed by blank line then continuation).
    2. Remove orphaned string continuation lines that appear after a complete
       statement (e.g., lines that are just string literals with closing parens
       but the expression start is missing from the diff context).
    3. Strip trailing incomplete function definitions.
    """
    import re

    lines = source.splitlines(keepends=True)
    result = []
    i = 0
    while i < len(lines):
        stripped = lines[i].rstrip('\n\r')
        stripped_s = stripped.strip()

        # Rule 1: remove blank lines inside multi-line expressions.
        # If previous line ends with a continuation operator and next non-blank
        # line is a string/expression continuation, skip the blank line.
        if not stripped_s and result:
            prev = result[-1].rstrip('\n\r').rstrip()
            if prev and prev[-1] in ('+', ',', '(', '[', '{', '\\'):
                # Skip blank line(s)
                i += 1
                continue

        # Rule 2: detect orphaned string continuation lines in the middle.
        # Pattern: an indented line that starts with a string literal and ends
        # with ) but the statement it belongs to is not present.
        # Only apply if previous non-blank line ends with a complete statement.
        if stripped_s and re.match(r"^['\"]", stripped_s):
            # Check if this looks like a continuation of a previous expression
            # Find the previous non-blank line
            prev_idx = len(result) - 1
            while prev_idx >= 0 and not result[prev_idx].strip():
                prev_idx -= 1
            if prev_idx >= 0:
                prev_stripped = result[prev_idx].rstrip('\n\r').rstrip()
                # If previous line ends with a complete statement (no open expr)
                # and this line is an orphaned continuation, skip it
                if prev_stripped and prev_stripped[-1] not in ('+', ',', '(', '[', '{', '\\'):
                    # This string line is orphaned — skip it and any following
                    # continuation lines
                    j = i
                    while j < len(lines):
                        ls = lines[j].strip()
                        if not ls:
                            j += 1
                            continue
                        if re.match(r"^['\"]", ls) or re.match(r"^\s*%\s*\(", ls):
                            j += 1
                            continue
                        if ls.startswith('%') or ls.endswith(')'):
                            j += 1
                            continue
                        break
                    i = j
                    continue

        result.append(lines[i])
        i += 1

    # Rule 3: strip trailing incomplete function/class definitions
    while result:
        last = result[-1].rstrip('\n\r').strip()
        if not last:
            result.pop()
            continue
        # Incomplete def/class: line ends with comma or open paren
        if last.endswith(',') or (last.startswith('def ') and not last.endswith(':')):
            result.pop()
            continue
        break

    return ''.join(result)


def _close_unclosed_expressions(source: str) -> str:
    """Close unclosed parentheses/brackets in incomplete expressions.
    
    Diff fragments often contain multi-line expressions where the closing
    delimiter is on a line not included in the diff.  For example:
    
        raise ValueError('message' +
                         str(x) + '. '
        next_statement = ...     # ← parser error: unclosed paren
    
    This helper finds lines where the running paren/bracket count is unbalanced
    and inserts closing delimiters before the next complete statement.
    """
    import re

    lines = source.splitlines(keepends=True)
    result = []
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    in_string = None

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Track paren/bracket/brace depth (simplified, ignoring strings properly
        # would require a full tokenizer, but for diff fragments this is sufficient)
        for ch in stripped:
            if in_string:
                if ch == in_string:
                    in_string = None
                continue
            if ch in ("'", '"'):
                in_string = ch
                continue
            if ch == '(':
                paren_depth += 1
            elif ch == ')':
                paren_depth = max(0, paren_depth - 1)
            elif ch == '[':
                bracket_depth += 1
            elif ch == ']':
                bracket_depth = max(0, bracket_depth - 1)
            elif ch == '{':
                brace_depth += 1
            elif ch == '}':
                brace_depth = max(0, brace_depth - 1)
        in_string = None  # reset at line boundary for robustness

        # If we're in an unclosed expression and the next line starts a new
        # statement (lower or equal indentation, starts with keyword), close
        # the expression first.
        if (paren_depth > 0 or bracket_depth > 0 or brace_depth > 0):
            # Look at next non-blank line
            next_line = None
            for j in range(i + 1, min(i + 3, len(lines))):
                if lines[j].strip():
                    next_line = lines[j]
                    break
            if next_line:
                next_stripped = next_line.strip()
                next_indent = len(next_line) - len(next_line.lstrip())
                curr_indent = len(line) - len(line.lstrip())
                # Next line is a new statement at same/lower indent
                if next_indent <= curr_indent and _looks_like_python_code(next_stripped):
                    # Close unclosed parens/brackets
                    closers = ')' * paren_depth + ']' * bracket_depth + '}' * brace_depth
                    # Append closers to current line
                    result.append(line.rstrip('\n\r') + closers + '\n')
                    paren_depth = 0
                    bracket_depth = 0
                    brace_depth = 0
                    continue

        result.append(line)

    return ''.join(result)


def _strip_leading_partial_lines(source: str) -> str:
    """Strip leading lines that are clearly partial expression continuations.

    Diff extraction can produce lines like:
        '...text...')         ← unmatched close paren
        str(y.shape) + '. '  ← string concat continuation
    These are fragments of expressions that began in code not included in
    the diff.  Remove them so the remaining code can parse.
    """
    import re

    lines = source.splitlines(keepends=True)
    start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            start = i + 1
            continue
        # Lines that look like actual Python code — stop stripping
        if _looks_like_python_code(stripped):
            break
        # Orphaned continuation: line is just string literals and/or closing parens
        if re.match(r"^[\s'\"()+%,.\[\]]*\)[\s'\"()+%,.\[\]]*$", stripped):
            start = i + 1
            continue
        # Line is purely a string literal (continuation from previous line)
        if re.match(r"^['\"]", stripped):
            start = i + 1
            continue
        # Plain text (not a Python keyword/statement) — skip it
        if not _looks_like_python_code(stripped):
            start = i + 1
            continue
        break

    if start > 0 and start < len(lines):
        return ''.join(lines[start:])
    return source


def _fixup_orphaned_clauses(source: str) -> str:
    """Convert leading elif/else/except/finally to valid standalone code.
    
    When diff extraction produces code starting with elif/else (without
    the preceding if), convert them so the code can parse.
    """
    import re

    lines = source.splitlines(keepends=True)
    if not lines:
        return source

    # Find first non-blank line
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        # elif → if
        if stripped.startswith('elif ') or stripped.startswith('elif('):
            indent = len(line) - len(line.lstrip())
            lines[i] = ' ' * indent + 'if' + stripped[4:] + ('\n' if not line.endswith('\n') else '')
        # else: → if True: (placeholder)
        elif stripped == 'else:':
            indent = len(line) - len(line.lstrip())
            lines[i] = ' ' * indent + 'if True:\n'
        # except/finally without try
        elif stripped.startswith('except') or stripped.startswith('finally'):
            indent = len(line) - len(line.lstrip())
            lines = [' ' * indent + 'try:\n', ' ' * indent + '    pass\n'] + lines[i:]
        break

    return ''.join(lines)



def _strip_orphaned_triple_quotes(source: str) -> str:
    """Strip orphaned triple-quote lines from diff-extracted code fragments.

    Diff extraction often captures the closing '\"\"\"' of a docstring without
    its opening counterpart, or an opening '\"\"\"' without the closing
    counterpart.  Both make the code unparseable when wrapped in a synthetic
    function.  This helper removes such orphaned triple-quote content.
    """
    lines = source.splitlines(keepends=True)
    # Strip leading blank/whitespace-only lines to find the first real line
    first_real = 0
    while first_real < len(lines) and not lines[first_real].strip():
        first_real += 1
    if first_real >= len(lines):
        return source
    # If the first real line is just a triple-quote (end of docstring), remove it
    first_content = lines[first_real].strip()
    if first_content in ('"""', "'''"):
        return ''.join(lines[:first_real] + lines[first_real + 1:])

    # Handle unterminated opening triple-quoted strings: the first real line
    # starts a triple-quoted string (e.g. '"""docstring...') but the
    # matching close never appears in the fragment.  Remove the opening line
    # and all subsequent docstring-content lines (plain text, not code).
    for quote in ('"""', "'''"):
        if quote in first_content:
            count = first_content.count(quote)
            if count == 1:
                # Opening quote without close — scan for close in later lines
                close_idx = None
                for j in range(first_real + 1, len(lines)):
                    if quote in lines[j]:
                        close_idx = j
                        break
                if close_idx is not None:
                    # Remove the entire docstring region
                    return ''.join(lines[:first_real] + lines[close_idx + 1:])
                else:
                    # No closing quote: remove opening line and all following
                    # plain-text lines (docstring body) until we hit something
                    # that looks like Python code.
                    code_start = len(lines)
                    for j in range(first_real + 1, len(lines)):
                        stripped = lines[j].strip()
                        if not stripped:
                            continue
                        if _looks_like_python_code(stripped):
                            code_start = j
                            break
                    return ''.join(lines[code_start:])

    return source


def _looks_like_python_code(stripped_line: str) -> bool:
    """Heuristic: does a stripped line look like a Python statement?"""
    import re
    # Python keywords/statements that start lines
    if re.match(r'^(if|elif|else|for|while|def|class|return|raise|import|from|'
                r'with|try|except|finally|assert|del|pass|break|continue|'
                r'yield|global|nonlocal|async|await|@)\b', stripped_line):
        return True
    # Assignment or augmented assignment
    if re.match(r'^[a-zA-Z_]\w*(\.\w+)*(\[.*\])?\s*(=|\+=|-=|\*=|/=|//=|%=|\*\*=|&=|\|=|\^=|<<=|>>=)', stripped_line):
        return True
    # Function/method call: name(...)
    if re.match(r'^[a-zA-Z_]\w*(\.\w+)*\s*\(', stripped_line):
        return True
    return False


def _wrap_hunk_as_function(hunk_source: str, index: int) -> Optional[str]:
    """Wrap a single code hunk in a function definition.
    
    Handles break/continue by adding a loop wrapper, and dedents the code
    to normalize indentation.  Progressively strips leading lines that are
    orphaned expression continuations from across hunk boundaries.
    """
    import textwrap
    
    dedented = textwrap.dedent(hunk_source)
    if not dedented.strip():
        return None
    
    # Strip orphaned triple-quote lines from diff fragments.
    dedented = _strip_orphaned_triple_quotes(dedented)
    if not dedented.strip():
        return None
    
    lines = dedented.splitlines(keepends=True)
    max_strip = min(len(lines), 15)
    
    for start in range(max_strip):
        candidate = ''.join(lines[start:])
        if not candidate.strip():
            continue
        cleaned = textwrap.dedent(candidate)
        if not cleaned.strip():
            continue
        cleaned = _strip_orphaned_triple_quotes(cleaned)
        cleaned = _strip_leading_partial_lines(cleaned)
        if not cleaned.strip():
            continue
        cleaned = _fixup_orphaned_clauses(cleaned)
        cleaned = _close_unclosed_expressions(cleaned)
        completed = _complete_trailing_blocks(cleaned)
        
        needs_loop = _hunk_needs_loop_wrapper(completed)
        
        if needs_loop:
            body = textwrap.indent(completed, "        ")
            wrapped = f"def _a3_hunk_{index}():\n    while True:\n{body}\n        break\n"
        else:
            body = textwrap.indent(completed, "    ")
            wrapped = f"def _a3_hunk_{index}():\n{body}\n"
        
        try:
            ast.parse(wrapped)
            return wrapped
        except SyntaxError:
            # Try without loop wrapper
            if needs_loop:
                body = textwrap.indent(completed, "    ")
                wrapped = f"def _a3_hunk_{index}():\n{body}\n"
                try:
                    ast.parse(wrapped)
                    return wrapped
                except SyntaxError:
                    pass
    
    return None


def _hunk_needs_loop_wrapper(source: str) -> bool:
    """Check if a code hunk has break/continue at a level without an enclosing loop.
    
    Note: ast.parse() accepts break/continue outside loops, but compile() rejects them.
    We use compile() to detect this.
    """
    import textwrap as _tw
    wrapped = f"def _tmp():\n" + _tw.indent(source, "    ") + "\n"
    try:
        compile(wrapped, '<test>', 'exec')
        return False  # Compiles fine without loop
    except SyntaxError as e:
        msg = str(e).lower()
        if 'break' in msg or 'continue' in msg:
            return True
        return False


def _complete_trailing_blocks(source: str) -> str:
    """Add 'pass' to trailing incomplete blocks (if/for/while/with/try without body)."""
    lines = source.rstrip().split('\n')
    if not lines:
        return source
    last = lines[-1]
    stripped = last.rstrip()
    if stripped.endswith(':'):
        indent = len(last) - len(last.lstrip())
        lines.append(' ' * (indent + 4) + 'pass')
    return '\n'.join(lines) + '\n'


def build_call_graph_from_directory(
    root_path: Path,
    exclude_patterns: List[str] = None
) -> CallGraph:
    """Build call graph from all Python files in a directory."""
    exclude_patterns = exclude_patterns or [
        '__pycache__', '.git', 'venv', '.venv', 'node_modules',
        '.egg-info', 'dist', 'build', '.tox', '.mypy_cache',
    ]
    
    import fnmatch
    
    combined = CallGraph()
    
    for py_file in root_path.rglob('*.py'):
        # Check exclusions using both substring and glob matching
        rel_str = str(py_file.relative_to(root_path))
        abs_str = str(py_file)
        excluded = False
        for p in exclude_patterns:
            # Glob-style patterns (contain *, ?, [)
            if any(c in p for c in ('*', '?', '[')):
                if fnmatch.fnmatch(rel_str, p):
                    excluded = True
                    break
            else:
                # Simple substring match (for __pycache__, .git, etc.)
                if p in abs_str:
                    excluded = True
                    break
        if excluded:
            continue
        
        # Compute module name from path
        try:
            rel_path = py_file.relative_to(root_path)
            parts = list(rel_path.parts[:-1]) + [py_file.stem]
            if parts[-1] == '__init__':
                parts = parts[:-1]
            module_name = '.'.join(parts) if parts else py_file.stem
        except ValueError:
            module_name = py_file.stem
        
        file_graph = build_call_graph_from_file(py_file, module_name)
        
        # Merge into combined
        for qname, func in file_graph.functions.items():
            combined.add_function(func)
        
        for caller, callees in file_graph.edges.items():
            for callee in callees:
                combined.add_edge(caller, callee)
        
        for caller, callees in file_graph.external_calls.items():
            for callee in callees:
                combined.add_external_call(caller, callee)
        
        for caller, sites in file_graph.call_sites_by_caller.items():
            if caller not in combined.call_sites_by_caller:
                combined.call_sites_by_caller[caller] = []
            combined.call_sites_by_caller[caller].extend(sites)
    
    # Populate FunctionInfo.call_sites from call_sites_by_caller
    for caller_qname, call_sites in combined.call_sites_by_caller.items():
        func_info = combined.functions.get(caller_qname)
        if func_info:
            func_info.call_sites.extend(call_sites)
    
    # ITERATION 531: Resolve cross-module calls
    # After collecting all functions from all modules, resolve external calls
    # that are actually to functions within the project
    resolved = combined.resolve_cross_module_calls()
    if resolved > 0:
        # Update call sites with resolved callees
        for caller_qname, call_sites in combined.call_sites_by_caller.items():
            for site in call_sites:
                if site.callee_name and site.callee_name in combined.functions:
                    # Already resolved
                    continue
                # Check if this was an external call that got resolved
                if caller_qname in combined.edges:
                    for resolved_callee in combined.edges[caller_qname]:
                        # Match by simple name
                        if site.callee_name and resolved_callee.endswith(site.callee_name):
                            site.callee_name = resolved_callee
                            break
    
    return combined


def print_call_graph(graph: CallGraph, max_funcs: int = 50) -> None:
    """Print a human-readable representation of the call graph."""
    print(f"Call Graph: {len(graph.functions)} functions, {sum(len(e) for e in graph.edges.values())} edges")
    print()
    
    funcs = list(graph.functions.keys())[:max_funcs]
    for qname in funcs:
        func = graph.functions[qname]
        callees = graph.get_callees(qname)
        external = graph.external_calls.get(qname, set())
        
        print(f"  {qname}")
        print(f"    File: {func.file_path}:{func.line_number}")
        print(f"    Params: {func.parameters}")
        if callees:
            print(f"    Calls: {callees}")
        if external:
            print(f"    External: {external}")
        print()


__all__ = [
    'CallSite',
    'FunctionInfo',
    'CallGraph',
    'CallGraphBuilder',
    'build_call_graph_from_file',
    'build_call_graph_from_directory',
    'print_call_graph',
]
