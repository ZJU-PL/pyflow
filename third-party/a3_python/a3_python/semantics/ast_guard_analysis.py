"""
AST-based guard detection for precise false positive filtering.

This module provides rigorous, AST-level analysis to detect:
1. Guard patterns that protect against null/zero/empty
2. Default parameter values that prevent edge cases
3. Safe Python constructs (slicing, iteration)
4. Intentional exception raising for validation

The key insight is that we can precisely determine if a potential
bug site is protected by analyzing the control flow and data flow
at the AST level, rather than relying on regex heuristics.
"""

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path


@dataclass
class GuardInfo:
    """Information about a guard that protects a variable."""
    variable: str
    guard_type: str  # 'none_check', 'truthiness', 'length_check', 'type_check', 'or_default'
    line_number: int
    protects_against: str  # 'null', 'zero', 'empty', 'type'
    confidence: float


@dataclass
class FunctionSemantics:
    """Semantic information extracted from a function."""
    name: str
    parameters: List[str]
    default_values: Dict[str, ast.expr]  # param -> default AST
    guards: Dict[str, List[GuardInfo]]   # variable -> guards protecting it
    safe_slicing_sites: Set[int]         # line numbers with safe slicing
    unsafe_indexing_sites: Set[int]      # line numbers with unsafe indexing
    exception_raises: Dict[int, str]     # line -> exception type
    is_method: bool
    is_test: bool
    
    def has_guard_for(self, variable: str, against: str = 'null') -> bool:
        """Check if variable has a guard against the specified condition."""
        if variable not in self.guards:
            return False
        return any(g.protects_against == against for g in self.guards[variable])
    
    def get_nonzero_defaults(self) -> Set[str]:
        """Get parameters with non-zero default values."""
        result = set()
        for param, default in self.default_values.items():
            if isinstance(default, ast.Constant):
                if isinstance(default.value, (int, float)) and default.value != 0:
                    result.add(param)
            elif isinstance(default, (ast.List, ast.Dict, ast.Set)):
                # Empty collections - don't count as non-zero
                pass
            elif isinstance(default, ast.Call):
                # Function call default - can't determine statically
                pass
        return result
    
    def is_safe_slicing_at_line(self, line: int) -> bool:
        """Check if the BOUNDS issue at given line is safe slicing."""
        return line in self.safe_slicing_sites
    
    def is_unsafe_indexing_at_line(self, line: int) -> bool:
        """Check if there's potentially unsafe indexing at given line."""
        return line in self.unsafe_indexing_sites


class ASTGuardAnalyzer(ast.NodeVisitor):
    """
    Analyzes Python AST to detect guard patterns.
    
    Detects patterns like:
    - if x is not None: use(x)
    - if x: use(x)  # truthiness
    - if len(x) > 0: use(x)
    - y = x or default
    - x = value if condition else default
    """
    
    def __init__(self, source: str):
        self.source = source
        self.lines = source.split('\n')
        
        # Analysis results
        self.functions: Dict[str, FunctionSemantics] = {}
        self.current_function: Optional[str] = None
        self.current_semantics: Optional[FunctionSemantics] = None
        
        # Guard tracking
        self.guarded_variables: Dict[str, Set[int]] = {}  # var -> lines where guarded
        self.current_guards: Set[str] = set()  # Currently active guards
        
    def analyze(self) -> Dict[str, FunctionSemantics]:
        """Analyze the source and return function semantics."""
        try:
            tree = ast.parse(self.source)
            self.visit(tree)
        except SyntaxError:
            pass  # Handle invalid Python gracefully
        return self.functions
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analyze a function definition."""
        self._analyze_function(node)
        
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Analyze an async function definition."""
        self._analyze_function(node)
    
    def _analyze_function(self, node):
        """Common function analysis logic."""
        old_function = self.current_function
        old_semantics = self.current_semantics
        
        self.current_function = node.name
        
        # Extract parameters and defaults
        params = []
        defaults = {}
        
        # Handle regular args
        args = node.args
        num_defaults = len(args.defaults)
        num_args = len(args.args)
        
        for i, arg in enumerate(args.args):
            params.append(arg.arg)
            # Defaults are right-aligned with args
            default_idx = i - (num_args - num_defaults)
            if default_idx >= 0:
                defaults[arg.arg] = args.defaults[default_idx]
        
        # Handle kwonly args
        for i, arg in enumerate(args.kwonlyargs):
            params.append(arg.arg)
            if args.kw_defaults[i] is not None:
                defaults[arg.arg] = args.kw_defaults[i]
        
        # Detect if this is a method (first param is self/cls)
        is_method = len(params) > 0 and params[0] in ('self', 'cls')
        
        # Detect if this is a test function
        is_test = node.name.startswith('test_') or node.name.startswith('test')
        
        self.current_semantics = FunctionSemantics(
            name=node.name,
            parameters=params,
            default_values=defaults,
            guards={},
            safe_slicing_sites=set(),
            unsafe_indexing_sites=set(),
            exception_raises={},
            is_method=is_method,
            is_test=is_test,
        )
        
        # Analyze function body
        self.current_guards = set()
        for stmt in node.body:
            self._analyze_statement(stmt)
        
        self.functions[node.name] = self.current_semantics
        
        self.current_function = old_function
        self.current_semantics = old_semantics
    
    def _analyze_statement(self, stmt: ast.stmt):
        """Analyze a statement for guards, patterns, and subscript operations."""
        if isinstance(stmt, ast.If):
            self._analyze_if(stmt)
        elif isinstance(stmt, ast.Assert):
            self._analyze_assert(stmt)
        elif isinstance(stmt, ast.Assign):
            self._analyze_assign(stmt)
            # Also check for subscripts in assignment value
            self._analyze_subscripts(stmt.value)
            for target in stmt.targets:
                if isinstance(target, ast.expr):
                    self._analyze_subscripts(target)
        elif isinstance(stmt, ast.Raise):
            self._analyze_raise(stmt)
        elif isinstance(stmt, ast.For):
            self._analyze_for(stmt)
        elif isinstance(stmt, (ast.Try, ast.ExceptHandler)):
            self._analyze_try(stmt)
        elif isinstance(stmt, ast.Expr):
            self._analyze_expr(stmt)
        elif isinstance(stmt, ast.Return):
            # Check for subscripts in return value
            if stmt.value:
                self._analyze_subscripts(stmt.value)
        elif isinstance(stmt, ast.AugAssign):
            # a[i] += 1, a[:] += [...], etc.
            self._analyze_subscripts(stmt.target)
            self._analyze_subscripts(stmt.value)
        
        # Recurse into compound statements
        if hasattr(stmt, 'body'):
            for child in stmt.body:
                self._analyze_statement(child)
        if hasattr(stmt, 'orelse'):
            for child in stmt.orelse:
                self._analyze_statement(child)
    
    def _analyze_assert(self, node: ast.Assert):
        """Analyze assert statements as guards."""
        guards = self._extract_guards_from_test(node.test, node.lineno)
        
        # Assert statements guard all subsequent code
        for var, info in guards.items():
            if var not in self.current_semantics.guards:
                self.current_semantics.guards[var] = []
            # Mark as assert_guard type for higher confidence
            info.guard_type = f'assert_{info.guard_type}'
            info.confidence = min(0.98, info.confidence + 0.05)
            self.current_semantics.guards[var].append(info)
    
    def _analyze_if(self, node: ast.If):
        """Analyze an if statement for guard patterns."""
        guards = self._extract_guards_from_test(node.test, node.lineno)
        
        # Add guards for the body
        for var, info in guards.items():
            if var not in self.current_semantics.guards:
                self.current_semantics.guards[var] = []
            self.current_semantics.guards[var].append(info)
        
        # Check for raise-before-access pattern: if not condition: raise Error
        # This means the ELSE path (after the if) is guarded
        if node.body and len(node.body) == 1 and isinstance(node.body[0], ast.Raise):
            # Invert the guard - the condition being False causes raise
            # So after this if, condition must be True
            if isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not):
                # if not x: raise -> x is guarded after this
                var = self._get_variable_name(node.test.operand)
                if var:
                    if var not in self.current_semantics.guards:
                        self.current_semantics.guards[var] = []
                    self.current_semantics.guards[var].append(
                        GuardInfo(
                            variable=var,
                            guard_type='raise_if_not',
                            line_number=node.lineno,
                            protects_against='null',
                            confidence=0.95
                        )
                    )
            elif isinstance(node.test, ast.Compare):
                # if x not in dict: raise -> after this, x is in dict
                if len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.NotIn):
                    key_var = self._get_variable_name(node.test.left)
                    dict_var = self._get_variable_name(node.test.comparators[0])
                    if key_var and dict_var:
                        guard_var = f"{dict_var}[{key_var}]"
                        if guard_var not in self.current_semantics.guards:
                            self.current_semantics.guards[guard_var] = []
                        self.current_semantics.guards[guard_var].append(
                            GuardInfo(
                                variable=guard_var,
                                guard_type='raise_if_not_in',
                                line_number=node.lineno,
                                protects_against='key_error',
                                confidence=0.95
                            )
                        )
    
    def _extract_guards_from_test(self, test: ast.expr, lineno: int) -> Dict[str, GuardInfo]:
        """Extract guard information from an if test."""
        guards = {}
        
        # Pattern: if x is not None
        if isinstance(test, ast.Compare):
            if len(test.ops) == 1 and len(test.comparators) == 1:
                op = test.ops[0]
                comp = test.comparators[0]
                
                if isinstance(op, ast.IsNot) and isinstance(comp, ast.Constant) and comp.value is None:
                    var = self._get_variable_name(test.left)
                    if var:
                        guards[var] = GuardInfo(
                            variable=var,
                            guard_type='none_check',
                            line_number=lineno,
                            protects_against='null',
                            confidence=0.95
                        )
                
                # Pattern: if len(x) > 0
                if isinstance(op, (ast.Gt, ast.GtE)) and isinstance(test.left, ast.Call):
                    if isinstance(test.left.func, ast.Name) and test.left.func.id == 'len':
                        if test.left.args:
                            var = self._get_variable_name(test.left.args[0])
                            if var:
                                guards[var] = GuardInfo(
                                    variable=var,
                                    guard_type='length_check',
                                    line_number=lineno,
                                    protects_against='empty',
                                    confidence=0.9
                                )
        
        # Pattern: if x (truthiness)
        elif isinstance(test, ast.Name):
            guards[test.id] = GuardInfo(
                variable=test.id,
                guard_type='truthiness',
                line_number=lineno,
                protects_against='null',  # Also protects against empty/zero
                confidence=0.85
            )
        
        # Pattern: if not x (inverse truthiness - guards else branch)
        elif isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            var = self._get_variable_name(test.operand)
            if var:
                # This guards the else branch, not the if branch
                # We'd need more sophisticated tracking for this
                pass
        
        # Pattern: if x and y
        elif isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
            for value in test.values:
                guards.update(self._extract_guards_from_test(value, lineno))
        
        # Pattern: if key in dict (membership check)
        elif isinstance(test, ast.Compare):
            if len(test.ops) == 1 and isinstance(test.ops[0], ast.In):
                key_var = self._get_variable_name(test.left)
                dict_var = self._get_variable_name(test.comparators[0])
                if key_var and dict_var:
                    # This guards both the key and the dict[key] access
                    guards[f"{dict_var}[{key_var}]"] = GuardInfo(
                        variable=f"{dict_var}[{key_var}]",
                        guard_type='membership_check',
                        line_number=lineno,
                        protects_against='key_error',
                        confidence=0.95
                    )
        
        return guards
    
    def _analyze_assign(self, node: ast.Assign):
        """Analyze assignments for guard patterns like x = y or default."""
        if isinstance(node.value, ast.BoolOp) and isinstance(node.value.op, ast.Or):
            # Pattern: x = y or default
            # The first operand might be None/empty, guarded by the second
            if len(node.value.values) >= 2:
                first = node.value.values[0]
                var = self._get_variable_name(first)
                
                if var:
                    for target in node.targets:
                        target_var = self._get_variable_name(target)
                        if target_var:
                            if target_var not in self.current_semantics.guards:
                                self.current_semantics.guards[target_var] = []
                            self.current_semantics.guards[target_var].append(
                                GuardInfo(
                                    variable=target_var,
                                    guard_type='or_default',
                                    line_number=node.lineno,
                                    protects_against='null',
                                    confidence=0.9
                                )
                            )
        
        # Pattern: x = dict.get(key, default)
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Attribute):
                if node.value.func.attr == 'get' and len(node.value.args) >= 2:
                    # dict.get() with default value - safe
                    dict_var = self._get_variable_name(node.value.func.value)
                    if dict_var and len(node.value.args) >= 1:
                        key_arg = node.value.args[0]
                        key_var = self._get_variable_name(key_arg)
                        if isinstance(key_arg, ast.Constant):
                            key_var = repr(key_arg.value)
                        
                        for target in node.targets:
                            target_var = self._get_variable_name(target)
                            if target_var and key_var:
                                if target_var not in self.current_semantics.guards:
                                    self.current_semantics.guards[target_var] = []
                                self.current_semantics.guards[target_var].append(
                                    GuardInfo(
                                        variable=target_var,
                                        guard_type='dict_get_default',
                                        line_number=node.lineno,
                                        protects_against='key_error',
                                        confidence=0.98
                                    )
                                )
                                # Also mark the access pattern as safe
                                access_var = f"{dict_var}[{key_var}]"
                                if access_var not in self.current_semantics.guards:
                                    self.current_semantics.guards[access_var] = []
                                self.current_semantics.guards[access_var].append(
                                    GuardInfo(
                                        variable=access_var,
                                        guard_type='dict_get_default',
                                        line_number=node.lineno,
                                        protects_against='key_error',
                                        confidence=0.98
                                    )
                                )
        
        # Pattern: x = y if condition else default
        if isinstance(node.value, ast.IfExp):
            # The target is protected by the ternary
            for target in node.targets:
                target_var = self._get_variable_name(target)
                if target_var:
                    if target_var not in self.current_semantics.guards:
                        self.current_semantics.guards[target_var] = []
                    self.current_semantics.guards[target_var].append(
                        GuardInfo(
                            variable=target_var,
                            guard_type='ternary_guard',
                            line_number=node.lineno,
                            protects_against='null',
                            confidence=0.8
                        )
                    )
    
    def _analyze_raise(self, node: ast.Raise):
        """Track intentional exception raises."""
        if node.exc:
            exc_name = None
            if isinstance(node.exc, ast.Call):
                if isinstance(node.exc.func, ast.Name):
                    exc_name = node.exc.func.id
                elif isinstance(node.exc.func, ast.Attribute):
                    exc_name = node.exc.func.attr
            elif isinstance(node.exc, ast.Name):
                exc_name = node.exc.id
            
            if exc_name and self.current_semantics:
                self.current_semantics.exception_raises[node.lineno] = exc_name
    
    def _analyze_for(self, node: ast.For):
        """Analyze for loops - iteration is safe for empty collections."""
        # for x in y - if y is empty, loop just doesn't execute
        # This is safe - no exception raised
        pass
    
    def _analyze_try(self, node):
        """Analyze try/except for intentional error handling."""
        # Errors in try blocks may be intentionally caught
        pass
    
    def _analyze_expr(self, node: ast.Expr):
        """Analyze expressions."""
        # Analyze all subscript operations in the expression
        self._analyze_subscripts(node.value)
    
    def _analyze_subscripts(self, node: ast.expr):
        """
        Analyze all subscript operations in an expression tree.
        
        Classifies each subscript as either:
        - SLICING (s[i:j], s[:n], s[n:], s[::k]) -> ALWAYS SAFE, never raises IndexError
        - SAFE INDEXING (split()[0], items()[0]) -> Safe due to guaranteed structure
        - INDEXING (s[i]) -> CAN raise IndexError
        
        Python Language Guarantee (PEP-8 / Language Reference):
        Slicing operations return a new sequence with elements in the given range.
        Out-of-bounds slice indices are silently clamped to valid range.
        Empty slices return empty sequences. NO EXCEPTION IS EVER RAISED.
        
        Additionally, certain method calls guarantee at least one element:
        - str.split() always returns at least ['']
        - dict.items()/keys()/values() iteration is safe
        """
        if isinstance(node, ast.Subscript):
            lineno = getattr(node, 'lineno', 0)
            
            if self._is_slice_subscript(node):
                # This is SLICING - always safe by Python semantics
                if self.current_semantics and lineno:
                    self.current_semantics.safe_slicing_sites.add(lineno)
            elif self._is_safe_indexing(node):
                # This is safe indexing - e.g., split()[0] always has element 0
                if self.current_semantics and lineno:
                    self.current_semantics.safe_slicing_sites.add(lineno)
            else:
                # This is INDEXING - can raise IndexError
                if self.current_semantics and lineno:
                    self.current_semantics.unsafe_indexing_sites.add(lineno)
        
        # Recurse into child nodes
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._analyze_subscripts(child)
    
    def _is_slice_subscript(self, node: ast.Subscript) -> bool:
        """
        Determine if a Subscript AST node is a slice operation (safe) or index (unsafe).
        
        Returns True for:
        - s[i:j]    -> ast.Slice with lower and/or upper
        - s[:n]     -> ast.Slice with upper only
        - s[n:]     -> ast.Slice with lower only
        - s[:]      -> ast.Slice with neither
        - s[::k]    -> ast.Slice with step
        - s[::-1]   -> ast.Slice with negative step
        
        Returns False for:
        - s[i]      -> ast.Constant, ast.Name, etc.
        - s[x]      -> any non-Slice expression
        """
        slice_node = node.slice
        
        # Direct slice syntax: s[a:b], s[:b], s[a:], s[::k]
        if isinstance(slice_node, ast.Slice):
            return True
        
        # Extended slice in older Python: s[a:b, c:d] (rare, but also safe)
        if isinstance(slice_node, ast.Tuple):
            # If ALL elements of the tuple are slices, it's safe
            # This handles numpy-style multi-dimensional slicing
            return all(isinstance(elt, ast.Slice) for elt in slice_node.elts)
        
        # Everything else is indexing (can raise IndexError)
        return False
    
    def _is_safe_indexing(self, node: ast.Subscript) -> bool:
        """
        Determine if an indexing operation is safe due to guaranteed structure.
        
        Safe patterns:
        1. split(...)[0] - str.split() ALWAYS returns at least one element
           Even "".split() returns [''], so [0] is always valid
        2. Negative indexing on guaranteed non-empty (handled separately)
        
        This is NOT pattern matching - it's semantic analysis based on
        Python's documented method contracts.
        """
        slice_node = node.slice
        value = node.value
        
        # Check for [0] index
        is_zero_index = (
            isinstance(slice_node, ast.Constant) and 
            slice_node.value == 0
        )
        
        if is_zero_index and isinstance(value, ast.Call):
            # Check if it's a split() call
            if isinstance(value.func, ast.Attribute):
                method_name = value.func.attr
                # str.split(), str.rsplit() always return at least one element
                # Python doc: "If sep is not specified or is None, a different 
                # splitting algorithm is applied... the result will contain no 
                # empty strings at the start or end if the string has leading 
                # or trailing whitespace."
                # BUT it still returns at least [''] for empty string
                if method_name in ('split', 'rsplit', 'splitlines'):
                    return True
        
        return False
    
    def _find_safe_slicing(self, node: ast.expr):
        """
        Legacy method - now calls _analyze_subscripts.
        Kept for backward compatibility.
        """
        self._analyze_subscripts(node)
    
    def _get_variable_name(self, node: ast.expr) -> Optional[str]:
        """Extract variable name from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_variable_name(node.value)
            if base:
                return f"{base}.{node.attr}"
        return None


class SafetyAnalyzer:
    """
    High-level analyzer that determines if a potential bug site is safe.
    
    Uses AST analysis to precisely determine:
    1. Is the variable guarded by a None check?
    2. Does the parameter have a non-zero default?
    3. Is this a safe slicing operation?
    4. Is this intentional validation (raise ValueError)?
    """
    
    def __init__(self):
        self.cache: Dict[str, Dict[str, FunctionSemantics]] = {}
    
    def analyze_file(self, file_path: Path) -> Dict[str, FunctionSemantics]:
        """Analyze a Python file and cache results."""
        key = str(file_path)
        if key in self.cache:
            return self.cache[key]
        
        try:
            source = file_path.read_text(encoding='utf-8', errors='ignore')
            analyzer = ASTGuardAnalyzer(source)
            result = analyzer.analyze()
            self.cache[key] = result
            return result
        except Exception:
            return {}
    
    def analyze_source(self, source: str) -> Dict[str, FunctionSemantics]:
        """Analyze source code directly."""
        analyzer = ASTGuardAnalyzer(source)
        return analyzer.analyze()
    
    def is_bug_guarded(
        self,
        source: str,
        function_name: str,
        bug_type: str,
        variable: Optional[str],
        line_number: Optional[int]
    ) -> Tuple[bool, float, str]:
        """
        Determine if a potential bug is guarded.
        
        Returns:
            (is_guarded, confidence, reason)
        """
        semantics = self.analyze_source(source)
        
        if function_name not in semantics:
            return False, 0.0, "Function not found in analysis"
        
        func = semantics[function_name]
        
        # Check self/cls for NULL_PTR
        if bug_type == 'NULL_PTR':
            if variable in ('self', 'cls') or variable == func.parameters[0] if func.parameters else False:
                if func.is_method:
                    return True, 0.99, "self/cls is never None in methods"
        
        # Check for guards
        if variable and variable in func.guards:
            guards = func.guards[variable]
            if bug_type == 'NULL_PTR':
                for g in guards:
                    if g.protects_against in ('null', 'empty'):
                        return True, g.confidence, f"Guarded by {g.guard_type} at line {g.line_number}"
            elif bug_type == 'DIV_ZERO':
                for g in guards:
                    if g.protects_against in ('zero', 'empty'):
                        return True, g.confidence, f"Guarded by {g.guard_type} at line {g.line_number}"
        
        # Check for non-zero defaults
        if bug_type == 'DIV_ZERO' and variable in func.get_nonzero_defaults():
            return True, 0.85, f"Parameter has non-zero default value"
        
        # Check for safe slicing
        if bug_type == 'BOUNDS' and line_number in func.safe_slicing_sites:
            return True, 0.95, "Python slicing never raises IndexError"
        
        # Check for intentional exception
        if line_number and line_number in func.exception_raises:
            exc_type = func.exception_raises[line_number]
            return True, 0.9, f"Intentional {exc_type} for validation"
        
        # Check for test function
        if func.is_test:
            return True, 0.9, "Test function - intentional edge case testing"
        
        return False, 0.0, "No guards detected"


# Global analyzer instance
_safety_analyzer = SafetyAnalyzer()


def is_bug_likely_guarded(
    source: str,
    function_name: str,
    bug_type: str,
    variable: Optional[str] = None,
    line_number: Optional[int] = None
) -> Tuple[bool, float, str]:
    """
    Convenience function to check if a bug is guarded.
    
    Returns:
        (is_guarded, confidence, reason)
    """
    return _safety_analyzer.is_bug_guarded(
        source, function_name, bug_type, variable, line_number
    )
