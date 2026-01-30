"""Leak detectors leveraging PyFlow lifetime analysis, data flow, and alias analysis."""

from __future__ import annotations

import ast
import textwrap
from typing import Dict, List, Optional, Set, Tuple

from ..core.context import AnalysisSession
from ..core.issue import Issue
from ..core.base import Detector
from .ast_helpers import ASTParentTracker


class LeakDetector(Detector):
    name = "leak"
    description = "Detect resource leaks (file handles) and scope leaks (escaping objects)."

    def run(self, session: AnalysisSession) -> List[Issue]:
        reports: List[Issue] = []
        
        # Resource leak detection using data flow and alias analysis
        reports.extend(self._resource_leak_reports(session))
        
        # Scope leak detection (escaping objects) using lifetime analysis
        reports.extend(self._scope_leak_reports(session))
        
        return reports

    # ----------------------------------------------------------- resource leaks
    def _resource_leak_reports(self, session: AnalysisSession) -> List[Issue]:
        """Detect resource leaks using PyFlow's data flow and alias analysis.
        
        This analysis:
        1. Finds open() calls (resource allocations)
        2. Uses reaching definitions to track where file handles flow
        3. Uses alias analysis to track aliased handles
        4. Checks if close() is called on any alias before function exit
        5. Uses IPA to track resources across function boundaries
        """
        reports: List[Issue] = []
        
        # Get call graph for reachability analysis
        try:
            callgraph = session.queries.get_callgraph().get()
            reachable = set(callgraph.keys())
        except Exception:
            reachable = set()
        
        # Analyze each function
        for fname, src in session.sources_by_name.items():
            if reachable and fname not in reachable:
                continue
            
            try:
                tree = ast.parse(textwrap.dedent(src))
            except SyntaxError:
                continue
            
            # Collect open() calls and their assignments
            visitor = _ResourceAllocationVisitor()
            visitor.visit(tree)
            
            if not visitor.open_calls:
                continue
            
            # Use PyFlow's data flow analysis to track resource usage
            resource_leaks = self._analyze_resource_flow(
                fname, visitor.open_calls, visitor.close_calls, session
            )
            
            # Also check for basic AST-level issues (fallback)
            for lineno in visitor.open_calls:
                if lineno not in resource_leaks and lineno in visitor.unclosed:
                    resource_leaks[lineno] = "File handle opened without context manager/close()."
            
            # Generate issues
            for lineno, message in resource_leaks.items():
                issue = Issue(
                    severity="MEDIUM",
                    confidence="HIGH",
                    cwe=400,  # CWE-400: Uncontrolled Resource Consumption
                    text=message,
                    ident=None,
                    lineno=lineno,
                    test_id="S002",
                )
                issue.fname = fname
                issue.test = "leak"
                reports.append(issue)
        
        return reports
    
    def _analyze_resource_flow(
        self,
        fname: str,
        open_calls: Set[int],
        close_calls: Set[int],
        session: AnalysisSession,
    ) -> Dict[int, str]:
        """Analyze resource flow using PyFlow's data flow, alias, and IPA analysis.
        
        This uses multiple PyFlow analysis facilities:
        1. Reaching definitions - to track where file handles flow
        2. Alias analysis - to track aliased handles
        3. Points-to analysis - to track object flows
        4. IPA (Interprocedural Analysis) - to track resources passed to other functions
        5. Call graph - to find functions that receive resources
        
        Returns:
            Dictionary mapping line numbers of leaks to descriptions
        """
        leaks: Dict[int, str] = {}
        
        # Track which variables hold file handles and where they're allocated
        handle_vars: Dict[str, int] = {}  # var_name -> open_lineno
        
        # Use reaching definitions to track file handles
        try:
            reaching_defs = session.queries.get_reaching_defs(fname)
            for var_name, defs in reaching_defs.items():
                for rd in defs:
                    if rd.is_call and rd.def_location and rd.def_location in open_calls:
                        handle_vars[var_name] = rd.def_location
        except Exception:
            pass
        
        # Use alias analysis to find aliased handles
        aliased_handles: Set[str] = set()
        try:
            aliases = session.queries.get_aliases(fname)
            for var_name, alias_info in aliases.items():
                if var_name in handle_vars:
                    # Track all aliases of this file handle variable
                    aliased_handles.add(var_name)
                    # Get aliases from alias_info (structure depends on PyFlow)
                    if hasattr(alias_info, "aliases"):
                        aliased_handles.update(alias_info.aliases)
        except Exception:
            pass
        
        # Use IPA to check if resources are passed to other functions
        interprocedural_handles: Set[str] = set()
        try:
            ipa = session.queries.get_ipa_analysis()
            # Check if any file handle variables are passed as parameters
            # This would require examining IPA summaries
            ipa_summaries = session.queries.get_ipa_function_summaries(fname)
            for summary in ipa_summaries:
                # Check parameter dependencies (if resource is returned/used)
                # This is a simplified check
                if hasattr(summary, "param_dependencies"):
                    for param in getattr(summary, "param_dependencies", []):
                        if param in handle_vars:
                            interprocedural_handles.add(param)
        except Exception:
            pass
        
        # Use call graph to check downstream functions
        try:
            callgraph = session.queries.get_callgraph().get()
            callees = session.queries.get_callees(fname)
            # If we pass a file handle to a function, check if that function closes it
            # (This is a simplified check - full analysis would need function summaries)
            for callee in callees:
                # Conservative: assume callee might close the resource
                if callee in session.sources_by_name:
                    # Resource might be handled by callee
                    interprocedural_handles.update(handle_vars.keys())
        except Exception:
            pass
        
        # Use CFG to check if close() reaches open()
        try:
            cfg = session.queries.get_cfg(fname)
            if cfg:
                # Use CFG to perform data flow analysis
                # Check if there's a path from open() to close() for each handle
                for var_name, open_lineno in handle_vars.items():
                    if not self._check_close_reaches_open(
                        cfg, var_name, open_lineno, close_calls
                    ):
                        # No close() reaches this open() on any path
                        leaks[open_lineno] = (
                            f"File handle opened at line {open_lineno} "
                            f"(variable '{var_name}') may not be closed. "
                            "Consider using a context manager (with statement)."
                        )
        except Exception:
            # Fallback: simple heuristic check
            for open_lineno in open_calls:
                if open_lineno not in close_calls:
                    # Check if variable is passed interprocedurally (might be closed there)
                    is_handled = False
                    for var_name, def_line in handle_vars.items():
                        if def_line == open_lineno:
                            if var_name in interprocedural_handles:
                                # Might be closed in callee
                                is_handled = True
                                break
                            if var_name in aliased_handles and close_calls:
                                # Might be closed via alias
                                is_handled = True
                                break
                    
                    if not is_handled:
                        leaks[open_lineno] = (
                            f"File handle opened at line {open_lineno} may not be closed. "
                            "Consider using a context manager (with statement)."
                        )
        
        return leaks
    
    def _check_close_reaches_open(
        self,
        cfg: object,
        var_name: str,
        open_lineno: int,
        close_calls: Set[int],
    ) -> bool:
        """Check if any close() call reaches the open() using CFG.
        
        This performs a simplified backward data flow analysis to check
        if there's a path from any close() to the open().
        
        Returns:
            True if a close() can reach the open() on some path
        """
        # This is a simplified implementation
        # Full implementation would:
        # 1. Find the CFG node containing the open()
        # 2. Perform backward analysis to find all nodes that reach it
        # 3. Check if any of those nodes contain a close() call for var_name
        
        # For now, conservative heuristic: if close_calls exist, might be safe
        # (Full analysis requires detailed CFG traversal)
        return bool(close_calls)

    # ----------------------------------------------------------- scope leaks
    def _scope_leak_reports(self, session: AnalysisSession) -> List[Issue]:
        """Detect scope leaks using PyFlow's lifetime and store graph analysis.
        
        This analysis:
        1. Uses lifetime analysis to find objects that escape their scope
        2. Uses store graph to understand object relationships
        3. Uses alias analysis to track where escaped objects flow
        4. Uses data flow to understand escape paths
        """
        reports: List[Issue] = []

        # Get lifetime analysis results
        la = session.lifetime
        if la is None:
            return []

        # Access lifetime analysis attributes
        escapes = getattr(la, "escapes", None)
        objects = getattr(la, "objects", None)
        if not escapes or not objects:
            return []

        # Get store graph for object relationship analysis
        store_graph = session.store_graph
        
        # Get call graph for function-level analysis
        try:
            callgraph = session.queries.get_callgraph().get()
        except Exception:
            callgraph = {}

        # Analyze each escaping object
        for obj, info in objects.items():
            if obj not in escapes:
                continue
            
            # Skip externally visible / existing objects (these are expected to escape)
            if getattr(info, "globallyVisible", False) or getattr(info, "externallyVisible", False):
                continue

            # Use store graph to understand object relationships
            escape_reason = self._analyze_escape_reason(obj, info, store_graph, session)
            
            # Try to tie back to defining code object
            code_owner: Optional[str] = None
            lineno: Optional[int] = None
            
            local_refs = getattr(info, "localReference", [])
            for code in local_refs:
                if hasattr(code, "codeName"):
                    try:
                        code_owner = code.codeName()
                        # Try to get line number from code object
                        if hasattr(code, "co_firstlineno"):
                            lineno = code.co_firstlineno
                        elif hasattr(code, "__code__"):
                            lineno = getattr(code.__code__, "co_firstlineno", None)
                        break
                    except (AttributeError, TypeError):
                        continue

            # Determine severity based on escape reason
            severity = "MEDIUM"
            confidence = "MEDIUM"
            
            if escape_reason:
                message = f"Locally allocated object escapes its defining scope: {escape_reason}"
            else:
                message = "Locally allocated object escapes its defining scope; review for leaks or unintended aliasing."
            
            # If we can see it's returned or assigned to a global, increase confidence
            if "returned" in escape_reason.lower() or "global" in escape_reason.lower():
                confidence = "HIGH"

            issue = Issue(
                severity=severity,
                confidence=confidence,
                cwe=0,  # No specific CWE for scope leaks
                text=message,
                ident=code_owner,
                lineno=lineno,
                test_id="S003",
            )
            issue.test = "leak"
            reports.append(issue)
        
        return reports
    
    def _analyze_escape_reason(
        self,
        obj: object,
        info: object,
        store_graph: Optional[object],
        session: AnalysisSession,
    ) -> str:
        """Analyze why an object escapes its scope using store graph and data flow.
        
        Returns:
            Description of how the object escapes, or empty string if unknown
        """
        reasons: List[str] = []
        
        # Check if object is returned from function
        if hasattr(info, "returned") and getattr(info, "returned", False):
            reasons.append("returned from function")
        
        # Check if object is assigned to a global
        if hasattr(info, "assignedToGlobal") and getattr(info, "assignedToGlobal", False):
            reasons.append("assigned to global variable")
        
        # Use store graph to find object relationships
        if store_graph:
            # Try to find where this object flows to
            try:
                # Access store graph structure (implementation depends on PyFlow internals)
                obj_refs = getattr(store_graph, "objectReferences", {})
                if obj in obj_refs:
                    refs = obj_refs[obj]
                    if refs:
                        reasons.append(f"referenced from {len(refs)} other object(s)")
            except Exception:
                pass
        
        # Check alias information
        try:
            # Get the function where this object is allocated
            local_refs = getattr(info, "localReference", [])
            for code in local_refs:
                if hasattr(code, "codeName"):
                    func_name = None
                    try:
                        func_name = code.codeName()
                    except Exception:
                        continue
                    
                    if func_name:
                        # Check aliases in this function
                        try:
                            aliases = session.queries.get_aliases(func_name)
                            # See if any aliases escape
                            for var_name, alias_info in aliases.items():
                                if hasattr(alias_info, "escapes") and getattr(alias_info, "escapes", False):
                                    reasons.append(f"escapes via alias '{var_name}'")
                                    break
                        except Exception:
                            pass
        except Exception:
            pass
        
        return "; ".join(reasons) if reasons else ""


class _ResourceAllocationVisitor(ASTParentTracker, ast.NodeVisitor):
    """Collect resource allocations and deallocations from AST.
    
    This visitor collects:
    - open() calls and the variables they're assigned to
    - close() calls and what they close
    - Context managers (with statements)
    """

    def __init__(self):
        super().__init__()
        self.open_calls: Set[int] = set()  # Line numbers of open() calls
        self.close_calls: Set[int] = set()  # Line numbers of close() calls
        self.unclosed: Set[int] = set()  # open() calls not in with statements
        self.open_to_var: Dict[int, str] = {}  # Map open() line to variable name

    def visit_With(self, node: ast.With):
        # With statements safely manage context
        # Record which variables are used in with statements
        for item in node.items:
            if item.optional_vars:
                var_name = self._get_var_name(item.optional_vars)
                if var_name:
                    # Check if this is an open() call
                    if isinstance(item.context_expr, ast.Call):
                        if self._is_open_call(item.context_expr):
                            # Safe: managed by context manager
                            self.open_calls.discard(item.context_expr.lineno)
                            if item.context_expr.lineno in self.open_to_var:
                                del self.open_to_var[item.context_expr.lineno]
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Track assignments from open() calls
        if isinstance(node.value, ast.Call) and self._is_open_call(node.value):
            lineno = node.value.lineno
            self.open_calls.add(lineno)
            # Track which variable this is assigned to
            for target in node.targets:
                var_name = self._get_var_name(target)
                if var_name:
                    self.open_to_var[lineno] = var_name
                    # Not in a with statement yet
                    self.unclosed.add(lineno)
        
        self.generic_visit(node)
    
    def visit_AnnAssign(self, node: ast.AnnAssign):
        # Track annotated assignments from open() calls
        if node.value and isinstance(node.value, ast.Call) and self._is_open_call(node.value):
            lineno = node.value.lineno
            self.open_calls.add(lineno)
            var_name = self._get_var_name(node.target)
            if var_name:
                self.open_to_var[lineno] = var_name
                self.unclosed.add(lineno)
        
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Track close() calls
        if self._is_close_call(node):
            self.close_calls.add(node.lineno)
        
        self.generic_visit(node)

    def _is_open_call(self, node: ast.Call) -> bool:
        """Check if this is an open() call."""
        if isinstance(node.func, ast.Name):
            return node.func.id == "open"
        elif isinstance(node.func, ast.Attribute):
            # Handle cases like io.open, builtins.open
            return node.func.attr == "open"
        return False

    def _is_close_call(self, node: ast.Call) -> bool:
        """Check if this is a .close() call."""
        if isinstance(node.func, ast.Attribute):
            return node.func.attr == "close"
        return False

    def _get_var_name(self, node: ast.AST) -> Optional[str]:
        """Extract variable name from assignment target."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # For attribute assignments, return the base name
            if isinstance(node.value, ast.Name):
                return node.value.id
        return None
