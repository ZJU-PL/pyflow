"""
AST Node Visitor for Security Checking.

This module provides an AST visitor that traverses Python code and identifies
security issues. The visitor pattern is used to examine different types of AST
nodes (function calls, imports, strings, etc.) and run security tests on them.

**Visitor Pattern:**
The visitor traverses the AST tree, calling specific visit methods for each
node type. For each node, it:
1. Builds a context with relevant information
2. Runs security tests appropriate for that node type
3. Collects and aggregates security scores

**Node Types Handled:**
- ClassDef: Class definitions
- FunctionDef: Function definitions
- Call: Function/method calls
- Import/ImportFrom: Module imports
- Str/Bytes/Constant: String and bytes literals
- File: Overall file-level checks

**Security Testing:**
Tests are organized by node type and run through the SecurityTester,
which executes registered security checks and collects issues.
"""

import ast
import logging
import operator

from . import constants
from . import tester as b_tester
from . import utils as b_utils

LOG = logging.getLogger(__name__)


class SecurityNodeVisitor:
    """
    AST visitor for security checking.
    
    This visitor traverses Python AST nodes and runs security tests on them.
    It maintains context about the current namespace, imports, and node
    information, which is passed to security tests.
    
    **Visitor Flow:**
    1. pre_visit: Sets up context for the node
    2. visit: Calls node-specific visitor method or runs generic tests
    3. post_visit: Cleans up (e.g., restores namespace)
    
    **Context Building:**
    For each node, builds a context dictionary containing:
    - Node information (lineno, col_offset, etc.)
    - Current namespace (module.class.function)
    - Import information (imports, aliases)
    - File information (filename, file_data)
    - Node-specific data (call info, string values, etc.)
    
    **Score Tracking:**
    Maintains scores for severity and confidence levels, aggregating
    results from all security tests run during traversal.
    
    Attributes:
        debug: Whether to enable debug logging
        nosec_lines: Lines with # nosec comments (to skip tests)
        scores: Dictionary tracking severity and confidence scores
        depth: Current traversal depth (for debugging)
        fname: Current filename being analyzed
        fdata: File data object (for reading source lines)
        testset: Set of security tests to run
        imports: Set of imported module names
        import_aliases: Dictionary mapping import aliases to full names
        tester: SecurityTester instance for running tests
        namespace: Current qualified namespace (module.class.function)
        metrics: Metrics collector for statistics
        context: Current context dictionary (updated per node)
    """
    def __init__(self, fname, fdata, testset, debug, nosec_lines, metrics):
        """
        Initialize a security node visitor.
        
        Args:
            fname: Filename being analyzed
            fdata: File data object (for reading source lines)
            testset: TestSet containing security tests to run
            debug: Whether to enable debug logging
            nosec_lines: Dictionary mapping line numbers to nosec test IDs
            metrics: Metrics collector for statistics
        """
        self.debug = debug
        self.nosec_lines = nosec_lines
        self.scores = {"SEVERITY": [0] * len(constants.RANKING), "CONFIDENCE": [0] * len(constants.RANKING)}
        self.depth = 0
        self.fname = fname
        self.fdata = fdata
        self.testset = testset
        self.imports = set()
        self.import_aliases = {}
        self.tester = b_tester.SecurityTester(self.testset, self.debug, nosec_lines, metrics)

        # Try to determine module qualified name from file path
        try:
            self.namespace = b_utils.get_module_qualname_from_path(fname)
        except b_utils.InvalidModulePath:
            LOG.warning("Unable to find qualified name for module: %s", self.fname)
            self.namespace = ""
        LOG.debug("Module qualified name: %s", self.namespace)
        self.metrics = metrics

    def visit_ClassDef(self, node):
        """
        Visitor for AST ClassDef nodes.
        
        Updates the namespace to include the class name, enabling
        qualified name tracking for nested classes.
        
        Args:
            node: AST ClassDef node
        """
        self.namespace = b_utils.namespace_path_join(self.namespace, node.name)

    def visit_FunctionDef(self, node):
        """
        Visitor for AST FunctionDef nodes.
        
        Updates context with function information and runs function-level
        security tests. Updates namespace to include function name.
        
        Args:
            node: AST FunctionDef node
        """
        self.context["function"] = node
        qualname = f"{self.namespace}.{b_utils.get_func_name(node)}"
        name = qualname.split(".")[-1]
        self.context.update({"qualname": qualname, "name": name})
        self.namespace = b_utils.namespace_path_join(self.namespace, name)
        self.update_scores(self.tester.run_tests(self.context, "FunctionDef"))

    def visit_Call(self, node):
        """
        Visitor for AST Call nodes.
        
        Extracts call information (function name, qualified name) and
        runs call-level security tests. This is where most security
        checks happen (dangerous function calls, etc.).
        
        Args:
            node: AST Call node
        """
        self.context["call"] = node
        qualname = b_utils.get_call_name(node, self.import_aliases)
        name = qualname.split(".")[-1]
        self.context.update({"qualname": qualname, "name": name})
        self.update_scores(self.tester.run_tests(self.context, "Call"))

    def visit_Import(self, node):
        """
        Visitor for AST Import nodes.
        
        Tracks imported modules and their aliases, then runs import-level
        security tests (e.g., checking for dangerous module imports).
        
        Args:
            node: AST Import node
        """
        for nodename in node.names:
            if nodename.asname:
                self.import_aliases[nodename.asname] = nodename.name
            self.imports.add(nodename.name)
            self.context["module"] = nodename.name
        self.update_scores(self.tester.run_tests(self.context, "Import"))

    def visit_ImportFrom(self, node):
        """
        Visitor for AST ImportFrom nodes.
        
        Tracks imports from specific modules, handling both regular imports
        and relative imports (when module is None). Runs import-level tests.
        
        Args:
            node: AST ImportFrom node
        """
        if node.module is None:
            # Relative import - treat as regular import
            return self.visit_Import(node)

        for nodename in node.names:
            full_name = f"{node.module}.{nodename.name}"
            self.import_aliases[nodename.asname or nodename.name] = full_name
            self.imports.add(full_name)
            self.context.update({"module": node.module, "name": nodename.name})
        self.update_scores(self.tester.run_tests(self.context, "ImportFrom"))

    def visit_Constant(self, node):
        """
        Visitor for AST Constant nodes (Python 3.8+).
        
        In Python 3.8+, several literal node types (Str, Bytes, Num, etc.)
        were folded into ast.Constant. This method dispatches to the
        appropriate visitor based on the value type.
        
        Args:
            node: AST Constant node
        """
        if isinstance(node.value, str):
            # `ast.Str` was folded into `ast.Constant` in Python 3.8+.
            # Keep running the `Str` checks, but tolerate `ast.Constant`.
            self.visit_Str(node)
        elif isinstance(node.value, bytes):
            # `ast.Bytes` was folded into `ast.Constant` in Python 3.8+.
            self.visit_Bytes(node)

    def visit_Str(self, node):
        """
        Visitor for AST String nodes.
        
        Extracts string value and runs string-level security tests
        (e.g., hardcoded passwords, SQL injection patterns). Skips
        docstrings (which are Expr nodes).
        
        Args:
            node: AST Str or Constant node with string value
        """
        # `ast.Str` has `.s`; `ast.Constant` stores strings in `.value`.
        self.context["str"] = node.s if hasattr(node, "s") else node.value
        if not isinstance(node._bandit_parent, ast.Expr):  # docstring
            self.context["linerange"] = b_utils.linerange(node._bandit_parent)
            self.update_scores(self.tester.run_tests(self.context, "Str"))

    def visit_Bytes(self, node):
        """
        Visitor for AST Bytes nodes.
        
        Extracts bytes value and runs bytes-level security tests.
        Skips docstrings.
        
        Args:
            node: AST Bytes or Constant node with bytes value
        """
        # `ast.Bytes` has `.s`; `ast.Constant` stores bytes in `.value`.
        self.context["bytes"] = node.s if hasattr(node, "s") else node.value
        if not isinstance(node._bandit_parent, ast.Expr):  # docstring
            self.context["linerange"] = b_utils.linerange(node._bandit_parent)
            self.update_scores(self.tester.run_tests(self.context, "Bytes"))

    def pre_visit(self, node):
        """
        Pre-visit setup for a node.
        
        Builds the context dictionary with information about the current node,
        including location information, imports, and file data. This context
        is passed to security tests.
        
        Args:
            node: AST node being visited
            
        Returns:
            True (always continues traversal)
        """
        self.context = {
            "imports": self.imports, "import_aliases": self.import_aliases,
            "node": node, "linerange": b_utils.linerange(node),
            "filename": self.fname, "file_data": self.fdata
        }
        
        # Add location information if available
        if hasattr(node, "lineno"):
            self.context["lineno"] = node.lineno
        if hasattr(node, "col_offset"):
            self.context["col_offset"] = node.col_offset
        if hasattr(node, "end_col_offset"):
            self.context["end_col_offset"] = node.end_col_offset

        if self.debug:
            LOG.debug(ast.dump(node))
        LOG.debug("entering: %s %s [%s]", hex(id(node)), type(node), self.depth)
        self.depth += 1
        LOG.debug(self.context)
        return True

    def visit(self, node):
        """
        Visit a node and run appropriate security tests.
        
        Looks for a node-specific visitor method (e.g., visit_Call for Call nodes).
        If found, calls it. Otherwise, runs generic tests for that node type.
        
        Args:
            node: AST node to visit
        """
        method = f"visit_{node.__class__.__name__}"
        visitor = getattr(self, method, None)
        if visitor:
            if self.debug:
                LOG.debug("%s called (%s)", method, ast.dump(node))
            visitor(node)
        else:
            # No specific visitor, run generic tests for this node type
            self.update_scores(self.tester.run_tests(self.context, node.__class__.__name__))

    def post_visit(self, node):
        """
        Post-visit cleanup for a node.
        
        Restores namespace when exiting function or class definitions,
        maintaining proper scope tracking.
        
        Args:
            node: AST node being exited
        """
        self.depth -= 1
        LOG.debug("%s\texiting : %s", self.depth, hex(id(node)))
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            # Restore parent namespace when exiting function/class
            self.namespace = b_utils.namespace_path_split(self.namespace)[0]

    def generic_visit(self, node):
        """
        Generic visitor that traverses all child nodes.
        
        This is the main traversal driver. It iterates over all fields of
        the node, and for each AST child node:
        1. Sets parent/sibling references (for context)
        2. Calls pre_visit to set up context
        3. Calls visit to run security tests
        4. Recursively visits children
        5. Calls post_visit to clean up
        
        The parent/sibling references are used by some security tests to
        understand the context in which a node appears.
        
        Args:
            node: AST node to traverse
        """
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                # Handle list of child nodes
                for idx, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        # Set parent and sibling references for context
                        item._bandit_sibling = value[idx + 1] if idx < len(value) - 1 else None
                        item._bandit_parent = node
                        if self.pre_visit(item):
                            self.visit(item)
                            self.generic_visit(item)
                            self.post_visit(item)
            elif isinstance(value, ast.AST):
                # Handle single child node
                value._bandit_sibling = None
                value._bandit_parent = node
                if self.pre_visit(value):
                    self.visit(value)
                    self.generic_visit(value)
                    self.post_visit(value)

    def update_scores(self, scores):
        """
        Update aggregate scores from test results.
        
        Accumulates severity and confidence scores from security tests.
        Scores are arrays indexed by ranking level (UNDEFINED, LOW, MEDIUM, HIGH).
        
        Args:
            scores: Dictionary with "SEVERITY" and "CONFIDENCE" arrays
        """
        if scores:
            for score_type in self.scores:
                self.scores[score_type] = list(map(operator.add, self.scores[score_type], scores[score_type]))

    def process(self, data):
        """
        Main processing loop - parse and analyze code.
        
        Parses the source code into an AST and traverses it to find
        security issues. After traversal, runs file-level tests.
        
        Args:
            data: Source code string to analyze
            
        Returns:
            Dictionary with "SEVERITY" and "CONFIDENCE" score arrays
        """
        f_ast = ast.parse(data)
        self.generic_visit(f_ast)
        # Run file-level tests after traversal
        self.context = {"file_data": self.fdata, "filename": self.fname, "lineno": 0, "linerange": [0, 1], "col_offset": 0}
        self.update_scores(self.tester.run_tests(self.context, "File"))
        return self.scores
