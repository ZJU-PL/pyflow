# AST node visitor for security checking
import ast
import logging
import operator

from . import constants
from . import tester as b_tester
from . import utils as b_utils

LOG = logging.getLogger(__name__)


class SecurityNodeVisitor:
    def __init__(self, fname, fdata, testset, debug, nosec_lines, metrics):
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

        try:
            self.namespace = b_utils.get_module_qualname_from_path(fname)
        except b_utils.InvalidModulePath:
            LOG.warning("Unable to find qualified name for module: %s", self.fname)
            self.namespace = ""
        LOG.debug("Module qualified name: %s", self.namespace)
        self.metrics = metrics

    def visit_ClassDef(self, node):
        """Visitor for AST ClassDef node"""
        self.namespace = b_utils.namespace_path_join(self.namespace, node.name)

    def visit_FunctionDef(self, node):
        """Visitor for AST FunctionDef nodes"""
        self.context["function"] = node
        qualname = f"{self.namespace}.{b_utils.get_func_name(node)}"
        name = qualname.split(".")[-1]
        self.context.update({"qualname": qualname, "name": name})
        self.namespace = b_utils.namespace_path_join(self.namespace, name)
        self.update_scores(self.tester.run_tests(self.context, "FunctionDef"))

    def visit_Call(self, node):
        """Visitor for AST Call nodes"""
        self.context["call"] = node
        qualname = b_utils.get_call_name(node, self.import_aliases)
        name = qualname.split(".")[-1]
        self.context.update({"qualname": qualname, "name": name})
        self.update_scores(self.tester.run_tests(self.context, "Call"))

    def visit_Import(self, node):
        """Visitor for AST Import nodes"""
        for nodename in node.names:
            if nodename.asname:
                self.import_aliases[nodename.asname] = nodename.name
            self.imports.add(nodename.name)
            self.context["module"] = nodename.name
        self.update_scores(self.tester.run_tests(self.context, "Import"))

    def visit_ImportFrom(self, node):
        """Visitor for AST ImportFrom nodes"""
        if node.module is None:
            return self.visit_Import(node)

        for nodename in node.names:
            full_name = f"{node.module}.{nodename.name}"
            self.import_aliases[nodename.asname or nodename.name] = full_name
            self.imports.add(full_name)
            self.context.update({"module": node.module, "name": nodename.name})
        self.update_scores(self.tester.run_tests(self.context, "ImportFrom"))

    def visit_Constant(self, node):
        """Visitor for AST Constant nodes (Python 3.8+)"""
        if isinstance(node.value, str):
            # `ast.Str` was folded into `ast.Constant` in Python 3.8+.
            # Keep running the `Str` checks, but tolerate `ast.Constant`.
            self.visit_Str(node)
        elif isinstance(node.value, bytes):
            # `ast.Bytes` was folded into `ast.Constant` in Python 3.8+.
            self.visit_Bytes(node)

    def visit_Str(self, node):
        """Visitor for AST String nodes"""
        # `ast.Str` has `.s`; `ast.Constant` stores strings in `.value`.
        self.context["str"] = node.s if hasattr(node, "s") else node.value
        if not isinstance(node._bandit_parent, ast.Expr):  # docstring
            self.context["linerange"] = b_utils.linerange(node._bandit_parent)
            self.update_scores(self.tester.run_tests(self.context, "Str"))

    def visit_Bytes(self, node):
        """Visitor for AST Bytes nodes"""
        # `ast.Bytes` has `.s`; `ast.Constant` stores bytes in `.value`.
        self.context["bytes"] = node.s if hasattr(node, "s") else node.value
        if not isinstance(node._bandit_parent, ast.Expr):  # docstring
            self.context["linerange"] = b_utils.linerange(node._bandit_parent)
            self.update_scores(self.tester.run_tests(self.context, "Bytes"))

    def pre_visit(self, node):
        """Pre-visit setup"""
        self.context = {
            "imports": self.imports, "import_aliases": self.import_aliases,
            "node": node, "linerange": b_utils.linerange(node),
            "filename": self.fname, "file_data": self.fdata
        }
        
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
        """Visit a node"""
        method = f"visit_{node.__class__.__name__}"
        visitor = getattr(self, method, None)
        if visitor:
            if self.debug:
                LOG.debug("%s called (%s)", method, ast.dump(node))
            visitor(node)
        else:
            self.update_scores(self.tester.run_tests(self.context, node.__class__.__name__))

    def post_visit(self, node):
        """Post-visit cleanup"""
        self.depth -= 1
        LOG.debug("%s\texiting : %s", self.depth, hex(id(node)))
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            self.namespace = b_utils.namespace_path_split(self.namespace)[0]

    def generic_visit(self, node):
        """Drive the visitor"""
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                for idx, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        item._bandit_sibling = value[idx + 1] if idx < len(value) - 1 else None
                        item._bandit_parent = node
                        if self.pre_visit(item):
                            self.visit(item)
                            self.generic_visit(item)
                            self.post_visit(item)
            elif isinstance(value, ast.AST):
                value._bandit_sibling = None
                value._bandit_parent = node
                if self.pre_visit(value):
                    self.visit(value)
                    self.generic_visit(value)
                    self.post_visit(value)

    def update_scores(self, scores):
        """Update scores from test results"""
        if scores:
            for score_type in self.scores:
                self.scores[score_type] = list(map(operator.add, self.scores[score_type], scores[score_type]))

    def process(self, data):
        """Main process loop - build and process the AST"""
        f_ast = ast.parse(data)
        self.generic_visit(f_ast)
        self.context = {"file_data": self.fdata, "filename": self.fname, "lineno": 0, "linerange": [0, 1], "col_offset": 0}
        self.update_scores(self.tester.run_tests(self.context, "File"))
        return self.scores
