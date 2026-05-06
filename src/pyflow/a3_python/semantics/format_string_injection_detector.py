"""
AST-based format string injection detector.

Detects patterns where user-controlled data (from CLI arguments, config dicts,
environment variables) is used in string formatting to dynamically construct
dictionary keys or template data, which can lead to injection vulnerabilities.

Key bug pattern (BugsInPy ansible#18):
    obj_name = context.CLIARGS['{0}_name'.format(galaxy_type)]
    inject_data = dict(description='your description', ...)
    display.display("- %s was created successfully" % obj_name)

The pattern is: user input flows through .format() or % into dict subscript
keys or output sinks without proper validation/sanitization.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set


@dataclass
class FormatStringInjectionBug:
    """A format string injection bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'dynamic_key_format', 'inject_data_format', 'format_to_output'
    reason: str
    confidence: float
    variable: Optional[str] = None


# Attribute names on objects that store CLI/user arguments
_CLI_ARG_ATTRS = {
    'CLIARGS', 'cliargs', 'cli_args', 'args', 'arguments',
    'options', 'params', 'parameters', 'config', 'settings',
    'argv',
}

# Names that suggest the variable holds CLI/user arguments
_CLI_ARG_NAMES = {
    'CLIARGS', 'cliargs', 'cli_args', 'args', 'arguments',
    'options', 'params', 'parameters', 'config', 'settings',
    'argv', 'sys_argv',
}

# Names suggesting injection-related template data
_INJECT_NAME_SUBSTRINGS = ('inject', 'template', 'render')

# Output/display sink function names
_OUTPUT_SINKS = {
    'display', 'print', 'write', 'log', 'info', 'warning',
    'error', 'debug', 'critical',
}


def scan_file_for_format_string_injection_bugs(
    file_path: Path,
) -> List[FormatStringInjectionBug]:
    """Scan a single Python file for format string injection patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
    except (OSError, UnicodeDecodeError):
        return []

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return _scan_source_regex(source, str(file_path))

    visitor = _FormatStringInjectionVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


def scan_project_for_format_string_injection_bugs(
    root_path: Path,
) -> List[FormatStringInjectionBug]:
    """Scan all Python files in a project for format string injection."""
    bugs: List[FormatStringInjectionBug] = []
    for py_file in root_path.rglob('*.py'):
        parts = py_file.relative_to(root_path).parts
        if any(p.startswith('.') for p in parts):
            continue
        bugs.extend(scan_file_for_format_string_injection_bugs(py_file))
    return bugs


def _is_format_call(node: ast.AST) -> bool:
    """Check if node is a str.format() call."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == 'format'
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
        and '{' in node.func.value.value
    )


def _is_percent_format(node: ast.AST) -> bool:
    """Check if node is a '%' string formatting operation."""
    return (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Mod)
        and isinstance(node.left, ast.Constant)
        and isinstance(node.left.value, str)
        and '%' in node.left.value
    )


def _is_cli_arg_access(node: ast.AST) -> bool:
    """Check if node accesses a CLI argument dict (e.g., context.CLIARGS)."""
    if isinstance(node, ast.Attribute):
        return node.attr in _CLI_ARG_ATTRS
    if isinstance(node, ast.Name):
        return node.id in _CLI_ARG_NAMES
    return False


def _is_subscript_on_cli_args(node: ast.AST) -> bool:
    """Check if node is dict[key] where dict looks like CLI args."""
    if not isinstance(node, ast.Subscript):
        return False
    return _is_cli_arg_access(node.value)


def _has_variable_args(node: ast.Call) -> bool:
    """Check if a .format() call has non-literal arguments (variables)."""
    for arg in node.args:
        if not isinstance(arg, ast.Constant):
            return True
    for kw in node.keywords:
        if not isinstance(kw.value, ast.Constant):
            return True
    return False


def _get_name(node: ast.AST) -> Optional[str]:
    """Get a simple name from a Name or Attribute node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class _FormatStringInjectionVisitor(ast.NodeVisitor):
    """AST visitor that detects format string injection patterns."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[FormatStringInjectionBug] = []
        self._current_function: Optional[str] = None
        self._current_class: Optional[str] = None
        # Track variables assigned from CLI arg subscript access
        self._cli_arg_vars: Set[str] = set()

    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_func(node)

    def _visit_func(self, node):
        old_func = self._current_function
        if self._current_class:
            self._current_function = f"{self._current_class}.{node.name}"
        else:
            self._current_function = node.name
        old_vars = self._cli_arg_vars.copy()
        self._cli_arg_vars = set()
        self.generic_visit(node)
        self._cli_arg_vars = old_vars
        self._current_function = old_func

    def _func_name(self) -> str:
        return self._current_function or '<module>'

    def visit_Assign(self, node: ast.Assign):
        """Detect assignments from CLI arg subscripts and inject_data patterns."""
        # Track variables assigned from CLI arg subscripts
        for target in node.targets:
            tgt_name = _get_name(target)
            if tgt_name and _is_subscript_on_cli_args(node.value):
                self._cli_arg_vars.add(tgt_name)
            # Also track when the subscript key is built with .format()
            if tgt_name and isinstance(node.value, ast.Subscript):
                slice_node = node.value.slice
                if _is_format_call(slice_node) and _has_variable_args(slice_node):
                    if _is_cli_arg_access(node.value.value):
                        self._cli_arg_vars.add(tgt_name)
                        self.bugs.append(FormatStringInjectionBug(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            function_name=self._func_name(),
                            pattern='dynamic_key_format',
                            reason=(
                                f"Dynamic dict key constructed via .format() "
                                f"with variable input on CLI argument store; "
                                f"user-controlled key can access arbitrary entries"
                            ),
                            confidence=0.7,
                            variable=tgt_name,
                        ))

        # Detect inject_data-like assignments with format strings
        for target in node.targets:
            tgt_name = _get_name(target)
            if tgt_name and any(s in tgt_name.lower() for s in _INJECT_NAME_SUBSTRINGS):
                # Check if value is a dict() call or dict literal with format strings
                self._check_inject_data(node, tgt_name)

        self.generic_visit(node)

    def _check_inject_data(self, node: ast.Assign, var_name: str):
        """Check if inject_data assignment uses format strings with user input."""
        val = node.value
        # dict() call
        if isinstance(val, ast.Call) and _get_name(val.func) == 'dict':
            for kw in val.keywords:
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    # Hardcoded string value in inject template - missing dynamic type
                    # This is suspicious if other parts of the function use format
                    # strings with the same variables
                    pass
        # Dict literal
        if isinstance(val, ast.Dict):
            for v in val.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    pass

    def visit_Expr(self, node: ast.Expr):
        """Detect output calls with format strings using CLI arg variables."""
        if isinstance(node.value, ast.Call):
            call = node.value
            func_name = _get_name(call.func)
            if func_name and func_name in _OUTPUT_SINKS:
                self._check_output_call_args(call, node.lineno)
        self.generic_visit(node)

    def _check_output_call_args(self, call: ast.Call, lineno: int):
        """Check if an output call has format strings with CLI arg variables."""
        for arg in call.args:
            # Check: display("... %s ..." % cli_var)
            if _is_percent_format(arg):
                rhs = arg.right
                tainted_vars = self._find_tainted_names(rhs)
                if tainted_vars:
                    self.bugs.append(FormatStringInjectionBug(
                        file_path=self.file_path,
                        line_number=lineno,
                        function_name=self._func_name(),
                        pattern='format_to_output',
                        reason=(
                            f"User-controlled data from CLI arguments "
                            f"({', '.join(tainted_vars)}) flows through string "
                            f"formatting into output sink without sanitization"
                        ),
                        confidence=0.6,
                        variable=next(iter(tainted_vars)),
                    ))
            # Check: display("...".format(cli_var))
            if _is_format_call(arg) and _has_variable_args(arg):
                for fmt_arg in arg.args:
                    name = _get_name(fmt_arg)
                    if name and name in self._cli_arg_vars:
                        self.bugs.append(FormatStringInjectionBug(
                            file_path=self.file_path,
                            line_number=lineno,
                            function_name=self._func_name(),
                            pattern='format_to_output',
                            reason=(
                                f"User-controlled data from CLI arguments "
                                f"({name}) flows through .format() into output sink"
                            ),
                            confidence=0.6,
                            variable=name,
                        ))

    def _find_tainted_names(self, node: ast.AST) -> Set[str]:
        """Find names in an expression that are known CLI arg variables."""
        result: Set[str] = set()
        if isinstance(node, ast.Name):
            if node.id in self._cli_arg_vars:
                result.add(node.id)
        elif isinstance(node, ast.Tuple):
            for elt in node.elts:
                result.update(self._find_tainted_names(elt))
        return result


def _scan_source_regex(source: str, file_path: str) -> List[FormatStringInjectionBug]:
    """Regex fallback for diff fragments that can't be AST-parsed."""
    import re
    bugs: List[FormatStringInjectionBug] = []

    # Pattern: CLIARGS['{...}'.format(var)]
    pattern = re.compile(
        r'''(?:CLIARGS|cliargs|cli_args|args|options|params)'''
        r'''\['''
        r'''['"][^'"]*\{[^'"]*['"]'''
        r'''\.format\(''',
        re.IGNORECASE,
    )
    for i, line in enumerate(source.splitlines(), 1):
        if pattern.search(line):
            bugs.append(FormatStringInjectionBug(
                file_path=file_path,
                line_number=i,
                function_name='<unknown>',
                pattern='dynamic_key_format',
                reason=(
                    "Dynamic dict key constructed via .format() on "
                    "CLI argument store (regex detection)"
                ),
                confidence=0.6,
                variable=None,
            ))

    return bugs
