"""
AST-based missing HTTP session configuration propagation detector.

Detects patterns where a function creates an HTTP session/client object
and uses it to make requests, but fails to propagate critical configuration
attributes (like max_redirects, timeout) from a configuration parameter.

Key bug pattern (BugsInPy httpie#2):
    def get_response(args, config_dir):
        requests_session = get_requests_session()
        # BUG: never sets requests_session.max_redirects = args.max_redirects
        # The session uses default max_redirects=30 instead of user's setting

    # In caller (core.py):
    try:
        response = get_response(args, config_dir)
    except requests.TooManyRedirects:
        error('Too many redirects (--max-redirects=%s).', args.max_redirects)

Fix pattern:
    def get_response(args, config_dir):
        requests_session = get_requests_session()
        requests_session.max_redirects = args.max_redirects  # propagate config
        ...

The detector flags functions that:
1. Take a config-like parameter (args, config, options, settings, params)
2. Create a session/client object via factory call or constructor
3. Access multiple attributes of the config parameter (confirming it's a config object)
4. Do NOT propagate session-related config attributes to the session object
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Dict


# Config-like parameter names
_CONFIG_PARAM_NAMES = {
    'args', 'config', 'options', 'settings', 'params', 'opts',
    'arguments', 'cfg', 'conf',
}

# Substrings in function/variable names indicating session/client objects
_SESSION_INDICATORS = {'session', 'client', 'connection', 'conn'}

# Factory function name patterns that create session objects
_SESSION_FACTORY_PATTERNS = {'session', 'client', 'connection'}

# Critical HTTP session configuration attributes that should be propagated.
# max_redirects is the most common source of assertion-like failures: when
# not set, the session uses the library default and TooManyRedirects fires
# at the wrong threshold.
_CRITICAL_SESSION_ATTRS = {
    'max_redirects',
}

# Minimum number of config param attribute accesses to confirm it's a config object
_MIN_CONFIG_ATTRS = 2


@dataclass
class MissingSessionConfigBug:
    """A missing session configuration propagation bug."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'missing_session_config'
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_missing_session_config_bugs(
    file_path: Path,
) -> List[MissingSessionConfigBug]:
    """Scan a Python file for missing HTTP session configuration propagation."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _MissingSessionConfigVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


class _MissingSessionConfigVisitor(ast.NodeVisitor):
    """AST visitor detecting missing session configuration propagation."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[MissingSessionConfigBug] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check_function(self, node: ast.FunctionDef) -> None:
        """Check a function for missing session config propagation."""
        # Step 1: Find config-like parameters
        config_params = self._find_config_params(node)
        if not config_params:
            return

        # Step 2: Find session-like variable assignments
        session_vars = self._find_session_vars(node)
        if not session_vars:
            return

        # Step 3: Collect attribute accesses on config params
        config_attrs_accessed: Dict[str, Set[str]] = {}
        for param_name in config_params:
            attrs = self._collect_attribute_accesses(node, param_name)
            if len(attrs) >= _MIN_CONFIG_ATTRS:
                config_attrs_accessed[param_name] = attrs

        if not config_attrs_accessed:
            return

        # Step 4: Check if session vars have critical attrs set
        for session_var, session_line in session_vars:
            attrs_set_on_session = self._collect_attribute_assignments(
                node, session_var
            )

            # Step 5: Check for missing critical config propagation
            for config_param, config_attrs in config_attrs_accessed.items():
                missing = _CRITICAL_SESSION_ATTRS - attrs_set_on_session
                if not missing:
                    continue

                # Only flag if the session is actually used (has method calls)
                if not self._is_var_used_for_calls(node, session_var):
                    continue

                for attr in missing:
                    self.bugs.append(MissingSessionConfigBug(
                        file_path=self.file_path,
                        line_number=session_line,
                        function_name=node.name,
                        pattern='missing_session_config',
                        reason=(
                            f"Session object '{session_var}' created but "
                            f"'{attr}' not set from config parameter "
                            f"'{config_param}'; requests may use "
                            f"incorrect default {attr}"
                        ),
                        confidence=0.55,
                        variable=session_var,
                    ))

    def _find_config_params(self, node: ast.FunctionDef) -> Set[str]:
        """Find parameter names that look like config/args objects."""
        params = set()
        for arg in node.args.args:
            name = arg.arg
            if name in _CONFIG_PARAM_NAMES:
                params.add(name)
        return params

    def _find_session_vars(self, node: ast.FunctionDef) -> List[tuple]:
        """Find local variables assigned from session-creating calls.

        Returns list of (var_name, line_number).
        """
        results = []
        for child in ast.walk(node):
            if not isinstance(child, ast.Assign):
                continue
            if len(child.targets) != 1:
                continue
            target = child.targets[0]
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id

            # Check if variable name suggests a session
            var_lower = var_name.lower()
            var_is_session = any(
                ind in var_lower for ind in _SESSION_INDICATORS
            )

            # Check if the RHS is a call to a session-creating function
            call_is_session = False
            if isinstance(child.value, ast.Call):
                call_name = self._get_call_name(child.value)
                if call_name:
                    call_lower = call_name.lower()
                    call_is_session = any(
                        ind in call_lower for ind in _SESSION_FACTORY_PATTERNS
                    )

            if var_is_session or call_is_session:
                results.append((var_name, child.lineno))
        return results

    def _get_call_name(self, call_node: ast.Call) -> Optional[str]:
        """Extract the function name from a Call node."""
        func = call_node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    def _collect_attribute_accesses(
        self, node: ast.FunctionDef, var_name: str
    ) -> Set[str]:
        """Collect all attribute names accessed on a variable."""
        attrs = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                if isinstance(child.value, ast.Name) and child.value.id == var_name:
                    attrs.add(child.attr)
        return attrs

    def _collect_attribute_assignments(
        self, node: ast.FunctionDef, var_name: str
    ) -> Set[str]:
        """Collect all attribute names assigned on a variable (var.attr = ...)."""
        attrs = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if (isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == var_name):
                        attrs.add(target.attr)
            elif isinstance(child, ast.AugAssign):
                target = child.target
                if (isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == var_name):
                    attrs.add(target.attr)
        return attrs

    def _is_var_used_for_calls(
        self, node: ast.FunctionDef, var_name: str
    ) -> bool:
        """Check if a variable is used to make method calls (var.method(...))."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func = child.func
                if (isinstance(func, ast.Attribute)
                        and isinstance(func.value, ast.Name)
                        and func.value.id == var_name):
                    return True
                # Also check if passed as argument to another call
                for arg in child.args:
                    if isinstance(arg, ast.Name) and arg.id == var_name:
                        return True
        return False
