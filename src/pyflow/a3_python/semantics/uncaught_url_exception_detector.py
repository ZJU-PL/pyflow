"""
AST-based uncaught URL/network exception detector.

Detects patterns where a URL/network operation (download, urlopen, etc.) is
called inside a branch guarded by urlparse().scheme without restricting the
scheme to known-safe values AND without a try/except for network errors.

Key bug pattern (BugsInPy ansible#13):
    elif urlparse(collection).scheme:            # Too broad: any scheme matches
        b_tar_path = _download_file(collection, ...)  # URLError not caught!

Fix pattern:
    elif urlparse(collection).scheme.lower() in ['http', 'https']:
        try:
            b_tar_path = _download_file(collection, ...)
        except urllib_error.URLError as err:
            raise AnsibleError(...)

The bug occurs because urlparse('my.namespace:1.0.0').scheme returns
'my.namespace' (truthy), so the branch is taken for inputs that are not
actual URLs, and the network call raises an unhandled exception.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set


@dataclass
class UncaughtURLExceptionBug:
    """An uncaught URL/network exception bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'unguarded_url_call', 'broad_scheme_check'
    reason: str
    confidence: float
    variable: Optional[str] = None


# Function names that indicate URL/network I/O likely to raise network errors
_NETWORK_CALL_NAMES = {
    'download', '_download', 'download_file', '_download_file',
    'urlopen', 'urlretrieve', 'fetch', 'fetch_url',
    'request', 'get', 'post', 'put', 'delete', 'head', 'patch',
}

# Substrings in function names that suggest network I/O
_NETWORK_CALL_SUBSTRINGS = ('download', 'urlopen', 'urlretrieve', 'fetch_url')

# Exception types that should catch network errors
_NETWORK_EXCEPTION_NAMES = {
    'URLError', 'HTTPError', 'ConnectionError', 'TimeoutError',
    'IOError', 'OSError', 'socket.error', 'RequestException',
    'Exception',
}

# Function names that join/construct URLs
_URL_JOIN_NAMES = {
    'urljoin', '_urljoin', 'url_join', 'join_url',
}

# Substrings in function names that suggest URL joining
_URL_JOIN_SUBSTRINGS = ('urljoin', 'url_join')


def scan_file_for_uncaught_url_exception_bugs(file_path: Path) -> List[UncaughtURLExceptionBug]:
    """Scan a single Python file for uncaught URL/network exception patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _UncaughtURLExceptionVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


class _UncaughtURLExceptionVisitor(ast.NodeVisitor):
    """AST visitor detecting uncaught URL/network exception patterns."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[UncaughtURLExceptionBug] = []
        self._current_function: Optional[str] = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old = self._current_function
        self._current_function = node.name
        self.generic_visit(node)
        self._current_function = old

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node: ast.If) -> None:
        """Check if-branches guarded by urlparse().scheme."""
        if self._is_broad_scheme_check(node.test):
            # Look for network calls in the body that are NOT inside try/except
            for stmt in node.body:
                self._check_for_unguarded_network_calls(stmt)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """Check try blocks for URL joining in loops with broad exception handlers.

        Detects pattern (BugsInPy ansible#14):
            try:
                ...
                while not done:
                    url = _urljoin(self.api_server, data['next_link'])
                    data = self._call_galaxy(url)
                    ...
            except Exception as e:
                display.vvvv(...)   # silently swallowed

        The bug: api_server may contain a path component (e.g. https://host/api/)
        and next_link from the API response also starts with /api/..., producing
        a malformed URL with a duplicated path prefix.  The exception from the
        resulting 404 is caught and silently discarded.
        """
        if self._catches_broad_exception(node):
            for stmt in ast.walk(node):
                if isinstance(stmt, (ast.While, ast.For)):
                    self._check_loop_for_url_join_without_parse(stmt, node)
        self.generic_visit(node)

    def _is_broad_scheme_check(self, test: ast.expr) -> bool:
        """
        Check if test is a broad urlparse().scheme truthiness test.

        Matches:
            urlparse(x).scheme         (truthy check)
        Does NOT match:
            urlparse(x).scheme.lower() in ['http', 'https']   (restricted)
            urlparse(x).scheme in ['http', 'https']            (restricted)
        """
        # Direct: urlparse(x).scheme (used as boolean)
        if self._is_urlparse_scheme_attr(test):
            return True

        # Also check for `urlparse(x).scheme` inside a Compare but with
        # no restriction to specific schemes -- unlikely pattern, skip

        return False

    def _is_urlparse_scheme_attr(self, node: ast.expr) -> bool:
        """Check if node is urlparse(...).scheme."""
        if not isinstance(node, ast.Attribute):
            return False
        if node.attr != 'scheme':
            return False
        # node.value should be a call to urlparse
        if not isinstance(node.value, ast.Call):
            return False
        func = node.value.func
        if isinstance(func, ast.Name) and func.id == 'urlparse':
            return True
        if isinstance(func, ast.Attribute) and func.attr == 'urlparse':
            return True
        return False

    def _check_for_unguarded_network_calls(self, node: ast.AST) -> None:
        """Find network calls in this subtree that are not inside try/except."""
        if isinstance(node, ast.Try):
            # Check if the except clauses catch network exceptions
            if self._catches_network_exceptions(node):
                return  # Protected by try/except
            # Otherwise check the body for unguarded calls
            for stmt in node.body:
                self._check_for_unguarded_network_calls(stmt)
            return

        # Check if this node itself is a network call
        if isinstance(node, (ast.Expr, ast.Assign, ast.AugAssign, ast.Return)):
            call = self._extract_call(node)
            if call and self._is_network_call(call):
                func_name = self._current_function or '<module>'
                call_name = self._get_call_name(call)
                self.bugs.append(UncaughtURLExceptionBug(
                    file_path=self.file_path,
                    line_number=call.lineno,
                    function_name=func_name,
                    pattern='broad_scheme_download',
                    reason=(
                        f"Call to '{call_name}' in branch guarded by "
                        f"urlparse().scheme truthiness check (without restricting "
                        f"to http/https) has no try/except for network errors. "
                        f"urlparse() parses any colon-delimited string as a URL "
                        f"scheme, so non-URL inputs like 'namespace:version' "
                        f"will reach this branch and the network call will raise "
                        f"an unhandled exception (e.g., URLError)."
                    ),
                    confidence=0.85,
                    variable=call_name,
                ))
                return

        # Recurse into child statements
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                self._check_for_unguarded_network_calls(child)

    def _catches_network_exceptions(self, try_node: ast.Try) -> bool:
        """Check if a try/except catches network-related exceptions."""
        for handler in try_node.handlers:
            if handler.type is None:
                return True  # bare except catches everything
            exc_names = self._get_exception_names(handler.type)
            if exc_names & _NETWORK_EXCEPTION_NAMES:
                return True
        return False

    def _get_exception_names(self, node: ast.expr) -> Set[str]:
        """Extract exception names from an except clause type."""
        names: Set[str] = set()
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Tuple):
            for elt in node.elts:
                names |= self._get_exception_names(elt)
        return names

    def _extract_call(self, node: ast.stmt) -> Optional[ast.Call]:
        """Extract a Call node from a statement."""
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            return node.value
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            return node.value
        if isinstance(node, ast.AugAssign) and isinstance(node.value, ast.Call):
            return node.value
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Call):
            return node.value
        return None

    def _is_network_call(self, call: ast.Call) -> bool:
        """Check if a call is to a network/download function."""
        name = self._get_call_name(call)
        if not name:
            return False
        name_lower = name.lower()
        if name_lower in _NETWORK_CALL_NAMES:
            return True
        for substr in _NETWORK_CALL_SUBSTRINGS:
            if substr in name_lower:
                return True
        return False

    def _get_call_name(self, call: ast.Call) -> Optional[str]:
        """Get the simple name of a function call."""
        func = call.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    # ------------------------------------------------------------------
    # Ansible#14 pattern: URL join in loop inside broad except handler
    # ------------------------------------------------------------------

    def _catches_broad_exception(self, try_node: ast.Try) -> bool:
        """Return True if the try catches bare Exception (or bare except)
        and does NOT re-raise."""
        for handler in try_node.handlers:
            if handler.type is None:
                # bare except
                if not self._handler_reraises(handler):
                    return True
            exc_names = self._get_exception_names(handler.type) if handler.type else set()
            if 'Exception' in exc_names or 'BaseException' in exc_names:
                if not self._handler_reraises(handler):
                    return True
        return False

    @staticmethod
    def _handler_reraises(handler: ast.ExceptHandler) -> bool:
        """Return True if the handler body contains a raise statement."""
        for node in ast.walk(handler):
            if isinstance(node, ast.Raise):
                return True
        return False

    def _check_loop_for_url_join_without_parse(
        self, loop_node: ast.AST, try_node: ast.Try
    ) -> None:
        """Check a loop body for URL join calls whose base arg is not urlparse-derived."""
        for node in ast.walk(loop_node):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_url_join_call(node):
                continue
            # Check if the base URL argument is an unparsed attribute/variable
            if len(node.args) < 2:
                continue
            base_arg = node.args[0]
            if self._is_unparsed_url_base(base_arg, try_node):
                func_name = self._current_function or '<module>'
                call_name = self._get_call_name(node) or 'urljoin'
                self.bugs.append(UncaughtURLExceptionBug(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    function_name=func_name,
                    pattern='url_join_path_duplication',
                    reason=(
                        f"Call to '{call_name}' inside a loop uses a base URL "
                        f"that may contain a path component (e.g. "
                        f"'https://host/api/'). The second argument comes from "
                        f"API response data that may also include the path "
                        f"prefix, producing a malformed URL with duplicated "
                        f"path segments. The resulting HTTP error is silently "
                        f"caught by a broad 'except Exception' handler, causing "
                        f"incomplete/missing results. Fix: use urlparse() to "
                        f"extract scheme+netloc before joining."
                    ),
                    confidence=0.80,
                    variable=call_name,
                ))

    def _is_url_join_call(self, call: ast.Call) -> bool:
        """Return True if *call* is to a URL-joining function."""
        name = self._get_call_name(call)
        if not name:
            return False
        name_lower = name.lower()
        if name_lower in _URL_JOIN_NAMES:
            return True
        for substr in _URL_JOIN_SUBSTRINGS:
            if substr in name_lower:
                return True
        return False

    def _is_unparsed_url_base(self, node: ast.expr, try_node: ast.Try) -> bool:
        """Return True if *node* looks like a URL base that has NOT been
        decomposed with urlparse first.

        Positive: self.api_server, self.url, config['url'], a plain variable
        Negative: a local variable assigned from urlparse(...).scheme/netloc,
                  or a string built from urlparse components.
        """
        # If the base is a string literal, it's fine (developer controls it)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return False
        # If the base is a call to urlparse or built from urlparse, it's fine
        if self._expr_uses_urlparse(node):
            return False
        # Check if the variable was assigned from a urlparse-based expression
        # within the same try block
        if isinstance(node, ast.Name):
            if self._var_assigned_from_urlparse(node.id, try_node):
                return False
        # Otherwise, self.xxx, config['xxx'], plain variables are suspect
        if isinstance(node, ast.Attribute):
            return True
        if isinstance(node, ast.Subscript):
            return True
        if isinstance(node, ast.Name):
            return True
        return False

    @staticmethod
    def _expr_uses_urlparse(node: ast.expr) -> bool:
        """Return True if the expression is derived from a urlparse() call."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func = child.func
                if isinstance(func, ast.Name) and func.id == 'urlparse':
                    return True
                if isinstance(func, ast.Attribute) and func.attr == 'urlparse':
                    return True
        return False

    @staticmethod
    def _var_assigned_from_urlparse(var_name: str, scope: ast.AST) -> bool:
        """Return True if *var_name* is assigned from a urlparse-derived
        expression anywhere in *scope*.  Follows one level of indirection
        (e.g. url_info = urlparse(...); base = f'{url_info.scheme}://...')."""
        # Collect variables directly assigned from urlparse(...)
        urlparse_vars: Set[str] = set()
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign):
                if _UncaughtURLExceptionVisitor._expr_uses_urlparse(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            urlparse_vars.add(target.id)

        # Check if var_name's assignment references urlparse directly
        # or uses a variable that came from urlparse
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == var_name:
                        if _UncaughtURLExceptionVisitor._expr_uses_urlparse(node.value):
                            return True
                        # Check if assignment RHS references any urlparse-derived variable
                        for child in ast.walk(node.value):
                            if isinstance(child, ast.Name) and child.id in urlparse_vars:
                                return True
                            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                                if child.value.id in urlparse_vars:
                                    return True
        return False
