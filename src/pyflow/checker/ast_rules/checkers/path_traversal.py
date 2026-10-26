# Check for path traversal vulnerabilities
import ast

from ...common import issue
from ..core import test_properties as test


def path_traversal_issue():
    """Create a path traversal issue"""
    return issue.Issue(
        severity="MEDIUM",
        confidence="HIGH",
        cwe=issue.Cwe.PATH_TRAVERSAL,
        text="Possible path traversal via untrusted input in file operation.",
    )


def _is_dynamic_path(node):
    """Check if a node represents a dynamic path (contains variables)"""
    if node is None or isinstance(node, (ast.Constant, ast.Str)):
        return False
    if isinstance(node, ast.JoinedStr):
        # f-string with potential path construction: only dynamic if it contains expressions
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        # String concatenation or % formatting: only dynamic if at least one side is dynamic
        return _is_dynamic_path(node.left) or _is_dynamic_path(node.right)
    if isinstance(node, ast.Call):
        name = ast.unparse(node.func)
        if name in {"input", "builtins.input"} or name.startswith(
            ("request.args.", "request.form.", "request.GET.", "request.POST.")
        ):
            return True
        # A computed path is not evidence of untrusted input. Preserve
        # evidence nested in construction calls without guessing their returns.
        return any(_is_dynamic_path(arg) for arg in node.args)
    return False


@test.checks("Call")
@test.with_id("B9008")
def open_file_with_user_input(context):
    """Check for open() with user-controlled path"""
    if context.call_function_name in ["open", "io.open"]:
        # Get raw call node to access AST
        call_node = context.node
        if call_node and hasattr(call_node, "args") and call_node.args:
            filepath_node = call_node.args[0]
            if _is_dynamic_path(filepath_node):
                return path_traversal_issue()


@test.checks("Call")
@test.with_id("B9009")
def pathlib_path_with_user_input(context):
    """Check for pathlib.Path operations with user-controlled path"""
    if context.call_function_name_qual:
        qual = context.call_function_name_qual
        # Check for pathlib.Path operations
        if qual.startswith("pathlib.Path.") or qual == "pathlib.Path":
            call_node = context.node
            if call_node and hasattr(call_node, "args") and call_node.args:
                # Path is usually the first argument
                path_node = call_node.args[0]
                if _is_dynamic_path(path_node):
                    return path_traversal_issue()


@test.checks("Call")
@test.with_id("B203")
def os_path_join_with_user_input(context):
    """Check for os.path.join with untrusted path component"""
    if context.call_function_name_qual in ["os.path.join", "os.pathsep.join"]:
        call_node = context.node
        if call_node and hasattr(call_node, "args"):
            # Get path arguments - if any argument contains variables, flag it
            for arg in call_node.args:
                if _is_dynamic_path(arg):
                    return path_traversal_issue()


@test.checks("Call")
@test.with_id("B204")
def os_open_with_user_input(context):
    """Check for os.open() with user-controlled path"""
    if context.call_function_name_qual == "os.open":
        call_node = context.node
        if call_node and hasattr(call_node, "args") and call_node.args:
            filepath_node = call_node.args[0]
            if _is_dynamic_path(filepath_node):
                return path_traversal_issue()


@test.checks("Call")
@test.with_id("B205")
def os_stat_with_user_input(context):
    """Check for os.stat() with untrusted path"""
    stat_funcs = [
        "os.stat",
        "os.lstat",
        "os.path.exists",
        "os.path.isfile",
        "os.path.isdir",
        "os.path.islink",
        "os.access",
    ]
    if context.call_function_name_qual in stat_funcs:
        call_node = context.node
        if call_node and hasattr(call_node, "args") and call_node.args:
            filepath_node = call_node.args[0]
            if _is_dynamic_path(filepath_node):
                return path_traversal_issue()


@test.checks("Call")
@test.with_id("B207")
def send_file_with_user_input(context):
    """Check for Flask's send_file or Django's FileResponse with untrusted path"""
    if context.call_function_name_qual in [
        "flask.send_file",
        "flask.send_from_directory",
    ]:
        call_node = context.node
        if call_node and hasattr(call_node, "args") and call_node.args:
            filepath_node = call_node.args[0]
            if _is_dynamic_path(filepath_node):
                return path_traversal_issue()
