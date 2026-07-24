"""
Enhanced command injection pattern checks.

Test IDs:
- B701: subprocess.run with shell=True and user input
- B702: subprocess.call with shell=True and user input
- B703: subprocess.Popen with shell=True and user input
- B704: os.system with user input
- B705: os.popen with user input
- B706: popen2.Popen with shell=True
- B707: commands.getoutput/getstatusoutput usage
- B708: command string formatting/shlex.join with user input
- B605: start_process_with_a_shell
- B606: start_process_with_no_shell
- B607: start_process_with_partial_path
"""

import ast
import re

from ..core import issue
from ..core import test_properties as test

# Pattern: starts with a drive letter (Windows) or path delimiter (/,\,.)
_FULL_PATH_RE = re.compile(r"^(?:[A-Za-z](?=\:)|[\\\/\.])")

USER_INPUT_MARKERS = (
    "user",
    "input",
    "request",
    "query",
    "param",
    "arg",
    "argv",
    "payload",
    "body",
    "form",
    "data",
    "value",
    "path",
    "filename",
    "command",
    "cmd",
)

COMMAND_SINKS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "os.system",
    "os.popen",
    "popen2.Popen",
    "commands.getoutput",
    "commands.getstatusoutput",
}

# Functions that start a process via a shell (vulnerable to injection).
# Excludes os.system, os.popen, commands.getstatusoutput — already
# covered by B604 in shell_injection.py.
COMMAND_SINKS_SHELL = {
    "os.popen2",
    "os.popen3",
    "os.popen4",
    "popen2.popen2",
    "popen2.popen3",
    "popen2.popen4",
    "popen2.Popen3",
    "popen2.Popen4",
    "commands.getoutput",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
}

# Functions that start a process without a shell (safer but still worth tracking)
COMMAND_SINKS_NO_SHELL = {
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.startfile",
}


def _new_issue(text):
    return issue.Issue(
        severity="HIGH",
        confidence="HIGH",
        cwe=issue.Cwe.COMMAND_INJECTION,
        text=text,
    )


def _first_arg(call_node):
    if call_node and isinstance(call_node, ast.Call) and call_node.args:
        return call_node.args[0]
    return None


def _is_shell_true(context):
    shell_arg = context.get_call_arg_value("shell")
    return shell_arg is True or shell_arg == "True"


def _name_looks_user_controlled(name):
    lowered = (name or "").lower()
    return any(marker in lowered for marker in USER_INPUT_MARKERS)


def _looks_like_user_source_attr(node):
    if isinstance(node, ast.Attribute):
        return _name_looks_user_controlled(node.attr) or _looks_like_user_source_attr(
            node.value
        )
    if isinstance(node, ast.Name):
        return _name_looks_user_controlled(node.id)
    if isinstance(node, ast.Subscript):
        return _looks_like_user_source_attr(node.value) or _is_user_input(node.slice)
    return False


def _is_string_formatting(node):
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_string = isinstance(node.left, (ast.Str, ast.JoinedStr)) or (
            isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)
        )
        right_string = isinstance(node.right, (ast.Str, ast.JoinedStr)) or (
            isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)
        )
        return left_string or right_string
    return False


def _is_shlex_join_with_user_input(node):
    if not isinstance(node, ast.Call):
        return False
    if not (isinstance(node.func, ast.Attribute) and node.func.attr == "join"):
        return False
    base = node.func.value
    if not (isinstance(base, ast.Name) and base.id == "shlex"):
        return False
    if not node.args:
        return False
    return _is_user_input(node.args[0])


def _is_user_controlled_command_path(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"join", "abspath", "normpath"}:
            return any(_is_user_input(arg) for arg in node.args)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_user_input(node.left) or _is_user_input(node.right)
    return False


def _is_user_input(node):
    """Check if a node represents user-controlled input.

    Conservative implementation to reduce false positives.
    Only flags high-confidence user input sources.
    """
    if node is None:
        return False

    # Constants are NEVER user-controlled
    if isinstance(node, (ast.Constant, ast.Str, ast.Num)):
        return False

    # List/Tuple/Dict literals - check contents
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_is_user_input(elt) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return any(_is_user_input(v) for v in node.values) if node.values else False

    if isinstance(node, ast.Name):
        # Only flag HIGH-CONFIDENCE markers
        name = node.id.lower()
        return name in (
            "input",
            "raw_input",
            "request",
            "args",
            "query",
            "form",
            "payload",
        )

    if isinstance(node, ast.Attribute):
        attr = node.attr.lower()
        # High-risk Flask/Django request attributes
        if attr in ("args", "form", "json", "data", "get_data", "post_data", "files"):
            # Check if it's a request attribute
            if isinstance(node.value, ast.Name):
                if node.value.id in ("request", "flask_request"):
                    return True
            elif isinstance(node.value, ast.Attribute):
                base = _attribute_name(node.value)
                if "request" in base.lower():
                    return True
        return False

    if isinstance(node, ast.Subscript):
        return _is_user_input(node.value) or _is_user_input(node.slice)

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in ("input", "raw_input"):
            return True
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in ("get", "getvalue", "get_json", "json"):
                return True
        return any(_is_user_input(arg) for arg in node.args)

    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(v, ast.FormattedValue) and _is_user_input(v.value)
            for v in node.values
        )

    if isinstance(node, ast.BinOp):
        return _is_user_input(node.left) or _is_user_input(node.right)

    return False


def _attribute_name(node):
    """Get dotted attribute name from AST."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _is_dangerous_command_expr(node):
    return (
        _is_user_input(node)
        or _is_string_formatting(node)
        or _is_shlex_join_with_user_input(node)
        or _is_user_controlled_command_path(node)
    )


@test.checks("Call")
@test.with_id("B701")
def subprocess_run_shell_true_user_input(context):
    if context.call_function_name_qual != "subprocess.run":
        return None
    if not _is_shell_true(context):
        return None

    cmd = _first_arg(context.node)
    if _is_dangerous_command_expr(cmd):
        return _new_issue(
            "subprocess.run() with shell=True uses user-controlled command input."
        )
    return None


@test.checks("Call")
@test.with_id("B702")
def subprocess_call_shell_true_user_input(context):
    if context.call_function_name_qual != "subprocess.call":
        return None
    if not _is_shell_true(context):
        return None

    cmd = _first_arg(context.node)
    if _is_dangerous_command_expr(cmd):
        return _new_issue(
            "subprocess.call() with shell=True uses user-controlled command input."
        )
    return None


@test.checks("Call")
@test.with_id("B703")
def subprocess_popen_shell_true_user_input(context):
    if context.call_function_name_qual != "subprocess.Popen":
        return None
    if not _is_shell_true(context):
        return None

    cmd = _first_arg(context.node)
    if _is_dangerous_command_expr(cmd):
        return _new_issue(
            "subprocess.Popen() with shell=True uses user-controlled command input."
        )
    return None


@test.checks("Call")
@test.with_id("B704")
def os_system_user_input(context):
    if context.call_function_name_qual != "os.system":
        return None

    cmd = _first_arg(context.node)
    if _is_dangerous_command_expr(cmd):
        return _new_issue("os.system() executes a user-controlled command string.")
    return None


@test.checks("Call")
@test.with_id("B705")
def os_popen_user_input(context):
    if context.call_function_name_qual != "os.popen":
        return None

    cmd = _first_arg(context.node)
    if _is_dangerous_command_expr(cmd):
        return _new_issue("os.popen() executes a user-controlled command string.")
    return None


@test.checks("Call")
@test.with_id("B706")
def popen2_shell_true(context):
    if context.call_function_name_qual != "popen2.Popen":
        return None

    if _is_shell_true(context) or _is_dangerous_command_expr(_first_arg(context.node)):
        return _new_issue(
            "popen2.Popen() with shell=True or dynamic command may allow command injection."
        )
    return None


@test.checks("Call")
@test.with_id("B707")
def commands_module_usage(context):
    if context.call_function_name_qual in {
        "commands.getoutput",
        "commands.getstatusoutput",
    }:
        return _new_issue(
            "commands module executes shell commands and may allow command injection."
        )
    return None


@test.checks("Call")
@test.with_id("B708")
def command_string_formatting(context):
    call_qual = context.call_function_name_qual
    node = context.node
    cmd = _first_arg(node)

    if call_qual in COMMAND_SINKS and (
        _is_string_formatting(cmd) or _is_shlex_join_with_user_input(cmd)
    ):
        return _new_issue(
            "Command string is built via formatting or shlex.join with user input; this may enable command injection."
        )

    if call_qual == "shlex.join" and node.args and _is_user_input(node.args[0]):
        return _new_issue(
            "shlex.join() is used with user input to construct a shell command."
        )

    return None


@test.checks("Call")
@test.with_id("B605")
def start_process_with_a_shell(context):
    qualname = context.call_function_name_qual
    if qualname not in COMMAND_SINKS_SHELL:
        return None
    if context.call_args_count < 1:
        return None
    cmd = context.node.args[0]
    if isinstance(cmd, ast.Constant) and isinstance(cmd.value, str):
        return issue.Issue(
            severity="LOW",
            confidence="HIGH",
            cwe=issue.Cwe.OS_COMMAND_INJECTION,
            text=f"Starting a process with a shell: {qualname}. "
            "Shell functions invoke a system shell to interpret the "
            "command string and are vulnerable to injection. "
            "Consider using subprocess with a list of arguments instead.",
        )
    return issue.Issue(
        severity="HIGH",
        confidence="HIGH",
        cwe=issue.Cwe.OS_COMMAND_INJECTION,
        text=f"Starting a process with a shell, possible injection "
        f"detected: {qualname}. The command argument is dynamically "
        "constructed and may allow shell injection.",
    )


@test.checks("Call")
@test.with_id("B606")
def start_process_with_no_shell(context):
    qualname = context.call_function_name_qual
    if qualname not in COMMAND_SINKS_NO_SHELL:
        return None
    return issue.Issue(
        severity="LOW",
        confidence="MEDIUM",
        cwe=issue.Cwe.OS_COMMAND_INJECTION,
        text=f"Starting a process without a shell: {qualname}. "
        "This call spawns a process by replacing the current one. "
        "While not vulnerable to shell injection, ensure arguments "
        "are properly validated.",
    )


@test.checks("Call")
@test.with_id("B607")
def start_process_with_partial_path(context):
    qualname = context.call_function_name_qual
    # Only check functions without dedicated path-safety checks
    # (B701-B708, B604 already cover COMMAND_SINKS and most COMMAND_SINKS_SHELL)
    if qualname not in COMMAND_SINKS_NO_SHELL:
        return None
    if context.call_args_count < 1:
        return None
    node = context.node.args[0]
    if isinstance(node, ast.List) and node.elts:
        node = node.elts[0]
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and not _FULL_PATH_RE.match(node.value)
    ):
        return issue.Issue(
            severity="LOW",
            confidence="HIGH",
            cwe=issue.Cwe.OS_COMMAND_INJECTION,
            text=f"Starting a process with a partial executable path: "
            f"'{node.value}'. The PATH environment variable is searched, "
            "which may allow a malicious actor to substitute a different "
            "executable. Use an absolute path to the executable.",
        )
    return None
