# Check for class pollution vulnerabilities (Python variant of prototype pollution)
# https://portswigger.net/daily-swig/prototype-pollution-like-bug-variant-discovered-in-python
import ast

from ..core import issue
from ..core import test_properties as test


def class_pollution_issue(description="", confidence="MEDIUM"):
    """Create a class pollution issue"""
    return issue.Issue(
        severity="HIGH",
        confidence=confidence,
        cwe=issue.Cwe.IMPROPER_INPUT_VALIDATION,
        text=f"Possible class pollution vulnerability: {description}",
    )


# Pattern sets for classification
SAFE_ATTRIBUTES = {
    "id",
    "name",
    "value",
    "data",
    "content",
    "text",
    "title",
    "description",
    "type",
    "kind",
    "status",
    "state",
    "level",
    "priority",
    "category",
    "version",
    "timestamp",
    "created",
    "updated",
    "modified",
    "author",
    "source",
    "target",
    "destination",
    "path",
    "url",
    "uri",
    "key",
    "get",
    "set",
    "add",
    "remove",
    "delete",
    "update",
    "create",
    "find",
    "search",
    "filter",
    "sort",
    "count",
    "length",
    "size",
    "empty",
    "config",
    "settings",
    "options",
    "params",
    "args",
    "kwargs",
    "default",
    "custom",
    "user",
    "system",
    "global",
    "local",
}

DANGEROUS_ATTRIBUTES = {
    "__class__",
    "__dict__",
    "__init__",
    "__new__",
    "__del__",
    "__getattr__",
    "__setattr__",
    "__delattr__",
    "__getattribute__",
    "__bases__",
    "__mro__",
    "__subclasses__",
    "__module__",
    "__name__",
    "__globals__",
    "__builtins__",
    "__code__",
    "__closure__",
    "__func__",
    "__self__",
    "__qualname__",
    "__annotations__",
    "__doc__",
    "__file__",
    "__package__",
    "__spec__",
}

USER_INPUT_INDICATORS = {
    "input",
    "get",
    "post",
    "request",
    "query",
    "params",
    "args",
    "form",
    "data",
    "body",
    "json",
    "xml",
    "yaml",
    "csv",
    "load",
    "parse",
    "decode",
    "deserialize",
    "unmarshal",
    "read",
    "open",
    "file",
    "stream",
    "socket",
    "network",
    "url",
    "path",
    "filename",
    "content",
    "message",
    "payload",
}


def _get_string_value(node):
    """Extract string value from AST node"""
    if isinstance(node, ast.Str):
        return node.s
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    elif isinstance(node, ast.Name):
        return node.id
    return None


def _is_user_input(node):
    """Check if node represents user input"""
    if isinstance(node, ast.Name):
        name = node.id.lower()
        return any(
            indicator in name for indicator in USER_INPUT_INDICATORS
        ) or name in {"request", "req", "params", "args", "kwargs", "data", "form"}
    elif isinstance(node, ast.Call) and hasattr(node.func, "attr"):
        return node.func.attr.lower() in {
            "get",
            "post",
            "input",
            "read",
            "load",
            "parse",
        }
    elif isinstance(node, ast.Attribute) and hasattr(node.value, "id"):
        obj_name = node.value.id.lower()
        return obj_name in {"request", "req", "self"} and node.attr.lower() in {
            "args",
            "form",
            "data",
            "json",
            "values",
            "get",
            "post",
        }
    return False


def _is_dangerous_attr(node):
    """Check if attribute name is dangerous"""
    value = _get_string_value(node)
    return value in DANGEROUS_ATTRIBUTES if value else False


def _is_safe_attr(node):
    """Check if attribute name is safe"""
    value = _get_string_value(node)
    return value in SAFE_ATTRIBUTES if value else False


def _has_user_input_in_string(node):
    """Check if string construction involves user input"""
    if isinstance(node, (ast.Str, ast.Constant)):
        return False
    elif isinstance(node, ast.Name):
        return _is_user_input(node)
    elif isinstance(node, ast.Attribute):
        return _is_user_input(node)
    elif isinstance(node, ast.Call):
        if hasattr(node.func, "attr") and node.func.attr in {
            "format",
            "replace",
            "join",
            "strip",
        }:
            return any(_is_user_input(arg) for arg in node.args)
        return _is_user_input(node)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _has_user_input_in_string(node.left) or _has_user_input_in_string(
            node.right
        )
    elif isinstance(node, ast.Mod):
        return _has_user_input_in_string(node.left) or any(
            _is_user_input(arg)
            for arg in (
                node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
            )
        )
    return False


def _has_validation(context):
    """Check for validation patterns in context"""
    if not hasattr(context, "node") or not context.node:
        return False
    parent = getattr(context.node, "_bandit_parent", None)
    if isinstance(parent, ast.If):
        test = parent.test
        if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name):
            return any(
                pattern in test.left.id.lower()
                for pattern in ["whitelist", "allowed", "valid", "safe"]
            )
        elif isinstance(test, ast.Call) and hasattr(test.func, "attr"):
            return test.func.attr.lower() in {
                "validate",
                "sanitize",
                "escape",
                "clean",
                "check",
                "verify",
            }
    return False


def _get_node_description(node):
    """Get human-readable description of node"""
    value = _get_string_value(node)
    if value:
        return f"'{value}'"
    elif isinstance(node, ast.Call):
        return "function call result"
    elif isinstance(node, ast.BinOp):
        return "string concatenation"
    else:
        return "expression"


@test.checks("Call")
@test.with_id("B701")
def setattr_with_user_input(context):
    """Check for setattr() calls that might use user input for attribute names"""
    if context.call_function_name_qual == "setattr" and len(context.node.args) >= 2:
        attr_arg = context.node.args[1]

        if _has_validation(context) or _is_safe_attr(attr_arg):
            return None

        if _is_dangerous_attr(attr_arg):
            return class_pollution_issue(
                f"setattr() called with dangerous attribute name: {_get_node_description(attr_arg)}",
                confidence="HIGH",
            )

        if _has_user_input_in_string(attr_arg):
            return class_pollution_issue(
                f"setattr() called with user-controlled attribute name: {_get_node_description(attr_arg)}",
                confidence="HIGH",
            )

        if isinstance(attr_arg, ast.Name):
            return class_pollution_issue(
                f"setattr() called with variable attribute name '{attr_arg.id}' - ensure proper validation",
                confidence="MEDIUM",
            )


@test.checks("Call")
@test.with_id("B702")
def unsafe_object_merge(context):
    """Check for unsafe object merging patterns that could lead to class pollution"""
    if (
        context.call_function_name_qual in ["dict.update", "object.__setattr__"]
        and context.node.args
    ):
        merge_arg = context.node.args[0]

        if _has_validation(context):
            return None

        if _is_user_input(merge_arg):
            return class_pollution_issue(
                f"Unsafe object merge using {context.call_function_name_qual} with user input - high class pollution risk",
                confidence="HIGH",
            )

        if isinstance(merge_arg, ast.Name):
            return class_pollution_issue(
                f"Object merge using {context.call_function_name_qual} with variable data '{merge_arg.id}' - ensure proper validation",
                confidence="MEDIUM",
            )


@test.checks("Call")
@test.with_id("B703")
def dynamic_attribute_assignment(context):
    """Check for dynamic attribute assignment patterns"""
    if (
        context.call_function_name_qual == "dict.update"
        and isinstance(context.node.func, ast.Attribute)
        and isinstance(context.node.func.value, ast.Attribute)
        and context.node.func.value.attr == "__dict__"
        and context.node.args
    ):

        merge_arg = context.node.args[0]

        if _has_validation(context):
            return None

        if _is_user_input(merge_arg):
            return class_pollution_issue(
                "Direct __dict__ manipulation with user input - high class pollution risk",
                confidence="HIGH",
            )
        else:
            return class_pollution_issue(
                "Direct __dict__ manipulation - ensure proper validation of merge data",
                confidence="MEDIUM",
            )


@test.checks("Assign")
@test.with_id("B704")
def unsafe_dict_assignment(context):
    """Check for unsafe dictionary assignments that might affect object attributes"""
    node = context.node

    if isinstance(node.value, (ast.Name, ast.Dict, ast.Call)):
        for target in node.targets:
            if isinstance(target, ast.Attribute) and target.attr == "__dict__":
                if _has_validation(context):
                    return None

                if _is_user_input(node.value):
                    return class_pollution_issue(
                        "Direct __dict__ assignment with user input - high class pollution risk",
                        confidence="HIGH",
                    )
                else:
                    return class_pollution_issue(
                        "Direct __dict__ assignment - ensure proper validation",
                        confidence="MEDIUM",
                    )

            elif (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Attribute)
                and target.value.attr == "__dict__"
                and isinstance(target.slice, ast.Index)
            ):

                key_node = target.slice.value
                if _has_user_input_in_string(key_node):
                    return class_pollution_issue(
                        f"Dynamic __dict__ key assignment with user-controlled key: {_get_node_description(key_node)}",
                        confidence="HIGH",
                    )
                elif _is_dangerous_attr(key_node):
                    return class_pollution_issue(
                        f"Dynamic __dict__ assignment with dangerous key: {_get_node_description(key_node)}",
                        confidence="HIGH",
                    )
                elif isinstance(key_node, ast.Name):
                    return class_pollution_issue(
                        f"Dynamic __dict__ key assignment with variable key '{key_node.id}' - ensure validation",
                        confidence="MEDIUM",
                    )


@test.checks("Call")
@test.with_id("B705")
def getattr_setattr_patterns(context):
    """Check for getattr/setattr patterns that might be exploitable"""
    if context.call_function_name_qual == "getattr" and len(context.node.args) >= 2:
        attr_arg = context.node.args[1]

        if _has_validation(context) or _is_safe_attr(attr_arg):
            return None

        if _is_dangerous_attr(attr_arg):
            return class_pollution_issue(
                f"getattr() called with dangerous attribute name: {_get_node_description(attr_arg)}",
                confidence="HIGH",
            )

        if _has_user_input_in_string(attr_arg):
            return class_pollution_issue(
                f"getattr() called with user-controlled attribute name: {_get_node_description(attr_arg)}",
                confidence="HIGH",
            )

        if isinstance(attr_arg, ast.Name):
            return class_pollution_issue(
                f"getattr() called with variable attribute name '{attr_arg.id}' - review for safety",
                confidence="LOW",
            )


@test.checks("Call")
@test.with_id("B706")
def vars_globals_locals_usage(context):
    """Check for usage of vars(), globals(), or locals() with user input"""
    func_name = context.call_function_name_qual

    if func_name in ["vars", "globals", "locals"]:
        # Check for patterns like: vars().update(user_input)
        parent = getattr(context.node, "_bandit_parent", None)
        if (
            parent
            and isinstance(parent, ast.Call)
            and hasattr(parent.func, "attr")
            and parent.func.attr == "update"
            and parent.args
            and _is_user_input(parent.args[0])
        ):
            return class_pollution_issue(
                f"Usage of {func_name}().update() with user input - high namespace pollution risk",
                confidence="HIGH",
            )
        elif (
            parent
            and isinstance(parent, ast.Call)
            and hasattr(parent.func, "attr")
            and parent.func.attr == "update"
        ):
            return class_pollution_issue(
                f"Usage of {func_name}().update() - ensure proper validation of update data",
                confidence="MEDIUM",
            )
        else:
            return class_pollution_issue(
                f"Usage of {func_name}() - may expose namespace to manipulation if result is modified",
                confidence="LOW",
            )
