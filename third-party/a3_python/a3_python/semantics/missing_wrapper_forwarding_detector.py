"""
AST-based missing-wrapper-attribute-forwarding detector.

Detects patterns where a wrapper/decorator subclass copies some attributes
from the wrapped object in __init__ but omits critical spec/config attributes,
leaving them as None (the parent default).

Key bug pattern (BugsInPy keras#37):
    class Bidirectional(Wrapper):
        def __init__(self, layer, ...):
            self.forward_layer = copy.copy(layer)
            self.stateful = layer.stateful
            self.return_sequences = layer.return_sequences
            self.return_state = layer.return_state
            ...
            super(Bidirectional, self).__init__(layer, **kwargs)
            # Missing: self.input_spec = layer.input_spec

    # self.input_spec remains None (parent default), causing crashes
    # when input validation or spec concatenation is attempted.

Fix pattern:
    - Add ``self.input_spec = layer.input_spec`` after super().__init__()

Also detects a related pattern: a class whose ``call()`` method accepts extra
keyword parameters (e.g. ``initial_state``) that require special __call__
handling, but the class doesn't override ``__call__`` to handle them.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple


# Parent class names that indicate a wrapper/decorator/layer pattern
_WRAPPER_BASE_NAMES = frozenset({
    'Wrapper', 'Layer', 'BaseLayer', 'BaseModel',
    'Proxy', 'Decorator', 'Adapter',
    'Module', 'BaseModule',
})

# Attributes that wrapper/layer classes should typically forward
# from the wrapped object to self
_IMPORTANT_FORWARDING_ATTRS = frozenset({
    'input_spec', 'output_spec', 'state_spec',
    'input_shape', 'output_shape',
    'dtype', 'name',
})

# Parameters in call() that typically require __call__ override
# to properly handle (e.g., RNN state management)
_SPECIAL_CALL_PARAMS = frozenset({
    'initial_state', 'constants', 'states',
})


@dataclass
class WrapperForwardingBug:
    """A missing-wrapper-forwarding bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str
    reason: str
    confidence: float
    variable: Optional[str] = None


def scan_file_for_wrapper_forwarding_bugs(file_path: Path) -> List[WrapperForwardingBug]:
    """Scan a single Python file for missing wrapper forwarding patterns."""
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    visitor = _WrapperForwardingVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


class _WrapperForwardingVisitor(ast.NodeVisitor):
    """AST visitor detecting missing attribute forwarding in wrapper classes."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[WrapperForwardingBug] = []

    def visit_ClassDef(self, node: ast.ClassDef):
        self._check_wrapper_class(node)
        self.generic_visit(node)

    def _check_wrapper_class(self, class_node: ast.ClassDef):
        """Check a class for missing wrapper attribute forwarding."""
        # Step 1: Check if class inherits from a wrapper/layer base
        base_names = self._get_base_class_names(class_node)
        is_wrapper_base = bool(base_names & _WRAPPER_BASE_NAMES)

        if not is_wrapper_base:
            return

        # Step 2: Find __init__ method
        init_method = None
        call_method = None
        dunder_call_method = None
        for item in class_node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name == '__init__':
                    init_method = item
                elif item.name == 'call':
                    call_method = item
                elif item.name == '__call__':
                    dunder_call_method = item

        if init_method is None:
            return

        # Step 3: Find the wrapped object parameter (first positional arg after self)
        wrapped_param = self._get_wrapped_param(init_method)
        if wrapped_param is None:
            return

        # Step 4: Check if __init__ copies attributes from the wrapped object
        forwarded_attrs = self._get_forwarded_attrs(init_method, wrapped_param)
        all_self_attrs_set = self._get_all_self_attrs_set(init_method)

        # Step 5: Check if super().__init__() is called
        if not self._has_super_init_call(init_method):
            return

        # Step 6: Detect missing attribute forwarding
        # Only flag if the class copies >=2 attributes from the wrapped object,
        # indicating the developer is aware of forwarding but may have missed some
        if len(forwarded_attrs) >= 2:
            missing_important = _IMPORTANT_FORWARDING_ATTRS - all_self_attrs_set
            if missing_important:
                # Check if any of the missing important attrs are plausibly
                # available on the wrapped object. Use heuristic: if the wrapped
                # param is named 'layer', 'model', 'module', or similar, it
                # likely has input_spec/output_spec.
                likely_has_spec = wrapped_param in (
                    'layer', 'model', 'module', 'cell', 'base_layer',
                    'inner_layer', 'wrapped', 'component',
                )
                if likely_has_spec and 'input_spec' in missing_important:
                    confidence = 0.60
                    # Boost confidence if call() has special params
                    # but no __call__ override
                    if (call_method is not None and
                            dunder_call_method is None and
                            self._call_has_special_params(call_method)):
                        confidence = 0.72

                    func_name = f"{class_node.name}.__init__"
                    self.bugs.append(WrapperForwardingBug(
                        file_path=self.file_path,
                        line_number=init_method.lineno,
                        function_name=func_name,
                        pattern='wrapper_missing_spec_forwarding',
                        reason=(
                            f"Wrapper class '{class_node.name}' copies "
                            f"{len(forwarded_attrs)} attributes from "
                            f"'{wrapped_param}' "
                            f"({', '.join(sorted(forwarded_attrs)[:3])}...) "
                            f"but does not set 'self.input_spec = "
                            f"{wrapped_param}.input_spec'. "
                            f"The parent class likely defaults input_spec to "
                            f"None, which may cause NULL_PTR when code later "
                            f"uses self.input_spec in operations expecting a "
                            f"non-None value (e.g. list concatenation or "
                            f"iteration for input validation)."
                        ),
                        confidence=confidence,
                        variable='self.input_spec',
                    ))

        # Step 7: Detect missing __call__ override for special call() params
        if (call_method is not None and
                dunder_call_method is None and
                self._call_has_special_params(call_method)):
            special_params = self._get_special_call_params(call_method)
            # Only flag if the call() method actually USES these params
            # (checks if param is not None inside the body)
            used_params = [p for p in special_params
                           if self._param_is_used_with_none_check(
                               call_method, p)]
            if used_params:
                func_name = f"{class_node.name}.call"
                confidence = 0.55
                # Higher confidence if the class is a wrapper with attribute forwarding
                if len(forwarded_attrs) >= 2:
                    confidence = 0.68

                self.bugs.append(WrapperForwardingBug(
                    file_path=self.file_path,
                    line_number=call_method.lineno,
                    function_name=func_name,
                    pattern='wrapper_call_missing_dunder_call',
                    reason=(
                        f"Wrapper class '{class_node.name}' has call() "
                        f"accepting {', '.join(used_params)} but no "
                        f"__call__() override. The parent's __call__() may "
                        f"not properly handle these parameters (e.g. "
                        f"setting up input_spec, state management). This "
                        f"can cause NULL_PTR or incorrect behavior when "
                        f"these parameters are passed through the public API."
                    ),
                    confidence=confidence,
                    variable=used_params[0] if used_params else None,
                ))

    @staticmethod
    def _get_base_class_names(class_node: ast.ClassDef) -> Set[str]:
        """Get simple names of base classes."""
        names = set()
        for base in class_node.bases:
            if isinstance(base, ast.Name):
                names.add(base.id)
            elif isinstance(base, ast.Attribute):
                names.add(base.attr)
        return names

    @staticmethod
    def _get_wrapped_param(init_method) -> Optional[str]:
        """Get the name of the wrapped object parameter (first positional arg after self)."""
        args = init_method.args
        # Skip 'self'
        positional = args.args[1:] if len(args.args) > 1 else []
        if not positional:
            return None
        return positional[0].arg

    @staticmethod
    def _get_forwarded_attrs(init_method, wrapped_param: str) -> Set[str]:
        """Find attributes copied from wrapped_param to self.

        Looks for patterns like:
            self.X = param.X
            self.X = param.Y
        """
        forwarded = set()
        for node in ast.walk(init_method):
            if not isinstance(node, ast.Assign):
                continue
            if len(node.targets) != 1:
                continue
            target = node.targets[0]
            # Check: self.X = ...
            if not (isinstance(target, ast.Attribute) and
                    isinstance(target.value, ast.Name) and
                    target.value.id == 'self'):
                continue
            # Check: ... = param.Y
            value = node.value
            if (isinstance(value, ast.Attribute) and
                    isinstance(value.value, ast.Name) and
                    value.value.id == wrapped_param):
                forwarded.add(target.attr)
        return forwarded

    @staticmethod
    def _get_all_self_attrs_set(init_method) -> Set[str]:
        """Get all self.X attributes set in __init__ (any value)."""
        attrs = set()
        for node in ast.walk(init_method):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Attribute) and
                            isinstance(target.value, ast.Name) and
                            target.value.id == 'self'):
                        attrs.add(target.attr)
        return attrs

    @staticmethod
    def _has_super_init_call(init_method) -> bool:
        """Check if __init__ calls super().__init__()."""
        for node in ast.walk(init_method):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # super().__init__()
            if (isinstance(func, ast.Attribute) and
                    func.attr == '__init__' and
                    isinstance(func.value, ast.Call) and
                    isinstance(func.value.func, ast.Name) and
                    func.value.func.id == 'super'):
                return True
            # super(Class, self).__init__()
            if (isinstance(func, ast.Attribute) and
                    func.attr == '__init__' and
                    isinstance(func.value, ast.Call) and
                    isinstance(func.value.func, ast.Name) and
                    func.value.func.id == 'super'):
                return True
        return False

    @staticmethod
    def _call_has_special_params(call_method) -> bool:
        """Check if call() method has special parameters that need __call__ handling."""
        for arg in call_method.args.args:
            if arg.arg in _SPECIAL_CALL_PARAMS:
                return True
        return False

    @staticmethod
    def _get_special_call_params(call_method) -> List[str]:
        """Get list of special parameter names in call()."""
        result = []
        for arg in call_method.args.args:
            if arg.arg in _SPECIAL_CALL_PARAMS:
                result.append(arg.arg)
        return result

    @staticmethod
    def _param_is_used_with_none_check(method, param_name: str) -> bool:
        """Check if parameter is used with a 'is not None' check in the method body.

        This indicates the parameter is actually handled when present.
        """
        _name_const = getattr(ast, 'NameConstant', None)
        for node in ast.walk(method):
            if not isinstance(node, ast.Compare):
                continue
            if not (isinstance(node.left, ast.Name) and
                    node.left.id == param_name and
                    len(node.ops) == 1 and
                    isinstance(node.ops[0], (ast.Is, ast.IsNot)) and
                    len(node.comparators) == 1):
                continue
            comp = node.comparators[0]
            # ast.Constant (Python 3.8+)
            if isinstance(comp, ast.Constant) and comp.value is None:
                return True
            # ast.NameConstant (Python 3.7 compat)
            if _name_const and isinstance(comp, _name_const) and comp.value is None:
                return True
        return False
