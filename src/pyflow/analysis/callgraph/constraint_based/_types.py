"""Runtime type, annotation, protocol, and dispatch semantics."""

from __future__ import annotations

import ast
from typing import Dict, List, Mapping, Optional, Set, Tuple

from .model import (
    AbstractValue,
    BOUND_CLASS_METHOD_KIND,
    BOUND_METHOD_KIND,
    CLASS_KIND,
    ContextKey,
    FUNC_KIND,
    INSTANCE_KIND,
    NONE_KIND,
    NONE_VALUE,
    PARTIAL_KIND,
    STRING_KIND,
    ScopeInfo,
    UNKNOWN_KIND,
    instance_class_name,
    make_string,
)


class _TypeAnalysisMixin:
    """Type-expression, protocol, and registration resolution."""

    _registry_like_names = {"register", "route", "callback", "on"}

    def _resolve_string_expression_values(
        self,
        expr: ast.AST,
        module_name: str,
        env: Optional[Mapping[str, Set[AbstractValue]]] = None,
    ) -> Set[str]:
        if isinstance(expr, ast.Constant):
            if isinstance(expr.value, str):
                return {expr.value}
            if isinstance(expr.value, int):
                return {f"#{expr.value}"}
            return set()
        if isinstance(expr, ast.Name) and expr.id == "None":
            return {"None"}
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            left = self._resolve_string_expression_values(expr.left, module_name, env)
            right = self._resolve_string_expression_values(expr.right, module_name, env)
            return {f"{lhs}{rhs}" for lhs in left for rhs in right}
        if isinstance(expr, ast.JoinedStr):
            parts: List[List[str]] = []
            for value in expr.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append([value.value])
                    continue
                inner = self._resolve_string_expression_values(value, module_name, env)
                if not inner:
                    return set()
                parts.append(sorted(inner))
            if not parts:
                return {""}
            out = {""}
            for chunk in parts:
                out = {f"{prefix}{piece}" for prefix in out for piece in chunk}
            return out
        if isinstance(expr, ast.FormattedValue):
            return self._resolve_string_expression_values(expr.value, module_name, env)
        lookup_env = env or self.module_bindings.get(module_name, {})
        resolved = self._eval_expr_static(expr, lookup_env)
        strings = {value.name for value in resolved if value.kind == STRING_KIND}
        if strings or lookup_env is self.module_bindings.get(module_name, {}):
            return strings
        fallback = self._eval_expr_static(
            expr, self.module_bindings.get(module_name, {})
        )
        return {value.name for value in fallback if value.kind == STRING_KIND}

    def _expr_qualname(self, expr: ast.AST) -> Optional[str]:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            base = self._expr_qualname(expr.value)
            if base:
                return f"{base}.{expr.attr}"
        return None

    def _annotation_union_items(self, expr: ast.AST) -> List[ast.AST]:
        if isinstance(expr, ast.Tuple):
            return list(expr.elts)
        return [expr]

    def _resolve_type_expression_values(
        self,
        expr: Optional[ast.AST],
        module_name: str,
        env: Optional[Mapping[str, Set[AbstractValue]]] = None,
    ) -> Set[AbstractValue]:
        if expr is None:
            return set()
        if isinstance(expr, ast.Constant):
            if expr.value is None:
                return {NONE_VALUE}
            if isinstance(expr.value, str):
                try:
                    parsed = ast.parse(expr.value, mode="eval")
                except SyntaxError:
                    return set()
                return self._resolve_type_expression_values(
                    parsed.body, module_name, env=env
                )

        if isinstance(expr, ast.Name) and expr.id == "None":
            return {NONE_VALUE}

        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.BitOr):
            out: Set[AbstractValue] = set()
            out.update(
                self._resolve_type_expression_values(expr.left, module_name, env)
            )
            out.update(
                self._resolve_type_expression_values(expr.right, module_name, env)
            )
            return out

        if isinstance(expr, ast.Tuple):
            out: Set[AbstractValue] = set()
            for item in expr.elts:
                out.update(self._resolve_type_expression_values(item, module_name, env))
            return out

        if isinstance(expr, ast.Subscript):
            base_name = self._expr_qualname(expr.value)
            if base_name in {"Optional", "typing.Optional"}:
                out = {NONE_VALUE}
                for item in self._annotation_union_items(expr.slice):
                    out.update(
                        self._resolve_type_expression_values(item, module_name, env)
                    )
                return out
            if base_name in {
                "Union",
                "typing.Union",
                "Annotated",
                "typing.Annotated",
                "Type",
                "typing.Type",
                "type",
            }:
                out: Set[AbstractValue] = set()
                for item in self._annotation_union_items(expr.slice):
                    out.update(
                        self._resolve_type_expression_values(item, module_name, env)
                    )
                return out
            if base_name in {"Literal", "typing.Literal"}:
                out: Set[AbstractValue] = set()
                for item in self._annotation_union_items(expr.slice):
                    if isinstance(item, ast.Constant):
                        if item.value is None:
                            out.add(NONE_VALUE)
                        elif isinstance(item.value, str):
                            out.add(make_string(item.value))
                        elif isinstance(item.value, int):
                            out.add(make_string(f"#{item.value}"))
                return out

        lookup_env = env or self.module_bindings.get(module_name, {})
        resolved = self._eval_expr_static(expr, lookup_env)
        if resolved:
            return resolved
        if lookup_env is not self.module_bindings.get(module_name, {}):
            return self._eval_expr_static(
                expr, self.module_bindings.get(module_name, {})
            )
        return set()

    def _type_guard_refinement(
        self,
        expr: Optional[ast.AST],
        module_name: str,
        env: Optional[Mapping[str, Set[AbstractValue]]] = None,
    ) -> Set[AbstractValue]:
        if expr is None:
            return set()
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            try:
                parsed = ast.parse(expr.value, mode="eval")
            except SyntaxError:
                return set()
            return self._type_guard_refinement(parsed.body, module_name, env)
        if isinstance(expr, ast.Subscript):
            base_name = self._expr_qualname(expr.value)
            if base_name in {
                "TypeGuard",
                "typing.TypeGuard",
                "TypeIs",
                "typing.TypeIs",
            }:
                out: Set[AbstractValue] = set()
                for item in self._annotation_union_items(expr.slice):
                    out.update(
                        self._resolve_type_expression_values(item, module_name, env)
                    )
                return out
        return set()

    def _registry_binding_payload(
        self,
        decorator_expr: ast.AST,
        scope: ScopeInfo,
        scope_context: ContextKey,
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> Tuple[Set[AbstractValue], Set[str]]:
        if not isinstance(decorator_expr, ast.Call):
            return set(), set()
        func_expr = decorator_expr.func
        if not isinstance(func_expr, ast.Attribute):
            return set(), set()
        if func_expr.attr not in self._registry_like_names:
            return set(), set()
        key_names: Set[str] = set()
        if decorator_expr.args:
            key_names.update(
                self._resolve_string_expression_values(
                    decorator_expr.args[0], scope.module, env=env
                )
            )
        if not key_names:
            return set(), set()
        owner_values = self._eval_expr(
            scope,
            scope_context,
            func_expr.value,
            env,
            callees,
            input_changed_scope_contexts,
        )
        return owner_values, key_names

    def _singledispatch_registration_payload(
        self,
        decorator_expr: ast.AST,
        scope: ScopeInfo,
        scope_context: ContextKey,
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> Tuple[Set[str], Set[AbstractValue]]:
        if not isinstance(decorator_expr, ast.Call):
            return set(), set()
        func_expr = decorator_expr.func
        if not isinstance(func_expr, ast.Attribute) or func_expr.attr != "register":
            return set(), set()
        owner_values = self._eval_expr(
            scope,
            scope_context,
            func_expr.value,
            env,
            callees,
            input_changed_scope_contexts,
        )
        generic_names = {
            value.name
            for value in owner_values
            if value.kind == FUNC_KIND and value.name in self.singledispatch_functions
        }
        if not generic_names:
            return set(), set()
        declared_types: Set[AbstractValue] = set()
        if decorator_expr.args:
            declared_types.update(
                self._resolve_type_expression_values(
                    decorator_expr.args[0], scope.module, env=env
                )
            )
        return generic_names, declared_types

    def _register_singledispatch_implementation(
        self,
        generic_name: str,
        function_name: str,
        dispatch_types: Set[AbstractValue],
    ) -> None:
        registrations = self.singledispatch_registrations[generic_name]
        for index, (existing_name, _existing_types) in enumerate(registrations):
            if existing_name == function_name:
                replacement = (function_name, set(dispatch_types))
                if registrations[index] != replacement:
                    registrations[index] = replacement
                    self._active_singledispatch_changed = True
                return
        registrations.append((function_name, set(dispatch_types)))
        self._active_singledispatch_changed = True

    def _singledispatch_registration_types(
        self, function_name: str
    ) -> Set[AbstractValue]:
        function_info = self.functions.get(function_name)
        if function_info is None or not function_info.params:
            return set()
        first_param = function_info.params[0]
        return self._resolve_type_expression_values(
            function_info.param_annotations.get(first_param),
            function_info.module,
        )

    def _matches_type_values(
        self, value: AbstractValue, type_values: Set[AbstractValue]
    ) -> bool:
        allowed_classes = {item.name for item in type_values if item.kind == CLASS_KIND}
        allowed_strings = {
            item.name for item in type_values if item.kind == STRING_KIND
        }
        allow_none = any(item.kind == NONE_KIND for item in type_values)

        protocol_classes = [
            class_name
            for class_name in allowed_classes
            if self._is_protocol_class(class_name)
        ]

        if value.kind == UNKNOWN_KIND:
            return True
        if value.kind == NONE_KIND:
            return allow_none
        if value.kind == STRING_KIND:
            return value.name in allowed_strings
        if protocol_classes and value.kind in {INSTANCE_KIND, CLASS_KIND}:
            if any(
                self._matches_protocol_structurally(value, protocol_name)
                for protocol_name in protocol_classes
            ):
                return True
        if value.kind == INSTANCE_KIND and allowed_classes:
            value_class = instance_class_name(value)
            order = self._class_lookup_order(value_class)
            return any(class_name in order for class_name in allowed_classes)
        if value.kind == CLASS_KIND and allowed_classes:
            order = self._class_lookup_order(value.name)
            return any(class_name in order for class_name in allowed_classes)
        return False

    def _is_callable_value(self, value: AbstractValue) -> bool:
        if value.kind in {
            FUNC_KIND,
            BOUND_METHOD_KIND,
            BOUND_CLASS_METHOD_KIND,
            CLASS_KIND,
            PARTIAL_KIND,
        }:
            return True
        if value.kind == INSTANCE_KIND:
            target_class_name = instance_class_name(value)
            lookup_order = self._class_lookup_order(target_class_name)
            for klass in lookup_order:
                class_info = self.classes.get(klass)
                if class_info and "__call__" in class_info.methods:
                    return True
        if value.kind == UNKNOWN_KIND:
            return True
        return False

    def _is_protocol_class(self, class_name: str) -> bool:
        protocol_markers = {
            "Protocol",
            "typing.Protocol",
            "typing_extensions.Protocol",
        }
        pending = [class_name]
        seen: Set[str] = set()
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            class_info = self.classes.get(current)
            if class_info is None:
                continue
            for base in class_info.bases:
                if base in protocol_markers:
                    return True
                if base not in seen:
                    pending.append(base)
        return False

    def _protocol_required_attrs(self, class_name: str) -> Set[str]:
        out: Set[str] = set()
        for proto in self._class_lookup_order(class_name):
            proto_info = self.classes.get(proto)
            if proto_info is None:
                continue
            if not self._is_protocol_class(proto) and proto != class_name:
                continue
            for method_name in proto_info.methods:
                if method_name.startswith("_") and method_name not in {"__call__"}:
                    continue
                out.add(method_name)
            out.update(self.class_fields.get(proto, {}).keys())
        return out

    def _matches_protocol_structurally(
        self, value: AbstractValue, protocol_name: str
    ) -> bool:
        required_attrs = self._protocol_required_attrs(protocol_name)
        if not required_attrs:
            return False
        return all(
            self._resolve_attribute({value}, attr_name) for attr_name in required_attrs
        )
