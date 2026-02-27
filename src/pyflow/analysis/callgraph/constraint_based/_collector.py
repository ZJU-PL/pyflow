"""Symbol collection and scope initialization for constraint-based call graph analysis."""

from __future__ import annotations

import ast
from collections import defaultdict
from typing import DefaultDict, Dict, Optional, Sequence, Set

from .model import (
    AbstractValue,
    CLASS_KIND,
    ClassInfo,
    FunctionInfo,
    ScopeInfo,
    decorator_id,
    make_class,
    make_func,
    make_string,
    copy_env,
)


class _CollectorMixin:
    """Collects functions, classes, and scopes from loaded modules."""

    def _iter_statement_bodies(self, stmt: ast.stmt):
        """Yield nested statement lists that may contain nested function defs."""
        if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            yield stmt.body
            yield stmt.orelse
        elif isinstance(stmt, ast.Try):
            yield stmt.body
            for handler in stmt.handlers:
                yield handler.body
            yield stmt.orelse
            yield stmt.finalbody
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            yield stmt.body
        elif isinstance(stmt, ast.Match):
            for case in stmt.cases:
                yield case.body

    def _infer_closure_vars(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> set[str]:
        """
        Infer free variables referenced by a function body.

        This is a lightweight lexical pass; runtime rebinding is handled later
        by the fixpoint when closure inputs are bound.
        """
        local_names: set[str] = {arg.arg for arg in node.args.posonlyargs}
        local_names.update(arg.arg for arg in node.args.args)
        local_names.update(arg.arg for arg in node.args.kwonlyargs)
        if node.args.vararg:
            local_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            local_names.add(node.args.kwarg.arg)

        loaded_names: Set[str] = set()
        global_names: Set[str] = set()
        nonlocal_names: Set[str] = set()

        class LocalNameVisitor(ast.NodeVisitor):
            def visit_Name(self, inner: ast.Name) -> None:
                if isinstance(inner.ctx, ast.Load):
                    loaded_names.add(inner.id)
                elif isinstance(inner.ctx, (ast.Store, ast.Del)):
                    local_names.add(inner.id)

            def visit_FunctionDef(self, inner: ast.FunctionDef) -> None:
                local_names.add(inner.name)

            def visit_AsyncFunctionDef(self, inner: ast.AsyncFunctionDef) -> None:
                local_names.add(inner.name)

            def visit_ClassDef(self, inner: ast.ClassDef) -> None:
                local_names.add(inner.name)

            def visit_Global(self, inner: ast.Global) -> None:
                global_names.update(inner.names)

            def visit_Nonlocal(self, inner: ast.Nonlocal) -> None:
                nonlocal_names.update(inner.names)

        visitor = LocalNameVisitor()
        for stmt in node.body:
            visitor.visit(stmt)

        closure = {
            name
            for name in loaded_names
            if name not in local_names and name not in global_names
        }
        closure.update(nonlocal_names)
        return closure

    def _infer_lambda_closure_vars(self, node: ast.Lambda) -> set[str]:
        """Lambda variant of free-variable inference."""
        local_names: set[str] = {arg.arg for arg in node.args.posonlyargs}
        local_names.update(arg.arg for arg in node.args.args)
        local_names.update(arg.arg for arg in node.args.kwonlyargs)
        if node.args.vararg:
            local_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            local_names.add(node.args.kwarg.arg)

        loaded_names: set[str] = set()
        stored_names: set[str] = set()
        for inner in ast.walk(node.body):
            if isinstance(inner, ast.Name):
                if isinstance(inner.ctx, ast.Load):
                    loaded_names.add(inner.id)
                elif isinstance(inner.ctx, (ast.Store, ast.Del)):
                    stored_names.add(inner.id)
        local_names.update(stored_names)
        return {name for name in loaded_names if name not in local_names}

    def _infer_global_nonlocal_names(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> tuple[set[str], set[str]]:
        """Collect `global` and `nonlocal` declarations in direct function body."""
        global_names: Set[str] = set()
        nonlocal_names: Set[str] = set()

        class ScopeDirectiveVisitor(ast.NodeVisitor):
            def visit_Global(self, inner: ast.Global) -> None:
                global_names.update(inner.names)

            def visit_Nonlocal(self, inner: ast.Nonlocal) -> None:
                nonlocal_names.update(inner.names)

            def visit_FunctionDef(self, inner: ast.FunctionDef) -> None:
                return

            def visit_AsyncFunctionDef(self, inner: ast.AsyncFunctionDef) -> None:
                return

            def visit_ClassDef(self, inner: ast.ClassDef) -> None:
                return

        visitor = ScopeDirectiveVisitor()
        for stmt in node.body:
            visitor.visit(stmt)
        return set(global_names), set(nonlocal_names)

    def _collect_nested_functions(
        self,
        module_name: str,
        parent_qualname: str,
        statements: Sequence[ast.stmt],
    ) -> None:
        """Recursively collect nested function definitions under `parent_qualname`."""
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nested_qualname = f"{parent_qualname}.{stmt.name}"
                global_names, nonlocal_names = self._infer_global_nonlocal_names(stmt)
                self.functions[nested_qualname] = self._build_function_info(
                    module_name,
                    nested_qualname,
                    stmt,
                    is_method=False,
                    is_staticmethod=False,
                    is_classmethod=False,
                    owner_class=None,
                    parent_scope=parent_qualname,
                    global_names=global_names,
                    nonlocal_names=nonlocal_names,
                    closure_vars=self._infer_closure_vars(stmt),
                )
                self._collect_nested_functions(module_name, nested_qualname, stmt.body)

            for body in self._iter_statement_bodies(stmt):
                self._collect_nested_functions(module_name, parent_qualname, body)

    def _collect_class_symbol(
        self,
        module_name: str,
        node: ast.ClassDef,
        class_qualname: str,
        parent_class_qualname: Optional[str] = None,
    ) -> None:
        """
        Collect class metadata, methods, and nested classes.

        Nested classes are also published into parent class fields so attribute
        access like `A.B` can resolve.
        """
        class_info = ClassInfo(
            qualname=class_qualname,
            module=module_name,
            node=node,
            bases_raw=list(node.bases),
            bases=[],
            methods={},
            static_methods=set(),
            class_methods=set(),
        )
        self.classes[class_qualname] = class_info
        if parent_class_qualname is not None:
            self.class_fields[parent_class_qualname][node.name].add(
                make_class(class_qualname)
            )

        for child in node.body:
            if isinstance(child, ast.ClassDef):
                nested_qualname = f"{class_qualname}.{child.name}"
                self._collect_class_symbol(
                    module_name,
                    child,
                    nested_qualname,
                    parent_class_qualname=class_qualname,
                )
                continue
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            method_qualname = f"{class_qualname}.{child.name}"
            decorator_names = {decorator_id(deco) for deco in child.decorator_list}
            is_staticmethod = (
                "staticmethod" in decorator_names
                or "builtins.staticmethod" in decorator_names
            )
            is_classmethod = (
                "classmethod" in decorator_names
                or "builtins.classmethod" in decorator_names
            )
            global_names, nonlocal_names = self._infer_global_nonlocal_names(child)
            self.functions[method_qualname] = self._build_function_info(
                module_name,
                method_qualname,
                child,
                is_method=True,
                is_staticmethod=is_staticmethod,
                is_classmethod=is_classmethod,
                owner_class=class_qualname,
                parent_scope=None,
                global_names=global_names,
                nonlocal_names=nonlocal_names,
                closure_vars=self._infer_closure_vars(child),
            )
            class_info.methods[child.name] = method_qualname
            if is_staticmethod:
                class_info.static_methods.add(child.name)
            if is_classmethod:
                class_info.class_methods.add(child.name)
            self._collect_nested_functions(module_name, method_qualname, child.body)

    def _collect_symbols(self) -> None:
        """Collect top-level functions/classes and bootstrap module exports."""
        for module_name, module_info in self.modules.items():
            exports: DefaultDict[str, Set[AbstractValue]] = defaultdict(set)
            for node in module_info.tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualname = f"{module_name}.{node.name}"
                    global_names, nonlocal_names = self._infer_global_nonlocal_names(
                        node
                    )
                    self.functions[qualname] = self._build_function_info(
                        module_name,
                        qualname,
                        node,
                        is_method=False,
                        is_staticmethod=False,
                        is_classmethod=False,
                        owner_class=None,
                        parent_scope=None,
                        global_names=global_names,
                        nonlocal_names=nonlocal_names,
                        closure_vars=self._infer_closure_vars(node),
                    )
                    exports[node.name].add(make_func(qualname))
                    self._collect_nested_functions(module_name, qualname, node.body)
                elif isinstance(node, ast.ClassDef):
                    class_qualname = f"{module_name}.{node.name}"
                    self._collect_class_symbol(module_name, node, class_qualname)
                    exports[node.name].add(make_class(class_qualname))

            self._collect_lambdas(module_name, module_info.tree)

            # Basic top-level alias/constant propagation for direct assignments.
            for node in module_info.tree.body:
                if not isinstance(node, ast.Assign):
                    continue
                assigned_values: Set[AbstractValue] = set()
                if isinstance(node.value, ast.Name):
                    rhs_name = node.value.id
                    assigned_values.update(exports.get(rhs_name, set()))
                elif isinstance(node.value, ast.Constant):
                    if isinstance(node.value.value, str):
                        assigned_values.add(make_string(node.value.value))
                    elif isinstance(node.value.value, int):
                        assigned_values.add(make_string(f"#{node.value.value}"))
                if not assigned_values:
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        exports[target.id].update(assigned_values)

            self.module_bindings[module_name] = {
                name: set(values) for name, values in exports.items()
            }

    def _collect_lambdas(self, module_name: str, module_tree: ast.Module) -> None:
        """Collect lambda expressions with stable per-scope synthetic names."""
        scope_stack: list[str] = [module_name]
        lambda_counters: dict[str, int] = {}

        def _register_lambda(node: ast.Lambda) -> None:
            parent_scope = scope_stack[-1]
            line = getattr(node, "lineno", -1)
            col = getattr(node, "col_offset", -1)
            lambda_counters[parent_scope] = lambda_counters.get(parent_scope, 0) + 1
            base_name = f"<lambda{lambda_counters[parent_scope]}>"
            qualname = f"{parent_scope}.{base_name}"
            suffix = 1
            while qualname in self.functions:
                suffix += 1
                qualname = f"{parent_scope}.{base_name}#{suffix}"

            self.functions[qualname] = self._build_function_info(
                module_name=module_name,
                qualname=qualname,
                node=node,
                is_method=False,
                is_staticmethod=False,
                is_classmethod=False,
                owner_class=None,
                parent_scope=parent_scope,
                global_names=set(),
                nonlocal_names=set(),
                closure_vars=self._infer_lambda_closure_vars(node),
            )
            self.lambda_functions[(parent_scope, line, col)] = qualname
            self.lambda_functions_by_node[id(node)] = qualname

        class LambdaCollector(ast.NodeVisitor):
            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                parent_scope = scope_stack[-1]
                qualname = f"{parent_scope}.{node.name}"
                scope_stack.append(qualname)
                self.generic_visit(node)
                scope_stack.pop()

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                parent_scope = scope_stack[-1]
                qualname = f"{parent_scope}.{node.name}"
                scope_stack.append(qualname)
                self.generic_visit(node)
                scope_stack.pop()

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                parent_scope = scope_stack[-1]
                qualname = f"{parent_scope}.{node.name}"
                scope_stack.append(qualname)
                self.generic_visit(node)
                scope_stack.pop()

            def visit_Lambda(self, node: ast.Lambda) -> None:
                _register_lambda(node)
                self.generic_visit(node)

        LambdaCollector().visit(module_tree)

    def _build_function_info(
        self,
        module_name: str,
        qualname: str,
        node: ast.AST,
        is_method: bool,
        is_staticmethod: bool,
        is_classmethod: bool,
        owner_class: Optional[str],
        parent_scope: Optional[str],
        global_names: Set[str],
        nonlocal_names: Set[str],
        closure_vars: Set[str],
    ) -> FunctionInfo:
        """Build a normalized `FunctionInfo` record from a function-like AST node."""
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            posonly_params = [arg.arg for arg in node.args.posonlyargs]
            pos_or_kw_params = [arg.arg for arg in node.args.args]
            kwonly_params = [arg.arg for arg in node.args.kwonlyargs]
            params = [*posonly_params, *pos_or_kw_params, *kwonly_params]
            vararg = node.args.vararg.arg if node.args.vararg else None
            kwarg = node.args.kwarg.arg if node.args.kwarg else None
        else:
            raise TypeError(f"Unsupported function node type: {type(node)!r}")
        return FunctionInfo(
            qualname=qualname,
            module=module_name,
            node=node,
            posonly_params=posonly_params,
            pos_or_kw_params=pos_or_kw_params,
            kwonly_params=kwonly_params,
            params=params,
            vararg=vararg,
            kwarg=kwarg,
            is_method=is_method,
            is_staticmethod=is_staticmethod,
            is_classmethod=is_classmethod,
            owner_class=owner_class,
            global_names=set(global_names),
            nonlocal_names=set(nonlocal_names),
            parent_scope=parent_scope,
            closure_vars=set(closure_vars),
        )

    def _resolve_import_bindings(self) -> None:
        """Apply import statements to module-level binding maps."""
        for module_name, module_info in self.modules.items():
            bindings = self.module_bindings[module_name]
            env = copy_env(bindings)

            for node in module_info.tree.body:
                if isinstance(node, ast.Import):
                    self._bind_import(node, module_name, env)
                elif isinstance(node, ast.ImportFrom):
                    self._bind_import_from(node, module_name, env)

            self.module_bindings[module_name] = env

    def _resolve_class_bases(self) -> None:
        """Resolve class base expressions to qualnames used by MRO lookup."""
        self._mro_cache.clear()
        for class_info in self.classes.values():
            bindings = self.module_bindings.get(class_info.module, {})
            resolved: list[str] = []
            for base_expr in class_info.bases_raw:
                values = self._eval_expr_static(base_expr, bindings)
                for value in values:
                    if value.kind == CLASS_KIND and value.name in self.classes:
                        resolved.append(value.name)
                    elif value.kind == CLASS_KIND:
                        resolved.append(value.name)
                    elif value.kind == "func" and "." in value.name:
                        resolved.append(value.name)
            class_info.bases = resolved

    def _initialize_scopes(self) -> None:
        """Convert collected symbols into executable `ScopeInfo` records."""
        for module_name, module_info in self.modules.items():
            self.scopes[module_name] = ScopeInfo(
                name=module_name,
                module=module_name,
                body=list(module_info.tree.body),
                posonly_params=[],
                pos_or_kw_params=[],
                kwonly_params=[],
                params=[],
                vararg=None,
                kwarg=None,
                method_self_param=None,
                method_cls_param=None,
                global_names=set(),
                nonlocal_names=set(),
                parent_scope=None,
                closure_vars=set(),
            )

        for function_info in self.functions.values():
            method_self = None
            method_cls = None
            positional_method_params = [
                *function_info.posonly_params,
                *function_info.pos_or_kw_params,
            ]
            if (
                function_info.is_method
                and isinstance(
                    function_info.node, (ast.FunctionDef, ast.AsyncFunctionDef)
                )
                and positional_method_params
            ):
                if function_info.is_classmethod:
                    method_cls = positional_method_params[0]
                elif not function_info.is_staticmethod:
                    method_self = positional_method_params[0]

            if isinstance(function_info.node, ast.Lambda):
                body = [ast.Return(value=function_info.node.body)]
            else:
                body = list(function_info.node.body)

            self.scopes[function_info.qualname] = ScopeInfo(
                name=function_info.qualname,
                module=function_info.module,
                body=body,
                posonly_params=list(function_info.posonly_params),
                pos_or_kw_params=list(function_info.pos_or_kw_params),
                kwonly_params=list(function_info.kwonly_params),
                params=list(function_info.params),
                vararg=function_info.vararg,
                kwarg=function_info.kwarg,
                method_self_param=method_self,
                method_cls_param=method_cls,
                global_names=set(function_info.global_names),
                nonlocal_names=set(function_info.nonlocal_names),
                parent_scope=function_info.parent_scope,
                closure_vars=set(function_info.closure_vars),
            )
