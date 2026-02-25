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
    make_module,
    copy_env,
)


class _CollectorMixin:
    """Collects functions, classes, and scopes from loaded modules."""

    def _iter_statement_bodies(self, stmt: ast.stmt):
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

    def _collect_nested_functions(
        self,
        module_name: str,
        parent_qualname: str,
        statements: Sequence[ast.stmt],
    ) -> None:
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nested_qualname = f"{parent_qualname}.{stmt.name}"
                self.functions[nested_qualname] = self._build_function_info(
                    module_name,
                    nested_qualname,
                    stmt,
                    is_method=False,
                    is_staticmethod=False,
                    is_classmethod=False,
                    owner_class=None,
                    closure_vars=self._infer_closure_vars(stmt),
                )
                self._collect_nested_functions(module_name, nested_qualname, stmt.body)

            for body in self._iter_statement_bodies(stmt):
                self._collect_nested_functions(module_name, parent_qualname, body)

    def _collect_symbols(self) -> None:
        for module_name, module_info in self.modules.items():
            exports: DefaultDict[str, Set[AbstractValue]] = defaultdict(set)
            for node in module_info.tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualname = f"{module_name}.{node.name}"
                    self.functions[qualname] = self._build_function_info(
                        module_name,
                        qualname,
                        node,
                        is_method=False,
                        is_staticmethod=False,
                        is_classmethod=False,
                        owner_class=None,
                        closure_vars=self._infer_closure_vars(node),
                    )
                    exports[node.name].add(make_func(qualname))
                    self._collect_nested_functions(module_name, qualname, node.body)
                elif isinstance(node, ast.ClassDef):
                    class_qualname = f"{module_name}.{node.name}"
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
                    exports[node.name].add(make_class(class_qualname))

                    for child in node.body:
                        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            continue
                        method_qualname = f"{class_qualname}.{child.name}"
                        decorator_names = {
                            decorator_id(deco) for deco in child.decorator_list
                        }
                        is_staticmethod = (
                            "staticmethod" in decorator_names
                            or "builtins.staticmethod" in decorator_names
                        )
                        is_classmethod = (
                            "classmethod" in decorator_names
                            or "builtins.classmethod" in decorator_names
                        )
                        self.functions[method_qualname] = self._build_function_info(
                            module_name,
                            method_qualname,
                            child,
                            is_method=True,
                            is_staticmethod=is_staticmethod,
                            is_classmethod=is_classmethod,
                            owner_class=class_qualname,
                            closure_vars=self._infer_closure_vars(child),
                        )
                        class_info.methods[child.name] = method_qualname
                        if is_staticmethod:
                            class_info.static_methods.add(child.name)
                        if is_classmethod:
                            class_info.class_methods.add(child.name)
                        self._collect_nested_functions(
                            module_name, method_qualname, child.body
                        )

            # Basic top-level alias propagation for direct assignments.
            for node in module_info.tree.body:
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
                    rhs_name = node.value.id
                    rhs_values = exports.get(rhs_name, set())
                    if not rhs_values:
                        continue
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            exports[target.id].update(rhs_values)

            self.module_bindings[module_name] = {
                name: set(values) for name, values in exports.items()
            }

    def _build_function_info(
        self,
        module_name: str,
        qualname: str,
        node: ast.AST,
        is_method: bool,
        is_staticmethod: bool,
        is_classmethod: bool,
        owner_class: Optional[str],
        closure_vars: Set[str],
    ) -> FunctionInfo:
        assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        params = [arg.arg for arg in node.args.posonlyargs]
        params.extend(arg.arg for arg in node.args.args)
        params.extend(arg.arg for arg in node.args.kwonlyargs)
        vararg = node.args.vararg.arg if node.args.vararg else None
        kwarg = node.args.kwarg.arg if node.args.kwarg else None
        return FunctionInfo(
            qualname=qualname,
            module=module_name,
            node=node,
            params=params,
            vararg=vararg,
            kwarg=kwarg,
            is_method=is_method,
            is_staticmethod=is_staticmethod,
            is_classmethod=is_classmethod,
            owner_class=owner_class,
            closure_vars=set(closure_vars),
        )

    def _resolve_import_bindings(self) -> None:
        for module_name, module_info in self.modules.items():
            bindings = self.module_bindings[module_name]
            env = copy_env(bindings)

            for node in module_info.tree.body:
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported_name = alias.name
                        as_name = alias.asname or imported_name.split(".")[0]
                        env[as_name] = {make_module(imported_name)}
                elif isinstance(node, ast.ImportFrom):
                    source_module = self._resolve_import_module_name(
                        module_name, node.module, node.level
                    )
                    if not source_module:
                        continue
                    source_exports = self.module_bindings.get(source_module, {})
                    for alias in node.names:
                        if alias.name == "*":
                            for exported_name, exported_values in source_exports.items():
                                env[exported_name].update(exported_values)
                            continue
                        local_name = alias.asname or alias.name
                        if alias.name in source_exports:
                            env.setdefault(local_name, set()).update(source_exports[alias.name])
                        else:
                            env.setdefault(local_name, set()).add(
                                make_func(f"{source_module}.{alias.name}")
                            )

            self.module_bindings[module_name] = env

    def _resolve_class_bases(self) -> None:
        self._mro_cache.clear()
        for class_info in self.classes.values():
            bindings = self.module_bindings.get(class_info.module, {})
            resolved: list[str] = []
            for base_expr in class_info.bases_raw:
                values = self._eval_expr_static(base_expr, bindings)
                for value in values:
                    if value.kind == CLASS_KIND and value.name in self.classes:
                        resolved.append(value.name)
            class_info.bases = resolved

    def _initialize_scopes(self) -> None:
        for module_name, module_info in self.modules.items():
            self.scopes[module_name] = ScopeInfo(
                name=module_name,
                module=module_name,
                body=list(module_info.tree.body),
                params=[],
                vararg=None,
                kwarg=None,
                method_self_param=None,
                method_cls_param=None,
                closure_vars=set(),
            )

        for function_info in self.functions.values():
            assert isinstance(function_info.node, (ast.FunctionDef, ast.AsyncFunctionDef))
            method_self = None
            method_cls = None
            if function_info.is_method and function_info.params:
                if function_info.is_classmethod:
                    method_cls = function_info.params[0]
                elif not function_info.is_staticmethod:
                    method_self = function_info.params[0]

            self.scopes[function_info.qualname] = ScopeInfo(
                name=function_info.qualname,
                module=function_info.module,
                body=list(function_info.node.body),
                params=list(function_info.params),
                vararg=function_info.vararg,
                kwarg=function_info.kwarg,
                method_self_param=method_self,
                method_cls_param=method_cls,
                closure_vars=set(function_info.closure_vars),
            )
