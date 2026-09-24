"""Semi-naive propagation for the constraint callgraph's relational core."""

from __future__ import annotations

import ast
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import DefaultDict, Iterable, Optional

from .model import (
    AbstractValue,
    FUNC_KIND,
    GLOBAL_CONTEXT,
    make_class,
    make_func,
)

BindingKey = tuple[str, str]


@dataclass(frozen=True)
class CopyConstraint:
    owner: str
    source: BindingKey
    target: BindingKey


@dataclass(frozen=True)
class CallConstraint:
    owner: str
    target: Optional[BindingKey]
    fixed_targets: frozenset[AbstractValue]
    arguments: tuple[Optional[BindingKey], ...]
    destination: Optional[BindingKey]


class SemiNaiveConstraintSolver:
    """Compile simple value-flow facts and propagate only newly added atoms.

    Unsupported Python constructs are deliberately ignored here and remain the
    responsibility of the full abstract interpreter.  Every emitted fact is a
    monotone may-fact, so using this solver as a pre-pass cannot remove an edge.
    """

    def __init__(self, builder) -> None:
        self.builder = builder
        self.facts: DefaultDict[BindingKey, set[AbstractValue]] = defaultdict(set)
        self.dependents: DefaultDict[
            BindingKey, set[CopyConstraint | CallConstraint]
        ] = defaultdict(set)
        self.constraints_by_owner: DefaultDict[
            str, set[CopyConstraint | CallConstraint]
        ] = defaultdict(set)
        self.queue: deque[tuple[BindingKey, frozenset[AbstractValue]]] = deque()
        self.activation_queue: deque[str] = deque()
        self.active_scopes: set[str] = set()
        self.compiled_scopes: set[str] = set()
        self.resolved_calls: set[tuple[CallConstraint, str]] = set()
        self.edges: DefaultDict[str, set[str]] = defaultdict(set)
        self.constraints = 0
        self.propagated_facts = 0

    @staticmethod
    def _return_key(scope_name: str) -> BindingKey:
        return scope_name, "<return>"

    def _add(self, key: BindingKey, values: Iterable[AbstractValue]) -> bool:
        incoming = set(values) - self.facts[key]
        if not incoming:
            return False
        self.facts[key].update(incoming)
        self.propagated_facts += len(incoming)
        self.queue.append((key, frozenset(incoming)))
        return True

    def _register_copy(self, constraint: CopyConstraint) -> None:
        if constraint in self.dependents[constraint.source]:
            return
        self.dependents[constraint.source].add(constraint)
        self.constraints_by_owner[constraint.owner].add(constraint)
        self.constraints += 1
        if constraint.owner in self.active_scopes:
            self._add(constraint.target, self.facts[constraint.source])

    def _register_call(self, constraint: CallConstraint) -> None:
        if constraint in self.constraints_by_owner[constraint.owner]:
            return
        self.constraints_by_owner[constraint.owner].add(constraint)
        if constraint.target is not None:
            self.dependents[constraint.target].add(constraint)
        self.constraints += 1
        if constraint.owner in self.active_scopes:
            targets = set(constraint.fixed_targets)
            if constraint.target is not None:
                targets.update(self.facts[constraint.target])
            self._resolve_call(constraint, targets)

    def _activate(self, scope_name: str) -> None:
        if scope_name in self.active_scopes or scope_name not in self.builder.scopes:
            return
        self.active_scopes.add(scope_name)
        self.activation_queue.append(scope_name)

    def _materialize_activation(self, scope_name: str) -> None:
        self._compile_scope(scope_name)
        scope_key = (scope_name, GLOBAL_CONTEXT)
        for name, values in self.builder.scope_inputs.get(scope_key, {}).items():
            self._add((scope_name, name), values)
        for constraint in tuple(self.constraints_by_owner.get(scope_name, ())):
            if isinstance(constraint, CopyConstraint):
                self._add(constraint.target, self.facts[constraint.source])
            else:
                targets = set(constraint.fixed_targets)
                if constraint.target is not None:
                    targets.update(self.facts[constraint.target])
                self._resolve_call(constraint, targets)

    def _resolve_call(
        self, constraint: CallConstraint, target_delta: Iterable[AbstractValue]
    ) -> None:
        for value in target_delta:
            if value.kind != FUNC_KIND or value.name not in self.builder.scopes:
                continue
            function_info = self.builder.functions.get(value.name)
            decorators = getattr(getattr(function_info, "node", None), "decorator_list", ())
            is_singledispatch = any(
                (
                    isinstance(decorator, ast.Name)
                    and decorator.id == "singledispatch"
                )
                or (
                    isinstance(decorator, ast.Attribute)
                    and decorator.attr == "singledispatch"
                )
                for decorator in decorators
            )
            if value.name in self.builder.singledispatch_functions or is_singledispatch:
                continue
            marker = (constraint, value.name)
            if marker in self.resolved_calls:
                continue
            self.resolved_calls.add(marker)
            self.edges[constraint.owner].add(value.name)
            self._activate(value.name)
            callee = self.builder.scopes[value.name]
            positional = [*callee.posonly_params, *callee.pos_or_kw_params]
            for source, parameter in zip(constraint.arguments, positional):
                if source is None:
                    continue
                self._register_copy(
                    CopyConstraint(
                        constraint.owner,
                        source,
                        (value.name, parameter),
                    )
                )
            if constraint.destination is not None:
                self._register_copy(
                    CopyConstraint(
                        constraint.owner,
                        self._return_key(value.name),
                        constraint.destination,
                    )
                )

    def _scope_local_names(self, scope) -> set[str]:
        names = set(scope.params) | set(scope.closure_vars)

        class StoreVisitor(ast.NodeVisitor):
            def visit_Name(self, node: ast.Name) -> None:
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    names.add(node.id)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                names.add(node.name)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                names.add(node.name)

        visitor = StoreVisitor()
        for statement in scope.body:
            visitor.visit(statement)
        return names

    def _name_key(self, scope, local_names: set[str], name: str) -> BindingKey:
        if name in local_names:
            return scope.name, name
        return scope.module, name

    def _expression_key(
        self, scope, local_names: set[str], expression: ast.AST
    ) -> Optional[BindingKey]:
        if isinstance(expression, ast.Name):
            return self._name_key(scope, local_names, expression.id)
        return None

    def _compile_call(
        self,
        scope,
        local_names: set[str],
        call: ast.Call,
        destination: Optional[BindingKey],
    ) -> None:
        target = self._expression_key(scope, local_names, call.func)
        fixed_targets = frozenset(
            self.builder._eval_expr_static(
                call.func,
                self.builder.module_bindings.get(scope.module, {}),
            )
        )
        if target is None and not fixed_targets:
            return
        arguments = tuple(
            self._expression_key(scope, local_names, argument)
            for argument in call.args
        )
        self._register_call(
            CallConstraint(
                scope.name,
                target,
                fixed_targets,
                arguments,
                destination,
            )
        )

    def _compile_statements(
        self, scope, local_names: set[str], statements: Iterable[ast.stmt]
    ) -> None:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = next(
                    (
                        name
                        for name, info in self.builder.functions.items()
                        if info.node is statement
                    ),
                    None,
                )
                if qualname:
                    self._add((scope.name, statement.name), {make_func(qualname)})
                continue
            if isinstance(statement, ast.ClassDef):
                qualname = next(
                    (
                        name
                        for name, info in self.builder.classes.items()
                        if info.node is statement
                    ),
                    None,
                )
                if qualname:
                    self._add((scope.name, statement.name), {make_class(qualname)})
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                for target in targets:
                    if not isinstance(target, ast.Name) or value is None:
                        continue
                    destination = (scope.name, target.id)
                    source = self._expression_key(scope, local_names, value)
                    if source is not None:
                        self._register_copy(
                            CopyConstraint(scope.name, source, destination)
                        )
                    elif isinstance(value, ast.Call):
                        self._compile_call(scope, local_names, value, destination)
                continue
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                self._compile_call(scope, local_names, statement.value, None)
                continue
            if isinstance(statement, ast.Return) and statement.value is not None:
                destination = self._return_key(scope.name)
                source = self._expression_key(scope, local_names, statement.value)
                if source is not None:
                    self._register_copy(
                        CopyConstraint(scope.name, source, destination)
                    )
                elif isinstance(statement.value, ast.Call):
                    self._compile_call(
                        scope, local_names, statement.value, destination
                    )
                break
            if isinstance(statement, (ast.Return, ast.Raise)):
                break

    def _compile_scope(self, scope_name: str) -> None:
        if scope_name in self.compiled_scopes:
            return
        self.compiled_scopes.add(scope_name)
        scope = self.builder.scopes[scope_name]
        local_names = self._scope_local_names(scope)
        for name in local_names:
            if name in scope.params or name in scope.closure_vars:
                continue
            module_values = self.builder.module_bindings.get(scope.module, {}).get(
                name, set()
            )
            if module_values:
                self._add((scope.name, name), module_values)
        self._compile_statements(scope, local_names, scope.body)

    def solve(self) -> None:
        for module_name, bindings in self.builder.module_bindings.items():
            for name, values in bindings.items():
                self._add((module_name, name), values)

        for scope_name, scope in self.builder.scopes.items():
            if self.builder.options.analyze_reachable_only:
                seed = scope_name == "main" or (
                    self.builder.options.seed_entry_file_scopes
                    and scope.module == "main"
                )
            else:
                function = self.builder.functions.get(scope_name)
                klass = self.builder.classes.get(scope_name)
                seed = (
                    scope_name in self.builder.modules
                    or (function is not None and function.parent_scope is None)
                    or (klass is not None and klass.parent_scope is None)
                )
            if seed:
                self._activate(scope_name)

        while self.activation_queue or self.queue:
            if self.activation_queue:
                self._materialize_activation(self.activation_queue.popleft())
                continue
            key, delta = self.queue.popleft()
            for constraint in tuple(self.dependents.get(key, ())):
                if constraint.owner not in self.active_scopes:
                    continue
                if isinstance(constraint, CopyConstraint):
                    self._add(constraint.target, delta)
                else:
                    self._resolve_call(constraint, delta)

        for (scope_name, name), values in self.facts.items():
            if scope_name not in self.builder.scopes:
                continue
            scope = self.builder.scopes[scope_name]
            scope_key = (scope_name, GLOBAL_CONTEXT)
            if name == "<return>":
                self.builder._merge_value_set(
                    self.builder.scope_returns[scope_key], set(values), True
                )
            elif name in scope.params or name in scope.closure_vars:
                inputs = self.builder.scope_inputs.setdefault(
                    scope_key, {parameter: set() for parameter in scope.params}
                )
                self.builder._merge_value_set(
                    inputs.setdefault(name, set()), set(values), True
                )
        for caller, callees in self.edges.items():
            caller_key = (caller, GLOBAL_CONTEXT)
            self.builder.scope_callees[caller_key].update(callees)
            for callee in callees:
                self.builder.call_dependents[(callee, GLOBAL_CONTEXT)].add(caller_key)


def run_semi_naive_presolve(builder) -> SemiNaiveConstraintSolver:
    solver = SemiNaiveConstraintSolver(builder)
    solver.solve()
    return solver


__all__ = ["SemiNaiveConstraintSolver", "run_semi_naive_presolve"]
