"""Defensive capability analysis layered on the k-CFA pointer solver."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from pyflow.analysis.alias.kcfa import PointerAnalysis, PointerAnalysisResult
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.constraints import (
    CallConstraint,
    CopyConstraint,
    RaiseConstraint,
    ReturnConstraint,
    YieldConstraint,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.events import (
    PointerEvent,
    PointerEventKind,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.heap_model import (
    FieldKind,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import (
    BuiltinFunctionObject,
    ConstantObject,
    CoroutineObject,
    FunctionObject,
    GeneratorObject,
    NativeObject,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.variable import (
    FieldAccess,
)

from .defaults import default_capability_registry
from .escape import CapabilityEscapeEvent, EscapeKind
from .effects import ExternalEffectKind
from .model import (
    CapabilityAnalysisResult,
    CapabilityDiagnostic,
    CapabilityFinding,
    CapabilityOperation,
    CapabilityReportKind,
    SourceLocation,
)
from .registry import CapabilityPattern, CapabilityRegistry


class DefensiveCapabilityAnalysis:
    """Track security-sensitive objects through k-CFA points-to propagation."""

    def __init__(
        self,
        registry: CapabilityRegistry | None = None,
        *,
        k: int = 1,
        context_policy: str | None = None,
        report_public_exports: bool = True,
    ) -> None:
        self.registry = registry or default_capability_registry()
        self.k = k
        self.context_policy = context_policy
        self.report_public_exports = report_public_exports

    def analyze_source(self, source: str) -> CapabilityAnalysisResult:
        pointer_result = PointerAnalysis(
            source,
            k=self.k,
            context_policy=self.context_policy,
            native_effects=self._pointer_effects(),
        ).run()
        return self.analyze_pointer_result(pointer_result)

    def analyze_project(
        self,
        entry_file: str | Path,
        *,
        project_path: str | Path | None = None,
        library_paths: Iterable[str | Path] = (),
        import_level: int = -1,
    ) -> CapabilityAnalysisResult:
        pointer_result = PointerAnalysis.from_project(
            entry_file,
            project_path=project_path,
            library_paths=tuple(library_paths),
            k=self.k,
            context_policy=self.context_policy,
            native_effects=self._pointer_effects(),
            import_level=import_level,
        ).run()
        return self.analyze_pointer_result(pointer_result)

    def _pointer_effects(self) -> tuple[dict, ...]:
        return tuple(effect.to_pointer_effect() for effect in self.registry.effects)

    def analyze_pointer_result(
        self,
        pointer_result: PointerAnalysisResult,
    ) -> CapabilityAnalysisResult:
        result = CapabilityAnalysisResult()
        state = pointer_result.state

        for event in pointer_result.semantic_events:
            operation, access_path = self._event_operation_path(event)
            if operation is None or access_path is None:
                continue
            patterns = self.registry.match(access_path, operation)
            if access_path in {"builtins.open", "io.open"}:
                patterns = self._filter_open_patterns(event, patterns, state)
            for pattern in patterns:
                result.findings.append(
                    self._direct_finding(event, access_path, operation, pattern)
                )

            if event.kind is PointerEventKind.CALL:
                result.findings.extend(self._indirect_call_findings(event, state))
            elif event.kind is PointerEventKind.STORE:
                result.findings.extend(self._indirect_store_findings(event, state))

        result.diagnostics.extend(self._unknown_diagnostics(pointer_result))
        result.findings.extend(self._unresolved_call_findings(pointer_result))
        result.findings.extend(self._return_and_yield_findings(pointer_result))
        if self.report_public_exports:
            result.findings.extend(self._public_export_findings(pointer_result))
        return result.finalize()

    @staticmethod
    def _object_path(obj) -> str | None:
        if isinstance(obj, NativeObject):
            return obj.access_path
        if isinstance(obj, BuiltinFunctionObject):
            return f"builtins.{obj.function_name}"
        if isinstance(obj, FunctionObject):
            module = getattr(obj.container_scope, "module", None)
            filename = str(getattr(getattr(module, "stmt", None), "filename", ""))
            if "/stubs/" in filename or "\\stubs\\" in filename:
                return obj.ir.get_qualname()
        return None

    def _event_operation_path(
        self,
        event: PointerEvent,
    ) -> tuple[CapabilityOperation | None, str | None]:
        base_path = self._object_path(event.abstract_object)
        if base_path is None:
            return None, None
        if event.kind is PointerEventKind.CALL:
            return CapabilityOperation.CALL, base_path
        field = getattr(event.constraint, "field", None)
        if field is None:
            child = "*"
        elif field.kind in {FieldKind.ATTRIBUTE, FieldKind.KEY}:
            child = field.name or "*"
        else:
            child = "*"
        access_path = f"{base_path}.{child}"
        if event.kind is PointerEventKind.LOAD:
            return CapabilityOperation.READ, access_path
        if event.kind is PointerEventKind.STORE:
            return CapabilityOperation.WRITE, access_path
        return None, None

    def _direct_finding(
        self,
        event: PointerEvent,
        access_path: str,
        operation: CapabilityOperation,
        pattern: CapabilityPattern,
    ) -> CapabilityFinding:
        report_kind = (
            CapabilityReportKind.RUNTIME_GUARDED
            if pattern.runtime_guarded
            else CapabilityReportKind.DIRECT
        )
        return CapabilityFinding(
            location=self._event_location(event),
            capability=pattern.capability,
            category=pattern.category,
            operation=operation,
            access_path=access_path,
            report_kind=report_kind,
            reason=f"{operation.value} resolves to sensitive object {access_path}",
            context=str(event.context),
            trace=(access_path,),
        )

    def _indirect_call_findings(self, event: PointerEvent, state) -> list[CapabilityFinding]:
        """Report relevant objects passed into unanalyzed external code."""
        callee_path = self._object_path(event.abstract_object)
        if callee_path is None:
            return []
        constraint = event.constraint
        findings: list[CapabilityFinding] = []
        effects = self.registry.effects_for(callee_path)
        boundary_effects = tuple(
            effect
            for effect in effects
            if effect.kind
            not in {ExternalEffectKind.RETURN_ARGUMENT, ExternalEffectKind.RETURN_RECEIVER}
        )
        if not boundary_effects:
            boundary_effects = (None,)
        for effect in boundary_effects:
            if effect is None:
                arguments = list(constraint.args) + [
                    var for _, var in constraint.kwargs
                ]
                kind = EscapeKind.ARGUMENT
                reason = f"escapes through unanalyzed call {callee_path}"
                trace_step = f"argument to {callee_path}"
            else:
                arguments = self._effect_variables(constraint, effect.arguments)
                kind, action = self._effect_escape_description(effect.kind)
                reason = f"{action} by external call {callee_path}"
                trace_step = f"{effect.kind.value} at {callee_path}"
            for argument in arguments:
                ctx_var = state.get_variable(event.scope, event.context, argument)
                findings.extend(
                    self._escape_findings(
                        CapabilityEscapeEvent(
                            kind=kind,
                            objects=tuple(state.get_points_to(ctx_var)),
                            location=self._event_location(event),
                            context=str(event.context),
                            operation=CapabilityOperation.CALL,
                            boundary=callee_path,
                            reason=reason,
                            trace_step=trace_step,
                        ),
                        state,
                    )
                )
        return findings

    @staticmethod
    def _effect_variables(constraint, selectors):
        keyword_map = dict(constraint.kwargs)
        variables = []
        for selector in selectors:
            if selector == "*":
                variables.extend(constraint.args)
                variables.extend(keyword_map.values())
            elif isinstance(selector, int) and 0 <= selector < len(constraint.args):
                variables.append(constraint.args[selector])
            elif isinstance(selector, str) and selector in keyword_map:
                variables.append(keyword_map[selector])
        return variables

    @staticmethod
    def _effect_escape_description(kind: ExternalEffectKind):
        if kind is ExternalEffectKind.INVOKE_CALLBACK:
            return EscapeKind.CALLBACK_REGISTRATION, "may be invoked as a callback"
        if kind is ExternalEffectKind.SPAWN_CALLBACK:
            return EscapeKind.TASK_SPAWN, "may execute in a spawned task or process"
        if kind is ExternalEffectKind.SERIALIZE_ARGUMENT:
            return EscapeKind.SERIALIZATION, "may be serialized"
        return EscapeKind.ARGUMENT, "may be retained"

    def _indirect_store_findings(self, event: PointerEvent, state) -> list[CapabilityFinding]:
        """Report relevant objects written into unanalyzed external carriers."""
        carrier_path = self._object_path(event.abstract_object)
        if carrier_path is None:
            return []
        source = getattr(event.constraint, "source", None)
        if source is None:
            return []
        source_var = state.get_variable(event.scope, event.context, source)
        return self._escape_findings(
            CapabilityEscapeEvent(
                kind=EscapeKind.FIELD_STORE,
                objects=tuple(state.get_points_to(source_var)),
                location=self._event_location(event),
                context=str(event.context),
                operation=CapabilityOperation.WRITE,
                boundary=carrier_path,
                reason=f"is stored into unanalyzed carrier {carrier_path}",
                trace_step=f"store into {carrier_path}",
            ),
            state,
        )

    def _return_and_yield_findings(
        self,
        pointer_result: PointerAnalysisResult,
    ) -> list[CapabilityFinding]:
        """Report relevant values crossing callable return/yield boundaries."""
        findings: list[CapabilityFinding] = []
        state = pointer_result.state
        for scope, context, constraint in state.constraint_definitions:
            if isinstance(constraint, CopyConstraint) and constraint.target.name == "$return":
                source = constraint.source
                suffix = "is returned across a callable boundary"
                trace = "function return"
            elif isinstance(constraint, ReturnConstraint):
                source = constraint.callee_return
                suffix = "is returned across a callable boundary"
                trace = "function return"
            elif isinstance(constraint, YieldConstraint) and constraint.value is not None:
                source = constraint.value
                suffix = "is yielded across a generator boundary"
                trace = "generator yield"
            elif isinstance(constraint, RaiseConstraint):
                for source in (constraint.exception, constraint.cause):
                    if source is None:
                        continue
                    source_var = state.get_variable(scope, context, source)
                    findings.extend(
                        self._escape_findings(
                            CapabilityEscapeEvent(
                                kind=EscapeKind.RAISE,
                                objects=tuple(state.get_points_to(source_var)),
                                location=self._location(
                                    scope, self._constraint_site(constraint)
                                ),
                                context=str(context),
                                operation=CapabilityOperation.WRITE,
                                boundary="exception propagation",
                                reason="escapes through exception propagation",
                                trace_step="raised exception or cause",
                            ),
                            state,
                        )
                    )
                continue
            else:
                continue
            source_var = state.get_variable(scope, context, source)
            kind = (
                EscapeKind.YIELD
                if isinstance(constraint, YieldConstraint)
                else EscapeKind.RETURN
            )
            findings.extend(
                self._escape_findings(
                    CapabilityEscapeEvent(
                        kind=kind,
                        objects=tuple(state.get_points_to(source_var)),
                        location=self._location(scope, self._constraint_site(constraint)),
                        context=str(context),
                        operation=CapabilityOperation.WRITE,
                        boundary=trace,
                        reason=suffix,
                        trace_step=trace,
                    ),
                    state,
                )
            )
        return findings

    def _escape_findings(
        self,
        event: CapabilityEscapeEvent,
        state,
    ) -> list[CapabilityFinding]:
        findings = []
        for access_path, carrier_trace in self._relevant_reachable(event.objects, state):
            for pattern in self.registry.reachable(access_path):
                findings.append(
                    CapabilityFinding(
                        location=event.location,
                        capability=pattern.capability,
                        category=pattern.category,
                        operation=event.operation,
                        access_path=access_path,
                        report_kind=CapabilityReportKind.INDIRECT,
                        reason=f"relevant object {access_path} {event.reason}",
                        context=event.context,
                        trace=(access_path, *carrier_trace, event.trace_step),
                        escape_kind=event.kind.value,
                        boundary=event.boundary,
                    )
                )
        return findings

    def _relevant_reachable(self, roots, state):
        """Find relevant objects transitively reachable through heap carriers."""
        worklist = [(obj, ()) for obj in roots]
        seen = set()
        while worklist:
            obj, trace = worklist.pop()
            if obj in seen:
                continue
            seen.add(obj)
            access_path = self._object_path(obj)
            if access_path is not None and self.registry.reachable(access_path):
                yield access_path, trace
            closure_owner = obj
            if isinstance(obj, (GeneratorObject, CoroutineObject)):
                closure_owner = obj.func_obj
            if isinstance(closure_owner, FunctionObject):
                for name, captured_var in state.get_cell_vars(closure_owner).items():
                    worklist.extend(
                        (child, (*trace, f"closure cell {name}"))
                        for child in state.get_points_to(captured_var)
                    )
            for ctx_field, points_to in state._env.items():
                field_access = getattr(ctx_field, "content", ctx_field)
                if not isinstance(field_access, FieldAccess) or field_access.obj != obj:
                    continue
                label = str(field_access.field)
                worklist.extend(
                    (child, (*trace, f"carrier field {label}"))
                    for child in points_to
                )

    def _public_export_findings(
        self,
        pointer_result: PointerAnalysisResult,
    ) -> list[CapabilityFinding]:
        """Report relevant values exposed as public Python module globals."""
        findings: list[CapabilityFinding] = []
        state = pointer_result.state
        for scope, context, constraint in state.constraint_definitions:
            if scope.kind != "module":
                continue
            target = getattr(constraint, "target", None)
            if target is None:
                continue
            name = getattr(target, "name", "")
            if not name or name.startswith(("_", "$")):
                continue
            ctx_var = state.get_variable(scope, context, target)
            findings.extend(
                self._escape_findings(
                    CapabilityEscapeEvent(
                        kind=EscapeKind.PUBLIC_EXPORT,
                        objects=tuple(state.get_points_to(ctx_var)),
                        location=self._location(
                            scope, self._constraint_site(constraint)
                        ),
                        context=str(context),
                        operation=CapabilityOperation.WRITE,
                        boundary=name,
                        reason=f"is exposed by public module binding {name}",
                        trace_step=f"module export {name}",
                    ),
                    state,
                )
            )
        return findings

    def _unresolved_call_findings(
        self,
        pointer_result: PointerAnalysisResult,
    ) -> list[CapabilityFinding]:
        """Conservatively report relevant arguments at calls with no target."""
        findings: list[CapabilityFinding] = []
        state = pointer_result.state
        observed = {
            (event.scope, event.constraint)
            for event in pointer_result.semantic_events
            if event.kind is PointerEventKind.CALL
        }
        for scope, constraint in state.constraints.all():
            if not isinstance(constraint, CallConstraint) or (scope, constraint) in observed:
                continue
            callee = state.get_variable(scope, scope.context, constraint.callee)
            if not state.get_points_to(callee).is_empty():
                continue
            arguments = list(constraint.args) + [var for _, var in constraint.kwargs]
            for argument in arguments:
                ctx_var = state.get_variable(scope, scope.context, argument)
                findings.extend(
                    self._escape_findings(
                        CapabilityEscapeEvent(
                            kind=EscapeKind.ARGUMENT,
                            objects=tuple(state.get_points_to(ctx_var)),
                            location=self._location(scope, constraint.stmt),
                            context=str(scope.context),
                            operation=CapabilityOperation.CALL,
                            boundary="unresolved call",
                            reason="escapes through an unresolved call target",
                            trace_step="argument to unresolved call",
                        ),
                        state,
                    )
                )
        return findings

    def _filter_open_patterns(self, event, patterns, state):
        """Use the constant mode argument when available; otherwise report both."""
        args = event.constraint.args
        if len(args) < 2:
            mode = "r"
        else:
            mode = self._constant_string(state, event.scope, event.context, args[1])
        if mode is None:
            return patterns
        wants_write = any(token in mode for token in "wax+")
        wants_read = "r" in mode or "+" in mode or not wants_write
        return tuple(
            pattern
            for pattern in patterns
            if (pattern.capability == "file.read" and wants_read)
            or (pattern.capability == "file.write" and wants_write)
        )

    @staticmethod
    def _constant_string(state, scope, context, variable) -> str | None:
        ctx_var = state.get_variable(scope, context, variable)
        values = {
            obj.value
            for obj in state.get_points_to(ctx_var)
            if isinstance(obj, ConstantObject) and isinstance(obj.value, str)
        }
        return next(iter(values)) if len(values) == 1 else None

    def _unknown_diagnostics(
        self,
        pointer_result: PointerAnalysisResult,
    ) -> list[CapabilityDiagnostic]:
        diagnostics = []
        for detail in pointer_result.unknown_details():
            kind = "budget" if detail["kind"] == "solver_budget" else "unknown"
            diagnostics.append(CapabilityDiagnostic(
                kind=kind,
                message=f"{detail['kind']}: {detail['message']} ({detail['location']})",
            ))
        return diagnostics

    def _unresolved_call_diagnostics(
        self,
        pointer_result: PointerAnalysisResult,
    ) -> list[CapabilityDiagnostic]:
        diagnostics: list[CapabilityDiagnostic] = []
        state = pointer_result.state
        observed = {
            (event.scope, event.constraint)
            for event in pointer_result.semantic_events
            if event.kind is PointerEventKind.CALL
        }
        for scope, constraint in state.constraints.all():
            if not isinstance(constraint, CallConstraint):
                continue
            if (scope, constraint) in observed:
                continue
            callee = state.get_variable(scope, scope.context, constraint.callee)
            if not state.get_points_to(callee).is_empty():
                continue
            diagnostics.append(
                CapabilityDiagnostic(
                    kind="unknown",
                    message=f"unresolved call target: {constraint}",
                    location=self._location(scope, constraint.stmt),
                )
            )
        return diagnostics

    def _event_location(self, event: PointerEvent) -> SourceLocation:
        site = self._constraint_site(event.constraint)
        return self._location(event.scope, site)

    @staticmethod
    def _constraint_site(constraint):
        site = getattr(constraint, "stmt", None) or getattr(constraint, "site", None)
        if site is None:
            site = getattr(getattr(constraint, "alloc_site", None), "stmt", None)
        return site

    @staticmethod
    def _location(scope, site) -> SourceLocation:
        module = scope.module.stmt
        filename = getattr(module, "filename", "<unknown>")
        ast_node = site.get_ast() if site is not None and hasattr(site, "get_ast") else None
        # TAC call assignments can inherit a synthetic line while their callee
        # expression retains the original source location.
        call = getattr(site, "call", None)
        call_func = getattr(call, "func", None)
        if getattr(call_func, "lineno", 0):
            ast_node = call_func
        return SourceLocation(
            filename=str(filename),
            line=int(getattr(ast_node, "lineno", 0) or 0),
            column=int(getattr(ast_node, "col_offset", 0) or 0),
            end_line=int(getattr(ast_node, "end_lineno", 0) or 0),
            end_column=int(getattr(ast_node, "end_col_offset", 0) or 0),
        )


__all__ = ["DefensiveCapabilityAnalysis"]
