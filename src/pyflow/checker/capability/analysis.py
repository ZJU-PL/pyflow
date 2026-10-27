"""Defensive capability analysis layered on the k-CFA pointer solver."""

from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from pyflow.analysis.alias.kcfa import PointerAnalysis, PointerAnalysisResult
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.config import (
    DEFAULT_MAX_ITERATIONS,
)
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
    BuiltinMethodObject,
    ClassObject,
    ConstantObject,
    CoroutineObject,
    DictObject,
    FunctionObject,
    GeneratorObject,
    MethodObject,
    NativeModuleObject,
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

# Bundled stdlib models are analysed so that calls into them can be summarised,
# but their source lines are not part of the user's program.  Findings located
# in these files must never be reported as if the user had written them.
_BUNDLED_STUB_ROOT = (
    Path(__file__).resolve().parents[2] / "analysis" / "alias" / "kcfa" / "_pythonstan" / "stubs"
)


@lru_cache(maxsize=None)
def _is_bundled_stub(filename: str) -> bool:
    """Return True when ``filename`` is one of PyFlow's bundled stub models."""
    if not filename:
        return False
    try:
        Path(filename).resolve().relative_to(_BUNDLED_STUB_ROOT)
    except (OSError, ValueError):
        return False
    return True


def _detail_is_bundled_stub(location: str) -> bool:
    """Recognise ``/path/to/stub.py:line:column`` diagnostic locations."""
    filename = location.rsplit(":", 2)[0] if ":" in location else location
    return _is_bundled_stub(filename)


_DESCRIPTOR_HOOKS = ("__get__", "__set__", "__delete__")


def _normalize_descriptor_path(access_path: str) -> str:
    """Collapse solver-synthesised descriptor plumbing onto the base path.

    Attribute access is lowered through ``__get__``/``__set__``/``__delete__``
    hooks.  The synthetic hook itself is not a user operation, so findings
    should be attributed to the underlying object rather than to
    ``<object>.__get__.<return>``.
    """
    for hook in _DESCRIPTOR_HOOKS:
        access_path = access_path.replace(f".{hook}.<return>", "")
    return access_path


def _is_synthetic_descriptor_call(access_path: str, callee_name: str) -> bool:
    """Return True for descriptor-protocol calls invented by the solver."""
    if access_path.endswith(".__set_name__"):
        # ``__set_name__`` is invoked implicitly when a class is created; it is
        # never a capability the surrounding code exercises on purpose.
        return True
    if access_path.endswith(tuple(f".{hook}" for hook in _DESCRIPTOR_HOOKS)):
        return callee_name.startswith(("$descriptor_", "$optional_callee@", "$set_name@"))
    return False


_INTERNAL_CONSTRAINT_PREFIXES = (
    "$getattribute@",
    "$getattr@",
    "$setattr@",
    "$delattr@",
    "$descriptor_get@",
    "$descriptor_set@",
    "$descriptor_delete@",
    "$optional_method@",
    "$optional_callee@",
    "$set_name@",
    "$init_subclass@",
    "$new@",
    "$new_result@",
    "$bound_init@",
    "$init_base@",
    "$class@",
    "$class_result@",
    "$class_decorator@",
    "$class_decorated@",
    "$class_factory@",
    "$class_name@",
    "$class_namespace@",
    "$prepared_namespace@",
    "$original_bases@",
    "$effective_base@",
)


def _is_internal_constraint(constraint) -> bool:
    """Return True when a constraint was synthesised by the solver itself.

    Internal protocol probes use ``$<purpose>@<site>`` variable names, whereas
    user-level calls are represented by ``$call@<site>`` and three-address
    temporaries by plain ``$tmp_<n>`` names.  Their unresolved targets are
    plumbing, not gaps in the user's program.
    """
    callee = getattr(constraint, "callee", None)
    name = getattr(callee, "name", "") or ""
    return name.startswith(_INTERNAL_CONSTRAINT_PREFIXES)


class DefensiveCapabilityAnalysis:
    """Track security-sensitive objects through k-CFA points-to propagation."""

    def __init__(
        self,
        registry: CapabilityRegistry | None = None,
        *,
        k: int | None = None,
        context_policy: str | None = None,
        report_public_exports: bool = True,
        report_callable_boundaries: bool = False,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
    ) -> None:
        self.registry = registry or default_capability_registry()
        self.k = k
        self.context_policy = context_policy
        self.report_public_exports = report_public_exports
        self.report_callable_boundaries = report_callable_boundaries
        self.max_iterations = max_iterations

    def analyze_source(self, source: str) -> CapabilityAnalysisResult:
        pointer_result = PointerAnalysis(
            source,
            k=self.k,
            context_policy=self.context_policy,
            native_effects=self._pointer_effects(),
            max_iterations=self.max_iterations,
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
            max_iterations=self.max_iterations,
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
        reachability = _CapabilityReachability(state, self.registry)

        for event in pointer_result.semantic_events:
            operation, access_path = self._event_operation_path(event)
            if operation is None or access_path is None:
                continue
            patterns = self.registry.match(access_path, operation)
            if access_path in {"builtins.open", "io.open"} or access_path.endswith(".open"):
                patterns = self._filter_open_patterns(event, patterns, state, access_path)
            for pattern in patterns:
                result.findings.append(self._direct_finding(event, access_path, operation, pattern))

            if event.kind is PointerEventKind.CALL:
                result.findings.extend(self._indirect_call_findings(event, reachability))
            elif event.kind is PointerEventKind.STORE:
                result.findings.extend(self._indirect_store_findings(event, reachability))

        result.diagnostics.extend(self._unknown_diagnostics(pointer_result))
        result.diagnostics.extend(self._unresolved_call_diagnostics(pointer_result))
        result.findings.extend(self._unresolved_call_findings(pointer_result, reachability))
        if self.report_callable_boundaries:
            result.findings.extend(self._return_and_yield_findings(pointer_result, reachability))
        if self.report_public_exports:
            result.findings.extend(self._public_export_findings(pointer_result, reachability))
        result.findings = [
            finding
            for finding in result.findings
            if finding.location.line > 0 and not _is_bundled_stub(finding.location.filename)
        ]
        return result.finalize()

    @staticmethod
    def _object_path(obj) -> str | None:
        # A module object is a namespace, not a capability.  Treating it as
        # one makes ``import requests`` look like network I/O because the
        # registry's prefix query sees every member of the module.
        if isinstance(obj, NativeModuleObject):
            return None
        if isinstance(obj, NativeObject):
            return obj.access_path
        if isinstance(obj, BuiltinFunctionObject):
            return f"builtins.{obj.function_name}"
        if isinstance(obj, BuiltinMethodObject):
            receiver_path = DefensiveCapabilityAnalysis._object_path(obj.receiver)
            if receiver_path is not None:
                return f"{receiver_path}.{obj.method_name}"
            return None
        if isinstance(obj, DictObject):
            return "os.environ" if DefensiveCapabilityAnalysis._is_environ_dict(obj) else None
        if isinstance(obj, FunctionObject):
            module = getattr(obj.container_scope, "module", None)
            filename = str(getattr(getattr(module, "stmt", None), "filename", ""))
            if _is_bundled_stub(filename):
                return obj.ir.get_qualname()
        return None

    @staticmethod
    def _callable_class_path(obj) -> str | None:
        """Return a class constructor path without treating the class as a value."""
        if not isinstance(obj, ClassObject):
            return None
        module = getattr(obj.container_scope, "module", None)
        filename = str(getattr(getattr(module, "stmt", None), "filename", ""))
        if _is_bundled_stub(filename):
            return obj.ir.get_qualname()
        return None

    @staticmethod
    def _is_environ_dict(obj) -> bool:
        """Recognise the private dictionary binding used by the bundled os stub."""
        stmt = getattr(getattr(obj, "alloc_site", None), "stmt", None)
        target = getattr(stmt, "lval", None)
        value = getattr(stmt, "rval", None)
        return (
            isinstance(target, ast.Name)
            and target.id == "_pyflow_os_environ"
            and isinstance(value, ast.Dict)
        )

    def _event_operation_path(
        self,
        event: PointerEvent,
    ) -> tuple[CapabilityOperation | None, str | None]:
        base_path = self._object_path(event.abstract_object)
        if base_path is None and event.kind is PointerEventKind.CALL:
            base_path = self._callable_class_path(event.abstract_object)
        if base_path is None:
            return None, None
        if event.kind is PointerEventKind.CALL:
            callee_name = getattr(getattr(event.constraint, "callee", None), "name", "") or ""
            if _is_synthetic_descriptor_call(base_path, callee_name):
                return None, None
            return CapabilityOperation.CALL, _normalize_descriptor_path(base_path)
        base_path = _normalize_descriptor_path(base_path)
        if base_path.endswith(".__set_name__"):
            return None, None
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

    def _indirect_call_findings(self, event: PointerEvent, reachability) -> list[CapabilityFinding]:
        """Report relevant objects passed into unanalyzed external code."""
        state = reachability.state
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
                arguments = list(constraint.args) + [var for _, var in constraint.kwargs]
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
                        reachability,
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

    def _indirect_store_findings(
        self, event: PointerEvent, reachability
    ) -> list[CapabilityFinding]:
        """Report relevant objects written into unanalyzed external carriers."""
        state = reachability.state
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
            reachability,
        )

    def _return_and_yield_findings(
        self,
        pointer_result: PointerAnalysisResult,
        reachability,
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
                                location=self._location(scope, self._constraint_site(constraint)),
                                context=str(context),
                                operation=CapabilityOperation.WRITE,
                                boundary="exception propagation",
                                reason="escapes through exception propagation",
                                trace_step="raised exception or cause",
                            ),
                            reachability,
                        )
                    )
                continue
            else:
                continue
            source_var = state.get_variable(scope, context, source)
            kind = (
                EscapeKind.YIELD if isinstance(constraint, YieldConstraint) else EscapeKind.RETURN
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
                    reachability,
                )
            )
        return findings

    def _escape_findings(
        self,
        event: CapabilityEscapeEvent,
        reachability,
    ) -> list[CapabilityFinding]:
        findings = []
        follow_closures = event.kind is not EscapeKind.PUBLIC_EXPORT
        for access_path, patterns, carrier_trace in reachability.relevant(
            event.objects, follow_closures=follow_closures
        ):
            for pattern in patterns:
                findings.append(
                    CapabilityFinding(
                        location=event.location,
                        capability=pattern.capability,
                        category=pattern.category,
                        operation=event.operation,
                        access_path=access_path,
                        report_kind=CapabilityReportKind.INDIRECT,
                        reason=f"potential capability transfer: relevant object {access_path} {event.reason}",
                        context=event.context,
                        trace=(access_path, *carrier_trace, event.trace_step),
                        escape_kind=event.kind.value,
                        boundary=event.boundary,
                    )
                )
        return findings

    def _public_export_findings(
        self,
        pointer_result: PointerAnalysisResult,
        reachability,
    ) -> list[CapabilityFinding]:
        """Report relevant values exposed as public Python module globals."""
        findings: list[CapabilityFinding] = []
        state = pointer_result.state
        for scope, context, constraint in state.constraint_definitions:
            if scope.kind != "module":
                continue
            module_stmt = getattr(getattr(scope, "module", None), "stmt", None)
            if _is_bundled_stub(str(getattr(module_stmt, "filename", ""))):
                # Stub modules export their modelled functions on purpose; those
                # bindings are not user-authored public surface.
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
                        location=self._location(scope, self._constraint_site(constraint)),
                        context=str(context),
                        operation=CapabilityOperation.WRITE,
                        boundary=name,
                        reason=f"is exposed by public module binding {name}",
                        trace_step=f"module export {name}",
                    ),
                    reachability,
                )
            )
        return findings

    def _unresolved_call_findings(
        self,
        pointer_result: PointerAnalysisResult,
        reachability,
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
            if _is_internal_constraint(constraint):
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
                        reachability,
                    )
                )
        return findings

    def _filter_open_patterns(self, event, patterns, state, access_path: str):
        """Use the constant mode argument when available; otherwise report both."""
        constraint = event.constraint
        # Expanded arguments may contain the mode at an unknown position/key.
        if any(constraint.starred) or any(name is None for name, _ in constraint.kwargs):
            return patterns
        # ``p.open("w")`` binds the receiver, so the mode is the first
        # positional argument.  ``Path.open(p, "w")`` and ``open(path, "w")``
        # pass the receiver/path explicitly first.
        callee = event.abstract_object
        bound = isinstance(callee, MethodObject) and callee.instance_obj is not None
        mode_index = 0 if bound else 1
        modes = [constraint.args[mode_index]] if len(constraint.args) > mode_index else []
        modes.extend(var for name, var in constraint.kwargs if name == "mode")
        if len(modes) > 1:
            return patterns
        mode = self._constant_string(state, event.scope, event.context, modes[0]) if modes else "r"
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
        objects = tuple(state.get_points_to(ctx_var))
        if not objects or any(
            not isinstance(obj, ConstantObject) or not isinstance(obj.value, str) for obj in objects
        ):
            return None
        values = {obj.value for obj in objects}
        return next(iter(values)) if len(values) == 1 else None

    def _unknown_diagnostics(
        self,
        pointer_result: PointerAnalysisResult,
    ) -> list[CapabilityDiagnostic]:
        diagnostics = []
        locations = {}
        for scope, constraint in pointer_result.state.constraints.all():
            site = getattr(constraint, "call_site", None)
            if site is not None:
                locations[str(site)] = self._location(scope, site.statement)
        for detail in pointer_result.unknown_details():
            if detail["kind"] == "callee_empty" and any(
                prefix in (detail.get("message") or "") for prefix in _INTERNAL_CONSTRAINT_PREFIXES
            ):
                # Internal ``$<purpose>@<site>`` constraints probe optional
                # protocol hooks; an empty target means the hook is absent.
                continue
            kind = "budget" if detail["kind"] == "solver_budget" else "unknown"
            location = locations.get(detail["location"])
            if location is not None and _is_bundled_stub(location.filename):
                # Model-internal gaps in our own stdlib stubs should not make
                # a user's capability report look partial.
                continue
            if location is None and _detail_is_bundled_stub(detail["location"]):
                continue
            label = (
                f"{location.filename}:{location.line}:{location.column}"
                if location is not None
                else detail["location"]
            )
            diagnostics.append(
                CapabilityDiagnostic(
                    kind=kind,
                    message=f"{detail['kind']}: {detail['message']} ({label})",
                    location=location,
                )
            )
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
            if (scope, constraint) in observed or _is_internal_constraint(constraint):
                continue
            callee = state.get_variable(scope, scope.context, constraint.callee)
            if not state.get_points_to(callee).is_empty():
                continue
            location = self._location(scope, constraint.stmt)
            if _is_bundled_stub(location.filename):
                continue
            diagnostics.append(
                CapabilityDiagnostic(
                    kind="unknown",
                    message=f"unresolved call target: {constraint}",
                    location=location,
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
            call_site = getattr(constraint, "call_site", None)
            if call_site is not None:
                site = getattr(call_site, "statement", call_site)
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


_CLOSURE_CACHE_ENTRIES = 200_000


class _CapabilityReachability:
    """Index a solved heap once and reuse it for every potential transfer."""

    def __init__(self, state, registry: CapabilityRegistry) -> None:
        self.state = state
        self.registry = registry
        self.fields = {}
        self.patterns = {}
        self._closures: dict = {}
        self._cached_entries = 0
        for ctx_field, points_to in state._env.items():
            field_access = getattr(ctx_field, "content", ctx_field)
            if isinstance(field_access, FieldAccess):
                self.fields.setdefault(field_access.obj, []).append(
                    (str(field_access.field), points_to)
                )

    def relevant(self, roots, *, follow_closures: bool = True):
        """Follow heap fields and closure cells, retaining an explanatory path.

        Public exports deliberately stop at callables: a function that *uses*
        a capability is not itself a capability value, and descending into its
        free variables would report every helper that references ``open``.

        Closures are memoised per root object because the same value is stored
        millions of times in a large heap; the ``seen`` set still provides the
        cross-root de-duplication expected by callers.
        """
        seen = set()
        total_cached = getattr(self, "_cached_entries", 0)
        for root in roots:
            if root in seen:
                continue
            key = (root, follow_closures)
            cached = self._closures.get(key)
            if cached is None:
                cached = tuple(self._closure_from(root, follow_closures))
                if total_cached + len(cached) <= _CLOSURE_CACHE_ENTRIES:
                    self._closures[key] = cached
                    total_cached += len(cached)
                    self._cached_entries = total_cached
            for obj, access_path, patterns, trace in cached:
                if obj in seen:
                    continue
                seen.add(obj)
                if access_path is not None:
                    yield access_path, patterns, trace

    def _children(self, obj, follow_closures: bool):
        """Yield ``(child, label)`` pairs reachable from ``obj``."""
        closure_owner = obj
        if isinstance(obj, (GeneratorObject, CoroutineObject)):
            closure_owner = obj.func_obj
        if follow_closures and isinstance(closure_owner, FunctionObject):
            for name, captured_var in self.state.get_cell_vars(closure_owner).items():
                for child in self.state.get_points_to(captured_var):
                    yield child, f"closure cell {name}"
        if isinstance(obj, ClassObject):
            # Class dictionaries contain every method of the class.  They are
            # not values held by the object, and walking them turns
            # ``from pathlib import Path`` into dozens of "reachable"
            # file/network capabilities.
            return
        for label, points_to in self.fields.get(obj, ()):
            for child in points_to:
                yield child, f"carrier field {label}"

    def _closure_from(self, root, follow_closures: bool):
        """Return ``(obj, access_path, patterns, trace)`` reachable from root."""
        entries = []
        parents = {root: None}
        stack = [root]
        while stack:
            obj = stack.pop()
            if isinstance(obj, NativeModuleObject):
                # Importing a module does not exercise any of its members.
                continue
            access_path = DefensiveCapabilityAnalysis._object_path(obj)
            if access_path is not None:
                access_path = _normalize_descriptor_path(access_path)
            if access_path is not None and not access_path.endswith(".__set_name__"):
                if access_path not in self.patterns:
                    self.patterns[access_path] = self.registry.reachable(access_path)
                patterns = self.patterns[access_path]
                if patterns:
                    entries.append((obj, access_path, patterns, self._trace(obj, parents)))
            for child, label in self._children(obj, follow_closures):
                if child in parents:
                    continue
                parents[child] = (obj, label)
                stack.append(child)
        return entries

    @staticmethod
    def _trace(obj, parents) -> tuple[str, ...]:
        """Reconstruct the explanatory path for ``obj`` from parent links."""
        steps = []
        node = obj
        while True:
            link = parents.get(node)
            if link is None:
                break
            node, label = link
            steps.append(label)
        steps.reverse()
        return tuple(steps)


__all__ = ["DefensiveCapabilityAnalysis"]
