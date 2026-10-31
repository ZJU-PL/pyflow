"""Defensive capability analysis layered on the k-CFA pointer solver."""

from __future__ import annotations

import ast
from dataclasses import replace
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
    BuiltinInstanceObject,
    BuiltinMethodObject,
    ClassObject,
    ConstantObject,
    CoroutineObject,
    DictObject,
    FunctionObject,
    GeneratorObject,
    InstanceObject,
    MethodObject,
    NativeModuleObject,
    NativeObject,
    TupleObject,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.variable import (
    FieldAccess,
    VariableKind,
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


@lru_cache(maxsize=4096)
def _source_line(filename: str, line: int) -> str:
    """Return the stripped source line for diagnostics, or an empty string."""
    if not filename or line <= 0:
        return ""
    try:
        with open(filename, encoding="utf-8", errors="replace") as handle:
            for index, text in enumerate(handle, start=1):
                if index == line:
                    return text.strip()[:160]
    except OSError:
        return ""
    return ""


def _detail_is_bundled_stub(location: str) -> bool:
    """Recognise ``/path/to/stub.py:line:column`` diagnostic locations."""
    filename = location.rsplit(":", 2)[0] if ":" in location else location
    return _is_bundled_stub(filename)


_DESCRIPTOR_HOOKS = ("__get__", "__set__", "__delete__")

#: Builtin types whose instances are plain values, never resource handles.
#: Mapping a returned value of one of these to ``<callee>.<return>`` would turn
#: e.g. ``content = path.read_text()`` into a spurious file capability.
_NON_HANDLE_BUILTIN_TYPES = frozenset(
    {
        "list",
        "dict",
        "tuple",
        "set",
        "frozenset",
        "str",
        "bytes",
        "bytearray",
        "int",
        "float",
        "bool",
        "complex",
        "range",
        "slice",
        "memoryview",
        "type",
        "NoneType",
    }
)

#: Capability categories whose *return value* is itself a resource the
#: caller can use later (an open file, a socket, a process).  Returns of the
#: remaining categories (``code.execute``, ``module.dynamic_import``,
#: ``deserialization.unsafe``, ...) are ordinary data: ``eval`` returns the
#: evaluated value and ``import_module`` returns the imported module.
_RETURN_IDENTITY_CATEGORIES = frozenset({"file", "network", "process"})

#: Methods that read from / write to a file-like handle.
_HANDLE_READ_METHODS = frozenset({"read", "readline", "readlines", "__iter__", "__next__"})
_HANDLE_WRITE_METHODS = frozenset({"write", "writelines", "truncate"})

#: APIs whose *second* positional argument (or ``mode`` keyword) selects
#: between reading and writing, in addition to anything ending in ``.open``.
_MODE_AWARE_OPEN_PATHS = frozenset({"builtins.open", "io.open", "zipfile.ZipFile"})


def _is_mode_aware_open(access_path: str) -> bool:
    return access_path in _MODE_AWARE_OPEN_PATHS or access_path.endswith(".open")


def _can_denote_handle(obj) -> bool:
    """Return True for abstract objects whose value may be a resource handle."""
    if isinstance(obj, BuiltinInstanceObject):
        return obj.builtin_type not in _NON_HANDLE_BUILTIN_TYPES
    if isinstance(obj, NativeObject):
        return True
    if isinstance(obj, InstanceObject):
        # Instances of user/stub classes: ``io.TextIOWrapper``/``FileIO`` are
        # handles, ``_StatResult`` is metadata.  Both are worth tracking.
        return True
    return False


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


_BUILTIN_NON_ESCAPING = frozenset(
    f"builtins.{name}"
    for name in (
        "len",
        "iter",
        "next",
        "isinstance",
        "issubclass",
        "print",
        "repr",
        "str",
        "bytes",
        "bytearray",
        "int",
        "float",
        "bool",
        "type",
        "id",
        "hash",
        "all",
        "any",
        "min",
        "max",
        "sum",
        "enumerate",
        "zip",
        "reversed",
        "sorted",
        "list",
        "tuple",
        "dict",
        "set",
        "frozenset",
        "range",
        "slice",
        "abs",
        "round",
        "format",
        "ascii",
        "bin",
        "oct",
        "hex",
        "ord",
        "chr",
        "callable",
        "dir",
        "vars",
    )
)


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
        self._return_identities: dict = {}
        self._return_capabilities: dict = {}
        self._stub_scopes: set[str] = set()

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
        self._return_identities = self._collect_return_identities(pointer_result)
        self._stub_scopes = self._bundled_stub_scope_names(pointer_result)
        reachability = _CapabilityReachability(self, state, self.registry)

        for event in pointer_result.semantic_events:
            operation, access_path = self._event_operation_path(event)
            if operation is None or access_path is None:
                continue
            patterns = self._match_patterns(access_path, operation)
            if (
                patterns
                and operation is CapabilityOperation.CALL
                and _is_mode_aware_open(access_path)
            ):
                patterns = self._filter_open_patterns(event, patterns, state, access_path)
            for pattern in patterns:
                result.findings.append(
                    self._direct_finding(event, access_path, operation, pattern, state)
                )

            if event.kind is PointerEventKind.CALL:
                result.findings.extend(self._indirect_call_findings(event, reachability))
            elif event.kind is PointerEventKind.STORE:
                result.findings.extend(self._indirect_store_findings(event, reachability))

        result.diagnostics.extend(self._unknown_diagnostics(pointer_result))
        result.diagnostics.extend(self._unresolved_call_diagnostics(pointer_result))
        result.diagnostics.extend(self._completeness_diagnostics(pointer_result))
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
        result.diagnostics = _dedupe_diagnostics(result.diagnostics)
        result.coverage = self._coverage(pointer_result)
        return result.finalize()

    def _object_path(self, obj) -> str | None:
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
            receiver_path = self._object_path(obj.receiver)
            if receiver_path is not None:
                return f"{receiver_path}.{obj.method_name}"
            return None
        if isinstance(obj, DictObject):
            return "os.environ" if self._is_environ_dict(obj) else None
        if isinstance(obj, FunctionObject):
            module = getattr(obj.container_scope, "module", None)
            filename = str(getattr(getattr(module, "stmt", None), "filename", ""))
            if _is_bundled_stub(filename):
                return obj.ir.get_qualname()
            return None
        # Resource handles returned by a capability-producing call (``open``,
        # ``Path.open`` ...) get a synthetic identity so that method calls on
        # the handle and transfers of the handle itself stay visible.
        return self._return_identities.get(obj)

    def _collect_return_identities(self, pointer_result: PointerAnalysisResult) -> dict:
        """Map objects returned by capability calls to ``<callee>.<return>``.

        The solver discards the callee identity for stub-modelled and builtin
        return values (``open`` returns ``BuiltinInstanceObject('file')``), so
        a file handle, socket or urlopen response had no access path at all
        and every transfer of it was invisible.  Re-attach the identity here,
        but only for objects that can actually denote a handle: scalar and
        container results (``read_text()`` returns ``str``) are left alone.
        """
        state = pointer_result.state
        identities: dict = {}
        self._return_capabilities = {}
        for event in pointer_result.semantic_events:
            if event.kind is not PointerEventKind.CALL:
                continue
            callee_path = self._object_path_of_callee(event)
            if callee_path is None:
                continue
            if not self.registry.reachable(callee_path):
                continue
            target = getattr(event.constraint, "target", None)
            if target is None:
                continue
            target_var = state.get_variable(event.scope, event.context, target)
            result_path = f"{callee_path}.<return>"
            capabilities = self._return_capability_set(event, callee_path, state)
            if capabilities is not None:
                capabilities = frozenset(
                    capability
                    for capability in capabilities
                    if self._capability_category(capability) in _RETURN_IDENTITY_CATEGORIES
                )
                if not capabilities:
                    # The call's return value is data, not a resource handle.
                    continue
            for obj in state.get_points_to(target_var):
                if not _can_denote_handle(obj):
                    continue
                identities.setdefault(obj, result_path)
                if capabilities is not None:
                    # Keyed by object: two ``open`` calls with different modes
                    # share the ``builtins.open.<return>`` identity string.
                    self._return_capabilities[obj] = capabilities
        return identities

    def _capability_category(self, capability: str) -> str:
        for pattern in self.registry.patterns:
            if pattern.capability == capability:
                return pattern.category
        return capability.split(".", 1)[0]

    def _return_capability_set(self, event, callee_path: str, state) -> frozenset[str] | None:
        """Refine the capabilities of a handle using the constant open mode."""
        patterns = self.registry.match(callee_path, CapabilityOperation.CALL)
        if not patterns:
            return None
        if _is_mode_aware_open(callee_path):
            patterns = self._filter_open_patterns(event, patterns, state, callee_path)
        return frozenset(pattern.capability for pattern in patterns)

    def _object_path_of_callee(self, event: PointerEvent) -> str | None:
        obj = event.abstract_object
        path = self._object_path(obj)
        if path is None:
            path = self._callable_class_path(obj)
        return path

    def _match_patterns(
        self, access_path: str, operation: CapabilityOperation
    ) -> tuple[CapabilityPattern, ...]:
        """Match a path, resolving synthetic ``<return>`` handle identities."""
        patterns = self.registry.match(access_path, operation)
        if patterns or ".<return>" not in access_path:
            return patterns
        normalized = access_path
        while ".<return>" in normalized:
            normalized = normalized.replace(".<return>", "")
        method = normalized.rsplit(".", 1)[-1]
        if method in _HANDLE_READ_METHODS:
            wanted = {"file.read"}
        elif method in _HANDLE_WRITE_METHODS:
            wanted = {"file.write"}
        else:
            # ``close``/``seek``/``__enter__`` on a handle are not a capability
            # use of their own.
            return ()
        origin = normalized.rsplit(".", 1)[0]
        for candidate in (origin, normalized):
            matched = self.registry.match(candidate, operation)
            if matched:
                filtered = tuple(p for p in matched if p.capability in wanted)
                return filtered or matched
        return ()

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
        if base_path is None and isinstance(event.abstract_object, NativeModuleObject):
            base_path = event.abstract_object.access_path
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
        state=None,
    ) -> CapabilityFinding:
        report_kind = (
            CapabilityReportKind.RUNTIME_GUARDED
            if pattern.runtime_guarded
            else CapabilityReportKind.DIRECT
        )
        return CapabilityFinding(
            location=self._event_location(event, state),
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
        if _is_internal_constraint(event.constraint):
            return []
        state = reachability.state
        callee_path = self._object_path(event.abstract_object)
        if callee_path is None or callee_path in _BUILTIN_NON_ESCAPING:
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
        # ``constraints.all()`` drops the defining context, so a call inside a
        # function invoked with a non-empty context looked up the argument in
        # the empty context and found nothing.  Use the recorded definitions.
        for scope, context, constraint in state.constraint_definitions:
            if not isinstance(constraint, CallConstraint) or (scope, constraint) in observed:
                continue
            if _is_internal_constraint(constraint):
                continue
            callee_name = getattr(getattr(constraint, "callee", None), "name", "") or ""
            if callee_name.startswith(("$call@", "$metaclass_call@")):
                # Re-dispatch of ``obj(...)`` through ``__call__``; the solver
                # tracker reports it once for genuinely non-callable values.
                continue
            callee = state.get_variable(scope, context, constraint.callee)
            if not state.get_points_to(callee).is_empty():
                continue
            arguments = list(constraint.args) + [var for _, var in constraint.kwargs]
            for argument in arguments:
                ctx_var = state.get_variable(scope, context, argument)
                findings.extend(
                    self._escape_findings(
                        CapabilityEscapeEvent(
                            kind=EscapeKind.ARGUMENT,
                            objects=tuple(state.get_points_to(ctx_var)),
                            location=self._location(scope, constraint.stmt),
                            context=str(context),
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
        if not isinstance(constraint, CallConstraint):
            return patterns
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
        stats = pointer_result.statistics()
        fixpoint_complete = bool(stats.get("fixpoint_complete", True))
        locations = {}
        for scope, constraint in pointer_result.state.constraints.all():
            site = getattr(constraint, "call_site", None)
            if site is not None:
                locations[str(site)] = self._location(scope, site.statement)
        for detail in pointer_result.unknown_details():
            if not fixpoint_complete and detail["kind"] == "callee_empty":
                # The worklist was cut short, so "empty points-to set" is not
                # evidence that the call is genuinely unresolved; the budget
                # diagnostic below reports the truncated analysis instead.
                continue
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
            if location is None and self._is_stub_detail(detail):
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

    def _bundled_stub_scope_names(self, pointer_result: PointerAnalysisResult) -> set[str]:
        """Return qualnames of scopes that live in PyFlow's bundled stubs."""
        names: set[str] = set()
        for scope, _context, _constraint in pointer_result.state.constraint_definitions:
            module = getattr(scope, "module", None)
            filename = str(getattr(getattr(module, "stmt", None), "filename", ""))
            if not _is_bundled_stub(filename):
                continue
            name = getattr(scope, "get_qualname", None)
            if not callable(name):
                name = getattr(getattr(scope, "stmt", None), "get_qualname", None)
            if callable(name):
                names.add(str(name()))
        return names

    def _user_incomplete_reasons(self, pointer_result: PointerAnalysisResult) -> list[dict]:
        """Incompleteness that can affect user code (not bundled model internals)."""
        return [
            reason
            for reason in pointer_result.incomplete_reasons()
            if reason.get("scope") not in self._stub_scopes
        ]

    def _is_stub_detail(self, detail: dict) -> bool:
        location = str(detail.get("location") or "")
        if not location:
            return False
        scope_name = location.split(":", 1)[0]
        return scope_name in self._stub_scopes or _detail_is_bundled_stub(location)

    def _coverage(self, pointer_result: PointerAnalysisResult) -> dict:
        """Return solver completeness flags so ``complete`` is auditable."""
        stats = pointer_result.statistics()
        return {
            "solver_complete": bool(stats.get("complete", False)),
            "fixpoint_complete": bool(stats.get("fixpoint_complete", False)),
            "frontend_complete": bool(stats.get("frontend_complete", False)),
            "semantic_complete": bool(stats.get("semantic_complete", False)),
            "stop_reason": pointer_result.stop_reason,
            "incomplete_kinds": sorted(
                {reason.get("kind") for reason in self._user_incomplete_reasons(pointer_result)}
            ),
        }

    def _completeness_diagnostics(
        self,
        pointer_result: PointerAnalysisResult,
    ) -> list[CapabilityDiagnostic]:
        """Surface solver incompleteness that the unknown tracker does not.

        ``status`` used to be derived only from tracker entries, so a solver
        that explicitly reported ``semantic_incomplete`` (native calls without
        an exhaustive effect summary, widening, ...) still produced
        ``status: complete``.  Emit one aggregated diagnostic per category so
        the documented meaning of ``complete`` holds.
        """
        stats = pointer_result.statistics()
        diagnostics: list[CapabilityDiagnostic] = []
        if not stats.get("frontend_complete", True):
            diagnostics.append(
                CapabilityDiagnostic(
                    kind="unsupported",
                    message=(
                        "frontend translation was incomplete; operations in the "
                        "affected scopes may be missing"
                    ),
                )
            )
        if not stats.get("semantic_complete", True) and stats.get("fixpoint_complete", True):
            # When the worklist was cut short, the budget diagnostic already
            # explains the incompleteness.
            reasons = self._user_incomplete_reasons(pointer_result)
            if not reasons:
                return diagnostics
            kinds = {reason.get("kind") for reason in reasons}
            native_only = bool(kinds) and kinds <= {"native_effect"}
            if native_only:
                # Calls into unmodelled native code are already reported
                # conservatively (every argument escapes, returns get a
                # ``<callee>.<return>`` identity), so this does not hide a
                # transfer.  Surface it as a note without flipping the status.
                diagnostics.append(
                    CapabilityDiagnostic(
                        kind="note",
                        message=(
                            f"{len(reasons)} operation(s) had no exhaustive native "
                            "effect summary; capability identity behind their "
                            "return values is opaque"
                        ),
                    )
                )
            else:
                diagnostics.append(
                    CapabilityDiagnostic(
                        kind="unknown",
                        message=(
                            "semantic model incomplete: at least one operation had no "
                            "exhaustive effect model (widening, protocol resolution, or "
                            "unmodelled lowering); capabilities behind it may be missing"
                        ),
                    )
                )
        return diagnostics

    def _unresolved_call_diagnostics(
        self,
        pointer_result: PointerAnalysisResult,
    ) -> list[CapabilityDiagnostic]:
        diagnostics: list[CapabilityDiagnostic] = []
        if not pointer_result.statistics().get("fixpoint_complete", True):
            # A truncated worklist leaves many callees empty for reasons that
            # have nothing to do with the user's code.
            return diagnostics
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
            callee_name = getattr(getattr(constraint, "callee", None), "name", "") or ""
            if callee_name.startswith(("$call@", "$metaclass_call@")) and (
                self._site_has_callable_target(state, constraint.call_site)
            ):
                # ``obj(...)`` may-call where another target resolved (``None``
                # and a decorator); the empty re-dispatch is not a gap.
                continue
            callee = state.get_variable(scope, scope.context, constraint.callee)
            if not state.get_points_to(callee).is_empty():
                continue
            location = self._location(scope, constraint.stmt)
            if _is_bundled_stub(location.filename):
                continue
            message = f"unresolved call target: {constraint}"
            source = _source_line(location.filename, location.line)
            if source:
                message = f"{message} | {source}"
            message = f"{message} ({location.filename}:{location.line}:{location.column})"
            diagnostics.append(
                CapabilityDiagnostic(kind="unknown", message=message, location=location)
            )
        return diagnostics

    @staticmethod
    def _site_has_callable_target(state, call_site) -> bool:
        """Whether some constraint for this call site resolves to a callable."""
        wanted = str(call_site)
        for scope, other in state.constraints.all():
            if not isinstance(other, CallConstraint):
                continue
            if str(getattr(other, "call_site", None)) != wanted:
                continue
            name = getattr(getattr(other, "callee", None), "name", "") or ""
            if name.startswith(("$call@", "$metaclass_call@")):
                continue
            callee = state.get_variable(scope, scope.context, other.callee)
            for obj in state.get_points_to(callee):
                if isinstance(
                    obj,
                    (
                        FunctionObject,
                        MethodObject,
                        ClassObject,
                        BuiltinFunctionObject,
                        BuiltinMethodObject,
                    ),
                ):
                    return True
        return False

    def _event_location(self, event: PointerEvent, state=None) -> SourceLocation:
        site = self._constraint_site(event.constraint)
        loc = self._location(event.scope, site)
        if _is_bundled_stub(loc.filename) and hasattr(event.context, "call_sites"):
            sm = getattr(state, "_scope_manager", None)
            for cs in reversed(event.context.call_sites):
                curr = getattr(sm, "names2scope", {}).get(getattr(cs, "scope_name", ""))
                while curr is not None and not getattr(curr, "filename", None):
                    curr = getattr(sm, "father", {}).get(curr)
                if (
                    curr is not None
                    and getattr(curr, "filename", None)
                    and not _is_bundled_stub(curr.filename)
                ):
                    call_stmt = getattr(cs, "statement", None)
                    if call_stmt is not None:
                        caller_loc = self._location(curr, call_stmt)
                        if caller_loc.line > 0:
                            return caller_loc
        return loc

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
        module = getattr(scope, "module", None)
        module_stmt = getattr(module, "stmt", None)
        filename = (
            getattr(module_stmt, "filename", None)
            or getattr(scope, "filename", None)
            or "<unknown>"
        )
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


def _dedupe_diagnostics(diagnostics: list[CapabilityDiagnostic]) -> list[CapabilityDiagnostic]:
    """Collapse diagnostics repeated once per analysed calling context.

    The solver records an unresolved call per ``(scope, constraint)`` pair, so
    a single decorator inside a function instantiated in N contexts produced N
    identical entries -- enough to turn one report into megabytes of output.
    """
    counts: dict[tuple, int] = {}
    merged: dict[tuple, CapabilityDiagnostic] = {}
    for diagnostic in diagnostics:
        key = (diagnostic.kind, diagnostic.message, diagnostic.location)
        counts[key] = counts.get(key, 0) + 1
        merged.setdefault(key, diagnostic)
    unique: list[CapabilityDiagnostic] = []
    for key, diagnostic in merged.items():
        repeated = counts[key]
        if repeated > 1:
            diagnostic = replace(
                diagnostic,
                message=f"{diagnostic.message} (repeated in {repeated} calling contexts)",
            )
        unique.append(diagnostic)
    return unique


class _CapabilityReachability:
    """Index a solved heap once and reuse it for every potential transfer."""

    def __init__(
        self, analysis: "DefensiveCapabilityAnalysis", state, registry: CapabilityRegistry
    ) -> None:
        self.analysis = analysis
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
                content = getattr(captured_var, "content", captured_var)
                if getattr(content, "kind", None) is VariableKind.GLOBAL:
                    continue
                scope = getattr(captured_var, "scope", None)
                if scope is not None and getattr(scope, "kind", None) == "module":
                    continue
                for child in self.state.get_points_to(captured_var):
                    yield child, f"closure cell {name}"
        if isinstance(obj, MethodObject) and obj.instance_obj is not None:
            # A bound method carries its ``self``; handing ``host.handler`` to
            # a plugin hands over everything reachable from the instance.
            yield obj.instance_obj, "bound method receiver"
        if isinstance(obj, (ClassObject, InstanceObject)):
            class_obj = obj if isinstance(obj, ClassObject) else getattr(obj, "class_obj", None)
            if class_obj is None or self._is_bundled_stub_class(class_obj):
                # Bundled model classes list every member (``Path.open``...);
                # walking those turns a Path *instance* into dozens of
                # spurious file capabilities.
                if isinstance(obj, ClassObject):
                    return
            else:
                for label, points_to in self.fields.get(class_obj, ()):
                    for child in points_to:
                        if self._is_class_method(class_obj, child):
                            continue
                        yield child, f"class attribute {label}"
        for label, points_to in self.fields.get(obj, ()):
            for child in points_to:
                yield child, f"carrier field {label}"

    @staticmethod
    def _is_class_method(class_obj: ClassObject, child) -> bool:
        """Return True when ``child`` is a method defined on ``class_obj``."""
        if not isinstance(child, FunctionObject):
            return False
        if getattr(child, "class_obj", None) is class_obj:
            return True
        scope = getattr(child, "container_scope", None)
        return getattr(scope, "obj", None) is class_obj

    @staticmethod
    def _is_bundled_stub_class(class_obj: ClassObject) -> bool:
        module = getattr(getattr(class_obj, "container_scope", None), "module", None)
        filename = str(getattr(getattr(module, "stmt", None), "filename", ""))
        return _is_bundled_stub(filename)

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
            access_path = self.analysis._object_path(obj)
            if access_path is not None:
                access_path = _normalize_descriptor_path(access_path)
            if access_path is not None and not access_path.endswith(".__set_name__"):
                if access_path not in self.patterns:
                    patterns = self.registry.reachable(access_path)
                    if not patterns and obj in self.analysis._return_identities:
                        # A *mapped* handle (``builtins.open.<return>``) carries
                        # the capability of the call that produced it.  Opaque
                        # native returns are deliberately excluded: the value
                        # returned by ``importlib.import_module`` is a module,
                        # not the capability to import one.
                        origin = access_path
                        while ".<return>" in origin:
                            origin = origin.replace(".<return>", "")
                        patterns = self.registry.reachable(origin)
                    self.patterns[access_path] = patterns
                patterns = self.patterns[access_path]
                if patterns:
                    allowed = self.analysis._return_capabilities.get(obj)
                    if allowed is not None:
                        patterns = tuple(p for p in patterns if p.capability in allowed)
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
