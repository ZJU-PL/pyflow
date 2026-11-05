"""Shared typeshed-backed resolution for external symbols.

The inference engine consumes external facts through a small callback.  This
module provides the default implementation backed by PyFlow's vendored
typeshed snapshot.  A single lazily-created service is shared by all engines so
stub parsing and module collection are amortized across analyses.
"""

from __future__ import annotations

import threading

from pyflow.analysis.typeinfo.core.typesystem import ProperType
from pyflow.language.modules.project_resolution import ProjectContext

_service: object | None = None
_service_lock = threading.Lock()
_resolve_lock = threading.RLock()

# Individual symbols where a receiver-aware engine model is more useful than
# the (technically accurate) stub shape.
_MODEL_OVERRIDE_SYMBOLS = frozenset({"os.environ", "os.environb"})


def _get_service():
    global _service
    if _service is not None:
        return _service
    with _service_lock:
        if _service is None:
            # Imported lazily: TypeInfoService imports the inference engine.
            from pyflow.analysis.typeinfo.query.service import TypeInfoService

            # Keep the shared resolver independent of the process CWD: only
            # the vendored typeshed (and its bundled stubs) may contribute.
            _service = TypeInfoService(ProjectContext(None, sys_path=[], smart_sys_path=False))
        return _service


def resolve_typeshed_symbol(qualified_name: str) -> ProperType | None:
    """Resolve a qualified stdlib/third-party symbol from vendored typeshed."""
    if "." not in qualified_name:
        return None
    if qualified_name in _MODEL_OVERRIDE_SYMBOLS:
        return None
    with _resolve_lock:
        return _resolve_typeshed_symbol(qualified_name)


def _resolve_typeshed_symbol(qualified_name: str) -> ProperType | None:
    service = _get_service()
    parts = qualified_name.split(".")
    # ``pkg.mod.Class.member`` has no single module boundary; find the longest
    # prefix backed by a stub, then let the service resolve dotted members.
    for index in range(len(parts) - 1, 0, -1):
        module_name = ".".join(parts[:index])
        if module_name in {
            "typing",
            "typing_extensions",
            "__future__",
        }:
            # The engine models typing special forms itself; resolving them as
            # runtime stub classes shadows Union/Optional/AsyncIterable models.
            return None
        if service.stub_resolver.resolve_path(module_name) is None:
            continue
        name = ".".join(parts[index:])
        try:
            return service.type_of(module_name, name)
        except Exception:
            # An external fact is always optional; inference must keep going.
            return None
    return None


def reset_typeshed_service() -> None:
    """Drop the shared service (used by tests that change typeshed roots)."""
    global _service
    with _service_lock:
        _service = None


def resolve_typeshed_method_kind(qualified_name: str) -> str | None:
    """Return ``instance``/``class``/``static`` for a stubbed method.

    Attribute lookup on a class object normally keeps an instance method's
    ``self`` parameter (an unbound function) but must drop a classmethod's
    ``cls``.  ``TypeInfoService`` knows the decorator, so expose it to the
    inference engine instead of guessing from the parameter list.
    """
    if "." not in qualified_name:
        return None
    parts = qualified_name.split(".")
    with _resolve_lock:
        service = _get_service()
        for index in range(len(parts) - 1, 0, -1):
            module_name = ".".join(parts[:index])
            if module_name in {"typing", "typing_extensions", "__future__"}:
                return None
            if service.stub_resolver.resolve_path(module_name) is None:
                continue
            name = ".".join(parts[index:])
            try:
                info = service.signature_of(module_name, name)
            except Exception:
                return None
            return None if info is None else info.method_kind
    return None


def resolve_typeshed_type_parameter_names(qualified_class: str) -> tuple[str, ...]:
    """Return the stub class's type-parameter names in declaration order."""
    if "." not in qualified_class:
        return ()
    parts = qualified_class.split(".")
    with _resolve_lock:
        service = _get_service()
        for index in range(len(parts) - 1, 0, -1):
            module_name = ".".join(parts[:index])
            if service.stub_resolver.resolve_path(module_name) is None:
                continue
            name = ".".join(parts[index:])
            try:
                class_info = service.class_info(f"{module_name}.{name}")
            except Exception:
                return ()
            if class_info is None:
                return ()
            return tuple(parameter.name for parameter in class_info.typ.type.type_parameters)
    return ()


def resolve_typeshed_class_members(full_name: str) -> dict[str, ProperType]:
    """Return the bound member types a stub declares for a class.

    ``full_name`` uses the runtime naming (``builtins.list``,
    ``pathlib.Path``).  Members are already receiver-bound, matching the
    representation used by ``ClassDescriptor.members``.
    """
    if "." not in full_name:
        return {}
    parts = full_name.split(".")
    with _resolve_lock:
        service = _get_service()
        for index in range(len(parts) - 1, 0, -1):
            module_name = ".".join(parts[:index])
            if module_name in {"typing", "typing_extensions", "__future__"}:
                return {}
            if service.stub_resolver.resolve_path(module_name) is None:
                continue
            name = ".".join(parts[index:])
            try:
                class_info = service.class_info(f"{module_name}.{name}")
            except Exception:
                return {}
            if class_info is None:
                return {}
            return dict(class_info.typ.type.members)
    return {}


def resolve_typeshed_declared_return(qualified_name: str) -> bool | None:
    """Whether a stubbed callable declares an explicit return annotation."""
    if "." not in qualified_name:
        return None
    parts = qualified_name.split(".")
    with _resolve_lock:
        service = _get_service()
        for index in range(len(parts) - 1, 0, -1):
            module_name = ".".join(parts[:index])
            if module_name in {"typing", "typing_extensions", "__future__"}:
                return None
            if service.stub_resolver.resolve_path(module_name) is None:
                continue
            name = ".".join(parts[index:])
            try:
                info = service.signature_of(module_name, name)
            except Exception:
                return None
            if info is None:
                return None
            return info.raw_returns is not None
    return None
