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
