"""Fail-closed runtime backstop for operations outside static Python semantics.

The guard uses CPython audit events, which are emitted below most Python-level
monkey-patching.  Audit hooks are process-global and cannot be removed; install
one only in a dedicated child process or at application startup.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import os
import sys
import threading
from typing import Any, Callable, Iterable


class CapabilityViolation(PermissionError):
    """Raised when protected execution attempts a denied capability."""

    def __init__(self, capability: str, event: str) -> None:
        super().__init__(f"denied capability {capability!r} at audit event {event!r}")
        self.capability = capability
        self.event = event


@dataclass(frozen=True)
class RuntimeCapabilityEvent:
    capability: str
    audit_event: str
    arguments: tuple[str, ...] = ()


@dataclass
class RuntimeCapabilityPolicy:
    """Allow-list policy. Unknown audit events are ignored, known ones fail closed."""

    allowed: frozenset[str] = frozenset()
    enforce: bool = True
    events: list[RuntimeCapabilityEvent] = field(default_factory=list)
    callback: Callable[[RuntimeCapabilityEvent], None] | None = None

    @classmethod
    def allowing(cls, capabilities: Iterable[str], *, enforce: bool = True):
        return cls(frozenset(capabilities), enforce=enforce)

    def permits(self, capability: str) -> bool:
        return any(fnmatchcase(capability, pattern) for pattern in self.allowed)


_PREFIX_CAPABILITIES = (
    ("subprocess.", "process.execute"),
    ("os.system", "process.execute"),
    ("os.exec", "process.execute"),
    ("os.spawn", "process.execute"),
    ("os.posix_spawn", "process.execute"),
    ("os.kill", "process.control"),
    ("socket.connect", "network.socket"),
    ("socket.bind", "network.socket"),
    ("socket.getaddrinfo", "network.dns"),
    ("socket.gethostby", "network.dns"),
    ("ctypes.dlopen", "native.access"),
    ("ctypes.dlsym", "native.access"),
    ("pickle.find_class", "deserialization.unsafe"),
    ("marshal.loads", "deserialization.unsafe"),
    ("webbrowser.open", "application.launch"),
    ("os.remove", "file.write"),
    ("os.rename", "file.write"),
    ("os.replace", "file.write"),
    ("os.mkdir", "file.write"),
    ("os.rmdir", "file.write"),
    ("os.listdir", "file.metadata"),
    ("os.scandir", "file.metadata"),
    ("os.chdir", "file.metadata"),
    ("import", "module.dynamic_import"),
)


def capability_for_audit_event(event: str, args: tuple[Any, ...]) -> str | None:
    """Map a CPython audit event to the capability vocabulary."""
    if event == "compile":
        return "code.execute"
    if event == "exec" and args:
        filename = getattr(args[0], "co_filename", "")
        if not filename or str(filename).startswith("<"):
            return "code.execute"
    if event == "open":
        mode = args[1] if len(args) > 1 else "r"
        flags = args[2] if len(args) > 2 else 0
        if isinstance(mode, str) and any(char in mode for char in "wax+"):
            return "file.write"
        if isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
            return "file.write"
        return "file.read"
    if event == "socket.__new__":
        return "network.socket"
    for prefix, capability in _PREFIX_CAPABILITIES:
        if event == prefix or event.startswith(prefix if prefix.endswith(".") else prefix + "."):
            return capability
    return None


class RuntimeCapabilityGuard:
    """Callable CPython audit hook implementing a capability allow list."""

    def __init__(self, policy: RuntimeCapabilityPolicy) -> None:
        self.policy = policy
        self._local = threading.local()

    def __call__(self, event: str, args: tuple[Any, ...]) -> None:
        if getattr(self._local, "active", False):
            return
        capability = capability_for_audit_event(event, args)
        if capability is None:
            return
        self._local.active = True
        try:
            record = RuntimeCapabilityEvent(
                capability=capability,
                audit_event=event,
                arguments=tuple(_safe_argument(value) for value in args[:4]),
            )
            self.policy.events.append(record)
            if self.policy.callback is not None:
                self.policy.callback(record)
            if self.policy.enforce and not self.policy.permits(capability):
                raise CapabilityViolation(capability, event)
        finally:
            self._local.active = False


def install_runtime_guard(policy: RuntimeCapabilityPolicy) -> RuntimeCapabilityGuard:
    """Permanently install a process-global guard and return it."""
    guard = RuntimeCapabilityGuard(policy)
    sys.addaudithook(guard)
    return guard


def _safe_argument(value: Any) -> str:
    try:
        rendered = repr(value)
    except Exception:
        rendered = f"<{type(value).__name__}>"
    return rendered[:240]


__all__ = [
    "CapabilityViolation",
    "RuntimeCapabilityEvent",
    "RuntimeCapabilityGuard",
    "RuntimeCapabilityPolicy",
    "capability_for_audit_event",
    "install_runtime_guard",
]
