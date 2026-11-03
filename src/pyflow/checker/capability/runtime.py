"""Optional observation and denial of classified CPython audit events.

Python-level audit hooks are not a sandbox for malicious code. Unclassified
events are ignored, and the hook does not validate static capability transfers.
Hooks are process-global and cannot be removed through the public API; install
one only in a dedicated child process or at application startup.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import os
import sys
import threading
from typing import Any, Callable, Iterable


class CapabilityViolation(BaseException):
    """Raised when the hook observes a classified, denied operation.

    Deliberately *not* an ``OSError``/``PermissionError``: ordinary code (and
    the import machinery, which maps ``OSError`` to a failed module lookup)
    routinely catches those, which silently converted a denial into a
    ``ModuleNotFoundError`` or into a swallowed ``except OSError: pass``.
    A denied capability must not be catchable by ``except Exception``.
    """

    def __init__(self, capability: str, event: str) -> None:
        super().__init__(f"denied capability {capability!r} at audit event {event!r}")
        self.capability = capability
        self.event = event


@dataclass(frozen=True)
class RuntimeCapabilityEvent:
    capability: str
    audit_event: str
    arguments: tuple[str, ...] = ()
    decision: str = "allow"
    capabilities: tuple[str, ...] = ()


#: A static ``network.io`` finding covers the underlying socket/DNS audit
#: events.  The reverse is deliberately not true: allowing only
#: ``network.socket`` does not grant the broader ``network.io`` capability.
_NETWORK_POLICY_ALIASES = {
    "network.socket": ("network.io",),
    "network.dns": ("network.io",),
}


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
        candidates = (capability, *_NETWORK_POLICY_ALIASES.get(capability, ()))
        return any(
            fnmatchcase(candidate, pattern) for candidate in candidates for pattern in self.allowed
        )


_PREFIX_CAPABILITIES = (
    ("subprocess.", "process.execute"),
    ("os.system", "process.execute"),
    ("os.exec", "process.execute"),
    ("os.spawn", "process.execute"),
    ("os.posix_spawn", "process.execute"),
    ("os.fork", "process.execute"),
    ("os.forkpty", "process.execute"),
    ("os.kill", "process.control"),
    ("os.killpg", "process.control"),
    ("socket.connect", "network.socket"),
    ("socket.bind", "network.socket"),
    ("socket.getaddrinfo", "network.dns"),
    ("socket.gethostby", "network.dns"),
    ("ctypes.dlopen", "native.access"),
    ("ctypes.dlsym", "native.access"),
    ("mmap.__new__", "native.access"),
    ("pickle.find_class", "deserialization.unsafe"),
    ("marshal.loads", "deserialization.unsafe"),
    ("webbrowser.open", "application.launch"),
    ("os.startfile", "application.launch"),
    ("os.remove", "file.write"),
    ("os.unlink", "file.write"),
    ("os.rename", "file.write"),
    ("os.replace", "file.write"),
    ("os.mkdir", "file.write"),
    ("os.rmdir", "file.write"),
    ("os.link", "file.write"),
    ("os.symlink", "file.write"),
    ("os.truncate", "file.write"),
    ("shutil.copyfile", "file.write"),
    ("shutil.copytree", "file.write"),
    ("shutil.move", "file.write"),
    ("shutil.rmtree", "file.write"),
    ("tempfile.mkstemp", "file.write"),
    ("tempfile.mkdtemp", "file.write"),
    ("os.listdir", "file.metadata"),
    ("os.scandir", "file.metadata"),
    ("os.chdir", "file.metadata"),
    ("os.chmod", "file.metadata"),
    ("os.chown", "file.metadata"),
    ("os.chroot", "file.metadata"),
    ("os.utime", "file.metadata"),
    ("os.access", "file.metadata"),
    ("os.getxattr", "file.metadata"),
    ("os.setxattr", "file.metadata"),
    ("os.lockf", "file.metadata"),
    ("os.putenv", "information.environment"),
    ("os.unsetenv", "information.environment"),
    ("import", "module.dynamic_import"),
)


_IMPORT_EVENTS = frozenset({"open", "compile", "exec", "marshal.loads", "os.listdir", "os.scandir"})
_IMPORT_FRAME_ROOTS = (
    "importlib._bootstrap",
    "importlib._bootstrap_external",
    "importlib.machinery",
    "zipimport",
)


def _is_import_machinery_frame(frame: Any) -> bool:
    """Return True for a frame belonging to CPython's import machinery."""
    name = ""
    getter = getattr(getattr(frame, "f_globals", None), "get", None)
    if callable(getter):
        name = str(getter("__name__", "") or "")
    return any(name == root or name.startswith(root + ".") for root in _IMPORT_FRAME_ROOTS)


def _in_import_machinery() -> bool:
    """Detect whether the current audit event came from module loading.

    The import system reads source/pyc files, compiles source, and unmarshals
    bytecode.  Those are implementation details of the already-classified
    ``import`` event, not separate user choices to read a file, execute code,
    or deserialize untrusted data.
    """
    try:
        frame = sys._getframe(1)
    except (AttributeError, ValueError):
        return False
    # Skip the guard/classification frames.  Only the nearest external frame
    # determines ownership: user code executed at import time must not be
    # mistaken for importlib's own file/compile activity merely because an
    # importlib frame exists further down the stack.
    while frame is not None and frame.f_globals.get("__name__") == __name__:
        frame = frame.f_back
    return _is_import_machinery_frame(frame) if frame is not None else False


def capability_for_audit_event(event: str, args: tuple[Any, ...]) -> str | None:
    """Map a CPython audit event to the capability vocabulary."""
    if event in _IMPORT_EVENTS and _in_import_machinery():
        return None
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


def capabilities_for_audit_event(event: str, args: tuple[Any, ...]) -> frozenset[str]:
    """Return every capability required by an audit event.

    Most events require exactly one capability.  Read/write file modes such as
    ``r+`` and ``os.O_RDWR`` require both, and a policy must allow both.
    """
    if event in _IMPORT_EVENTS and _in_import_machinery():
        return frozenset()
    if event == "open":
        mode = args[1] if len(args) > 1 else "r"
        flags = args[2] if len(args) > 2 else 0
        if isinstance(mode, str):
            write = any(char in mode for char in "wax+")
            read = "r" in mode or "+" in mode or not write
            required = set()
            if read:
                required.add("file.read")
            if write:
                required.add("file.write")
            if required:
                return frozenset(required)
        if isinstance(flags, int):
            access = flags & os.O_ACCMODE if hasattr(os, "O_ACCMODE") else flags & 3
            required = set()
            if access != os.O_WRONLY:
                required.add("file.read")
            if access == os.O_WRONLY or access == os.O_RDWR:
                required.add("file.write")
            if flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                required.add("file.write")
            if required:
                return frozenset(required)
    capability = capability_for_audit_event(event, args)
    return frozenset((capability,)) if capability is not None else frozenset()


class RuntimeCapabilityGuard:
    """Callable CPython audit hook implementing a capability allow list."""

    def __init__(self, policy: RuntimeCapabilityPolicy) -> None:
        self.policy = policy
        self._local = threading.local()

    def __call__(self, event: str, args: tuple[Any, ...]) -> None:
        if getattr(self._local, "active", False):
            return
        capabilities = capabilities_for_audit_event(event, args)
        if not capabilities:
            return
        self._local.active = True
        try:
            denied_capability = next(
                (
                    capability
                    for capability in sorted(capabilities)
                    if self.policy.enforce and not self.policy.permits(capability)
                ),
                None,
            )
            denied = denied_capability is not None
            record = RuntimeCapabilityEvent(
                capability=denied_capability or capability_for_audit_event(event, args) or "",
                audit_event=event,
                arguments=tuple(_safe_argument(value) for value in args[:4]),
                decision="deny" if denied else "allow",
                capabilities=tuple(sorted(capabilities)),
            )
            self.policy.events.append(record)
            if self.policy.callback is not None:
                self.policy.callback(record)
            if denied:
                raise CapabilityViolation(denied_capability, event)
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
    "capabilities_for_audit_event",
    "install_runtime_guard",
]
