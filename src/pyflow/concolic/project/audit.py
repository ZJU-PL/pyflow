"""Runtime side-effect wall for isolated concolic workers."""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from typing import Generator


class SideEffectDetected(RuntimeError):
    """Raised when analyzed code attempts an externally visible side effect."""


_BLOCKED_OPEN_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_TRUNC
_BLOCKED_EVENTS = {
    "os.chdir",
    "os.chmod",
    "os.chown",
    "os.link",
    "os.mkdir",
    "os.remove",
    "os.rename",
    "os.rmdir",
    "os.symlink",
    "os.truncate",
    "os.unlink",
    "shutil.copyfile",
    "shutil.move",
    "subprocess.Popen",
}
_BLOCKED_PREFIXES = (
    "socket.",
    "sqlite3.",
    "ftplib.",
    "smtplib.",
    "urllib.Request",
    "webbrowser.",
)
_enabled = False
_installed = False


def _audit_hook(event: str, args: tuple[object, ...]) -> None:
    if not _enabled:
        return
    if event == "open":
        _check_open(args)
        return
    if event in _BLOCKED_EVENTS or event.startswith(_BLOCKED_PREFIXES):
        raise SideEffectDetected(f'blocked side effect: audit event "{event}"')


def _check_open(args: tuple[object, ...]) -> None:
    if len(args) < 3:
        return
    target, mode, flags = args[:3]
    if target in {"/dev/null", "nul"}:
        return
    write_mode = isinstance(mode, str) and any(character in mode for character in "wax+")
    write_flags = isinstance(flags, int) and bool(flags & _BLOCKED_OPEN_FLAGS)
    if write_mode or write_flags:
        raise SideEffectDetected(f"blocked file write: {target!r}")


def install_audit_wall() -> None:
    global _installed
    if not _installed:
        sys.addaudithook(_audit_hook)
        _installed = True


@contextmanager
def enabled_audit_wall() -> Generator[None, None, None]:
    global _enabled
    install_audit_wall()
    previous = _enabled
    previous_bytecode_setting = sys.dont_write_bytecode
    # Importing the target must remain read-only while the wall is active.
    # Otherwise CPython's best-effort ``__pycache__`` creation is
    # indistinguishable from a target calling ``os.mkdir`` in an audit hook.
    sys.dont_write_bytecode = True
    _enabled = True
    try:
        yield
    finally:
        _enabled = previous
        sys.dont_write_bytecode = previous_bytecode_setting
