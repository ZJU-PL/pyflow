"""Isolated opt-in runtime probing for dependency resolution."""

from __future__ import annotations

import json
import subprocess
import sys


_DEFAULT_TIMEOUT_SECONDS = 5.0
_PAYLOAD_PREFIX = "__PYFLOW_RUNTIME_PROBE__:"

_PROBE_SCRIPT = r"""
import builtins
import contextlib
import json
import sys
import types

FILE_PATH = sys.argv[1]
ALLOW_STUBS = sys.argv[2] == "1"
SOURCE = sys.stdin.read()
PAYLOAD_PREFIX = "__PYFLOW_RUNTIME_PROBE__:"
PROTOCOL_STDOUT = sys.stdout

class _DiscardWriter:
    def write(self, value):
        return len(value)

    def flush(self):
        return None

def _noop(*args, **kwargs):
    return None

def _make_stub_module(module_name):
    module = types.ModuleType(module_name)
    module.__file__ = f"<stub:{module_name}>"
    module.__getattr__ = lambda name, _module_name=module_name: _noop
    return module

orig_import = builtins.__import__

def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    try:
        return orig_import(name, globals, locals, fromlist, level)
    except ImportError:
        if not ALLOW_STUBS:
            raise
        parts = [part for part in name.split(".") if part]
        if not parts:
            raise
        parent = None
        module = None
        for index in range(1, len(parts) + 1):
            fullname = ".".join(parts[:index])
            module = sys.modules.get(fullname)
            if module is None:
                module = _make_stub_module(fullname)
                sys.modules[fullname] = module
            if parent is not None:
                setattr(parent, parts[index - 1], module)
            parent = module
        return module

builtins.__import__ = _safe_import
namespace = {
    "__name__": "__pyflow_analysis__",
    "__file__": FILE_PATH,
    "input": lambda *args, **kwargs: "",
}

try:
    import os as _os
    _os.system = lambda *args, **kwargs: 0
    _os.popen = lambda *args, **kwargs: None
except Exception:
    pass

try:
    compiled = compile(SOURCE, FILE_PATH, "exec")
    with contextlib.redirect_stdout(_DiscardWriter()), contextlib.redirect_stderr(_DiscardWriter()):
        exec(compiled, namespace)
except Exception as error:
    print(
        PAYLOAD_PREFIX + json.dumps({"error": f"{type(error).__name__}: {error}"}),
        file=PROTOCOL_STDOUT,
    )
    sys.exit(1)
finally:
    builtins.__import__ = orig_import

functions = []
for name, obj in namespace.items():
    if name.startswith("_") or not callable(obj):
        continue
    code = getattr(obj, "__code__", None)
    if code is not None and getattr(code, "co_filename", None) == FILE_PATH:
        functions.append(name)

print(
    PAYLOAD_PREFIX + json.dumps({"functions": sorted(functions)}),
    file=PROTOCOL_STDOUT,
)
"""


def probe_function_names(
    source: str,
    file_path: str,
    *,
    allow_stub_imports: bool,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> list[str]:
    """Execute source in a child interpreter and report locally defined callables."""

    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                _PROBE_SCRIPT,
                file_path,
                "1" if allow_stub_imports else "0",
            ],
            input=source,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"runtime probe timed out after {timeout_seconds:g} seconds"
        ) from error

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    payload = None
    for line in reversed(stdout.splitlines()):
        if line.startswith(_PAYLOAD_PREFIX):
            try:
                payload = json.loads(line[len(_PAYLOAD_PREFIX) :])
            except json.JSONDecodeError as error:
                raise RuntimeError("runtime probe returned an invalid result") from error
            break
    if completed.returncode != 0:
        detail = payload.get("error") if isinstance(payload, dict) else None
        raise RuntimeError(detail or stderr or stdout or "runtime probe failed")
    if not isinstance(payload, dict):
        raise RuntimeError("runtime probe returned no valid result")
    return list(payload.get("functions", ()))


__all__ = ["probe_function_names"]
