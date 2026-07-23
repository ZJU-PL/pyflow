"""Isolated opt-in runtime probing for dependency resolution."""

from __future__ import annotations

import json
import subprocess
import sys


_PROBE_SCRIPT = r"""
import builtins
import json
import sys
import types

FILE_PATH = sys.argv[1]
ALLOW_STUBS = sys.argv[2] == "1"
SOURCE = sys.stdin.read()

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
    exec(compiled, namespace)
except Exception as error:
    print(json.dumps({"error": f"{type(error).__name__}: {error}"}))
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

print(json.dumps({"functions": sorted(functions)}))
"""


def probe_function_names(
    source: str,
    file_path: str,
    *,
    allow_stub_imports: bool,
) -> list[str]:
    """Execute source in a child interpreter and report locally defined callables."""

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
    )
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        raise RuntimeError(stderr or stdout or "runtime probe failed")
    payload = json.loads(stdout or "{}")
    return list(payload.get("functions", ()))


__all__ = ["probe_function_names"]
