"""
Selective concolic execution (concrete CPython run + structured trace).

This module implements the concrete side of the hybrid workflow described in
python-barrier-certificate-theory.md §4.4–§4.11:

- Run the program concretely on CPython.
- Record opcode-level trace for *owned* code (the program under analysis).
- Record call-interface observations for calls from owned code into non-owned
  (library) code, including C calls (best-effort).

The resulting trace can be converted into an ExecutionOracle that guides the
symbolic VM to replay the same path while applying contracts/summaries at call
sites. This is for witness production and debugging, not for proving SAFE.
"""

from __future__ import annotations

import io
import os
import sys
import types
from collections import defaultdict
from dataclasses import dataclass, field
from contextlib import contextmanager
from typing import Any, Callable, DefaultDict, Optional

from ..semantics.oracles import CallObservation, CallSiteKey
from .concolic import ConcreteInput


@dataclass(frozen=True)
class CodeKey:
    """Stable identifier for a code object (used for grouping offsets)."""

    filename: str
    qualname: str
    firstlineno: int

    @staticmethod
    def from_code(code: types.CodeType) -> "CodeKey":
        qualname = getattr(code, "co_qualname", code.co_name)
        return CodeKey(code.co_filename, qualname, code.co_firstlineno)


@dataclass
class SelectiveConcolicTrace:
    """
    Result of a selective concolic run.

    - owned_offsets: opcode offsets executed in owned code, grouped by CodeKey
    - call_observations: library call observations keyed by callsite
    - exception: the top-level exception that terminated execution (if any)
    """

    owned_filenames: set[str]
    owned_offsets: dict[CodeKey, list[int]] = field(default_factory=dict)
    call_observations: dict[CallSiteKey, list[CallObservation]] = field(default_factory=dict)
    call_events: list[tuple[CallSiteKey, CallObservation]] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exception_type: Optional[str] = None
    exception_repr: Optional[str] = None


def _normalize_callable_id(callable_obj: Any) -> str:
    """
    Best-effort stable identifier for a callable.

    Convention:
    - builtins: "len", "dict.get", ...
    - module functions/builtins: "math.sqrt", "json.dumps", ...
    """
    module = getattr(callable_obj, "__module__", None)
    qualname = getattr(callable_obj, "__qualname__", None) or getattr(callable_obj, "__name__", None)
    if not qualname:
        qualname = type(callable_obj).__name__

    if module and module not in {"builtins", "__main__"}:
        return f"{module}.{qualname}"
    return qualname


def _normalize_frame_callable_id(frame: types.FrameType) -> str:
    """
    Best-effort stable identifier for a Python function call, from the callee frame.
    """
    module = frame.f_globals.get("__name__", None)
    qualname = getattr(frame.f_code, "co_qualname", frame.f_code.co_name)
    if module and module not in {"builtins", "__main__"}:
        return f"{module}.{qualname}"
    return qualname


class SelectiveConcolicExecutor:
    """
    Concrete executor that records:
    - opcode offsets for owned code
    - call observations for library calls from owned code
    """

    def __init__(self, max_opcode_events: int = 200_000):
        self.max_opcode_events = max_opcode_events

    def execute(
        self,
        code_obj: types.CodeType,
        concrete_input: ConcreteInput,
        owned_filenames: set[str],
    ) -> SelectiveConcolicTrace:
        """
        Execute code_obj concretely and record a selective trace.
        """
        owned_offsets: DefaultDict[CodeKey, list[int]] = defaultdict(list)
        call_observations: DefaultDict[CallSiteKey, list[CallObservation]] = defaultdict(list)
        call_events: list[tuple[CallSiteKey, CallObservation]] = []
        last_call_event_index: dict[CallSiteKey, int] = {}

        owned_realpaths = {_safe_realpath(p) for p in owned_filenames}

        def is_owned(code: types.CodeType) -> bool:
            return _safe_realpath(code.co_filename) in owned_realpaths

        # Capture stdout/stderr
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        # Save and extend sys.path for imports
        old_path = sys.path.copy()
        old_modules = sys.modules
        exception_type: Optional[str] = None
        exception_repr: Optional[str] = None
        file_dir: Optional[str] = None

        try:
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture

            if concrete_input.file_path:
                file_dir = os.path.dirname(os.path.abspath(concrete_input.file_path))
                if file_dir and file_dir not in sys.path:
                    sys.path.insert(0, file_dir)

            globals_dict = self._build_globals(concrete_input, code_obj)
            with _monitor_selective_concolic(
                entry_code=code_obj,
                is_owned=is_owned,
                max_events=self.max_opcode_events,
                owned_offsets=owned_offsets,
                call_observations=call_observations,
                call_events=call_events,
                last_call_event_index=last_call_event_index,
            ):
                with _isolated_imports(file_dir):
                    # Execute as a no-arg function; this works for module code objects too.
                    func = types.FunctionType(code_obj, globals_dict)
                    func(*concrete_input.args)

        except Exception as e:
            exception_type = type(e).__name__
            exception_repr = repr(e)
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            sys.path = old_path
            sys.modules = old_modules

        return SelectiveConcolicTrace(
            owned_filenames=set(owned_filenames),
            owned_offsets=dict(owned_offsets),
            call_observations=dict(call_observations),
            call_events=list(call_events),
            stdout=stdout_capture.getvalue(),
            stderr=stderr_capture.getvalue(),
            exception_type=exception_type,
            exception_repr=exception_repr,
        )

    def _build_globals(self, concrete_input: ConcreteInput, code_obj: types.CodeType) -> dict[str, Any]:
        """
        Build a globals dict for execution (module-like).

        Mirrors ConcreteExecutor behavior, but keeps this module standalone.
        """
        globals_dict: dict[str, Any] = dict(concrete_input.globals_dict)
        globals_dict["__builtins__"] = __builtins__

        if "__name__" not in globals_dict:
            globals_dict["__name__"] = concrete_input.module_name or "__main__"

        if "__file__" not in globals_dict and concrete_input.file_path:
            globals_dict["__file__"] = concrete_input.file_path

        if "__package__" not in globals_dict:
            module_name = concrete_input.module_name or "__main__"
            globals_dict["__package__"] = module_name.rsplit(".", 1)[0] if "." in module_name else None

        if "__spec__" not in globals_dict:
            globals_dict["__spec__"] = None

        if "__doc__" not in globals_dict:
            globals_dict["__doc__"] = code_obj.co_name if hasattr(code_obj, "co_name") else None

        if "__cached__" not in globals_dict:
            globals_dict["__cached__"] = None

        if "__loader__" not in globals_dict:
            globals_dict["__loader__"] = None

        return globals_dict


def _discover_top_level_modules(search_dir: str) -> set[str]:
    """
    Identify importable top-level module/package names rooted at `search_dir`.

    This is a best-effort isolation mechanism to avoid sys.modules collisions when
    executing multiple different programs in-process (e.g. under pytest) that
    share common module names like "utils" or "lib".
    """
    if not search_dir or not os.path.isdir(search_dir):
        return set()

    names: set[str] = set()
    for entry in os.listdir(search_dir):
        if entry.endswith(".py"):
            stem = entry[:-3]
            if stem and stem != "__init__":
                names.add(stem)
            continue

        full = os.path.join(search_dir, entry)
        if os.path.isdir(full) and os.path.isfile(os.path.join(full, "__init__.py")):
            names.add(entry)

    return names


@contextmanager
def _isolated_imports(search_dir: Optional[str]):
    """
    Temporarily isolate imports rooted at `search_dir`.

    Strategy:
    - Compute top-level module/package names present in the directory.
    - Remove those modules (and their submodules) from sys.modules before exec.
    - After exec, remove any newly loaded modules with those names and restore
      prior entries exactly.

    This ensures that `import foo` inside the executed code will resolve against
    the intended directory rather than a stale sys.modules entry from a previous
    run in the same process.
    """
    module_roots = _discover_top_level_modules(search_dir) if search_dir else set()
    if not module_roots:
        yield
        return

    saved: dict[str, Any] = {}
    for name, module in list(sys.modules.items()):
        if name in module_roots or any(name.startswith(root + ".") for root in module_roots):
            saved[name] = module
            sys.modules.pop(name, None)

    try:
        yield
    finally:
        # Remove any modules imported during the run for these roots.
        for name in list(sys.modules.keys()):
            if name in module_roots or any(name.startswith(root + ".") for root in module_roots):
                sys.modules.pop(name, None)
        # Restore original entries.
        sys.modules.update(saved)


def _safe_realpath(path: str) -> str:
    """
    Realpath for filesystem paths, without mangling pseudo-filenames like "<stdin>".
    """
    if not path or (path.startswith("<") and path.endswith(">")):
        return path
    return os.path.realpath(os.path.abspath(path))


@contextmanager
def _monitor_selective_concolic(
    *,
    entry_code: types.CodeType,
    is_owned: Callable[[types.CodeType], bool],
    max_events: int,
    owned_offsets: DefaultDict[CodeKey, list[int]],
    call_observations: DefaultDict[CallSiteKey, list[CallObservation]],
    call_events: list[tuple[CallSiteKey, CallObservation]],
    last_call_event_index: dict[CallSiteKey, int],
):
    """
    Selective concolic tracing using sys.monitoring (PEP 669).

    NOTE: sys.settrace / sys.setprofile disable sys.monitoring events in Python 3.14,
    so this tracer is implemented entirely in terms of monitoring events.
    """
    if not hasattr(sys, "monitoring"):
        yield
        return

    tool_id: Optional[int] = None
    old_local_events: dict[types.CodeType, int] = {}
    instruction_count = 0

    def acquire_tool_id() -> int:
        # Under pytest/coverage/debuggers, the reserved tool ids may already be taken.
        # Scan for any free id.
        for candidate in range(0, 64):
            try:
                if sys.monitoring.get_tool(candidate) is None:
                    sys.monitoring.use_tool_id(candidate, "a3_python.selective_concolic")
                    return candidate
            except Exception:
                continue
        raise RuntimeError("No sys.monitoring tool id available for selective concolic tracing")

    owned_event_mask_local = sys.monitoring.events.INSTRUCTION | sys.monitoring.events.CALL

    def enable_local(code: types.CodeType, events: int) -> None:
        if code not in old_local_events:
            old_local_events[code] = sys.monitoring.get_local_events(tool_id, code)
        sys.monitoring.set_local_events(tool_id, code, old_local_events[code] | events)

    pending_py_calls: list[tuple[types.CodeType, CallSiteKey, str]] = []
    pending_c_calls: list[tuple[types.CodeType, int, CallSiteKey, str, Any]] = []
    pending_c_raises: list[tuple[types.CodeType, CallSiteKey, str]] = []

    def on_py_start(code: types.CodeType, _offset: int):
        if is_owned(code):
            enable_local(code, owned_event_mask_local)

    def on_instruction(code: types.CodeType, offset: int):
        nonlocal instruction_count
        if not is_owned(code):
            return
        instruction_count += 1
        if instruction_count > max_events:
            raise RuntimeError(f"Selective concolic exceeded {max_events} instruction events")
        owned_offsets[CodeKey.from_code(code)].append(offset)

    def on_call(code: types.CodeType, offset: int, callable_obj: Any, _arg0: Any):
        # CALL events are enabled only for owned code, but keep the predicate anyway.
        if not is_owned(code):
            return

        site = CallSiteKey.from_code(code, offset)
        func_id = _normalize_callable_id(callable_obj)

        callee_code = getattr(callable_obj, "__code__", None)
        if isinstance(callee_code, types.CodeType):
            if is_owned(callee_code):
                return
            # Python library call: enable return events for this callee.
            enable_local(callee_code, sys.monitoring.events.PY_RETURN)
            pending_py_calls.append((callee_code, site, func_id))
            return

        # C/builtin call: return values are not observable via monitoring; exceptions are.
        pending_c_calls.append((code, offset, site, func_id, callable_obj))
        return

    def pop_pending_py(code: types.CodeType) -> Optional[tuple[CallSiteKey, str]]:
        for i in range(len(pending_py_calls) - 1, -1, -1):
            callee_code, site, func_id = pending_py_calls[i]
            if callee_code is code:
                pending_py_calls.pop(i)
                return site, func_id
        return None

    def record_observation(site: CallSiteKey, obs: CallObservation) -> None:
        call_observations[site].append(obs)
        call_events.append((site, obs))
        last_call_event_index[site] = len(call_events) - 1

    def on_py_return(code: types.CodeType, _offset: int, return_value: Any):
        pending = pop_pending_py(code)
        if not pending:
            return
        site, func_id = pending
        record_observation(
            site,
            CallObservation(
                function_id=func_id,
                kind="python",
                args=None,
                has_return_value=True,
                return_value=return_value,
                exception_type=None,
                exception_repr=None,
            ),
        )

    def on_py_unwind(code: types.CodeType, _offset: int, exc: BaseException):
        pending = pop_pending_py(code)
        if not pending:
            return
        site, func_id = pending
        record_observation(
            site,
            CallObservation(
                function_id=func_id,
                kind="python",
                args=None,
                has_return_value=False,
                return_value=None,
                exception_type=type(exc).__name__,
                exception_repr=repr(exc),
            ),
        )

    def pop_pending_c(code: types.CodeType, offset: int, callable_obj: Any) -> Optional[tuple[CallSiteKey, str]]:
        for i in range(len(pending_c_calls) - 1, -1, -1):
            c_code, c_offset, site, func_id, c_callable = pending_c_calls[i]
            if c_code is code and c_offset == offset and c_callable is callable_obj:
                pending_c_calls.pop(i)
                return site, func_id
        return None

    def on_c_return(code: types.CodeType, offset: int, callable_obj: Any, _arg0: Any):
        if not is_owned(code):
            return
        pending = pop_pending_c(code, offset, callable_obj)
        if not pending:
            return
        site, func_id = pending
        record_observation(
            site,
            CallObservation(
                function_id=func_id,
                kind="c",
                args=None,
                has_return_value=False,  # return not observable
                return_value=None,
                exception_type=None,
                exception_repr=None,
            ),
        )

    def on_c_raise(code: types.CodeType, offset: int, callable_obj: Any, _arg0: Any):
        if not is_owned(code):
            return
        pending = pop_pending_c(code, offset, callable_obj)
        if not pending:
            return
        site, func_id = pending
        pending_c_raises.append((code, site, func_id))

    def on_raise(code: types.CodeType, _offset: int, exc: BaseException):
        if not pending_c_raises:
            return
        last_code, site, func_id = pending_c_raises[-1]
        if last_code is not code:
            return
        pending_c_raises.pop()
        record_observation(
            site,
            CallObservation(
                function_id=func_id,
                kind="c",
                args=None,
                has_return_value=False,
                return_value=None,
                exception_type=type(exc).__name__,
                exception_repr=repr(exc),
            ),
        )

    tool_id = acquire_tool_id()
    old_global_events = sys.monitoring.get_events(tool_id)

    sys.monitoring.register_callback(tool_id, sys.monitoring.events.PY_START, on_py_start)
    sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, on_instruction)
    sys.monitoring.register_callback(tool_id, sys.monitoring.events.CALL, on_call)
    sys.monitoring.register_callback(tool_id, sys.monitoring.events.PY_RETURN, on_py_return)
    sys.monitoring.register_callback(tool_id, sys.monitoring.events.PY_UNWIND, on_py_unwind)
    sys.monitoring.register_callback(tool_id, sys.monitoring.events.C_RETURN, on_c_return)
    sys.monitoring.register_callback(tool_id, sys.monitoring.events.C_RAISE, on_c_raise)
    sys.monitoring.register_callback(tool_id, sys.monitoring.events.RAISE, on_raise)

    sys.monitoring.set_events(
        tool_id,
        sys.monitoring.events.PY_START
        | sys.monitoring.events.PY_UNWIND
        | sys.monitoring.events.CALL
        | sys.monitoring.events.C_RETURN
        | sys.monitoring.events.C_RAISE
        | sys.monitoring.events.RAISE,
    )

    try:
        if is_owned(entry_code):
            enable_local(entry_code, owned_event_mask_local)
        yield
    finally:
        try:
            sys.monitoring.set_events(tool_id, old_global_events)
            for code, events in old_local_events.items():
                try:
                    sys.monitoring.set_local_events(tool_id, code, events)
                except Exception:
                    pass
        finally:
            try:
                sys.monitoring.free_tool_id(tool_id)
            except Exception:
                pass
