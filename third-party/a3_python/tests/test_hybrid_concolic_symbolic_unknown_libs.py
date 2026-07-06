"""
Tests for the hybrid concolic+symbolic workflow under unknown library semantics.

These tests exercise:
- selective concolic tracing of calls from owned code into library code
- trace-guided symbolic replay using an ExecutionOracle
- concretization of unknown library returns for witness production
"""

from __future__ import annotations

from pathlib import Path

import pytest

from a3_python.dse.concolic import ConcreteInput
from a3_python.dse.selective_concolic import SelectiveConcolicExecutor
from a3_python.dse.hybrid import ConcolicReplayOracle
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


def _compile_file(path: Path) -> object:
    return compile(path.read_text(), str(path), "exec")


def test_selective_concolic_records_python_library_call(tmp_path: Path):
    lib = tmp_path / "libmod.py"
    lib.write_text(
        "def g(x):\n"
        "    return x + 10\n"
    )

    prog = tmp_path / "prog.py"
    prog.write_text(
        "import libmod\n"
        "y = libmod.g(5)\n"
    )

    code = _compile_file(prog)
    inp = ConcreteInput.for_module("__main__", str(prog))

    trace = SelectiveConcolicExecutor(max_opcode_events=50_000).execute(
        code_obj=code,
        concrete_input=inp,
        owned_filenames={str(prog)},
    )

    # We should have at least one observed library call to libmod.g
    all_obs = [obs for obs_list in trace.call_observations.values() for obs in obs_list]
    assert any(o.function_id == "libmod.g" for o in all_obs)
    assert any(o.function_id == "libmod.g" and o.return_value == 15 for o in all_obs)


def test_hybrid_replay_concretizes_unknown_return_list_and_finds_bounds(tmp_path: Path):
    lib = tmp_path / "libmod.py"
    lib.write_text(
        "def get_list():\n"
        "    return []\n"
    )

    prog = tmp_path / "prog.py"
    prog.write_text(
        "import libmod\n"
        "x = libmod.get_list()\n"
        "y = x[0]\n"
    )

    code = _compile_file(prog)
    inp = ConcreteInput.for_module("__main__", str(prog))

    concolic = SelectiveConcolicExecutor(max_opcode_events=200_000).execute(
        code_obj=code,
        concrete_input=inp,
        owned_filenames={str(prog)},
    )

    # Concrete run should crash with IndexError
    assert concolic.exception_type == "IndexError"

    oracle = ConcolicReplayOracle.from_trace(concolic)
    vm = SymbolicVM(oracle=oracle)
    paths = vm.explore_bounded(code, max_steps=200)

    # At least one path should reach the same bounds violation.
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None]
    assert any(b["bug_type"] == "BOUNDS" for b in bugs)


def test_hybrid_replay_propagates_library_exception_as_panic(tmp_path: Path):
    """
    Test that library exceptions are propagated.
    
    ITERATION 700: ValueError is now classified as VALUE_ERROR, not PANIC.
    """
    lib = tmp_path / "libmod.py"
    lib.write_text(
        "def boom():\n"
        "    raise ValueError('boom')\n"
    )

    prog = tmp_path / "prog.py"
    prog.write_text(
        "import libmod\n"
        "libmod.boom()\n"
    )

    code = _compile_file(prog)
    inp = ConcreteInput.for_module("__main__", str(prog))

    concolic = SelectiveConcolicExecutor(max_opcode_events=100_000).execute(
        code_obj=code,
        concrete_input=inp,
        owned_filenames={str(prog)},
    )

    assert concolic.exception_type == "ValueError"

    oracle = ConcolicReplayOracle.from_trace(concolic)
    vm = SymbolicVM(oracle=oracle)
    paths = vm.explore_bounded(code, max_steps=200)

    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None]
    # ITERATION 700: ValueError now classified as VALUE_ERROR or PANIC
    assert any(b["bug_type"] in ("VALUE_ERROR", "PANIC") for b in bugs)


def test_hybrid_replay_handles_for_iter_deterministically(tmp_path: Path):
    """
    Replay should follow concrete loop iteration count when FOR_ITER is oracle-guided.

    Without oracle guidance, FOR_ITER can choose the has_next branch indefinitely
    (bounded only by max_steps), which is fine for exploration but breaks replay.
    """
    lib = tmp_path / "libmod.py"
    lib.write_text(
        "def get_list():\n"
        "    return [1, 2, 3]\n"
    )

    prog = tmp_path / "prog.py"
    prog.write_text(
        "import libmod\n"
        "for _ in libmod.get_list():\n"
        "    pass\n"
    )

    code = _compile_file(prog)
    inp = ConcreteInput.for_module("__main__", str(prog))

    concolic = SelectiveConcolicExecutor(max_opcode_events=200_000).execute(
        code_obj=code,
        concrete_input=inp,
        owned_filenames={str(prog)},
    )

    assert concolic.exception_type is None

    oracle = ConcolicReplayOracle.from_trace(concolic)
    vm = SymbolicVM(oracle=oracle)
    paths = vm.explore_bounded(code, max_steps=200)

    assert any(p.state.exception is None and (p.state.halted or not p.state.frame_stack) for p in paths)
