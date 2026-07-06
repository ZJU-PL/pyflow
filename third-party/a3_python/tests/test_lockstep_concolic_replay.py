"""
Lockstep concolic execution + symbolic replay tests.

These tests ensure we can:
- run a concrete CPython execution with selective concolic tracing,
- build an oracle, and
- replay the same path inside the Z3 SymbolicVM without divergence.
"""

from __future__ import annotations

from pathlib import Path

from a3_python.dse.concolic import ConcreteInput
from a3_python.dse.lockstep import run_lockstep


def _compile_file(path: Path) -> object:
    return compile(path.read_text(), str(path), "exec")


def test_lockstep_handles_library_returning_none(tmp_path: Path):
    lib = tmp_path / "libmod.py"
    lib.write_text(
        "def f():\n"
        "    return None\n"
    )

    prog = tmp_path / "prog.py"
    prog.write_text(
        "import libmod\n"
        "x = libmod.f()\n"
        "y = 1 if x is None else 2\n"
    )

    code = _compile_file(prog)
    inp = ConcreteInput.for_module("__main__", str(prog))

    res = run_lockstep(code_obj=code, concrete_input=inp, owned_filenames={str(prog)}, max_steps=200)
    assert res.status == "ok"
    assert res.concrete_exception_type is None
    assert res.symbolic_exception is None
    assert res.observed_call_events >= 1


def test_lockstep_records_c_calls_without_return_values(tmp_path: Path):
    prog = tmp_path / "prog.py"
    prog.write_text(
        "x = len([1, 2, 3])\n"
    )

    code = _compile_file(prog)
    inp = ConcreteInput.for_module("__main__", str(prog))

    res = run_lockstep(code_obj=code, concrete_input=inp, owned_filenames={str(prog)}, max_steps=200)
    assert res.status == "ok"
    assert res.concrete_exception_type is None
    assert res.symbolic_exception is None

