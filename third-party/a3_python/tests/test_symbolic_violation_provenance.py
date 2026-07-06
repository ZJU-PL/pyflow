"""
Tests provenance fields for security violations discovered in SymbolicVM.

These fields are reporting-only metadata and must not affect BUG/SAFE/UNKNOWN.
"""

import z3

from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.z3model.taint_lattice import TaintLabel, SourceType, create_violation


def test_symbolic_vm_sets_pts_reachability_and_depth_on_violation():
    code = compile("x = 1\n", "test_provenance.py", "exec")

    vm = SymbolicVM(solver=z3.Solver(), verbose=False)
    path = vm.load_code(code)

    # Execute a couple of steps so step_count advances.
    for _ in range(3):
        succs = vm.step(path)
        path = succs[0]
        if path.state.halted:
            break

    # Create a synthetic lattice violation and feed it through the VM hook.
    label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "test")
    violation = create_violation("CODE_INJECTION", "test_provenance.py:0", label)

    prev_steps = path.state.step_count
    vm._set_security_detection_flag(path.state, violation)

    assert violation.reachability_pts.reachable_lb == 1
    assert violation.reachability_pts.reachable_ub == 1
    assert violation.depth_k == prev_steps

