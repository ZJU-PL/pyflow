from a3_python.barriers.hscc2004 import prove_guarded_div_zero_in_affine_loops


def test_hscc2004_guarded_div_zero_loop_proves_safe():
    def f(d: int):
        x = 0
        while d != 0:
            x = 1 / d
            d -= 1
        return x

    proofs = prove_guarded_div_zero_in_affine_loops(f.__code__, timeout_ms=2000)
    assert proofs, "Expected at least one HSCC'04 guarded DIV_ZERO proof"
    assert all(p.inductiveness.is_inductive for p in proofs)


def test_hscc2004_unrelated_guard_does_not_claim_div_zero_safe():
    def g(d: int, n: int):
        i = 0
        while i < n:
            _ = 1 / d
            i += 1
        return i

    proofs = prove_guarded_div_zero_in_affine_loops(g.__code__, timeout_ms=2000)
    assert proofs == []
