from a3_python.barriers.sos_toolbox import prove_guarded_hazards_compact


def test_compact_bounds_prove_div_zero_safe():
    def f(d: int):
        while 1 <= d <= 5:
            _ = 10 / d
            d -= 1
        return d

    proofs = prove_guarded_hazards_compact(f.__code__)
    assert any(p.bug_type == "DIV_ZERO" and p.variable == "d" for p in proofs)


def test_compact_bounds_prove_sqrt_safe():
    import math

    def g(x: int):
        while 0 <= x <= 9:
            _ = math.sqrt(x)
            x -= 1
        return x

    proofs = prove_guarded_hazards_compact(g.__code__)
    assert any(p.bug_type == "FP_DOMAIN" and p.variable == "x" for p in proofs)


def test_noncompact_bounds_do_not_overclaim():
    def h(x: int):
        while x >= 0:
            _ = 10 / x
            x -= 1
        return x

    proofs = prove_guarded_hazards_compact(h.__code__)
    assert proofs == []
