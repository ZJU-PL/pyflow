from a3_python.barriers.sos_safety import prove_guarded_hazards_unreachable


def test_sos_for_safety_proves_guarded_div_zero_site_unreachable():
    def f(d: int):
        x = 0
        while d != 0:
            x = 1 / d
            d -= 1
        return x

    proofs = prove_guarded_hazards_unreachable(f.__code__)
    assert any(p.bug_type == "DIV_ZERO" and p.variable == "d" for p in proofs)


def test_sos_for_safety_proves_guarded_sqrt_domain_safe():
    import math

    def g(x: int):
        y = 0.0
        while x >= 0:
            y = math.sqrt(x)
            x -= 1
        return y

    proofs = prove_guarded_hazards_unreachable(g.__code__)
    assert any(p.bug_type == "FP_DOMAIN" and p.variable == "x" for p in proofs)


def test_sos_for_safety_does_not_overclaim_unrelated_guard():
    import math

    def h(x: int, n: int):
        y = 0.0
        i = 0
        while i < n:
            y = math.sqrt(x)
            i += 1
        return y

    proofs = prove_guarded_hazards_unreachable(h.__code__)
    assert proofs == []
