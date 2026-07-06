import types

from a3_python.barriers.sos_safety import sos_guarded_div_zero_in_affine_loops


def _compile_fn(src: str, name: str) -> types.CodeType:
    ns: dict[str, object] = {}
    exec(src, ns)
    return ns[name].__code__


def test_sos_guarded_div_zero_proof_detected():
    code = _compile_fn(
        """
def f(x):
    while x > 0:
        y = 10 / x
        x -= 1
    return y
""",
        "f",
    )
    proofs = sos_guarded_div_zero_in_affine_loops(code)
    assert proofs, "Expected SOS proof for guarded division"
    assert any(p.variable == "x" for p in proofs)
