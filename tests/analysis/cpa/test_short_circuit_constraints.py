from pyflow.analysis.cpa.constraintextractor import ExtractDataflow
from pyflow.analysis.ipa.constraintextractor import ConstraintExtractor
from pyflow.language.python import ast


class _CPAHarness(ExtractDataflow):
    def __init__(self):
        self.calls = []
        self.fresh = object()

    def __call__(self, node, targets=None):
        self.calls.append((node, targets))
        return node

    def _freshLocalSlot(self, prefix):
        assert prefix == "short_circuit"
        return self.fresh


class _IPAHarness(ConstraintExtractor):
    def __init__(self):
        self.calls = []
        self.fresh = object()

    def __call__(self, node, targets=None):
        self.calls.append((node, targets))
        return node

    def _freshLocal(self, prefix):
        assert prefix == "short_circuit"
        return self.fresh


def test_cpa_short_circuit_terms_flow_to_assignment_target():
    harness = _CPAHarness()
    terms = [ast.Local("a"), ast.Local("b")]
    target = object()

    result = harness.visitShortCircutBool(ast.ShortCircutOr(terms), [target])

    assert result is None
    assert harness.calls == [(terms[0], [target]), (terms[1], [target])]


def test_ipa_short_circuit_expression_uses_shared_fresh_result():
    harness = _IPAHarness()
    terms = [ast.Local("a"), ast.Local("b")]

    result = harness.visitShortCircutBool(ast.ShortCircutAnd(terms))

    assert result is harness.fresh
    assert harness.calls == [
        (terms[0], [harness.fresh]),
        (terms[1], [harness.fresh]),
    ]
