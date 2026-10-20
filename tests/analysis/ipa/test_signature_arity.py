"""Large valid calls must not be mistaken for runaway analysis."""

from pyflow.analysis.cpasignature import CPASignature
from pyflow.analysis.ipa.calling.cpa import CPAContextSignature


def test_signatures_allow_more_than_thirty_arguments():
    code = object()
    args = (None,) * 40
    assert CPASignature(code, None, args).params == args
    assert CPAContextSignature(code, None, (), args).vparams == args
