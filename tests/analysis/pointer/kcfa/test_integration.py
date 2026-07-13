from pyflow.analysis.pointer._pythonstan.analysis import AnalysisConfig
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.analysis import PointerAnalysis
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.config import Config
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.context_selector import (
    ContextPolicy,
    parse_policy,
)


def test_pointer_analysis_uses_analysis_config_wrapper():
    config = Config(context_policy="1-cfa")
    analysis = PointerAnalysis(
        AnalysisConfig("pointer", "PointerAnalysis", options=config.to_dict())
    )

    assert analysis.kcfa_config.context_policy == "1-cfa"
    assert parse_policy(analysis.kcfa_config.context_policy) is ContextPolicy.CALL_1


def test_pointer_analysis_default_config_via_analysis_config():
    analysis = PointerAnalysis(
        AnalysisConfig("pointer", "PointerAnalysis", options=Config().to_dict())
    )

    assert analysis.kcfa_config.context_policy == "2-cfa"
