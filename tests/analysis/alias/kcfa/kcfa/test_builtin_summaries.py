from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.builtin_api_handler import (
    BuiltinAPIHandler,
    BuiltinSummaryManager,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.config import Config
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.state import PointerAnalysisState


def test_builtin_summary_manager_requires_state_before_lookup():
    manager = BuiltinSummaryManager(Config())

    assert not manager.has_summary("list")
    assert manager.get_handler() is None


def test_builtin_summary_manager_delegates_to_current_handler():
    manager = BuiltinSummaryManager(Config())
    state = PointerAnalysisState()

    manager.set_state(state)

    assert isinstance(manager.get_handler(), BuiltinAPIHandler)
    assert manager.has_summary("list")
    assert manager.has_summary("iter")
    assert manager.has_summary("int")
    assert manager.has_summary("object")
    assert not manager.has_summary("definitely_not_builtin")
