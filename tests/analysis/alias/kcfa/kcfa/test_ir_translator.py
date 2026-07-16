"""Tests for IR translator (IR to constraints).

IR translation is verified through solver integration tests.
These tests verify translator initialization only.
"""

import pytest
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.ir_translator import IRTranslator
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa import Config
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.variable import VariableFactory


class TestIRTranslatorInitialization:
    """Tests for IRTranslator initialization."""
    
    def test_basic_initialization(self):
        """Test creating IR translator."""
        config = Config()
        translator = IRTranslator(config)
        
        assert translator.config == config
        assert translator._var_factory is not None
        assert isinstance(translator._var_factory, VariableFactory)


# NOTE: IR translation is comprehensively tested via:
# - test_solver_core.py (constraint-level verification)
# - test_integration.py (end-to-end scenarios)
# - test_kcfa_basic_integration.py (manual verification)
#
# Testing individual IR statement translation would duplicate
# higher-level tests without adding value.
