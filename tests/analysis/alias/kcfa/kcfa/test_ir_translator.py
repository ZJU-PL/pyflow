"""Tests for IR translator (IR to constraints).

IR translation is verified through solver integration tests.
These tests verify translator initialization only.
"""

import ast

import pytest
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.constraints import (
    AllocConstraint,
    CallConstraint,
    LoadConstraint,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.ir_translator import IRTranslator
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa import Config
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.variable import (
    Variable,
    VariableFactory,
    VariableKind,
)
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRAssign, IRModule


class TestIRTranslatorInitialization:
    """Tests for IRTranslator initialization."""
    
    def test_basic_initialization(self):
        """Test creating IR translator."""
        config = Config()
        translator = IRTranslator(config)
        
        assert translator.config == config
        assert translator._var_factory is not None
        assert isinstance(translator._var_factory, VariableFactory)

    def test_not_calls_truth_protocol_without_propagating_its_return(self):
        translator = IRTranslator(Config())
        translator._current_scope = IRModule("test", ast.parse(""), name="test")
        operand = Variable("operand", VariableKind.LOCAL)
        target = Variable("result", VariableKind.LOCAL)
        statement = IRAssign(
            ast.Assign(
                targets=[ast.Name(id="result", ctx=ast.Store())],
                value=ast.UnaryOp(
                    op=ast.Not(),
                    operand=ast.Name(id="operand", ctx=ast.Load()),
                ),
            )
        )

        constraints = translator._translate_unary_op(
            operand, target, ast.Not(), statement
        )

        assert sum(isinstance(item, LoadConstraint) for item in constraints) == 2
        calls = [item for item in constraints if isinstance(item, CallConstraint)]
        assert len(calls) == 2
        assert all(item.target is None for item in calls)
        allocations = [
            item for item in constraints if isinstance(item, AllocConstraint)
        ]
        assert len(allocations) == 1
        assert allocations[0].target == target


# NOTE: IR translation is comprehensively tested via:
# - test_solver_core.py (constraint-level verification)
# - test_integration.py (end-to-end scenarios)
# - test_kcfa_basic_integration.py (manual verification)
#
# Testing individual IR statement translation would duplicate
# higher-level tests without adding value.
