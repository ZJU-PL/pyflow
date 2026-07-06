"""
Tests for contract system.

Verifies that contracts are properly structured and sound (over-approximating).
"""

import pytest
from a3_python.contracts import (
    Contract, HeapEffect, ExceptionEffect, ValueConstraint,
    register_contract, get_contract, list_contracts
)


def test_havoc_contract_is_maximal():
    """
    The havoc contract should be the maximal over-approximation.
    
    This is the sound default for unknown calls.
    """
    contract = Contract.havoc("unknown_function")
    
    assert contract.function_name == "unknown_function"
    assert contract.is_havoc()
    assert contract.heap_effect.may_write == {'*'}
    assert contract.heap_effect.may_read == {'*'}
    assert contract.heap_effect.may_allocate is True
    assert contract.exception_effect.may_raise == {'*'}
    assert contract.exception_effect.always_raises is False
    assert contract.provenance == "default"


def test_pure_heap_effect():
    """Pure functions have no heap effects."""
    effect = HeapEffect.pure()
    
    assert len(effect.may_read) == 0
    assert len(effect.may_write) == 0
    assert effect.may_allocate is False


def test_no_raise_exception_effect():
    """Functions that never raise have empty exception set."""
    effect = ExceptionEffect.no_raise()
    
    assert len(effect.may_raise) == 0
    assert effect.always_raises is False


def test_get_contract_returns_havoc_for_unknown():
    """
    Unknown functions should get the havoc contract.
    
    This ensures soundness: we make no assumptions about unknown calls.
    """
    contract = get_contract("totally_unknown_function_xyz123")
    
    assert contract.is_havoc()
    assert contract.function_name == "totally_unknown_function_xyz123"


def test_stdlib_len_contract():
    """
    Test that len() has a reasonable contract.
    
    len() should be pure with non-negative int return and may raise TypeError.
    """
    contract = get_contract("len")
    
    assert contract.function_name == "len"
    assert contract.provenance == "stdlib_spec"
    
    # Pure function
    assert len(contract.heap_effect.may_write) == 0
    assert not contract.heap_effect.may_allocate
    
    # Returns non-negative int
    assert contract.return_constraint.type_constraint == "int"
    assert contract.return_constraint.range_constraint == (0, None)
    
    # May raise TypeError
    assert "TypeError" in contract.exception_effect.may_raise
    assert not contract.exception_effect.always_raises


def test_stdlib_abs_contract():
    """
    Test that abs() has a reasonable contract.
    
    abs() should be pure with non-negative numeric return.
    """
    contract = get_contract("abs")
    
    assert contract.function_name == "abs"
    assert contract.provenance == "stdlib_spec"
    
    # Pure function
    assert len(contract.heap_effect.may_write) == 0
    assert not contract.heap_effect.may_allocate
    
    # Returns non-negative numeric
    assert contract.return_constraint.type_constraint == "numeric"
    assert contract.return_constraint.range_constraint == (0, None)


def test_stdlib_int_contract():
    """
    Test that int() contract is conservative.
    
    int() may allocate (new int object) and may raise exceptions.
    """
    contract = get_contract("int")
    
    assert contract.function_name == "int"
    assert contract.provenance == "stdlib_spec"
    
    # May allocate new object
    assert contract.heap_effect.may_allocate is True
    
    # Returns int
    assert contract.return_constraint.type_constraint == "int"
    
    # May raise TypeError or ValueError
    assert "TypeError" in contract.exception_effect.may_raise
    assert "ValueError" in contract.exception_effect.may_raise


def test_stdlib_str_contract_is_conservative():
    """
    Test that str() contract is conservatively over-approximated.
    
    str() calls __str__ which may be arbitrary code, so we must be conservative.
    """
    contract = get_contract("str")
    
    assert contract.function_name == "str"
    assert contract.provenance == "stdlib_spec"
    
    # __str__ may read arbitrary heap locations
    assert '*' in contract.heap_effect.may_read
    
    # __str__ can raise anything (user code)
    assert '*' in contract.exception_effect.may_raise
    
    # Returns string
    assert contract.return_constraint.type_constraint == "str"


def test_stdlib_isinstance_contract():
    """
    Test that isinstance() is pure.
    
    isinstance() is a pure type check operation.
    """
    contract = get_contract("isinstance")
    
    assert contract.function_name == "isinstance"
    assert contract.provenance == "stdlib_spec"
    
    # Pure
    assert len(contract.heap_effect.may_write) == 0
    assert len(contract.heap_effect.may_read) == 0
    assert not contract.heap_effect.may_allocate
    
    # Returns bool
    assert contract.return_constraint.type_constraint == "bool"


def test_contract_registration():
    """
    Test that custom contracts can be registered and retrieved.
    """
    custom_contract = Contract(
        function_name="my_custom_function",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="int"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect.no_raise(),
        provenance="test"
    )
    
    register_contract(custom_contract)
    
    retrieved = get_contract("my_custom_function")
    assert retrieved.function_name == "my_custom_function"
    assert retrieved.provenance == "test"
    assert retrieved.return_constraint.type_constraint == "int"


def test_list_contracts_includes_stdlib():
    """
    Test that we can enumerate registered contracts.
    
    Should include stdlib contracts like len, abs, etc.
    """
    contracts = list_contracts()
    
    assert "len" in contracts
    assert "abs" in contracts
    assert "int" in contracts
    assert "str" in contracts
    assert "isinstance" in contracts


def test_soundness_principle_havoc():
    """
    Document the soundness principle: default havoc is safe.
    
    For any unknown function f, the havoc contract R_havoc must satisfy:
    Sem_f ⊆ R_havoc
    
    This is achieved by assuming arbitrary heap effects and exceptions.
    """
    unknown_contract = get_contract("random_unknown_func")
    
    # Havoc contract allows any behavior
    assert unknown_contract.is_havoc()
    
    # This means:
    # - Any heap location may be read/written
    # - Any exception may be raised
    # - Any value may be returned
    # Therefore: Sem_f ⊆ R_havoc for all f


def test_contract_refinement_preserves_soundness():
    """
    Document contract refinement principle.
    
    When refining a contract (making it more precise), we must ensure:
    Sem_f ⊆ R_refined
    
    DSE can witness behaviors but cannot prove R_refined is sound.
    """
    # Start with havoc
    havoc = Contract.havoc("example_func")
    assert havoc.is_havoc()
    
    # Refine to pure function (this would need justification!)
    refined = Contract(
        function_name="example_func",
        arg_constraints=[],
        return_constraint=ValueConstraint(type_constraint="int"),
        heap_effect=HeapEffect.pure(),
        exception_effect=ExceptionEffect.no_raise(),
        provenance="source_analysis"  # Justified by analyzing source
    )
    
    # The refinement R_refined ⊆ R_havoc
    assert not refined.is_havoc()
    assert len(refined.heap_effect.may_write) < len(havoc.heap_effect.may_write)
    
    # But we need justification that Sem_f ⊆ R_refined!
    # This is why provenance matters.
