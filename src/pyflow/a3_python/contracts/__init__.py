"""
Contract system for unknown calls.

Models unknown function calls as over-approximating relations R_f ⊆ In × Out,
ensuring soundness: Sem_f ⊆ R_f.
"""

from a3_python.contracts.schema import (
    Contract,
    HeapEffect,
    ExceptionEffect,
    ValueConstraint,
    register_contract,
    get_contract,
    list_contracts,
)

# Import stdlib contracts to register them
import a3_python.contracts.stdlib

# Import relational summaries to register them (elevation plan)
import a3_python.contracts.builtin_relations
import a3_python.contracts.stdlib_module_relations

__all__ = [
    "Contract",
    "HeapEffect",
    "ExceptionEffect",
    "ValueConstraint",
    "register_contract",
    "get_contract",
    "list_contracts",
]
