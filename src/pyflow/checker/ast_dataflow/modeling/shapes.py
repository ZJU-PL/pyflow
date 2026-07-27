"""Declarative call-result shape contracts, including optional benchmarks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True, order=True)
class IndexPartition:
    modulus: int
    residues: frozenset[int]

    def __post_init__(self) -> None:
        if self.modulus <= 0:
            raise ValueError("index partition modulus must be positive")
        if not self.residues:
            raise ValueError("index partition requires at least one residue")


@dataclass(frozen=True)
class CallShapeContract:
    """Place taint from one argument into partitions of a call-result shape."""

    call_name: str
    input_index: int
    index_partitions: tuple[IndexPartition, ...]
    assumptions: frozenset[str] = frozenset()


class CallShapeContractRegistry:
    def __init__(self, contracts: Iterable[CallShapeContract] = ()) -> None:
        self._contracts: dict[str, list[CallShapeContract]] = {}
        for contract in contracts:
            self._contracts.setdefault(contract.call_name, []).append(contract)

    def for_call(self, name: str) -> tuple[CallShapeContract, ...]:
        return tuple(self._contracts.get(name, ()))


def sast_python3_benchmark_shapes() -> CallShapeContractRegistry:
    """Optional historical microbenchmark assumptions; never enabled by default."""

    return CallShapeContractRegistry(
        (
            CallShapeContract(
                call_name="array.array",
                input_index=1,
                index_partitions=(IndexPartition(2, frozenset({0})),),
                assumptions=frozenset(
                    {
                        "SAST-Python3 fixture treats array.array output as tainted "
                        "at even indices"
                    }
                ),
            ),
        )
    )
