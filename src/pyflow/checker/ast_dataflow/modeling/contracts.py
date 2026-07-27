"""Declarative sanitizer and validator contracts for taint models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping


class PortKind(str, Enum):
    PARAMETER = "parameter"
    RECEIVER = "receiver"
    RETURN = "return"
    YIELD = "yield"
    RAISE = "raise"


@dataclass(frozen=True, order=True)
class ContractPort:
    kind: PortKind
    index: int | None = None
    path: tuple[str, ...] = ()


@dataclass(frozen=True)
class TaintTransform:
    """A finite, composable transformation over taint kinds."""

    removes: frozenset[str] = frozenset()
    maps: Mapping[str, str] = field(default_factory=dict)
    preserves_unmentioned: bool = True

    def apply(self, kinds: Iterable[str]) -> frozenset[str]:
        result: set[str] = set()
        remove_all = "*" in self.removes
        for kind in kinds:
            if remove_all or kind in self.removes:
                continue
            mapped = self.maps.get(kind)
            if mapped is not None:
                result.add(mapped)
            elif self.preserves_unmentioned:
                result.add(kind)
        return frozenset(result)

    def then(self, other: "TaintTransform") -> "ComposedTaintTransform":
        return ComposedTaintTransform((self, other))


@dataclass(frozen=True)
class ComposedTaintTransform:
    transforms: tuple[TaintTransform, ...]

    def apply(self, kinds: Iterable[str]) -> frozenset[str]:
        result = frozenset(kinds)
        for transform in self.transforms:
            result = transform.apply(result)
        return result


@dataclass(frozen=True)
class SanitizerContract:
    """Semantic contract for a sanitizer, encoder, or validator call."""

    call_name: str
    input_port: ContractPort
    output_port: ContractPort
    transform: TaintTransform
    guard: str | None = None
    mutates_input: bool = False
    assumptions: frozenset[str] = frozenset()


class SanitizerContractRegistry:
    def __init__(self, contracts: Iterable[SanitizerContract] = ()) -> None:
        self._contracts: dict[str, list[SanitizerContract]] = {}
        for contract in contracts:
            self.register(contract)

    def register(self, contract: SanitizerContract) -> None:
        self._contracts.setdefault(contract.call_name, []).append(contract)

    def for_call(self, name: str) -> tuple[SanitizerContract, ...]:
        return tuple(self._contracts.get(name, ()))
