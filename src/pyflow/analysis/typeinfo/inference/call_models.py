"""Extensible argument-sensitive models for external callable behavior."""

from __future__ import annotations

from typing import Callable, Protocol

from pyflow.analysis.typeinfo.core.typesystem import ProperType
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue

CallModel = Callable[
    [list[AbstractTypeValue], dict[str, AbstractTypeValue]],
    AbstractTypeValue,
]


class CallModelProvider(Protocol):
    """Provide a semantic result for a fully qualified external call."""

    def infer_call(
        self,
        qualified_name: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
    ) -> AbstractTypeValue | None: ...


class MappingCallModelProvider:
    """A registry-backed provider for application and library models."""

    def __init__(self) -> None:
        self._models: dict[str, CallModel] = {}

    def register(self, qualified_name: str, model: CallModel) -> None:
        """Register or replace an argument-sensitive call model."""
        self._models[qualified_name] = model

    def register_return_type(
        self,
        qualified_name: str,
        return_type: ProperType,
    ) -> None:
        """Register a call with a fixed public return type."""
        self.register(
            qualified_name,
            lambda _arguments, _keywords: AbstractTypeValue.from_type(return_type),
        )

    def infer_call(
        self,
        qualified_name: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
    ) -> AbstractTypeValue | None:
        """Evaluate a registered model, returning ``None`` when absent."""
        model = self._models.get(qualified_name)
        return None if model is None else model(arguments, keywords)
