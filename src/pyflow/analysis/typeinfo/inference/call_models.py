"""Extensible argument-sensitive models for external callable behavior."""

from __future__ import annotations

import threading
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


class CallModelRegistry:
    """Process-wide registry of call-model providers (plugin hook).

    Libraries and applications register providers once instead of threading
    them through every engine constructor.  Explicitly passed providers are
    still consulted first, and ``unregister`` makes the registry safe for
    tests.
    """

    def __init__(self) -> None:
        self._providers: list[CallModelProvider] = []
        self._lock = threading.RLock()

    def register(self, provider: CallModelProvider) -> None:
        """Add *provider* unless it is already registered."""
        with self._lock:
            if not any(existing is provider for existing in self._providers):
                self._providers.append(provider)

    def unregister(self, provider: CallModelProvider) -> None:
        """Remove *provider* if present."""
        with self._lock:
            self._providers = [existing for existing in self._providers if existing is not provider]

    def providers(self) -> tuple[CallModelProvider, ...]:
        """Return the registered providers in registration order."""
        with self._lock:
            return tuple(self._providers)


_GLOBAL_CALL_MODELS = CallModelRegistry()


def register_call_model_provider(provider: CallModelProvider) -> CallModelProvider:
    """Register a call-model provider for every future inference engine."""
    _GLOBAL_CALL_MODELS.register(provider)
    return provider


def unregister_call_model_provider(provider: CallModelProvider) -> None:
    """Remove a previously registered call-model provider."""
    _GLOBAL_CALL_MODELS.unregister(provider)


def global_call_model_providers() -> tuple[CallModelProvider, ...]:
    """Return the process-wide providers."""
    return _GLOBAL_CALL_MODELS.providers()
