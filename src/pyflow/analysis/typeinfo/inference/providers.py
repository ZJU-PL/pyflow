"""Core interfaces for callable type-inference providers."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, get_type_hints

if TYPE_CHECKING:
    from collections.abc import Callable

_LOGGER = logging.getLogger(__name__)

__all__ = ["HintInference", "InferenceProvider", "NoInference"]


class InferenceProvider(ABC):
    """Supply runtime-style type hints for a callable."""

    def __init__(self) -> None:
        self._metrics: dict[str, float | int] = {
            "failed_inferences": 0,
            "successful_inferences": 0,
            "sent_requests": 0,
            "total_setup_time": 0,
        }

    @abstractmethod
    def provide(self, method: Callable) -> dict[str, Any]:
        """Return parameter and return-type hints for ``method``."""

    def get_metrics(self) -> dict[str, Any]:
        """Return metrics collected by the provider."""
        return self._metrics


class NoInference(InferenceProvider):
    """Provider that deliberately supplies no type information."""

    def provide(self, method: Callable) -> dict[str, Any]:
        """Return no hints for ``method``."""
        return {}


class HintInference(InferenceProvider):
    """Provider backed by standard PEP 484 annotations."""

    def provide(self, method: Callable) -> dict[str, Any]:
        """Resolve annotations for ``method``, falling back to no hints."""
        try:
            return get_type_hints(method)
        except (AttributeError, NameError, TypeError) as exc:
            _LOGGER.debug("Could not retrieve type hints for %s", method)
            _LOGGER.debug(exc)
            return {}
