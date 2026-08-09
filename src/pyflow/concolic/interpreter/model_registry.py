"""Registry-backed dispatch for library behavior models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

ModelHandler = Callable[[Any, str, list[Any], dict[str, Any]], Any]


@dataclass(frozen=True)
class RegisteredModel:
    module: str
    name: str | None
    handler: ModelHandler


class SummaryModelRegistry:
    """Resolve exact function models before module-level model families."""

    def __init__(self) -> None:
        self._functions: dict[tuple[str, str], ModelHandler] = {}
        self._modules: dict[str, ModelHandler] = {}

    def register_function(self, module: str, name: str, handler: ModelHandler) -> None:
        key = (module, name)
        if key in self._functions:
            raise ValueError(f"model already registered for {module}.{name}")
        self._functions[key] = handler

    def register_module(self, module: str, handler: ModelHandler) -> None:
        if module in self._modules:
            raise ValueError(f"model family already registered for {module}")
        self._modules[module] = handler

    def resolve(self, module: str, name: str) -> ModelHandler | None:
        return self._functions.get((module, name)) or self._modules.get(module)

    def models(self) -> tuple[RegisteredModel, ...]:
        functions = (
            RegisteredModel(module, name, handler)
            for (module, name), handler in self._functions.items()
        )
        modules = (
            RegisteredModel(module, None, handler) for module, handler in self._modules.items()
        )
        return tuple(
            sorted(
                (*functions, *modules),
                key=lambda model: (model.module, model.name or ""),
            )
        )

    def copy(self) -> "SummaryModelRegistry":
        duplicate = SummaryModelRegistry()
        duplicate._functions.update(self._functions)
        duplicate._modules.update(self._modules)
        return duplicate


def register_model_families(
    registry: SummaryModelRegistry,
    modules: Iterable[str],
    handler: ModelHandler,
) -> None:
    for module in modules:
        registry.register_module(module, handler)
