"""Registry-backed dispatch for library behavior models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable

ModelHandler = Callable[[Any, str, str, list[Any], dict[str, Any]], Any]


class ModelPrecision(str, Enum):
    """How strongly an operation model describes the concrete callable."""

    EXACT = "exact"
    REFINED = "refined"
    OPAQUE = "opaque"


@dataclass(frozen=True)
class ModelResult:
    """A modeled value together with the provenance of its semantics."""

    value: Any
    precision: ModelPrecision = ModelPrecision.EXACT
    assumptions: tuple[Any, ...] = ()
    guidance: tuple[Any, ...] = ()


@dataclass(frozen=True)
class OpaqueCallSignature:
    """A stable identity for one dynamically typed external operation."""

    module: str
    name: str
    argument_kinds: tuple[str, ...]
    keyword_kinds: tuple[tuple[str, str], ...]

    @property
    def display_name(self) -> str:
        return f"{self.module}.{self.name}"


@dataclass(frozen=True)
class OpaqueCallSample:
    """One CPython observation used to refine an opaque operation."""

    arguments: tuple[Any, ...]
    keywords: tuple[tuple[str, Any], ...]
    result_kind: str | None
    result: Any = None
    exception_type: str | None = None
    exception_message: str | None = None

    @property
    def raised(self) -> bool:
        return self.exception_type is not None


@dataclass
class OpaqueRefinementStore:
    """Share concrete observations across executions of one exploration."""

    _samples: dict[OpaqueCallSignature, list[OpaqueCallSample]] = field(default_factory=dict)
    observations: int = 0
    refinements: int = 0

    def samples(self, signature: OpaqueCallSignature) -> tuple[OpaqueCallSample, ...]:
        return tuple(self._samples.get(signature, ()))

    def observe(
        self,
        signature: OpaqueCallSignature,
        sample: OpaqueCallSample,
        *,
        max_refinements: int | None = None,
    ) -> bool | None:
        """Record a sample, returning ``None`` when a refinement budget blocks it."""
        self.observations += 1
        samples = self._samples.setdefault(signature, [])
        if sample in samples:
            return False
        if max_refinements is not None and self.refinements >= max_refinements:
            return None
        samples.append(sample)
        self.refinements += 1
        return True

    def record(self, signature: OpaqueCallSignature, sample: OpaqueCallSample) -> bool:
        return self.observe(signature, sample) is True


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
