"""Internal call-model registry for shipped IFDS analyses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Iterable, Mapping


STATE_OPEN = "open"
STATE_CLOSE = "close"
STATE_USE = "use"


def _sanitizer_categories_for(configuration, name: str) -> FrozenSet[str]:
    categories = getattr(configuration, "sanitizer_categories", {})
    if not hasattr(categories, "get"):
        return frozenset()
    return frozenset(categories.get(name, ()))


@dataclass(frozen=True)
class CallModel:
    """Unified semantic model for a symbolic call target."""

    name: str
    taint_source: bool = False
    taint_sink: bool = False
    taint_sanitizer: bool = False
    taint_categories: FrozenSet[str] = frozenset()
    sanitizer_categories: FrozenSet[str] = frozenset()
    sink_arg_positions: FrozenSet[int] = frozenset({0})
    rule_id: str | None = None
    cwe: str | None = None
    severity: str | None = None
    suggestion: str | None = None
    nullness_nullable_return: bool = False
    typestate_actions: FrozenSet[str] = frozenset()
    resource_arg_positions: FrozenSet[int] = frozenset({0})
    track_method_receiver: bool = True

    def merged(self, other: "CallModel") -> "CallModel":
        if self.name != other.name:
            raise ValueError("Cannot merge call models with different names")
        return CallModel(
            name=self.name,
            taint_source=self.taint_source or other.taint_source,
            taint_sink=self.taint_sink or other.taint_sink,
            taint_sanitizer=self.taint_sanitizer or other.taint_sanitizer,
            taint_categories=self.taint_categories | other.taint_categories,
            sanitizer_categories=(
                self.sanitizer_categories | other.sanitizer_categories
            ),
            sink_arg_positions=self.sink_arg_positions | other.sink_arg_positions,
            rule_id=self.rule_id or other.rule_id,
            cwe=self.cwe or other.cwe,
            severity=self.severity or other.severity,
            suggestion=self.suggestion or other.suggestion,
            nullness_nullable_return=(
                self.nullness_nullable_return or other.nullness_nullable_return
            ),
            typestate_actions=self.typestate_actions | other.typestate_actions,
            resource_arg_positions=(
                self.resource_arg_positions | other.resource_arg_positions
            ),
            track_method_receiver=(
                self.track_method_receiver or other.track_method_receiver
            ),
        )


class CallModelRegistry:
    """Lookup table for symbolic call semantics."""

    def __init__(self, models: Iterable[CallModel] = ()) -> None:
        merged: dict[str, CallModel] = {}
        for model in models:
            current = merged.get(model.name)
            merged[model.name] = model if current is None else current.merged(model)
        self._models = merged

    @classmethod
    def from_taint_configuration(cls, configuration) -> "CallModelRegistry":
        models: list[CallModel] = []
        models.extend(
            CallModel(name=name, taint_source=True)
            for name in configuration.source_names
        )
        models.extend(
            CallModel(name=name, taint_sink=True)
            for name in configuration.sink_names
        )
        models.extend(
            CallModel(
                name=name,
                taint_sanitizer=True,
                sanitizer_categories=_sanitizer_categories_for(configuration, name),
            )
            for name in configuration.sanitizer_names
        )
        return cls(models)

    @classmethod
    def from_typestate_configuration(cls, configuration) -> "CallModelRegistry":
        models: list[CallModel] = []
        models.extend(
            CallModel(
                name=name,
                typestate_actions=frozenset({STATE_OPEN}),
                resource_arg_positions=configuration.resource_arg_positions,
                track_method_receiver=configuration.track_method_receiver,
            )
            for name in configuration.open_names
        )
        models.extend(
            CallModel(
                name=name,
                typestate_actions=frozenset({STATE_CLOSE}),
                resource_arg_positions=configuration.resource_arg_positions,
                track_method_receiver=configuration.track_method_receiver,
            )
            for name in configuration.close_names
        )
        models.extend(
            CallModel(
                name=name,
                typestate_actions=frozenset({STATE_USE}),
                resource_arg_positions=configuration.resource_arg_positions,
                track_method_receiver=configuration.track_method_receiver,
            )
            for name in configuration.use_names
        )
        return cls(models)

    @classmethod
    def from_nullness_configuration(cls, configuration) -> "CallModelRegistry":
        models = [
            CallModel(name=name, nullness_nullable_return=True)
            for name in configuration.nullable_return_names
        ]
        return cls(models)

    def merged(self, *others: "CallModelRegistry") -> "CallModelRegistry":
        models = list(self._models.values())
        for other in others:
            models.extend(other._models.values())
        return CallModelRegistry(models)

    def model_for_name(self, name: str | None) -> CallModel | None:
        if name is None:
            return None
        return self._models.get(name)

    def as_mapping(self) -> Mapping[str, CallModel]:
        return dict(self._models)
