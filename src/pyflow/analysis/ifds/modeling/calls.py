"""Internal call-model registry for shipped IFDS analyses."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import FrozenSet, Iterable, Mapping

from pyflow.analysis.taint.policy import call_name_suffix_matches


STATE_OPEN = "open"
STATE_CLOSE = "close"
STATE_USE = "use"


@dataclass(frozen=True)
class CallModel:
    """Unified semantic model for a symbolic call target."""

    name: str
    source_kinds: FrozenSet[str] = frozenset()
    sink_kinds: FrozenSet[str] = frozenset()
    sanitizer_kinds: FrozenSet[str] = frozenset()
    sink_arg_positions: FrozenSet[int] = frozenset({0})
    sink_all_arguments: bool = False
    rule_id: str | None = None
    cwe: str | None = None
    severity: str | None = None
    suggestion: str | None = None
    nullness_nullable_return: bool = False
    typestate_actions: FrozenSet[str] = frozenset()
    typestate_action_protocols: FrozenSet[tuple[str, str]] = frozenset()
    resource_arg_positions: FrozenSet[int] = frozenset({0})
    track_method_receiver: bool = True
    receiver_types: FrozenSet[str] = frozenset()
    callee_qualnames: FrozenSet[str] = frozenset()
    module_prefixes: FrozenSet[str] = frozenset()
    return_kind: str | None = None

    def semantic_key(self) -> tuple[object, ...]:
        """Return model semantics independent of its qualified call spelling."""
        return (
            self.source_kinds,
            self.sink_kinds,
            self.sanitizer_kinds,
            self.sink_arg_positions,
            self.sink_all_arguments,
            self.rule_id,
            self.cwe,
            self.severity,
            self.suggestion,
            self.nullness_nullable_return,
            self.typestate_actions,
            self.typestate_action_protocols,
            self.resource_arg_positions,
            self.track_method_receiver,
            self.receiver_types,
            self.callee_qualnames,
            self.module_prefixes,
            self.return_kind,
        )

    def alias_compatible_with(self, other: "CallModel") -> bool:
        """Whether two qualified spellings can safely share short-name lookup."""
        if (
            self.source_kinds != other.source_kinds
            or self.sink_kinds != other.sink_kinds
            or self.sanitizer_kinds != other.sanitizer_kinds
            or self.sink_all_arguments != other.sink_all_arguments
            or self.nullness_nullable_return != other.nullness_nullable_return
            or self.typestate_actions != other.typestate_actions
            or self.typestate_action_protocols != other.typestate_action_protocols
            or self.resource_arg_positions != other.resource_arg_positions
            or self.track_method_receiver != other.track_method_receiver
            or self.receiver_types != other.receiver_types
            or self.callee_qualnames != other.callee_qualnames
            or self.module_prefixes != other.module_prefixes
            or self.return_kind != other.return_kind
        ):
            return False
        for left, right in (
            (self.rule_id, other.rule_id),
            (self.cwe, other.cwe),
            (self.severity, other.severity),
            (self.suggestion, other.suggestion),
        ):
            if left is not None and right is not None and left != right:
                return False
        return True

    def merged(self, other: "CallModel") -> "CallModel":
        if self.name != other.name:
            raise ValueError("Cannot merge call models with different names")
        return CallModel(
            name=self.name,
            source_kinds=self.source_kinds | other.source_kinds,
            sink_kinds=self.sink_kinds | other.sink_kinds,
            sanitizer_kinds=self.sanitizer_kinds | other.sanitizer_kinds,
            sink_arg_positions=self.sink_arg_positions | other.sink_arg_positions,
            sink_all_arguments=(self.sink_all_arguments or other.sink_all_arguments),
            rule_id=self.rule_id or other.rule_id,
            cwe=self.cwe or other.cwe,
            severity=self.severity or other.severity,
            suggestion=self.suggestion or other.suggestion,
            nullness_nullable_return=(
                self.nullness_nullable_return or other.nullness_nullable_return
            ),
            typestate_actions=self.typestate_actions | other.typestate_actions,
            typestate_action_protocols=(
                self.typestate_action_protocols | other.typestate_action_protocols
            ),
            resource_arg_positions=(
                self.resource_arg_positions | other.resource_arg_positions
            ),
            track_method_receiver=(
                self.track_method_receiver or other.track_method_receiver
            ),
            receiver_types=self.receiver_types | other.receiver_types,
            callee_qualnames=self.callee_qualnames | other.callee_qualnames,
            module_prefixes=self.module_prefixes | other.module_prefixes,
            return_kind=self.return_kind or other.return_kind,
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
    def from_typestate_configuration(cls, configuration) -> "CallModelRegistry":
        models: list[CallModel] = []
        models.extend(
            CallModel(
                name=name,
                typestate_actions=frozenset({STATE_OPEN}),
                typestate_action_protocols=frozenset({(STATE_OPEN, "resource")}),
                resource_arg_positions=configuration.resource_arg_positions,
                track_method_receiver=configuration.track_method_receiver,
            )
            for name in configuration.open_names
        )
        models.extend(
            CallModel(
                name=name,
                typestate_actions=frozenset({STATE_CLOSE}),
                typestate_action_protocols=frozenset({(STATE_CLOSE, "resource")}),
                resource_arg_positions=configuration.resource_arg_positions,
                track_method_receiver=configuration.track_method_receiver,
            )
            for name in configuration.close_names
        )
        models.extend(
            CallModel(
                name=name,
                typestate_actions=frozenset({STATE_USE}),
                typestate_action_protocols=frozenset({(STATE_USE, "resource")}),
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
        exact = self._models.get(name)
        if exact is not None:
            return exact

        # Source code commonly refers to an imported framework object through
        # a shorter spelling (``request.args.get`` instead of
        # ``flask.request.args.get``).  Resolve such aliases only when the
        # suffix identifies one model unambiguously; ambiguous leaf names such
        # as ``loads`` remain unresolved rather than producing a false match.
        candidates = [
            model
            for model_name, model in self._models.items()
            if call_name_suffix_matches(model_name, name)
        ]
        if not candidates and "." in name:
            leaf = name.rsplit(".", 1)[-1]
            candidates = [
                model
                for model_name, model in self._models.items()
                if model_name.rsplit(".", 1)[-1] == leaf
            ]
        if len(candidates) == 1:
            return candidates[0]
        if candidates and "." in name:
            first = candidates[0]
            if all(first.alias_compatible_with(model) for model in candidates[1:]):
                merged = replace(first, name=name)
                for model in candidates[1:]:
                    merged = merged.merged(replace(model, name=name))
                return merged
        return None

    def as_mapping(self) -> Mapping[str, CallModel]:
        return dict(self._models)
