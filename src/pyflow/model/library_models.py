"""Declarative Models-as-Data registry for Python libraries and frameworks.

Unifies decorator semantics (pass-through class/function decorators,
descriptors, overloads, entry points), framework route/command discovery, and
higher-order callable callback/effect/taint summaries into one data-driven
registry backed by :file:`builtin_models.json` and extensible with project- or
user-supplied model packs.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import json
from pathlib import Path
import threading
from typing import Any

LIBRARY_MODELS_SCHEMA_VERSION = "library_models.v1"

_BUILTIN_MODELS_PATH = Path(__file__).resolve().parent / "builtin_models.json"


@dataclass(frozen=True, slots=True)
class DecoratorModel:
    """Declarative semantics of a Python decorator."""

    qualified_names: tuple[str, ...]
    target_kind: str = "any"  # "class" | "function" | "any"
    # "passthrough" | "factory_or_passthrough" | "descriptor" | "overload" | "singledispatch"
    # | "entrypoint"
    behavior: str = "passthrough"
    synthesizes_init: bool = False
    returns_context_manager: bool = False
    entrypoint_kind: str | None = None

    @property
    def is_passthrough(self) -> bool:
        return self.behavior in {"passthrough", "factory_or_passthrough"}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DecoratorModel":
        return cls(
            qualified_names=tuple(str(n) for n in data.get("qualified_names", ())),
            target_kind=str(data.get("target_kind", "any")),
            behavior=str(data.get("behavior", "passthrough")),
            synthesizes_init=bool(data.get("synthesizes_init", False)),
            returns_context_manager=bool(data.get("returns_context_manager", False)),
            entrypoint_kind=data.get("entrypoint_kind"),
        )


@dataclass(frozen=True, slots=True)
class FrameworkRouteModel:
    """Declarative factory + route/command decorator specification."""

    name: str
    entrypoint_kind: str  # "http" | "cli" | "task" | "event"
    factory_classes: tuple[str, ...]
    decorator_methods: tuple[str, ...]
    hint_tokens: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FrameworkRouteModel":
        return cls(
            name=str(data["name"]),
            entrypoint_kind=str(data.get("entrypoint_kind", "http")),
            factory_classes=tuple(str(n) for n in data.get("factory_classes", ())),
            decorator_methods=tuple(str(n) for n in data.get("decorator_methods", ())),
            hint_tokens=tuple(str(n) for n in data.get("hint_tokens", ())),
        )


@dataclass(frozen=True, slots=True)
class CallableSummaryModel:
    """Declarative callback, return-type, container-effect, and taint summary."""

    qualified_name: str
    callback_arg_positions: tuple[int, ...] = ()
    callback_kwarg_names: tuple[str, ...] = ()
    return_type_annotation: str | None = None
    container_effect: str | None = None
    taint_role: str | None = None
    taint_kinds: tuple[str, ...] = ()
    cwe: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CallableSummaryModel":
        return cls(
            qualified_name=str(data["qualified_name"]),
            callback_arg_positions=tuple(int(i) for i in data.get("callback_arg_positions", ())),
            callback_kwarg_names=tuple(str(k) for k in data.get("callback_kwarg_names", ())),
            return_type_annotation=data.get("return_type_annotation"),
            container_effect=data.get("container_effect"),
            taint_role=data.get("taint_role"),
            taint_kinds=tuple(str(k) for k in data.get("taint_kinds", ())),
            cwe=data.get("cwe"),
        )


class LibraryModelRegistry:
    """Indexed registry of declarative decorator, framework, and callable models."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._decorators_by_name: dict[str, DecoratorModel] = {}
        self._decorators_by_short: dict[str, list[DecoratorModel]] = {}
        self._framework_routes: list[FrameworkRouteModel] = []
        self._callables_by_name: dict[str, CallableSummaryModel] = {}
        self._callables_by_suffix: dict[str, list[CallableSummaryModel]] = {}

    def register_decorator(self, model: DecoratorModel) -> None:
        with self._lock:
            for qname in model.qualified_names:
                self._decorators_by_name[qname] = model
                short = qname.rsplit(".", 1)[-1]
                bucket = self._decorators_by_short.setdefault(short, [])
                if model not in bucket:
                    bucket.append(model)

    def register_framework_route(self, model: FrameworkRouteModel) -> None:
        with self._lock:
            self._framework_routes = [
                existing for existing in self._framework_routes if existing.name != model.name
            ]
            self._framework_routes.append(model)

    def register_callable(self, model: CallableSummaryModel) -> None:
        with self._lock:
            self._callables_by_name[model.qualified_name] = model
            parts = model.qualified_name.split(".")
            if len(parts) >= 2:
                suffix = ".".join(parts[-2:])
                bucket = self._callables_by_suffix.setdefault(suffix, [])
                bucket[:] = [m for m in bucket if m.qualified_name != model.qualified_name]
                bucket.append(model)

    def load_dict(self, payload: Mapping[str, Any]) -> None:
        """Load models from a parsed JSON/YAML-style mapping."""
        for raw_dec in payload.get("decorators", ()):
            self.register_decorator(DecoratorModel.from_dict(raw_dec))
        for raw_fw in payload.get("framework_routes", ()):
            self.register_framework_route(FrameworkRouteModel.from_dict(raw_fw))
        for raw_call in payload.get("callables", ()):
            self.register_callable(CallableSummaryModel.from_dict(raw_call))

    def load_json_file(self, path: str | Path) -> None:
        """Load additional declarative models from a JSON file on disk."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, Mapping):
            raise ValueError(f"Expected JSON object in model file: {path}")
        self.load_dict(data)

    def lookup_decorator(self, qualified_name: str) -> DecoratorModel | None:
        """Look up a decorator model by exact qualified name."""
        with self._lock:
            direct = self._decorators_by_name.get(qualified_name)
            if direct is not None:
                return direct
            # Try builtins prefix for bare builtin decorators (`property`, `classmethod`).
            if "." not in qualified_name:
                return self._decorators_by_name.get(f"builtins.{qualified_name}")
            return None

    def is_passthrough_class_decorator(self, qualified_name: str) -> bool:
        """Whether *qualified_name* is known to preserve a decorated class's identity."""
        model = self.lookup_decorator(qualified_name)
        return model is not None and model.is_passthrough and model.target_kind in {"class", "any"}

    def is_passthrough_function_decorator(self, qualified_name: str) -> bool:
        """Whether *qualified_name* is known to preserve a decorated function's identity."""
        model = self.lookup_decorator(qualified_name)
        return (
            model is not None and model.is_passthrough and model.target_kind in {"function", "any"}
        )

    def lookup_callable(self, qualified_name: str) -> CallableSummaryModel | None:
        """Look up a callable summary model by exact name or unambiguous 2-part suffix."""
        with self._lock:
            direct = self._callables_by_name.get(qualified_name)
            if direct is not None:
                return direct
            if "." not in qualified_name:
                return self._callables_by_name.get(f"builtins.{qualified_name}")
            parts = qualified_name.split(".")
            suffix = ".".join(parts[-2:])
            matches = self._callables_by_suffix.get(suffix, ())
            if len(matches) == 1:
                return matches[0]
            return None

    def framework_routes(
        self, *, entrypoint_kinds: Iterable[str] | None = None
    ) -> tuple[FrameworkRouteModel, ...]:
        """Return registered framework route models, optionally filtered by kind."""
        allowed = frozenset(entrypoint_kinds) if entrypoint_kinds is not None else None
        with self._lock:
            if allowed is None:
                return tuple(self._framework_routes)
            return tuple(
                model for model in self._framework_routes if model.entrypoint_kind in allowed
            )

    def factory_classes(self, *, entrypoint_kinds: Iterable[str] | None = None) -> frozenset[str]:
        return frozenset(
            cls
            for model in self.framework_routes(entrypoint_kinds=entrypoint_kinds)
            for cls in model.factory_classes
        )

    def decorator_methods(self, *, entrypoint_kinds: Iterable[str] | None = None) -> frozenset[str]:
        return frozenset(
            method
            for model in self.framework_routes(entrypoint_kinds=entrypoint_kinds)
            for method in model.decorator_methods
        )

    def hint_tokens(self, *, entrypoint_kinds: Iterable[str] | None = None) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for model in self.framework_routes(entrypoint_kinds=entrypoint_kinds):
            for token in model.hint_tokens:
                seen[token] = None
        return tuple(seen)

    def all_callables(self) -> tuple[CallableSummaryModel, ...]:
        with self._lock:
            return tuple(self._callables_by_name.values())

    def all_decorators(self) -> tuple[DecoratorModel, ...]:
        with self._lock:
            seen: list[DecoratorModel] = []
            for model in self._decorators_by_name.values():
                if model not in seen:
                    seen.append(model)
            return tuple(seen)

    def clone(self) -> "LibraryModelRegistry":
        """Create an isolated copy (useful for per-project packs and tests)."""
        copy = LibraryModelRegistry()
        with self._lock:
            for dec in self.all_decorators():
                copy.register_decorator(dec)
            for fw in self._framework_routes:
                copy.register_framework_route(fw)
            for call in self._callables_by_name.values():
                copy.register_callable(call)
        return copy


_DEFAULT_REGISTRY: LibraryModelRegistry | None = None
_DEFAULT_REGISTRY_LOCK = threading.RLock()


def default_library_models() -> LibraryModelRegistry:
    """Return the process-wide default :class:`LibraryModelRegistry` loaded from JSON."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is not None:
        return _DEFAULT_REGISTRY
    with _DEFAULT_REGISTRY_LOCK:
        if _DEFAULT_REGISTRY is None:
            registry = LibraryModelRegistry()
            if _BUILTIN_MODELS_PATH.is_file():
                registry.load_json_file(_BUILTIN_MODELS_PATH)
            _DEFAULT_REGISTRY = registry
        return _DEFAULT_REGISTRY


def load_library_models(
    extra_model_files: Iterable[str | Path] = (),
    *,
    include_builtins: bool = True,
) -> LibraryModelRegistry:
    """Build a :class:`LibraryModelRegistry`, optionally extending the bundled defaults."""
    registry = default_library_models().clone() if include_builtins else LibraryModelRegistry()
    for file_path in extra_model_files:
        registry.load_json_file(file_path)
    return registry


__all__ = [
    "CallableSummaryModel",
    "DecoratorModel",
    "FrameworkRouteModel",
    "LIBRARY_MODELS_SCHEMA_VERSION",
    "LibraryModelRegistry",
    "default_library_models",
    "load_library_models",
]
