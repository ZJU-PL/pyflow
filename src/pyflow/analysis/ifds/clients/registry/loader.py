"""Framework-aware lazy rule-pack loader.

Loads JSON rule packs on demand based on framework detection via import
string matching.  Packs are cached per process — each is parsed once.

Usage::

    from pyflow.analysis.ifds.clients.registry import load_registry

    registry = load_registry()
    registry.detect(["from flask import Flask", "open('file')"])
    models = registry.active_models()
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, Iterable, Mapping, Sequence

from .._call_model import (
    STATE_CLOSE,
    STATE_OPEN,
    STATE_USE,
    CallModel,
    CallModelRegistry,
)
from ..typestate_engine import typestate_action_for_protocol

_log = logging.getLogger(__name__)

# JSON rule packs live under src/pyflow/config/ — resolve relative to this file
_REGISTRY_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent / "config"
RULE_PACK_SCHEMA_VERSION = 1
_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_KNOWN_TYPES = frozenset({"taint", "typestate", "nullness"})


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    message: str
    severity: str = "error"


class RulePackValidationError(ValueError):
    def __init__(self, path: Path, issues: Sequence[ValidationIssue]) -> None:
        self.path = path
        self.issues = tuple(issues)
        super().__init__(
            f"Invalid IFDS rule pack {path.name}: "
            + "; ".join(issue.message for issue in issues)
        )


@dataclass(frozen=True)
class RuleMetadata:
    """Security metadata attached to a registry rule."""

    rule_id: str
    title: str
    cwe: str | None = None
    severity: str | None = None
    suggestion: str | None = None
    calls: tuple[str, ...] = ()
    pattern_type: str = "call_model"


class RulePack:
    """A single framework rule pack loaded from a JSON file."""

    def __init__(self, data: dict, *, source_path: Path | None = None) -> None:
        self.schema_version: int = data.get("schema_version", 0)
        self.version: str = str(data.get("version", ""))
        self.source_path = source_path
        self.framework: str = data.get("framework", "unknown")
        self.type: str = data.get("type", "taint")
        self.description: str = data.get("description", "")
        self.detection: dict = data.get("detection", {})
        self._models_data: list[dict] = data.get("models", [])
        self._rules_data: list[dict] = data.get("rules", [])

    @property
    def detection_imports(self) -> tuple[str, ...]:
        return tuple(self.detection.get("imports", ()))

    @property
    def detection_patterns(self) -> tuple[str, ...]:
        return tuple(self.detection.get("patterns", ()))

    def matches(self, source_lines: Iterable[str]) -> bool:
        """Return True when *source_lines* indicate this framework is used."""
        text = "\n".join(source_lines)
        for imp in self.detection_imports:
            if imp in text:
                return True
        for pat in self.detection_patterns:
            if pat in text:
                return True
        return False

    def to_call_models(self) -> tuple[CallModel, ...]:
        models: list[CallModel] = []
        for entry in self._models_data:
            model = _call_model_from_entry(entry)
            if model is not None:
                models.append(model)
        for rule in self._rules_data:
            models.extend(_call_models_from_rule(rule))
        return tuple(models)

    def rule_metadata(self) -> tuple[RuleMetadata, ...]:
        metadata: list[RuleMetadata] = []
        for rule in self._rules_data:
            rule_id = str(rule.get("id", "")).strip()
            if not rule_id:
                continue
            metadata.append(
                RuleMetadata(
                    rule_id=rule_id,
                    title=str(rule.get("title", rule_id)),
                    cwe=_optional_str(rule.get("cwe")),
                    severity=_optional_str(rule.get("severity")),
                    suggestion=_optional_str(rule.get("suggestion")),
                    calls=tuple(_iter_rule_calls(rule)),
                    pattern_type=str(rule.get("pattern_type", "call_model")),
                )
            )
        return tuple(metadata)


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_string_set(value: object) -> FrozenSet[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value}) if value else frozenset()
    if isinstance(value, (list, tuple, set, frozenset)):
        return frozenset(str(item) for item in value if str(item))
    return frozenset()


def _parse_int_set(value: object, default: Iterable[int]) -> FrozenSet[int]:
    if value is None:
        return frozenset(default)
    values = value if isinstance(value, (list, tuple, set, frozenset)) else (value,)
    parsed: set[int] = set()
    for item in values:
        try:
            parsed.add(int(item))
        except (TypeError, ValueError):
            continue
    return frozenset(parsed)


def _taint_categories(entry: dict) -> FrozenSet[str]:
    return _parse_string_set(entry.get("categories")) | _parse_string_set(
        entry.get("category")
    )


def _call_model_from_entry(entry: dict) -> CallModel | None:
    name = str(entry.get("call", "")).strip()
    if not name:
        return None
    return CallModel(
        name=name,
        taint_source=entry.get("taint_source", False),
        taint_sink=entry.get("taint_sink", False),
        taint_sanitizer=entry.get("taint_sanitizer", False),
        taint_categories=_taint_categories(entry),
        sanitizer_categories=_parse_string_set(entry.get("sanitizer_categories")),
        sink_arg_positions=_parse_int_set(entry.get("sink_arg_positions"), [0]),
        rule_id=_optional_str(entry.get("rule_id")),
        cwe=_optional_str(entry.get("cwe")),
        severity=_optional_str(entry.get("severity")),
        suggestion=_optional_str(entry.get("suggestion")),
        nullness_nullable_return=entry.get("nullness_nullable_return", False),
        typestate_actions=_parse_typestate(entry),
        typestate_action_protocols=_parse_typestate_action_protocols(entry),
        resource_arg_positions=_parse_int_set(entry.get("resource_arg_positions"), [0]),
        track_method_receiver=entry.get("track_method_receiver", True),
        receiver_types=_parse_string_set(entry.get("receiver_types")),
        callee_qualnames=_parse_string_set(entry.get("callee_qualnames")),
        module_prefixes=_parse_string_set(entry.get("module_prefixes")),
    )


def _iter_rule_calls(rule: dict) -> tuple[str, ...]:
    names: list[str] = []
    for key in ("calls", "call", "sources", "sinks", "sanitizers"):
        raw = rule.get(key, ())
        if isinstance(raw, str):
            raw = (raw,)
        for name in raw or ():
            text = str(name).strip()
            if text and text not in names:
                names.append(text)
    return tuple(names)


def _call_models_from_rule(rule: dict) -> tuple[CallModel, ...]:
    pattern_type = str(rule.get("pattern_type", "")).strip().lower()
    taint_source = pattern_type == "taint_source"
    taint_sink = pattern_type == "taint_sink"
    taint_sanitizer = pattern_type == "taint_sanitizer"

    models: list[CallModel] = []
    for key, source, sink, sanitizer in (
        ("sources", True, False, False),
        ("sinks", False, True, False),
        ("sanitizers", False, False, True),
        ("calls", taint_source, taint_sink, taint_sanitizer),
        ("call", taint_source, taint_sink, taint_sanitizer),
    ):
        raw_names = rule.get(key, ())
        if isinstance(raw_names, str):
            raw_names = (raw_names,)
        for raw_name in raw_names or ():
            name = str(raw_name).strip()
            if not name:
                continue
            models.append(
                CallModel(
                    name=name,
                    taint_source=source,
                    taint_sink=sink,
                    taint_sanitizer=sanitizer,
                    taint_categories=_taint_categories(rule),
                    sanitizer_categories=_parse_string_set(
                        rule.get("sanitizer_categories")
                    ),
                    sink_arg_positions=_parse_int_set(
                        rule.get("sink_arg_positions"), [0]
                    ),
                    rule_id=_optional_str(rule.get("id")),
                    cwe=_optional_str(rule.get("cwe")),
                    severity=_optional_str(rule.get("severity")),
                    suggestion=_optional_str(rule.get("suggestion")),
                )
            )
    return tuple(models)


def _parse_typestate(entry: dict) -> FrozenSet[str]:
    explicit_actions = {
        action for action, _protocol in _parse_typestate_action_protocols(entry)
    }
    if explicit_actions:
        return frozenset(explicit_actions)
    actions: set[str] = set()
    if entry.get("typestate_open"):
        actions.add(STATE_OPEN)
    if entry.get("typestate_close"):
        actions.add(STATE_CLOSE)
    if entry.get("typestate_use"):
        actions.add(STATE_USE)
    return frozenset(actions)


def _parse_typestate_action_protocols(entry: dict) -> FrozenSet[tuple[str, str]]:
    protocol = _optional_str(entry.get("typestate_protocol"))
    raw_actions = (
        entry.get("typestate_action")
        if "typestate_action" in entry
        else entry.get("typestate_actions")
    )
    if protocol is None or raw_actions is None:
        return frozenset()
    pairs: set[tuple[str, str]] = set()
    for raw_action in _parse_string_set(raw_actions):
        engine_action = typestate_action_for_protocol(protocol, raw_action)
        if engine_action is not None:
            pairs.add((engine_action, protocol))
    return frozenset(pairs)


def _discover_pack_paths(base_dir: Path) -> list[Path]:
    """Yield all ``.json`` pack files under *base_dir*, including subdirectories.

    Subdirectories such as ``typestate/`` and ``nullness/`` are scanned
    one level deep.  Schema files (``*.schema.json``) are excluded.
    """
    paths: list[Path] = []
    for entry in sorted(base_dir.iterdir()):
        if entry.name.endswith(".schema.json"):
            continue
        if entry.is_dir():
            for child in sorted(entry.glob("*.json")):
                if not child.name.endswith(".schema.json"):
                    paths.append(child)
        elif entry.suffix == ".json":
            paths.append(entry)
    return paths


@lru_cache(maxsize=1)
def _available_packs() -> tuple[RulePack, ...]:
    packs: list[RulePack] = []
    for path in _discover_pack_paths(_REGISTRY_DIR):
        try:
            data = json.loads(path.read_text())
            issues = validate_rule_pack_data(data, path=path)
            if issues:
                raise RulePackValidationError(path, issues)
            packs.append(RulePack(data, source_path=path))
        except Exception:
            _log.debug("Failed to load rule pack %s", path.name, exc_info=True)
    return tuple(packs)


def validate_rule_pack_data(
    data: object, *, path: Path | None = None
) -> tuple[ValidationIssue, ...]:
    """Validate one rule pack without requiring a third-party schema library."""
    label = str(path or "<memory>")
    issues: list[ValidationIssue] = []

    def error(location: str, message: str) -> None:
        issues.append(ValidationIssue(f"{label}:{location}", message))

    if not isinstance(data, dict):
        error("$", "root must be an object")
        return tuple(issues)
    if data.get("schema_version") != RULE_PACK_SCHEMA_VERSION:
        error(
            "schema_version",
            f"must equal {RULE_PACK_SCHEMA_VERSION}",
        )
    for key in ("framework", "version", "type"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            error(key, "must be a non-empty string")
    raw_type = str(data.get("type", "")).strip()
    if raw_type and raw_type not in _KNOWN_TYPES:
        error(
            "type",
            f"must be one of {sorted(_KNOWN_TYPES)}, got {raw_type!r}",
        )

    models = data.get("models", [])
    if not isinstance(models, list):
        error("models", "must be an array")
        models = []
    for index, model in enumerate(models):
        location = f"models[{index}]"
        if not isinstance(model, dict):
            error(location, "must be an object")
            continue
        call = model.get("call")
        if not isinstance(call, str) or not call.strip():
            error(f"{location}.call", "must be a non-empty string")
        _validate_positions(model, location, error)
        severity = model.get("severity")
        if severity is not None and str(severity).lower() not in _SEVERITIES:
            error(f"{location}.severity", f"unknown severity {severity!r}")

    rules = data.get("rules", [])
    if not isinstance(rules, list):
        error("rules", "must be an array")
        rules = []
    seen_rule_ids: set[str] = set()
    for index, rule in enumerate(rules):
        location = f"rules[{index}]"
        if not isinstance(rule, dict):
            error(location, "must be an object")
            continue
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            error(f"{location}.id", "must be a non-empty string")
        elif rule_id in seen_rule_ids:
            error(f"{location}.id", f"duplicate rule id {rule_id!r}")
        else:
            seen_rule_ids.add(rule_id)
        if not isinstance(rule.get("title"), str) or not rule["title"].strip():
            error(f"{location}.title", "must be a non-empty string")
        if not tuple(_iter_rule_calls(rule)):
            error(location, "must reference at least one call")
        severity = rule.get("severity")
        if severity is not None and str(severity).lower() not in _SEVERITIES:
            error(f"{location}.severity", f"unknown severity {severity!r}")
        cwe = rule.get("cwe")
        if cwe is not None and not re_fullmatch_cwe(cwe):
            error(f"{location}.cwe", "must match CWE-<number>")
        _validate_positions(rule, location, error)
    return tuple(issues)


def _validate_positions(entry: dict, location: str, error) -> None:
    for key in ("sink_arg_positions", "resource_arg_positions"):
        value = entry.get(key)
        if value is None:
            continue
        if not isinstance(value, list) or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in value
        ):
            error(f"{location}.{key}", "must contain non-negative integers")


def re_fullmatch_cwe(value: object) -> bool:
    text = str(value)
    return text.startswith("CWE-") and text[4:].isdigit()


def validate_registry() -> tuple[ValidationIssue, ...]:
    """Validate every shipped rule pack and report all errors."""
    issues: list[ValidationIssue] = []
    # Track (framework, subdirectory) pairs; same framework name across
    # different subdirectory levels (e.g. root + taint/ + typestate/ + nullness/)
    # is intentional — each file covers a different analysis concern.
    seen_frameworks: dict[str, dict[str, Path]] = {}
    seen_rule_ids: dict[str, dict[str, Path]] = {}
    for path in _discover_pack_paths(_REGISTRY_DIR):
        try:
            data = json.loads(path.read_text())
        except Exception as exc:
            issues.append(ValidationIssue(str(path), f"invalid JSON: {exc}"))
            continue
        issues.extend(validate_rule_pack_data(data, path=path))
        if not isinstance(data, dict):
            continue
        subdir = path.parent.relative_to(_REGISTRY_DIR).as_posix()
        framework = data.get("framework")
        if isinstance(framework, str):
            group = seen_frameworks.setdefault(framework, {})
            previous = group.get(subdir)
            if previous is not None:
                issues.append(
                    ValidationIssue(
                        str(path),
                        f"framework {framework!r} also defined by {previous.name} "
                        f"in the same directory {subdir!r}",
                    )
                )
            group[subdir] = path
        for rule in (
            data.get("rules", ()) if isinstance(data.get("rules"), list) else ()
        ):
            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
                continue
            rule_id = rule["id"]
            group = seen_rule_ids.setdefault(rule_id, {})
            previous = group.get(subdir)
            if previous is not None:
                issues.append(
                    ValidationIssue(
                        str(path),
                        f"rule id {rule_id!r} also defined by {previous.name} "
                        f"in the same directory {subdir!r}",
                    )
                )
            group[subdir] = path
    return tuple(issues)


class Registry:
    """Lazy-loaded, framework-aware and type-aware call model registry.

    Packs carry both a ``framework`` (stdlib, flask, django, …) and a ``type``
    (taint, typestate, nullness).  Activation and detection can be filtered by
    type so that callers load only the models relevant to their analysis.
    """

    _KNOWN_TYPES = _KNOWN_TYPES  # alias the module-level constant

    def __init__(self) -> None:
        self._active_packs: list[RulePack] = []
        self._activated_sources: set[int] = set()

    # ── helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _pack_type(pack: RulePack) -> str:
        return getattr(pack, "type", "taint")

    # ── activation & detection ───────────────────────────────────────

    def activate(
        self, *framework_names: str, type: str | None = None
    ) -> None:
        """Explicitly activate packs, optionally filtered by *type*."""
        for pack in _available_packs():
            pid = id(pack)
            if pack.framework not in framework_names:
                continue
            if type is not None and self._pack_type(pack) != type:
                continue
            if pid not in self._activated_sources:
                self._activated_sources.add(pid)
                self._active_packs.append(pack)

    def detect(
        self, source_lines: Iterable[str], *, type: str | None = None
    ) -> FrozenSet[str]:
        """Scan *source_lines* for framework markers and activate matching packs."""
        lines = tuple(source_lines)
        detected_frameworks: set[str] = set()
        for pack in _available_packs():
            pid = id(pack)
            if pid in self._activated_sources:
                continue
            if type is not None and self._pack_type(pack) != type:
                continue
            if pack.matches(lines):
                self._activated_sources.add(pid)
                self._active_packs.append(pack)
                detected_frameworks.add(pack.framework)
        return frozenset(detected_frameworks)

    def activate_all(self, *, type: str | None = None) -> None:
        """Activate every available pack, optionally filtered by *type*."""
        for pack in _available_packs():
            pid = id(pack)
            if type is not None and self._pack_type(pack) != type:
                continue
            if pid not in self._activated_sources:
                self._activated_sources.add(pid)
                self._active_packs.append(pack)

    # ── introspection ────────────────────────────────────────────────

    @property
    def detected_frameworks(self) -> FrozenSet[str]:
        return frozenset(
            pack.framework for pack in self._active_packs
        )

    def available_frameworks(self, *, type: str | None = None) -> FrozenSet[str]:
        """Return all known framework names, optionally filtered by *type*."""
        return frozenset(
            pack.framework
            for pack in _available_packs()
            if type is None or self._pack_type(pack) == type
        )

    def available_types(self) -> FrozenSet[str]:
        """Return pack types known to the registry."""
        return self._KNOWN_TYPES

    # ── custom packs ─────────────────────────────────────────────────

    def load_custom(self, *paths: str | Path) -> None:
        """Load custom rule packs from JSON files or directories."""
        for raw in paths:
            path = Path(raw)
            if not path.exists():
                _log.warning("Custom registry path not found: %s", path)
                continue
            if path.is_dir():
                for child in sorted(path.glob("*.json")):
                    self._load_custom_file(child)
            else:
                self._load_custom_file(path)

    def _load_custom_file(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text())
        except Exception as exc:
            _log.warning("Failed to parse custom rule pack %s: %s", path.name, exc)
            return
        issues = validate_rule_pack_data(data, path=path)
        if issues:
            for issue in issues:
                _log.warning(
                    "Validation issue in %s: %s", path.name, issue.message
                )
            return
        pack = RulePack(data, source_path=path)
        self._active_packs.append(pack)

    # ── model access ─────────────────────────────────────────────────

    def active_models(
        self, *, type: str | None = None
    ) -> CallModelRegistry:
        """Return a ``CallModelRegistry`` merging active packs, optionally filtered by *type*."""
        models: list[CallModel] = []
        for pack in self._active_packs:
            if type is not None and self._pack_type(pack) != type:
                continue
            models.extend(pack.to_call_models())
        return CallModelRegistry(models)

    def active_rule_metadata(self) -> tuple[RuleMetadata, ...]:
        """Return reporting metadata for active rich registry rules."""
        metadata: list[RuleMetadata] = []
        for pack in self._active_packs:
            metadata.extend(pack.rule_metadata())
        return tuple(metadata)

    def as_config(
        self,
        *,
        extra_sources: Iterable[str] = (),
        extra_sinks: Iterable[str] = (),
        extra_sanitizers: Iterable[str] = (),
    ):
        """Build a ``TaintConfiguration`` from active taint models."""
        from ...clients.taint import TaintConfiguration

        models = self.active_models(type="taint")
        mapping = models.as_mapping()
        sources: set[str] = set(extra_sources)
        sinks: set[str] = set(extra_sinks)
        sanitizers: set[str] = set(extra_sanitizers)
        sanitizer_categories: dict[str, FrozenSet[str]] = {}
        for name, model in mapping.items():
            if model.taint_source:
                sources.add(name)
            if model.taint_sink:
                sinks.add(name)
            if model.taint_sanitizer:
                sanitizers.add(name)
                if model.sanitizer_categories:
                    sanitizer_categories[name] = model.sanitizer_categories
        return TaintConfiguration(
            source_names=frozenset(sources),
            sink_names=frozenset(sinks),
            sanitizer_names=frozenset(sanitizers),
            sanitizer_categories=sanitizer_categories,
        )

    def as_nullness_config(
        self,
        *,
        extra_nullable_returns: Iterable[str] = (),
    ):
        """Build a ``NullnessConfiguration`` from active nullness models."""
        from ...clients.nullness import NullnessConfiguration

        models = self.active_models(type="nullness")
        mapping = models.as_mapping()
        nullable_returns: set[str] = set(extra_nullable_returns)
        for name, model in mapping.items():
            if model.nullness_nullable_return:
                nullable_returns.add(name)
        return NullnessConfiguration(
            nullable_return_names=frozenset(nullable_returns),
            call_models=models,
        )

    def as_typestate_config(
        self,
        *,
        extra_open: Iterable[str] = (),
        extra_close: Iterable[str] = (),
        extra_use: Iterable[str] = (),
    ):
        """Build a ``TypestateConfiguration`` from active typestate models."""
        from ...clients.typestate import TypestateConfiguration
        from .._call_model import STATE_CLOSE, STATE_OPEN, STATE_USE

        models = self.active_models(type="typestate")
        mapping = models.as_mapping()
        open_names: set[str] = set(extra_open)
        close_names: set[str] = set(extra_close)
        use_names: set[str] = set(extra_use)
        protocol_names: set[str] = set()
        for name, model in mapping.items():
            if STATE_OPEN in model.typestate_actions:
                open_names.add(name)
            if STATE_CLOSE in model.typestate_actions:
                close_names.add(name)
            if STATE_USE in model.typestate_actions:
                use_names.add(name)
            for _action, protocol in model.typestate_action_protocols:
                protocol_names.add(protocol)
        return TypestateConfiguration(
            open_names=frozenset(open_names) if open_names else frozenset({"open"}),
            close_names=frozenset(close_names) if close_names else frozenset({"close"}),
            use_names=frozenset(use_names) if use_names else frozenset({"read", "write", "send", "recv"}),
            enabled_protocols=frozenset(protocol_names) if protocol_names else frozenset({"resource"}),
            call_models=models,
        )


def load_registry() -> Registry:
    """Return the singleton process-wide registry."""
    return Registry()
