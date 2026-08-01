"""Framework-aware lazy rule-pack loader.

Loads JSON rule packs on demand based on framework detection via import
string matching.  Packs are cached per process — each is parsed once.

Usage::

    from pyflow.analysis.ifds.modeling.registry import load_registry

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
from typing import FrozenSet, Iterable, Sequence

from ..calls import (
    STATE_CLOSE,
    STATE_OPEN,
    STATE_USE,
    CallModel,
    CallModelRegistry,
)
from ..typestate import typestate_action_for_protocol
from pyflow.analysis.entrypoints import (
    EntryPointDefaults,
    EntryPointMode,
)
from pyflow.analysis.taint import TaintPolicy, TaintRule

_log = logging.getLogger(__name__)

# JSON rule packs live under src/pyflow/config/ — resolve relative to this file
_REGISTRY_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent / "config"
RULE_PACK_SCHEMA_VERSION = 2
_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_KNOWN_TYPES = frozenset({"taint", "typestate", "nullness"})
_ROOT_KEYS = frozenset(
    {
        "schema_version",
        "framework",
        "version",
        "type",
        "description",
        "detection",
        "entrypoints",
        "models",
        "rules",
    }
)
_MODEL_KEYS_BY_TYPE = {
    "taint": frozenset(
        {"call", "sources", "sinks", "sanitizers", "severity", "cwe", "suggestion"}
    ),
    "typestate": frozenset(
        {
            "call",
            "typestate_action",
            "typestate_protocol",
            "resource_arg_positions",
            "track_method_receiver",
            "receiver_types",
            "module_prefixes",
        }
    ),
    "nullness": frozenset({"call", "nullness_nullable_return"}),
}
_RULE_KEYS = frozenset(
    {"id", "title", "sources", "sinks", "severity", "cwe", "suggestion"}
)
_ENDPOINT_KEYS = frozenset({"kind", "port"})
_SANITIZER_KEYS = frozenset({"kinds", "port"})
_DETECTION_KEYS = frozenset({"imports", "patterns"})
_ENTRYPOINT_KEYS = frozenset({"mode", "include_synthetic_modules", "taint_parameters"})
_REQUIRED_ROOT_KEYS = frozenset(
    {"schema_version", "framework", "version", "type", "models", "rules"}
)


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
            f"Invalid PyFlow rule pack {path.name}: "
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
        self.entrypoints: dict = data.get("entrypoints", {})
        self._models_data: list[dict] = data.get("models", [])
        self._rules_data: list[dict] = data.get("rules", [])

    @property
    def detection_imports(self) -> tuple[str, ...]:
        return tuple(self.detection.get("imports", ()))

    @property
    def detection_patterns(self) -> tuple[str, ...]:
        return tuple(self.detection.get("patterns", ()))

    @property
    def entry_point_defaults(self) -> EntryPointDefaults:
        raw_mode = self.entrypoints.get("mode")
        return EntryPointDefaults(
            mode=EntryPointMode(raw_mode) if raw_mode is not None else None,
            include_synthetic_modules=self.entrypoints.get("include_synthetic_modules"),
            taint_parameters=self.entrypoints.get("taint_parameters"),
        )

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
        return tuple(models)

    def taint_rules(self) -> tuple[TaintRule, ...]:
        if self.type != "taint":
            return ()
        return tuple(_taint_rule_from_entry(rule) for rule in self._rules_data)

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
                    calls=(),
                    pattern_type="taint_flow",
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


def _taint_kinds(entries: object) -> FrozenSet[str]:
    if not isinstance(entries, list):
        return frozenset()
    return frozenset(
        str(entry.get("kind", "")).strip()
        for entry in entries
        if isinstance(entry, dict) and str(entry.get("kind", "")).strip()
    )


def _sink_positions(entries: object) -> FrozenSet[int]:
    if not isinstance(entries, list):
        return frozenset({0})
    positions: set[int] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        port = entry.get("port")
        if not isinstance(port, dict):
            continue
        parameter = port.get("parameter")
        if isinstance(parameter, int) and not isinstance(parameter, bool):
            positions.add(parameter)
    return frozenset(positions or {0})


def _sink_all_arguments(entries: object) -> bool:
    return isinstance(entries, list) and any(
        isinstance(entry, dict) and entry.get("port") == "all" for entry in entries
    )


def _sanitizer_kinds(entries: object) -> FrozenSet[str]:
    if not isinstance(entries, list):
        return frozenset()
    kinds: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("kinds", ())
        if raw == "all":
            kinds.add("*")
        else:
            kinds.update(_parse_string_set(raw))
    return frozenset(kinds)


def _call_model_from_entry(entry: dict) -> CallModel | None:
    name = str(entry.get("call", "")).strip()
    if not name:
        return None
    return CallModel(
        name=name,
        source_kinds=_taint_kinds(entry.get("sources")),
        sink_kinds=_taint_kinds(entry.get("sinks")),
        sanitizer_kinds=_sanitizer_kinds(entry.get("sanitizers")),
        sink_arg_positions=_sink_positions(entry.get("sinks")),
        sink_all_arguments=_sink_all_arguments(entry.get("sinks")),
        cwe=_optional_str(entry.get("cwe")),
        severity=_optional_str(entry.get("severity")),
        suggestion=_optional_str(entry.get("suggestion")),
        nullness_nullable_return=entry.get("nullness_nullable_return", False),
        typestate_actions=_parse_typestate(entry),
        typestate_action_protocols=_parse_typestate_action_protocols(entry),
        resource_arg_positions=_parse_int_set(entry.get("resource_arg_positions"), [0]),
        track_method_receiver=entry.get("track_method_receiver", True),
        receiver_types=_parse_string_set(entry.get("receiver_types")),
        module_prefixes=_parse_string_set(entry.get("module_prefixes")),
    )


def _taint_rule_from_entry(rule: dict) -> TaintRule:
    return TaintRule(
        rule_id=str(rule["id"]),
        title=str(rule["title"]),
        source_kinds=_parse_string_set(rule.get("sources")),
        sink_kinds=_parse_string_set(rule.get("sinks")),
        severity=str(rule.get("severity", "medium")),
        cwe=_optional_str(rule.get("cwe")),
        suggestion=_optional_str(rule.get("suggestion")),
    )


def _parse_typestate(entry: dict) -> FrozenSet[str]:
    explicit_actions = {
        action for action, _protocol in _parse_typestate_action_protocols(entry)
    }
    if explicit_actions:
        return frozenset(explicit_actions)
    return frozenset()


def _parse_typestate_action_protocols(entry: dict) -> FrozenSet[tuple[str, str]]:
    protocol = _optional_str(entry.get("typestate_protocol"))
    raw_actions = entry.get("typestate_action")
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
        data = json.loads(path.read_text())
        issues = validate_rule_pack_data(data, path=path)
        if issues:
            raise RulePackValidationError(path, issues)
        packs.append(RulePack(data, source_path=path))
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
    for key in sorted(set(data) - _ROOT_KEYS):
        error(key, "unknown schema-v2 field")
    for key in sorted(_REQUIRED_ROOT_KEYS - set(data)):
        error(key, "is required")
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
    detection = data.get("detection")
    if detection is not None:
        if not isinstance(detection, dict):
            error("detection", "must be an object")
        else:
            for key in sorted(set(detection) - _DETECTION_KEYS):
                error(f"detection.{key}", "unknown schema-v2 detection field")
            for key in ("imports", "patterns"):
                value = detection.get(key)
                if value is not None and (
                    not isinstance(value, list)
                    or any(not isinstance(item, str) for item in value)
                ):
                    error(f"detection.{key}", "must be an array of strings")

    entrypoints = data.get("entrypoints")
    if entrypoints is not None:
        if raw_type != "taint":
            error("entrypoints", "is only valid in taint packs")
        if not isinstance(entrypoints, dict):
            error("entrypoints", "must be an object")
        else:
            for key in sorted(set(entrypoints) - _ENTRYPOINT_KEYS):
                error(f"entrypoints.{key}", "unknown schema-v2 entrypoint field")
            mode = entrypoints.get("mode")
            if mode is not None and mode not in {item.value for item in EntryPointMode}:
                error("entrypoints.mode", "must be a supported entrypoint mode")
            for key in ("include_synthetic_modules", "taint_parameters"):
                value = entrypoints.get(key)
                if value is not None and not isinstance(value, bool):
                    error(f"entrypoints.{key}", "must be a boolean")

    models = data.get("models", [])
    if not isinstance(models, list):
        error("models", "must be an array")
        models = []
    for index, model in enumerate(models):
        location = f"models[{index}]"
        if not isinstance(model, dict):
            error(location, "must be an object")
            continue
        allowed_model_keys = _MODEL_KEYS_BY_TYPE.get(raw_type, frozenset({"call"}))
        for key in sorted(set(model) - allowed_model_keys):
            error(f"{location}.{key}", "unknown schema-v2 model field")
        call = model.get("call")
        if not isinstance(call, str) or not call.strip():
            error(f"{location}.call", "must be a non-empty string")
        legacy_keys = {
            "taint_source",
            "taint_sink",
            "taint_sanitizer",
            "category",
            "categories",
            "sanitizer_categories",
            "sink_arg_positions",
            "pattern_type",
        }
        for key in sorted(legacy_keys & model.keys()):
            error(f"{location}.{key}", "is not valid in schema v2")
        if raw_type == "taint":
            _validate_taint_model(model, location, error)
        elif raw_type == "typestate":
            for key in ("typestate_action", "typestate_protocol"):
                if not isinstance(model.get(key), str) or not model[key].strip():
                    error(f"{location}.{key}", "must be a non-empty string")
            _validate_positions(model, location, error)
        elif raw_type == "nullness":
            if model.get("nullness_nullable_return") is not True:
                error(
                    f"{location}.nullness_nullable_return",
                    "must be true",
                )
        else:
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
        for key in sorted(set(rule) - _RULE_KEYS):
            error(f"{location}.{key}", "unknown schema-v2 rule field")
        for key in ("id", "title", "sources", "sinks", "severity"):
            if key not in rule:
                error(f"{location}.{key}", "is required")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            error(f"{location}.id", "must be a non-empty string")
        elif rule_id in seen_rule_ids:
            error(f"{location}.id", f"duplicate rule id {rule_id!r}")
        else:
            seen_rule_ids.add(rule_id)
        if not isinstance(rule.get("title"), str) or not rule["title"].strip():
            error(f"{location}.title", "must be a non-empty string")
        if raw_type != "taint":
            error(location, "rules are only valid in taint packs")
        for key in ("sources", "sinks"):
            value = rule.get(key)
            if (
                not isinstance(value, list)
                or not value
                or any(not isinstance(item, str) or not item.strip() for item in value)
            ):
                error(f"{location}.{key}", "must contain non-empty kind names")
        for key in ("calls", "call", "pattern_type", "sink_arg_positions"):
            if key in rule:
                error(f"{location}.{key}", "is not valid in schema v2")
        severity = rule.get("severity")
        if severity is not None and str(severity).lower() not in _SEVERITIES:
            error(f"{location}.severity", f"unknown severity {severity!r}")
        cwe = rule.get("cwe")
        if cwe is not None and not re_fullmatch_cwe(cwe):
            error(f"{location}.cwe", "must match CWE-<number>")
    if raw_type == "taint":
        modeled_sink_kinds = {
            str(endpoint.get("kind"))
            for model in models
            if isinstance(model, dict)
            for endpoint in model.get("sinks", [])
            if isinstance(endpoint, dict) and endpoint.get("kind")
        }
        ruled_sink_kinds = {
            str(kind)
            for rule in rules
            if isinstance(rule, dict)
            for kind in rule.get("sinks", [])
        }
        for kind in sorted(modeled_sink_kinds - ruled_sink_kinds):
            error("rules", f"sink kind {kind!r} has no source-to-sink rule")
        for kind in sorted(ruled_sink_kinds - modeled_sink_kinds):
            error("rules", f"rule references unmodeled sink kind {kind!r}")
    return tuple(issues)


def _validate_taint_model(entry: dict, location: str, error) -> None:
    if not any(entry.get(key) for key in ("sources", "sinks", "sanitizers")):
        error(location, "must define at least one source, sink, or sanitizer")
    for key in ("sources", "sinks"):
        endpoints = entry.get(key, [])
        if not isinstance(endpoints, list):
            error(f"{location}.{key}", "must be an array")
            continue
        for index, endpoint in enumerate(endpoints):
            endpoint_location = f"{location}.{key}[{index}]"
            if not isinstance(endpoint, dict):
                error(endpoint_location, "must be an object")
                continue
            for field in sorted(set(endpoint) - _ENDPOINT_KEYS):
                error(f"{endpoint_location}.{field}", "unknown endpoint field")
            kind = endpoint.get("kind")
            if not isinstance(kind, str) or not kind.strip():
                error(f"{endpoint_location}.kind", "must be a non-empty string")
            port = endpoint.get("port")
            if key == "sources" and port != "return":
                error(f"{endpoint_location}.port", "source port must be 'return'")
            if key == "sinks" and port != "all" and not _valid_parameter_port(port):
                error(
                    f"{endpoint_location}.port",
                    "sink port must be 'all' or contain a non-negative parameter index",
                )

    sanitizers = entry.get("sanitizers", [])
    if not isinstance(sanitizers, list):
        error(f"{location}.sanitizers", "must be an array")
        return
    for index, sanitizer in enumerate(sanitizers):
        sanitizer_location = f"{location}.sanitizers[{index}]"
        if not isinstance(sanitizer, dict):
            error(sanitizer_location, "must be an object")
            continue
        for field in sorted(set(sanitizer) - _SANITIZER_KEYS):
            error(f"{sanitizer_location}.{field}", "unknown sanitizer field")
        kinds = sanitizer.get("kinds")
        if kinds != "all" and (
            not isinstance(kinds, list)
            or not kinds
            or any(not isinstance(kind, str) or not kind.strip() for kind in kinds)
        ):
            error(
                f"{sanitizer_location}.kinds",
                "must be 'all' or a non-empty array of kind names",
            )
        if sanitizer.get("port") != "return":
            error(
                f"{sanitizer_location}.port",
                "only return sanitizers are currently supported",
            )


def _valid_parameter_port(port: object) -> bool:
    if not isinstance(port, dict) or set(port) != {"parameter"}:
        return False
    parameter = port["parameter"]
    return (
        isinstance(parameter, int)
        and not isinstance(parameter, bool)
        and parameter >= 0
    )


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
        self._activated_sources: set[tuple[str, str, str, str]] = set()

    # ── helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _pack_type(pack: RulePack) -> str:
        return getattr(pack, "type", "taint")

    @classmethod
    def _pack_key(cls, pack: RulePack) -> tuple[str, str, str, str]:
        return (
            str(pack.source_path or ""),
            pack.framework,
            cls._pack_type(pack),
            pack.version,
        )

    # ── activation & detection ───────────────────────────────────────

    def activate(self, *framework_names: str, type: str | None = None) -> None:
        """Explicitly activate packs, optionally filtered by *type*."""
        available = self.available_frameworks(type=type)
        unknown = sorted(set(framework_names) - available)
        if unknown:
            raise ValueError(
                "Unknown PyFlow rule-pack framework(s): " + ", ".join(unknown)
            )
        for pack in _available_packs():
            pid = self._pack_key(pack)
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
            pid = self._pack_key(pack)
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
            pid = self._pack_key(pack)
            if type is not None and self._pack_type(pack) != type:
                continue
            if pid not in self._activated_sources:
                self._activated_sources.add(pid)
                self._active_packs.append(pack)

    # ── introspection ────────────────────────────────────────────────

    @property
    def detected_frameworks(self) -> FrozenSet[str]:
        return frozenset(pack.framework for pack in self._active_packs)

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
                raise FileNotFoundError(f"Custom registry path not found: {path}")
            if path.is_dir():
                for child in sorted(path.glob("*.json")):
                    self._load_custom_file(child)
            else:
                self._load_custom_file(path)

    def _load_custom_file(self, path: Path) -> None:
        data = json.loads(path.read_text())
        issues = validate_rule_pack_data(data, path=path)
        if issues:
            raise RulePackValidationError(path, issues)
        pack = RulePack(data, source_path=path)
        self._active_packs.append(pack)

    # ── model access ─────────────────────────────────────────────────

    def active_models(self, *, type: str | None = None) -> CallModelRegistry:
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

    def active_taint_rules(self) -> tuple[TaintRule, ...]:
        """Return typed source-to-sink policies from active taint packs."""
        rules: list[TaintRule] = []
        for pack in self._active_packs:
            rules.extend(pack.taint_rules())
        return tuple(rules)

    def as_config(
        self,
    ):
        """Build a ``TaintConfiguration`` from active taint models."""
        from ...analyses.taint import TaintConfiguration

        return TaintConfiguration(
            call_models=self.active_models(type="taint"),
            rules=self.active_taint_rules(),
        )

    def as_taint_policy(self) -> TaintPolicy:
        """Project active strict-v2 taint packs into an engine-neutral policy."""
        defaults = EntryPointDefaults()
        for pack in self._active_packs:
            if self._pack_type(pack) == "taint":
                defaults = defaults.overlay(pack.entry_point_defaults)
        return TaintPolicy.from_call_models(
            self.active_models(type="taint"),
            self.active_taint_rules(),
            entry_point_defaults=defaults,
        )

    def as_nullness_config(
        self,
        *,
        extra_nullable_returns: Iterable[str] = (),
    ):
        """Build a ``NullnessConfiguration`` from active nullness models."""
        from ...analyses.nullness import NullnessConfiguration

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
        from ...analyses.typestate import TypestateConfiguration

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
            use_names=(
                frozenset(use_names)
                if use_names
                else frozenset({"read", "write", "send", "recv"})
            ),
            enabled_protocols=(
                frozenset(protocol_names) if protocol_names else frozenset({"resource"})
            ),
            call_models=models,
        )


def load_registry() -> Registry:
    """Return the singleton process-wide registry."""
    return Registry()
