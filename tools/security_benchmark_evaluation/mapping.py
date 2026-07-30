"""Analyzer rule-to-CWE mappings independent from execution configuration."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


_CWE = re.compile(r"(?i)\bCWE[-_ ]?(\d+)\b")


def canonical_cwe(value: object) -> str | None:
    if isinstance(value, dict):
        value = value.get("id")
    if isinstance(value, int) and not isinstance(value, bool):
        return f"CWE-{value}"
    if not isinstance(value, str):
        return None
    match = _CWE.search(value)
    return f"CWE-{int(match.group(1))}" if match else None


def cwes_from(value: object) -> set[str]:
    values = value if isinstance(value, (list, tuple, set)) else [value]
    return {cwe for item in values if (cwe := canonical_cwe(item)) is not None}


@dataclass(frozen=True)
class RuleMapping:
    exact: Mapping[str, tuple[str, ...]]
    regex: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...]

    def cwes_for(self, rule_id: str | None) -> set[str]:
        if not rule_id:
            return set()
        result = set(self.exact.get(rule_id, ()))
        for pattern, cwes in self.regex:
            if pattern.search(rule_id):
                result.update(cwes)
        return result


class CweMappings:
    def __init__(self, engines: Mapping[str, RuleMapping] | None = None):
        self.engines = dict(engines or {})

    @classmethod
    def load(cls, path: str | Path | None) -> "CweMappings":
        if path is None:
            return cls()
        mapping_path = Path(path)
        try:
            payload = json.loads(mapping_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot load CWE mapping {mapping_path}: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise ValueError("CWE mapping must be an object with schema_version 1")
        raw_engines = payload.get("engines", {})
        if not isinstance(raw_engines, dict):
            raise ValueError("CWE mapping engines must be an object")
        engines: dict[str, RuleMapping] = {}
        for engine, raw in raw_engines.items():
            if not isinstance(engine, str) or not isinstance(raw, dict):
                raise ValueError("each CWE engine mapping must be an object")
            exact_raw = raw.get("rules", {})
            if not isinstance(exact_raw, dict):
                raise ValueError(f"{engine}.rules must be an object")
            exact: dict[str, tuple[str, ...]] = {}
            for rule, values in exact_raw.items():
                if not isinstance(rule, str):
                    raise ValueError(f"{engine}.rules keys must be strings")
                exact[rule] = _required_cwes(values, f"{engine}.rules[{rule!r}]")
            regex_entries: list[tuple[re.Pattern[str], tuple[str, ...]]] = []
            raw_regex = raw.get("regex_rules", [])
            if not isinstance(raw_regex, list):
                raise ValueError(f"{engine}.regex_rules must be a list")
            for index, entry in enumerate(raw_regex):
                if not isinstance(entry, dict) or not isinstance(
                    entry.get("pattern"), str
                ):
                    raise ValueError(f"{engine}.regex_rules[{index}] is invalid")
                try:
                    pattern = re.compile(entry["pattern"])
                except re.error as exc:
                    raise ValueError(
                        f"invalid regex in {engine}.regex_rules[{index}]: {exc}"
                    ) from exc
                regex_entries.append(
                    (
                        pattern,
                        _required_cwes(
                            entry.get("cwes"), f"{engine}.regex_rules[{index}].cwes"
                        ),
                    )
                )
            engines[engine] = RuleMapping(exact, tuple(regex_entries))
        return cls(engines)

    def cwes_for(self, engine: str, rule_id: str | None) -> set[str]:
        result: set[str] = set()
        for key in ("*", engine):
            mapping = self.engines.get(key)
            if mapping:
                result.update(mapping.cwes_for(rule_id))
        return result


def _required_cwes(value: object, label: str) -> tuple[str, ...]:
    values = value if isinstance(value, list) else [value]
    cwes = tuple(sorted(cwes_from(values)))
    if not cwes:
        raise ValueError(f"{label} must contain at least one CWE")
    return cwes
