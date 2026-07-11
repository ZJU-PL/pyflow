"""
CPG rule pack loader — reuses the IFDS registry JSON rule packs.

Loads framework-specific source/sink/sanitizer lists from the existing
JSON files under ``pyflow.analysis.ifds.clients.registry/`` and
converts them into :class:`CPGTaintEngine` configuration.

Usage::

    from pyflow.analysis.cpg.rules import load_rules

    engine = CPGTaintEngine(cpg)
    load_rules(engine, frameworks=["django", "flask"])
    paths = engine.find_taint_paths()
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from pyflow.analysis.cpg.taint import CPGTaintEngine

_RULES_DIR = Path(__file__).parent.parent / "ifds" / "clients" / "registry"

_FRAMEWORK_FILES: Dict[str, str] = {
    "django": "django.json",
    "flask": "flask.json",
    "fastapi": "fastapi.json",
    "sqlalchemy": "sqlalchemy.json",
    "stdlib": "stdlib.json",
    "cloud": "cloud.json",
    "concurrency": "concurrency.json",
    "injection": "injection.json",
    "network": "network.json",
    "nosql": "nosql.json",
    "requests": "requests.json",
    "sql": "sql.json",
}


def _load_pack(framework: str) -> Optional[dict]:
    filename = _FRAMEWORK_FILES.get(framework)
    if filename is None:
        return None
    path = _RULES_DIR / filename
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_rules(
    engine: CPGTaintEngine,
    *,
    frameworks: Optional[List[str]] = None,
) -> CPGTaintEngine:
    """Load source/sink/sanitizer rules from IFDS registry packs into
    a :class:`CPGTaintEngine`.

    When *frameworks* is ``None``, loads all available packs.

    Returns *engine* for chaining.
    """
    names = frameworks if frameworks else list(_FRAMEWORK_FILES.keys())
    for fw in names:
        data = _load_pack(fw)
        if data is None:
            continue
        models: List[dict] = data.get("models", [])
        for m in models:
            call_name = m.get("call", "")
            if not call_name:
                continue
            if m.get("taint_source"):
                engine.add_source(call_name)
            if m.get("taint_sink"):
                cwe = m.get("cwe", "")
                if not cwe and "rules" in data:
                    for rule in data.get("rules", []):
                        if call_name in rule.get("calls", ()):
                            cwe = rule.get("cwe", "")
                            break
                engine.add_sink(call_name, cwe=cwe)
            if m.get("taint_sanitizer"):
                engine.add_sanitizer(call_name)
    return engine


def load_taint_specs(
    engine: CPGTaintEngine,
    path: str | Path,
) -> CPGTaintEngine:
    """Load an Ansede-style taint specification JSON file.

    The supported shape is:
    ``{"sources": {"python": [...]}, "sinks": {...}, "sanitizers": {...}}``.
    Entries may be strings or objects containing at least ``name``; sink objects
    may also contain ``cwe``.
    """
    spec_path = Path(path)
    with open(spec_path, encoding="utf-8") as f:
        specs: Dict[str, Any] = json.load(f)
    engine.merge_taint_specs(specs)
    return engine


def detect_frameworks(source: str) -> List[str]:
    """Detect which frameworks are used in *source* via simple import matching.

    Returns a list of framework names that should have their rules loaded.
    """
    detected: Set[str] = set()
    source_lower = source.lower()
    for fw in _FRAMEWORK_FILES:
        data = _load_pack(fw)
        if data is None:
            continue
        detection = data.get("detection", {})
        for imp in detection.get("imports", []):
            if imp.lower() in source_lower:
                detected.add(fw)
                break
        for pat in detection.get("patterns", []):
            if pat.lower() in source_lower:
                detected.add(fw)
                break
    if not detected:
        detected.add("stdlib")
    return sorted(detected)
