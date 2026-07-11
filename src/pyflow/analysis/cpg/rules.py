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
                san_cwe = m.get("cwe", "")
                if not san_cwe and "rules" in data:
                    for rule in data.get("rules", []):
                        if call_name in rule.get("calls", ()):
                            san_cwe = rule.get("cwe", "")
                            break
                engine.add_sanitizer(
                    call_name,
                    cwes={san_cwe} if san_cwe else None,
                )
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


def load_yaml_rules(
    engine: CPGTaintEngine,
    path: str | Path,
) -> CPGTaintEngine:
    """Load an Ansede-style YAML rule pack into the taint engine.

    Supports two YAML schemas:

    1. **Registry pack** (same shape as IFDS JSON registry)::

           language: python
           framework: flask
           rules:
             - id: "..."
               cwe: CWE-89
               severity: high
               pattern_type: taint_sink
               sinks: ["cursor.execute("]

    2. **Taint spec** (same shape as taint_specs.json)::

           sources:
             python:
               - {name: "request.args", cwe: "CWE-20"}
           sinks:
             python:
               - {name: "cursor.execute", cwe: "CWE-89"}
           sanitizers:
             python:
               - {name: "html.escape", cwe: ["CWE-79"]}

    Requires ``pyyaml`` (not a core dependency; install separately).
    """
    try:
        import yaml
    except ImportError as exc:
        raise ImportError(
            "load_yaml_rules requires pyyaml. "
            "Install it with: pip install pyyaml"
        ) from exc

    yaml_path = Path(path)
    with open(yaml_path, encoding="utf-8") as f:
        data: Dict[str, Any] = yaml.safe_load(f)

    if "sources" in data or "sinks" in data or "sanitizers" in data:
        engine.merge_taint_specs(data)
        return engine

    _apply_registry_yaml(engine, data)
    return engine


def _apply_registry_yaml(engine: CPGTaintEngine, data: Dict[str, Any]) -> None:
    rules = data.get("rules", [])
    for rule in rules:
        pattern_type = rule.get("pattern_type", "")
        cwe = rule.get("cwe", "")
        if pattern_type == "taint_sink":
            sinks = rule.get("sinks", [])
            if isinstance(sinks, str):
                sinks = [sinks]
            for sink in sinks:
                clean = sink.rstrip("(= ")
                engine.add_sink(clean, cwe=cwe or clean)
        elif pattern_type == "taint_source":
            sources = rule.get("sources", [])
            if isinstance(sources, str):
                sources = [sources]
            for src in sources:
                clean = src.rstrip("(= ")
                engine.add_source(clean)
        elif pattern_type == "regex":
            regex = rule.get("regex", "")
            if regex:
                cwe = rule.get("cwe", "CWE-0")
                engine.add_sink(f"regex:{regex}", cwe=cwe)
