"""
CPG rule pack loader — reuses the IFDS registry JSON rule packs.

Loads framework-specific source/sink/sanitizer lists from the existing
JSON files under ``pyflow/config/`` and
converts them into :class:`CPGTaintEngine` configuration.

Usage::

    from pyflow.ir.cpg.rules import load_rules

    engine = CPGTaintEngine(cpg)
    load_rules(engine, frameworks=["django", "flask"])
    paths = engine.find_taint_paths()
"""

from __future__ import annotations

import json
from pathlib import Path
import logging
from functools import lru_cache
from typing import Any, Dict, List, Optional, Sequence, Set

from pyflow.ir.cpg.taint import CPGTaintEngine

# JSON rule packs live under src/pyflow/config/ — resolve relative to this file
_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "config"
_log = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _available_packs() -> Dict[str, Path]:
    """Auto-discover all registry packs by scanning the IFDS registry directory.

    Returns a mapping of framework name → JSON file path.  Only files with a
    valid ``framework`` field are included (``.schema.json`` is skipped).
    """
    packs: Dict[str, Path] = {}
    for path in sorted(_RULES_DIR.glob("*.json")):
        if path.name.endswith(".schema.json"):
            continue
        try:
            data = json.loads(path.read_text())
            fw = data.get("framework", "")
            if fw:
                packs[fw] = path
        except (json.JSONDecodeError, OSError):
            _log.debug("Skipping unreadable registry pack %s", path.name)
            continue
    return packs

_FRAMEWORK_ALIASES: Dict[str, str] = {
    "requests_lib": "requests",
    "subprocess_lib": "injection",
    "deserialization_py": "injection",
    "template_engines_py": "injection",
    "xml_parsers": "injection",
    "yaml_load": "injection",
    "pymongo": "nosql",
    "redis_py": "nosql",
    "boto3_aws": "cloud",
    "cloud_security": "cloud",
    "second_order_sql": "sql",
    "django_rest": "django",
}

_DETECTION_MARKERS: Dict[str, Dict[str, List[str]]] = {
    "django": {
        "imports": ["from django", "import django", "django.db", "django.http"],
        "patterns": ["RawSQL(", ".extra(", ".raw("],
    },
    "flask": {
        "imports": ["from flask", "import flask"],
        "patterns": ["Flask(", "@app.route", "@blueprint.route", "request.args"],
    },
    "fastapi": {
        "imports": ["from fastapi", "import fastapi"],
        "patterns": ["FastAPI(", "APIRouter(", "Depends(", "Request("],
    },
    "sqlalchemy": {
        "imports": ["from sqlalchemy", "import sqlalchemy"],
        "patterns": ["create_engine(", "session.execute(", "text("],
    },
    "requests": {
        "imports": ["import requests", "from requests", "import httpx"],
        "patterns": ["requests.get(", "requests.post(", "httpx.get("],
    },
    "injection": {
        "imports": [
            "import subprocess", "from subprocess", "import pickle",
            "import yaml", "import marshal", "import jsonpickle",
        ],
        "patterns": [
            "os.system(", "subprocess.run(", "eval(", "exec(",
            "pickle.loads(", "yaml.load(", "jsonpickle.decode(",
            "ElementTree.fromstring(",
        ],
    },
    "network": {
        "imports": ["import urllib", "from urllib", "import socket"],
        "patterns": ["urlopen(", "socket.connect("],
    },
    "nosql": {
        "imports": ["import pymongo", "from pymongo", "import redis", "from redis"],
        "patterns": ["MongoClient(", ".find(", "Redis("],
    },
    "cloud": {
        "imports": ["import boto3", "from boto3", "google.cloud"],
        "patterns": ["boto3.client(", "boto3.resource("],
    },
    "sql": {
        "imports": ["import sqlite3", "import psycopg2", "import pymysql"],
        "patterns": ["cursor.execute(", "executemany(", "executescript("],
    },
}


_FRAMEWORK_ALIASES: Dict[str, str] = {
    "requests_lib": "requests",
    "subprocess_lib": "injection",
    "deserialization_py": "injection",
    "template_engines_py": "injection",
    "xml_parsers": "injection",
    "yaml_load": "injection",
    "pymongo": "nosql",
    "redis_py": "nosql",
    "boto3_aws": "cloud",
    "cloud_security": "cloud",
    "second_order_sql": "sql",
    "django_rest": "django",
}


def _canonical_framework(name: str) -> str:
    return _FRAMEWORK_ALIASES.get(name, name)


def _load_pack(framework: str) -> Optional[dict]:
    packs = _available_packs()
    fw = _canonical_framework(framework)
    path = packs.get(fw)
    if path is None:
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _load_custom_pack(path: Path) -> Optional[dict]:
    """Load and validate a single custom rule-pack JSON file."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        _log.warning("Failed to parse custom rule pack %s: %s", path.name, exc)
        return None
    if not isinstance(data, dict) or "models" not in data:
        _log.warning("Custom rule pack %s has no 'models' array — skipped", path.name)
        return None
    return data


def _apply_registry_data(engine: CPGTaintEngine, data: dict) -> None:
    """Apply a single registry pack's models to a CPGTaintEngine."""
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


def load_rules(
    engine: CPGTaintEngine,
    *,
    frameworks: Optional[Sequence[str]] = None,
    custom_paths: Sequence[str | Path] = (),
) -> CPGTaintEngine:
    """Load source/sink/sanitizer rules from IFDS registry packs into
    a :class:`CPGTaintEngine`.

    When *frameworks* is ``None``, loads all available packs from the bundled
    IFDS registry directory.

    *custom_paths* may be JSON files or directories of JSON files following
    the same schema.  They are applied after bundled packs.

    Returns *engine* for chaining.
    """
    # Bundled packs
    pack_names = frameworks if frameworks is not None else list(_available_packs().keys())
    for fw in pack_names:
        data = _load_pack(_canonical_framework(fw))
        if data is not None:
            _apply_registry_data(engine, data)
    # Custom packs
    for raw in custom_paths:
        path = Path(raw)
        if not path.exists():
            _log.warning("Custom registry path not found: %s", path)
            continue
        if path.is_dir():
            for child in sorted(path.glob("*.json")):
                data = _load_custom_pack(child)
                if data is not None:
                    _apply_registry_data(engine, data)
        else:
            data = _load_custom_pack(path)
            if data is not None:
                _apply_registry_data(engine, data)
    return engine


def load_taint_specs(
    engine: CPGTaintEngine,
    path: str | Path,
    *,
    language: str = "python",
) -> CPGTaintEngine:
    """Load an Ansede-style taint specification JSON file.

    The supported shape is:
    ``{"sources": {"python": [...]}, "sinks": {...}, "sanitizers": {...}}``.
    Entries may be strings or objects containing at least ``name``; sink objects
    may also contain ``cwe``.

    Only entries matching *language* (default ``"python"``) from each section
    are loaded, so multi-language spec files are handled correctly.
    """
    spec_path = Path(path)
    with open(spec_path, encoding="utf-8") as f:
        specs: Dict[str, Any] = json.load(f)
    engine.merge_taint_specs(specs, language=language)
    return engine


def detect_frameworks(source: str) -> List[str]:
    """Detect which frameworks are used in *source* via simple import matching.

    Returns a list of framework names that should have their rules loaded.
    Falls back to ``stdlib`` when nothing is detected.
    """
    detected: Set[str] = set()
    source_lower = source.lower()

    for fw in set(_available_packs()) | set(_DETECTION_MARKERS) | set(_FRAMEWORK_ALIASES):
        data = _load_pack(fw)
        detection = dict(_DETECTION_MARKERS.get(_canonical_framework(fw), {}))
        if data is not None:
            pack_detection = data.get("detection", {})
            detection.setdefault("imports", [])
            detection.setdefault("patterns", [])
            detection["imports"].extend(pack_detection.get("imports", []))
            detection["patterns"].extend(pack_detection.get("patterns", []))
        for imp in detection.get("imports", []):
            if imp.lower() in source_lower:
                detected.add(_canonical_framework(fw))
                break
        for pat in detection.get("patterns", []):
            if pat.lower() in source_lower:
                detected.add(_canonical_framework(fw))
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
        engine.merge_taint_specs(data, language=data.get("language", "python"))
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
