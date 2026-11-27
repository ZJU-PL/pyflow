"""Isolated worker process for one project-scan attempt."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

from ..artifacts.replay import replay_runs
from ..exploration.engine import explore_file
from .audit import enabled_audit_wall

_TAG_KEY = "__pyflow_concolic_type__"


def encode_worker_value(value: Any) -> Any:
    """Encode Python values (including bytes/tuple/set/complex) into JSON-safe structures."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {_TAG_KEY: "bytes", "b64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, bytearray):
        return {_TAG_KEY: "bytearray", "b64": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, tuple):
        return {_TAG_KEY: "tuple", "items": [encode_worker_value(item) for item in value]}
    if isinstance(value, set):
        return {_TAG_KEY: "set", "items": [encode_worker_value(item) for item in value]}
    if isinstance(value, frozenset):
        return {_TAG_KEY: "frozenset", "items": [encode_worker_value(item) for item in value]}
    if isinstance(value, complex):
        return {_TAG_KEY: "complex", "real": value.real, "imag": value.imag}
    if isinstance(value, list):
        return [encode_worker_value(item) for item in value]
    if isinstance(value, dict):
        if all(isinstance(k, str) for k in value) and _TAG_KEY not in value:
            return {k: encode_worker_value(v) for k, v in value.items()}
        return {
            _TAG_KEY: "dict",
            "items": [[encode_worker_value(k), encode_worker_value(v)] for k, v in value.items()],
        }
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def decode_worker_value(value: Any) -> Any:
    """Decode tagged JSON structures back into Python values."""
    if isinstance(value, list):
        return [decode_worker_value(item) for item in value]
    if isinstance(value, dict):
        tag = value.get(_TAG_KEY)
        if tag == "bytes":
            return base64.b64decode(value["b64"].encode("ascii"))
        if tag == "bytearray":
            return bytearray(base64.b64decode(value["b64"].encode("ascii")))
        if tag == "tuple":
            return tuple(decode_worker_value(item) for item in value["items"])
        if tag == "set":
            return {decode_worker_value(item) for item in value["items"]}
        if tag == "frozenset":
            return frozenset(decode_worker_value(item) for item in value["items"])
        if tag == "complex":
            return complex(value["real"], value["imag"])
        if tag == "dict":
            return {decode_worker_value(k): decode_worker_value(v) for k, v in value["items"]}
        return {k: decode_worker_value(v) for k, v in value.items()}
    return value


def run_request(request: dict[str, Any]) -> dict[str, Any]:
    options = request.get("options", {})
    inputs = decode_worker_value(request["inputs"])
    if request.get("audit_wall", True):
        with enabled_audit_wall():
            result = explore_file(
                Path(request["path"]),
                entry=request["entry"],
                initial_inputs=inputs,
                **options,
            )
            replays = replay_runs(request["path"], request["entry"], result.runs)
    else:
        result = explore_file(
            Path(request["path"]),
            entry=request["entry"],
            initial_inputs=inputs,
            **options,
        )
        replays = replay_runs(request["path"], request["entry"], result.runs)
    return {
        "exploration": result.to_dict(),
        "replays": [replay.to_dict() for replay in replays],
    }


def main() -> int:
    try:
        request = json.load(sys.stdin)
        response = {"ok": True, "result": run_request(request)}
    except BaseException as error:
        response = {
            "ok": False,
            "error": {
                "type": type(error).__name__,
                "message": str(error),
            },
        }
    print(json.dumps(response, default=_json_default, sort_keys=True))
    return 0


def _json_default(value: Any) -> dict[str, str]:
    """Keep worker output valid when a target returns a non-JSON value."""
    return {"type": type(value).__name__, "repr": repr(value)}


if __name__ == "__main__":  # pragma: no cover - subprocess entry point
    raise SystemExit(main())
