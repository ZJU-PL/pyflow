"""Isolated worker process for one project-scan attempt."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .engine import explore_file
from .replay import replay_runs


def run_request(request: dict[str, Any]) -> dict[str, Any]:
    options = request.get("options", {})
    result = explore_file(
        Path(request["path"]),
        entry=request["entry"],
        initial_inputs=request["inputs"],
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
