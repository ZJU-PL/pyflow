from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JsonStore:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        safe = key.replace("/", "_")
        return self.root / f"{safe}.json"

    def read(self, key: str, default: Any = None) -> Any:
        path = self._path(key)
        if not path.exists():
            return default
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def write(self, key: str, value: Any) -> None:
        path = self._path(key)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(value, fh, sort_keys=True)
