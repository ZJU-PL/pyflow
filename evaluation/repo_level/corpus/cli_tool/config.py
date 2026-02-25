from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class Config:
    name: str = "myproject"
    version: str = "0.1.0"
    author: str = ""
    description: str = ""
    
    build_dir: Path = field(default_factory=lambda: Path("build"))
    output_dir: Path = field(default_factory=lambda: Path("dist"))
    cache_dir: Path = field(default_factory=lambda: Path(".cache"))
    
    debug: bool = False
    verbose: int = 0
    
    env: dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        if isinstance(self.build_dir, str):
            self.build_dir = Path(self.build_dir)
        if isinstance(self.output_dir, str):
            self.output_dir = Path(self.output_dir)
        if isinstance(self.cache_dir, str):
            self.cache_dir = Path(self.cache_dir)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["build_dir"] = str(self.build_dir)
        data["output_dir"] = str(self.output_dir)
        data["cache_dir"] = str(self.cache_dir)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        return cls(**data)

    def save(self, path: Path | str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as f:
            json.dump(self.to_dict(), f, indent=2)

    def merge(self, other: dict[str, Any]) -> Config:
        data = self.to_dict()
        for key, value in other.items():
            if value is not None:
                data[key] = value
        return Config.from_dict(data)


def load_config(path: Path | str | None = None) -> Config:
    if path is None:
        path = _find_config_file()
        if path is None:
            return Config()
    
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    
    with path.open("r") as f:
        data = json.load(f)
    
    env_overrides = _load_env_overrides()
    data.update(env_overrides)
    
    return Config.from_dict(data)


def _find_config_file() -> Path | None:
    candidates = [
        Path("pytool.json"),
        Path("pytool.config.json"),
        Path(".pytool.json"),
        Path("config/pytool.json"),
    ]
    
    for candidate in candidates:
        if candidate.exists():
            return candidate
    
    return None


def _load_env_overrides() -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    
    prefix = "PYTOOL_"
    for key, value in os.environ.items():
        if key.startswith(prefix):
            config_key = key[len(prefix):].lower()
            if config_key in ("debug",):
                overrides[config_key] = value.lower() in ("1", "true", "yes")
            elif config_key in ("verbose",):
                overrides[config_key] = int(value)
            else:
                overrides[config_key] = value
    
    return overrides


class ConfigManager:
    def __init__(self, config_dir: Path | str = "."):
        self.config_dir = Path(config_dir)
        self._configs: dict[str, Config] = {}
    
    def get(self, name: str = "default") -> Config:
        if name not in self._configs:
            path = self.config_dir / f"{name}.json"
            if path.exists():
                self._configs[name] = load_config(path)
            else:
                self._configs[name] = Config()
        return self._configs[name]
    
    def set(self, name: str, config: Config) -> None:
        self._configs[name] = config
    
    def save(self, name: str = "default") -> None:
        if name in self._configs:
            path = self.config_dir / f"{name}.json"
            self._configs[name].save(path)
    
    def list(self) -> list[str]:
        configs = list(self._configs.keys())
        for path in self.config_dir.glob("*.json"):
            name = path.stem
            if name not in configs:
                configs.append(name)
        return sorted(configs)
