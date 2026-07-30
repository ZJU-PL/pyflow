from __future__ import annotations

import os
from pathlib import Path


def validate_path(path: str | Path, must_exist: bool = False) -> Path:
    path = Path(path)
    
    if must_exist and not path.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")
    
    return path


def validate_env_var(var: str) -> tuple[str, str]:
    if "=" not in var:
        raise ValueError(f"Invalid environment variable format: {var}")
    
    key, value = var.split("=", 1)
    
    if not key:
        raise ValueError("Environment variable key cannot be empty")
    
    return key, value


def validate_port(port: int) -> int:
    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got {port}")
    return port


def validate_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"URL must start with http:// or https://: {url}")
    return url


class Validator:
    def __init__(self):
        self._errors: list[str] = []
    
    def add_error(self, message: str) -> None:
        self._errors.append(message)
    
    def validate_path(self, path: str | Path, must_exist: bool = False) -> Path | None:
        try:
            return validate_path(path, must_exist)
        except FileNotFoundError as e:
            self.add_error(str(e))
            return None
    
    def validate_port(self, port: int) -> int | None:
        try:
            return validate_port(port)
        except ValueError as e:
            self.add_error(str(e))
            return None
    
    @property
    def is_valid(self) -> bool:
        return len(self._errors) == 0
    
    @property
    def errors(self) -> list[str]:
        return list(self._errors)
    
    def clear(self) -> None:
        self._errors.clear()
