from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO


class ColoredFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
    }
    RESET = "\033[0m"

    def __init__(self, fmt: str | None = None, no_color: bool = False):
        super().__init__(fmt)
        self.no_color = no_color

    def format(self, record: logging.LogRecord) -> str:
        if not self.no_color and record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
        return super().format(record)


class FileFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        record.timestamp = datetime.now().isoformat()
        return super().format(record)


def setup_logging(
    level: str = "INFO",
    log_file: Path | str | None = None,
    no_color: bool = False,
    stream: TextIO | None = None,
) -> None:
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    root_logger.handlers.clear()
    
    console_handler = logging.StreamHandler(stream or sys.stderr)
    console_handler.setLevel(logging.DEBUG)
    console_fmt = "%(levelname)s: %(message)s"
    console_handler.setFormatter(ColoredFormatter(console_fmt, no_color=no_color))
    root_logger.addHandler(console_handler)
    
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        file_handler.setFormatter(logging.Formatter(file_fmt))
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


class LoggerAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        extra = kwargs.get("extra", {})
        extra.update(self.extra)
        kwargs["extra"] = extra
        return msg, kwargs


def create_file_logger(
    name: str,
    path: Path | str,
    level: str = "DEBUG",
    fmt: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    handler = logging.FileHandler(path)
    handler.setLevel(getattr(logging, level.upper()))
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)
    
    return logger


class ContextFilter(logging.Filter):
    def __init__(self, context: dict[str, Any] | None = None):
        super().__init__()
        self.context = context or {}

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in self.context.items():
            setattr(record, key, value)
        return True


class TeeHandler(logging.Handler):
    def __init__(self, *handlers: logging.Handler):
        super().__init__()
        self.handlers = handlers

    def emit(self, record: logging.LogRecord) -> None:
        for handler in self.handlers:
            handler.emit(record)

    def close(self) -> None:
        for handler in self.handlers:
            handler.close()
        super().close()
