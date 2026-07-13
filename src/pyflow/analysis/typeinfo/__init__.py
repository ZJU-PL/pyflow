"""Lightweight type-information collection for analysis clients.

This package contains both PyFlow's native type-info collector and
migrated type-system facilities from Pynguin.
"""

from .collector import (
    TypeEvidence,
    TypeInfo,
    collect_pyflow_type_info,
    collect_python_type_info,
)

from . import _config as config
from . import string_subtypes
from . import string_subtype_inference
from . import type_utils
from . import typetracing
from . import typesystem

__all__ = [
    "TypeEvidence",
    "TypeInfo",
    "collect_pyflow_type_info",
    "collect_python_type_info",
    "config",
    "string_subtypes",
    "string_subtype_inference",
    "type_inference",
    "type_utils",
    "typetracing",
    "typesystem",
]


def __getattr__(name: str):
    """Lazy-import type_inference to avoid a static-analysis import cycle."""
    if name == "type_inference":
        import importlib

        return importlib.import_module(".type_inference", __package__)
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
