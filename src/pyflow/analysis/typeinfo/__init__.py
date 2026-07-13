"""Lightweight type-information collection for analysis clients.

This package contains both PyFlow's native type-info collector and
migrated type-system facilities from Pynguin.
"""

from typing import Any

from .collector import (
    TypeEvidence,
    TypeInfo,
    collect_pyflow_type_info,
    collect_python_type_info,
)
from .annotation_resolver import (
    BuiltinTypeLookup,
    TypeLookup,
    resolve_annotation,
    resolve_forward_reference,
)
from .stub_loader import (
    ResolvedStub,
    StubClassInfo,
    StubDiagnostic,
    StubFunctionInfo,
    StubInfo,
    StubResolver,
    build_stub_map,
    parse_stub_file,
    parse_stub_source,
)

from . import _config as config
from . import annotation_resolver
from . import docstring_parser
from . import generic_binder
from . import gradual_typing
from . import string_subtypes
from . import string_subtype_inference
from . import stub_loader
from . import type_utils
from . import typetracing
from . import typesystem

__all__ = [
    "TypeEvidence",
    "TypeInfo",
    "BuiltinTypeLookup",
    "ResolvedStub",
    "StubClassInfo",
    "StubDiagnostic",
    "StubFunctionInfo",
    "StubInfo",
    "StubResolver",
    "TypeLookup",
    "annotation_resolver",
    "build_stub_map",
    "collect_pyflow_type_info",
    "collect_python_type_info",
    "config",
    "docstring_parser",
    "generic_binder",
    "gradual_typing",
    "string_subtypes",
    "string_subtype_inference",
    "stub_loader",
    "parse_stub_file",
    "parse_stub_source",
    "resolve_annotation",
    "resolve_forward_reference",
    "type_inference",
    "type_utils",
    "typetracing",
    "typesystem",
]


def __getattr__(name: str) -> Any:
    """Lazy-import type_inference to avoid a static-analysis import cycle."""
    if name == "type_inference":
        import importlib

        return importlib.import_module(".type_inference", __package__)
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
